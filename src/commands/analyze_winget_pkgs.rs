use std::{
    collections::{BTreeSet, HashMap},
    fs::File,
    io::{self, Seek, SeekFrom},
    num::NonZeroUsize,
    panic::{AssertUnwindSafe, catch_unwind},
    sync::Arc,
    time::Instant,
};

use anstream::println;
use camino::Utf8PathBuf;
use clap::Parser;
use color_eyre::{Result, eyre::ensure};
use futures_util::{StreamExt, stream};
use indicatif::MultiProgress;
use owo_colors::OwoColorize;
use serde::Serialize;
use tokio::{sync::Semaphore, task};
use walkdir::WalkDir;
use winget_types::{PackageVersion, installer::InstallerManifest, url::DecodedUrl};

use crate::{
    analysis::Analyzer,
    download::{DownloadAttemptStatus, Downloader},
    manifests::Url,
};

#[derive(Parser)]
#[clap(visible_alias = "analyze-all-installers")]
pub struct AnalyzeWingetPkgs {
    /// Path to a local winget-pkgs checkout
    #[arg(value_hint = clap::ValueHint::DirPath, default_value = ".")]
    path: Utf8PathBuf,

    /// Number of concurrent installer downloads
    #[arg(long, default_value_t = NonZeroUsize::new(num_cpus::get().saturating_mul(4)).unwrap())]
    concurrent_downloads: NonZeroUsize,

    /// Number of concurrent installer binary analyses
    #[arg(long, default_value_t = NonZeroUsize::new(num_cpus::get()).unwrap())]
    concurrent_analysis: NonZeroUsize,

    /// Number of concurrent installer manifest reads
    #[arg(long, default_value_t = NonZeroUsize::new(num_cpus::get()).unwrap())]
    concurrent_manifest_reads: NonZeroUsize,

    /// Output JSON report path
    #[arg(
        long,
        value_hint = clap::ValueHint::FilePath,
        default_value = "installer-analysis-report.json"
    )]
    report: Utf8PathBuf,

    /// Max failing URLs to print to stdout
    #[arg(long, default_value_t = 50)]
    max_failure_details: usize,
}

impl AnalyzeWingetPkgs {
    pub async fn run(self) -> Result<()> {
        ensure!(self.path.exists(), "{} does not exist", self.path);
        ensure!(self.path.is_dir(), "{} is not a directory", self.path);

        let started_at = chrono::Utc::now();
        let started = Instant::now();

        let installer_manifest_paths = self.get_installer_manifest_paths()?;

        let parse_outcomes =
            stream::iter(installer_manifest_paths.into_iter().map(|path| async move {
                task::spawn_blocking(move || parse_installer_manifest(path)).await
            }))
            .buffer_unordered(self.concurrent_manifest_reads.get())
            .collect::<Vec<_>>()
            .await;

        let mut installer_manifests_found = 0usize;
        let mut latest_manifests_by_package = HashMap::<String, ParsedInstallerManifest>::new();
        let mut manifest_errors = Vec::new();
        let mut manifest_panics = Vec::new();

        for outcome in parse_outcomes {
            match outcome {
                Ok(ManifestParseOutcome::Installer { manifest }) => {
                    installer_manifests_found += 1;
                    merge_latest_manifest(&mut latest_manifests_by_package, manifest);
                }
                Ok(ManifestParseOutcome::Error {
                    manifest_path,
                    message,
                }) => manifest_errors.push(ManifestFailure {
                    manifest_path,
                    message,
                }),
                Ok(ManifestParseOutcome::Panic {
                    manifest_path,
                    message,
                }) => manifest_panics.push(ManifestFailure {
                    manifest_path,
                    message,
                }),
                Err(join_error) => manifest_panics.push(ManifestFailure {
                    manifest_path: String::from("<unknown>"),
                    message: join_error.to_string(),
                }),
            }
        }

        let packages_analyzed = latest_manifests_by_package.len();

        let mut installers_by_url = HashMap::<DecodedUrl, Vec<InstallerReference>>::new();
        for manifest in latest_manifests_by_package.into_values() {
            for (url, reference) in manifest.installer_entries {
                installers_by_url.entry(url).or_default().push(reference);
            }
        }

        let installer_entries_total = installers_by_url.values().map(Vec::len).sum::<usize>();
        let unique_urls_total = installers_by_url.len();

        if let Some(parent) = self.report.parent()
            && !parent.as_str().is_empty()
        {
            tokio::fs::create_dir_all(parent).await?;
        }

        let mut report = build_report(
            &self,
            started_at,
            started.elapsed().as_millis(),
            installer_manifests_found,
            packages_analyzed,
            installer_entries_total,
            unique_urls_total,
            manifest_errors,
            manifest_panics,
            Vec::with_capacity(unique_urls_total),
        );

        write_report(&self.report, &report).await?;

        let downloader = Downloader::new_with_concurrent(self.concurrent_downloads)?;
        let multi_progress = MultiProgress::new();
        let analysis_limiter = Arc::new(Semaphore::new(self.concurrent_analysis.get()));
        let downloader = &downloader;

        let mut url_result_stream = stream::iter(installers_by_url.into_iter())
            .map(|(requested_url, references)| {
                let multi_progress = multi_progress.clone();
                let analysis_limiter = Arc::clone(&analysis_limiter);

                async move {
                    let download_status = downloader
                        .fetch_with_failure(
                            Url::from(requested_url.clone()).into(),
                            &multi_progress,
                        )
                        .await;

                    match download_status {
                        DownloadAttemptStatus::Success(downloaded_file) => {
                            let analysis_permit = match analysis_limiter.acquire_owned().await {
                                Ok(permit) => permit,
                                Err(error) => {
                                    return UrlAnalysisResult {
                                        url: requested_url.to_string(),
                                        references,
                                        status: AnalysisStatus::AnalysisPanic,
                                        message: Some(error.to_string()),
                                        info: None,
                                    };
                                }
                            };

                            let fallback_url = requested_url.to_string();
                            let references_on_join_error = references.clone();

                            match task::spawn_blocking(move || {
                                let _analysis_permit = analysis_permit;
                                analyze_download(requested_url, references, downloaded_file)
                            })
                            .await
                            {
                                Ok(result) => result,
                                Err(join_error) => UrlAnalysisResult {
                                    url: fallback_url,
                                    references: references_on_join_error,
                                    status: AnalysisStatus::AnalysisPanic,
                                    message: Some(join_error.to_string()),
                                    info: None,
                                },
                            }
                        }
                        DownloadAttemptStatus::Error(message) => UrlAnalysisResult {
                            url: requested_url.to_string(),
                            references,
                            status: AnalysisStatus::DownloadError,
                            message: Some(message),
                            info: None,
                        },
                        DownloadAttemptStatus::Panic(message) => UrlAnalysisResult {
                            url: requested_url.to_string(),
                            references,
                            status: AnalysisStatus::DownloadPanic,
                            message: Some(message),
                            info: None,
                        },
                    }
                }
            })
            .buffer_unordered(self.concurrent_downloads.get());

        while let Some(url_result) = url_result_stream.next().await {
            let status = url_result.status;

            match status {
                AnalysisStatus::Success => report.totals.success += 1,
                AnalysisStatus::DownloadError => report.totals.download_errors += 1,
                AnalysisStatus::DownloadPanic => report.totals.download_panics += 1,
                AnalysisStatus::AnalysisError => report.totals.analysis_errors += 1,
                AnalysisStatus::AnalysisPanic => report.totals.analysis_panics += 1,
            }

            if matches!(
                status,
                AnalysisStatus::AnalysisError | AnalysisStatus::AnalysisPanic
            ) {
                print_live_result(&url_result);
                report.results.push(url_result);
            }

            report.duration_ms = started.elapsed().as_millis();
            report.generated_at = chrono::Utc::now();
            write_report(&self.report, &report).await?;
        }

        let _ = multi_progress.clear();

        report.results.sort_unstable_by(|a, b| a.url.cmp(&b.url));
        report.duration_ms = started.elapsed().as_millis();
        report.generated_at = chrono::Utc::now();
        write_report(&self.report, &report).await?;

        print_summary(&report, self.max_failure_details);
        println!("{} {}", "Report written to".green(), self.report.blue());

        Ok(())
    }

    fn get_installer_manifest_paths(&self) -> walkdir::Result<Vec<Utf8PathBuf>> {
        let mut paths = Vec::new();

        for entry in WalkDir::new(&self.path) {
            let entry = entry?;
            let path = entry.path();

            let is_installer_manifest = path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.ends_with(".installer.yaml"));

            if is_installer_manifest
                && let Ok(path) = Utf8PathBuf::from_path_buf(path.to_path_buf())
            {
                paths.push(path);
            }
        }

        Ok(paths)
    }
}

fn parse_installer_manifest(path: Utf8PathBuf) -> ManifestParseOutcome {
    match catch_unwind(AssertUnwindSafe(|| -> Result<ParsedInstallerManifest> {
        let manifest = io::read_to_string(File::open(&path)?)?;
        let installer_manifest = serde_yaml::from_str::<InstallerManifest>(&manifest)?;

        let package_identifier = installer_manifest.package_identifier.to_string();
        let package_version = installer_manifest.package_version.clone();
        let manifest_path = path.to_string();

        let installer_entries = installer_manifest
            .installers
            .into_iter()
            .map(|installer| {
                let url = installer.url;
                let reference = InstallerReference {
                    manifest_path: manifest_path.clone(),
                    package_identifier: package_identifier.clone(),
                    package_version: package_version.to_string(),
                    architecture: installer.architecture.to_string(),
                    installer_type: installer.r#type.as_ref().map(ToString::to_string),
                };
                (url, reference)
            })
            .collect::<Vec<_>>();

        Ok(ParsedInstallerManifest {
            manifest_path,
            package_identifier,
            package_version,
            installer_entries,
        })
    })) {
        Ok(Ok(manifest)) => ManifestParseOutcome::Installer { manifest },
        Ok(Err(error)) => ManifestParseOutcome::Error {
            manifest_path: path.to_string(),
            message: error.to_string(),
        },
        Err(payload) => ManifestParseOutcome::Panic {
            manifest_path: path.to_string(),
            message: panic_payload_to_string(payload),
        },
    }
}

fn analyze_download(
    requested_url: DecodedUrl,
    references: Vec<InstallerReference>,
    mut downloaded_file: crate::download::DownloadedFile,
) -> UrlAnalysisResult {
    let analysis = catch_unwind(AssertUnwindSafe(|| -> Result<AnalysisInfo> {
        downloaded_file.file.seek(SeekFrom::Start(0))?;

        let analyzer = Analyzer::new(&mut downloaded_file.file, &downloaded_file.file_name)?;

        let installer_types = analyzer
            .installers
            .iter()
            .filter_map(|installer| installer.r#type.as_ref().map(ToString::to_string))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();

        Ok(AnalysisInfo {
            file_name: downloaded_file.file_name.clone(),
            final_url: downloaded_file.url.to_string(),
            sha_256: downloaded_file.sha_256.to_string(),
            extracted_installers: analyzer.installers.len(),
            installer_types,
            has_nested_zip_installers: analyzer.zip.is_some(),
            publisher: analyzer.publisher.map(|publisher| publisher.to_string()),
            package_name: analyzer
                .package_name
                .map(|package_name| package_name.to_string()),
            copyright: analyzer.copyright.map(|copyright| copyright.to_string()),
        })
    }));

    match analysis {
        Ok(Ok(info)) => UrlAnalysisResult {
            url: requested_url.to_string(),
            references,
            status: AnalysisStatus::Success,
            message: None,
            info: Some(info),
        },
        Ok(Err(error)) => UrlAnalysisResult {
            url: requested_url.to_string(),
            references,
            status: AnalysisStatus::AnalysisError,
            message: Some(error.to_string()),
            info: None,
        },
        Err(payload) => UrlAnalysisResult {
            url: requested_url.to_string(),
            references,
            status: AnalysisStatus::AnalysisPanic,
            message: Some(panic_payload_to_string(payload)),
            info: None,
        },
    }
}

fn build_report(
    command: &AnalyzeWingetPkgs,
    started_at: chrono::DateTime<chrono::Utc>,
    duration_ms: u128,
    installer_manifests_found: usize,
    packages_analyzed: usize,
    installer_entries_total: usize,
    unique_urls_total: usize,
    manifest_errors: Vec<ManifestFailure>,
    manifest_panics: Vec<ManifestFailure>,
    mut results: Vec<UrlAnalysisResult>,
) -> InstallerAnalysisReport {
    results.sort_unstable_by(|a, b| a.url.cmp(&b.url));

    let totals = ReportTotals {
        installer_manifests_found,
        packages_analyzed,
        installer_entries: installer_entries_total,
        unique_urls: unique_urls_total,
        success: results
            .iter()
            .filter(|result| result.status == AnalysisStatus::Success)
            .count(),
        download_errors: results
            .iter()
            .filter(|result| result.status == AnalysisStatus::DownloadError)
            .count(),
        download_panics: results
            .iter()
            .filter(|result| result.status == AnalysisStatus::DownloadPanic)
            .count(),
        analysis_errors: results
            .iter()
            .filter(|result| result.status == AnalysisStatus::AnalysisError)
            .count(),
        analysis_panics: results
            .iter()
            .filter(|result| result.status == AnalysisStatus::AnalysisPanic)
            .count(),
        manifest_errors: manifest_errors.len(),
        manifest_panics: manifest_panics.len(),
    };

    InstallerAnalysisReport {
        generated_at: chrono::Utc::now(),
        started_at,
        duration_ms,
        winget_pkgs_path: command.path.to_string(),
        settings: ReportSettings {
            concurrent_downloads: command.concurrent_downloads.get(),
            concurrent_analysis: command.concurrent_analysis.get(),
            concurrent_manifest_reads: command.concurrent_manifest_reads.get(),
        },
        totals,
        manifest_errors,
        manifest_panics,
        results,
    }
}

fn print_summary(report: &InstallerAnalysisReport, max_failure_details: usize) {
    println!(
        "Selected latest installer manifest for {} packages from {} installer manifests",
        report.totals.packages_analyzed.blue(),
        report.totals.installer_manifests_found.blue(),
    );
    println!(
        "Scanned {} installer entries across {} unique URLs",
        report.totals.installer_entries.blue(),
        report.totals.unique_urls.blue()
    );
    println!("Successful analyses: {}", report.totals.success.green());
    println!("Manifest errors: {}", report.totals.manifest_errors.red());
    println!("Manifest panics: {}", report.totals.manifest_panics.red());
    println!("Download errors: {}", report.totals.download_errors.red());
    println!("Download panics: {}", report.totals.download_panics.red());
    println!("Analysis errors: {}", report.totals.analysis_errors.red());
    println!("Analysis panics: {}", report.totals.analysis_panics.red());

    let mut failures = report
        .results
        .iter()
        .filter(|result| result.status != AnalysisStatus::Success)
        .collect::<Vec<_>>();

    failures.sort_unstable_by_key(|result| failure_rank(result.status));

    if !report.manifest_panics.is_empty() {
        println!("{}", "Manifest panic details:".yellow());
        for failure in report.manifest_panics.iter().take(max_failure_details) {
            println!("{} {}", failure.manifest_path.blue(), failure.message);
        }
    }

    if !report.manifest_errors.is_empty() {
        println!("{}", "Manifest error details:".yellow());
        for failure in report.manifest_errors.iter().take(max_failure_details) {
            println!("{} {}", failure.manifest_path.blue(), failure.message);
        }
    }

    if !failures.is_empty() {
        println!("{}", "URL failure details:".yellow());
        for failure in failures.into_iter().take(max_failure_details) {
            let summary = failure.message.as_deref().unwrap_or("Unknown failure");
            println!(
                "{} [{}] {}",
                failure.url.blue(),
                failure.status.as_str().red(),
                summary
            );
        }
    }
}

fn print_live_result(result: &UrlAnalysisResult) {
    match result.status {
        AnalysisStatus::Success => {
            let extracted_installers = result
                .info
                .as_ref()
                .map_or(0, |info| info.extracted_installers);
            println!(
                "{} [{}] extracted installers: {}",
                result.url.blue(),
                result.status.as_str().green(),
                extracted_installers,
            );
        }
        _ => println!(
            "{} [{}] {}",
            result.url.blue(),
            result.status.as_str().red(),
            result.message.as_deref().unwrap_or("Unknown failure"),
        ),
    }
}

async fn write_report(path: &Utf8PathBuf, report: &InstallerAnalysisReport) -> Result<()> {
    tokio::fs::write(path, serde_json::to_vec_pretty(report)?).await?;
    Ok(())
}

fn panic_payload_to_string(payload: Box<dyn std::any::Any + Send>) -> String {
    if let Some(message) = payload.downcast_ref::<&'static str>() {
        (*message).to_string()
    } else if let Some(message) = payload.downcast_ref::<String>() {
        message.clone()
    } else {
        String::from("Unknown panic payload")
    }
}

const fn failure_rank(status: AnalysisStatus) -> u8 {
    match status {
        AnalysisStatus::DownloadPanic => 0,
        AnalysisStatus::AnalysisPanic => 1,
        AnalysisStatus::DownloadError => 2,
        AnalysisStatus::AnalysisError => 3,
        AnalysisStatus::Success => 4,
    }
}

enum ManifestParseOutcome {
    Installer {
        manifest: ParsedInstallerManifest,
    },
    Error {
        manifest_path: String,
        message: String,
    },
    Panic {
        manifest_path: String,
        message: String,
    },
}

struct ParsedInstallerManifest {
    manifest_path: String,
    package_identifier: String,
    package_version: PackageVersion,
    installer_entries: Vec<(DecodedUrl, InstallerReference)>,
}

fn merge_latest_manifest(
    latest_manifests_by_package: &mut HashMap<String, ParsedInstallerManifest>,
    manifest: ParsedInstallerManifest,
) {
    if let Some(existing_manifest) = latest_manifests_by_package.get(&manifest.package_identifier) {
        let is_newer_version = manifest.package_version > existing_manifest.package_version;
        let same_version_newer_path = manifest.package_version == existing_manifest.package_version
            && manifest.manifest_path > existing_manifest.manifest_path;

        if !is_newer_version && !same_version_newer_path {
            return;
        }
    }

    latest_manifests_by_package.insert(manifest.package_identifier.clone(), manifest);
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct InstallerReference {
    manifest_path: String,
    package_identifier: String,
    package_version: String,
    architecture: String,
    installer_type: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AnalysisInfo {
    file_name: String,
    final_url: String,
    sha_256: String,
    extracted_installers: usize,
    installer_types: Vec<String>,
    has_nested_zip_installers: bool,
    publisher: Option<String>,
    package_name: Option<String>,
    copyright: Option<String>,
}

#[derive(Clone, Copy, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum AnalysisStatus {
    Success,
    DownloadError,
    DownloadPanic,
    AnalysisError,
    AnalysisPanic,
}

impl AnalysisStatus {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::DownloadError => "download_error",
            Self::DownloadPanic => "download_panic",
            Self::AnalysisError => "analysis_error",
            Self::AnalysisPanic => "analysis_panic",
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct UrlAnalysisResult {
    url: String,
    references: Vec<InstallerReference>,
    status: AnalysisStatus,
    message: Option<String>,
    info: Option<AnalysisInfo>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ManifestFailure {
    manifest_path: String,
    message: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ReportSettings {
    concurrent_downloads: usize,
    concurrent_analysis: usize,
    concurrent_manifest_reads: usize,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ReportTotals {
    installer_manifests_found: usize,
    packages_analyzed: usize,
    installer_entries: usize,
    unique_urls: usize,
    success: usize,
    download_errors: usize,
    download_panics: usize,
    analysis_errors: usize,
    analysis_panics: usize,
    manifest_errors: usize,
    manifest_panics: usize,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct InstallerAnalysisReport {
    generated_at: chrono::DateTime<chrono::Utc>,
    started_at: chrono::DateTime<chrono::Utc>,
    duration_ms: u128,
    winget_pkgs_path: String,
    settings: ReportSettings,
    totals: ReportTotals,
    manifest_errors: Vec<ManifestFailure>,
    manifest_panics: Vec<ManifestFailure>,
    results: Vec<UrlAnalysisResult>,
}
