use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    fs::File,
    io::{self, Seek, SeekFrom, Write},
    num::NonZeroUsize,
    panic::{AssertUnwindSafe, catch_unwind},
    str::FromStr,
    sync::Arc,
    time::{Duration, Instant},
};

use anstream::println;
use camino::{Utf8Path, Utf8PathBuf};
use clap::Parser;
use color_eyre::{Result, eyre::ensure};
use futures_util::{StreamExt, stream};
use indicatif::MultiProgress;
use owo_colors::OwoColorize;
use serde::{Deserialize, Serialize};
use tokio::{sync::Semaphore, task};
use walkdir::WalkDir;
use winget_types::{PackageVersion, installer::InstallerManifest, url::DecodedUrl};

use crate::{
    analysis::Analyzer,
    download::{DownloadAttemptStatus, Downloader, SlowDownloadPolicy},
    manifests::Url,
};

const CURRENT_REPORT_FORMAT_VERSION: u8 = 2;

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

    /// Output Markdown report path
    #[arg(long, value_hint = clap::ValueHint::FilePath)]
    markdown_report: Option<Utf8PathBuf>,

    /// Max failing URLs to print to stdout
    #[arg(long, default_value_t = 50)]
    max_failure_details: usize,

    /// Seconds to download before estimating whether a URL is too slow
    #[arg(long, default_value_t = 30)]
    slow_download_check_after_secs: u64,

    /// Cancel URLs whose projected total download time exceeds this many seconds
    #[arg(long, default_value_t = 300)]
    slow_download_max_total_secs: u64,

    /// Resume from an existing report, skipping recorded URLs and retrying `download_cancelled` URLs
    #[arg(long, value_hint = clap::ValueHint::FilePath, conflicts_with = "retry_cancelled_from")]
    resume_from: Option<Utf8PathBuf>,

    /// Retry only `download_cancelled` URLs from an existing report
    #[arg(long, value_hint = clap::ValueHint::FilePath, conflicts_with = "resume_from")]
    retry_cancelled_from: Option<Utf8PathBuf>,
}

impl AnalyzeWingetPkgs {
    pub async fn run(self) -> Result<()> {
        ensure!(
            self.slow_download_check_after_secs > 0,
            "--slow-download-check-after-secs must be greater than 0"
        );
        ensure!(
            self.slow_download_max_total_secs > 0,
            "--slow-download-max-total-secs must be greater than 0"
        );

        if let Some(markdown_report) = &self.markdown_report {
            let report = read_report(&self.report).await?;
            let markdown_report = normalize_markdown_report_path(markdown_report);

            if let Some(parent) = markdown_report.parent()
                && !parent.as_str().is_empty()
            {
                tokio::fs::create_dir_all(parent).await?;
            }

            tokio::fs::write(&markdown_report, render_markdown_report(&report)).await?;
            println!(
                "{} {}",
                "Markdown report written to".green(),
                markdown_report.blue()
            );
            return Ok(());
        }

        let started_at = chrono::Utc::now();
        let started = Instant::now();

        let (mut report, installers_by_url, base_duration_ms, resume_progress) =
            if let Some(resume_report_path) = &self.resume_from {
                let existing_report = read_report(resume_report_path).await?;
                ensure!(
                    existing_report.report_format_version == CURRENT_REPORT_FORMAT_VERSION,
                    "Unsupported report format version {} in {}",
                    existing_report.report_format_version,
                    resume_report_path
                );
                let winget_pkgs_path =
                    resolve_resume_winget_pkgs_path(&self, resume_report_path, &existing_report);
                let manifest_scan =
                    collect_manifest_scan(&winget_pkgs_path, self.concurrent_manifest_reads)
                        .await?;

                prepare_resume_report(
                    &self,
                    existing_report,
                    manifest_scan.installers_by_url,
                    started_at,
                    &winget_pkgs_path,
                )?
            } else if let Some(retry_cancelled_report_path) = &self.retry_cancelled_from {
                let existing_report = read_report(retry_cancelled_report_path).await?;
                ensure!(
                    existing_report.report_format_version == CURRENT_REPORT_FORMAT_VERSION,
                    "Unsupported report format version {} in {}",
                    existing_report.report_format_version,
                    retry_cancelled_report_path
                );
                let winget_pkgs_path = resolve_resume_winget_pkgs_path(
                    &self,
                    retry_cancelled_report_path,
                    &existing_report,
                );

                prepare_retry_cancelled_report(
                    &self,
                    existing_report,
                    started_at,
                    &winget_pkgs_path,
                )?
            } else {
                let manifest_scan =
                    collect_manifest_scan(&self.path, self.concurrent_manifest_reads).await?;
                let unique_urls_total = manifest_scan.unique_urls_total;

                let report = build_report(
                    &self,
                    &self.path,
                    started_at,
                    0,
                    manifest_scan.installer_manifests_found,
                    manifest_scan.packages_analyzed,
                    manifest_scan.installer_entries_total,
                    unique_urls_total,
                    manifest_scan.manifest_errors,
                    manifest_scan.manifest_panics,
                    Vec::with_capacity(unique_urls_total),
                    Vec::with_capacity(unique_urls_total),
                );

                (report, manifest_scan.installers_by_url, 0, None)
            };

        if let Some(resume_progress) = &resume_progress {
            match resume_progress.mode {
                ResumeMode::Resume => {
                    println!(
                        "Resuming {} recorded URLs, retrying {} cancelled URLs, {} URLs remaining",
                        resume_progress.recorded_urls.blue(),
                        resume_progress.retrying_cancelled_urls.yellow(),
                        resume_progress.pending_urls.blue(),
                    );
                }
                ResumeMode::RetryCancelled => {
                    println!(
                        "Retrying {} cancelled URLs from existing report",
                        resume_progress.retrying_cancelled_urls.yellow(),
                    );
                }
            }
        }

        if installers_by_url.is_empty() {
            ensure_report_output_dirs(&self).await?;
            report.duration_ms = base_duration_ms + started.elapsed().as_millis();
            report.generated_at = chrono::Utc::now();
            write_report(&self.report, &report)?;
            print_summary(&report, self.max_failure_details);
            println!("{} {}", "Report written to".green(), self.report.blue());
            return Ok(());
        }

        ensure_report_output_dirs(&self).await?;
        write_report(&self.report, &report)?;

        let slow_download_policy = SlowDownloadPolicy {
            evaluate_after: Duration::from_secs(self.slow_download_check_after_secs),
            max_projected_total: Duration::from_secs(self.slow_download_max_total_secs),
        };

        let downloader = Downloader::new_with_concurrent(self.concurrent_downloads)?;
        let multi_progress = MultiProgress::new();
        let analysis_limiter = Arc::new(Semaphore::new(self.concurrent_analysis.get()));
        let downloader = &downloader;

        let mut url_result_stream = stream::iter(installers_by_url.into_iter())
            .map(|(requested_url, references)| {
                let multi_progress = multi_progress.clone();
                let analysis_limiter = Arc::clone(&analysis_limiter);
                let slow_download_policy = slow_download_policy;

                async move {
                    let download_status = downloader
                        .fetch_with_failure(
                            Url::from(requested_url.clone()).into(),
                            &multi_progress,
                            Some(slow_download_policy),
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
                        DownloadAttemptStatus::Cancelled(message) => UrlAnalysisResult {
                            url: requested_url.to_string(),
                            references,
                            status: AnalysisStatus::DownloadCancelled,
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
                AnalysisStatus::DownloadCancelled => report.totals.download_cancelled += 1,
                AnalysisStatus::AnalysisError => report.totals.analysis_errors += 1,
                AnalysisStatus::AnalysisPanic => report.totals.analysis_panics += 1,
            }

            if status.is_download_failure() {
                print_live_result(&url_result);
                report.download_failures.push(url_result);
            } else {
                if status.is_analysis_failure() {
                    print_live_result(&url_result);
                }
                report.results.push(url_result);
            }

            report.duration_ms = base_duration_ms + started.elapsed().as_millis();
            report.generated_at = chrono::Utc::now();
            write_report(&self.report, &report)?;
        }

        let _ = multi_progress.clear();

        report
            .download_failures
            .sort_unstable_by(|a, b| a.url.cmp(&b.url));
        report.results.sort_unstable_by(|a, b| a.url.cmp(&b.url));
        report.duration_ms = base_duration_ms + started.elapsed().as_millis();
        report.generated_at = chrono::Utc::now();
        write_report(&self.report, &report)?;

        print_summary(&report, self.max_failure_details);
        println!("{} {}", "Report written to".green(), self.report.blue());

        Ok(())
    }

    fn get_installer_manifest_paths(path: &Utf8Path) -> walkdir::Result<Vec<Utf8PathBuf>> {
        let mut paths = Vec::new();

        for entry in WalkDir::new(path) {
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

async fn read_report(path: &Utf8PathBuf) -> Result<InstallerAnalysisReport> {
    let report = tokio::fs::read(path).await?;
    Ok(serde_json::from_slice(&report)?)
}

fn normalize_markdown_report_path(path: &Utf8Path) -> Utf8PathBuf {
    let mut markdown_report = path.to_path_buf();
    markdown_report.set_extension("md");
    markdown_report
}

async fn ensure_report_output_dirs(command: &AnalyzeWingetPkgs) -> Result<()> {
    if let Some(parent) = command.report.parent()
        && !parent.as_str().is_empty()
    {
        tokio::fs::create_dir_all(parent).await?;
    }

    if let Some(markdown_report) = &command.markdown_report
        && let Some(parent) = markdown_report.parent()
        && !parent.as_str().is_empty()
    {
        tokio::fs::create_dir_all(parent).await?;
    }

    Ok(())
}

async fn collect_manifest_scan(
    winget_pkgs_path: &Utf8Path,
    concurrent_manifest_reads: NonZeroUsize,
) -> Result<ManifestScan> {
    ensure!(
        winget_pkgs_path.exists(),
        "{} does not exist",
        winget_pkgs_path
    );
    ensure!(
        winget_pkgs_path.is_dir(),
        "{} is not a directory",
        winget_pkgs_path
    );

    let installer_manifest_paths =
        AnalyzeWingetPkgs::get_installer_manifest_paths(winget_pkgs_path)?;

    let mut installer_manifests_found = 0usize;
    let mut latest_manifests_by_package = HashMap::<String, ParsedInstallerManifest>::new();
    let mut manifest_errors = Vec::new();
    let mut manifest_panics = Vec::new();

    let mut parse_outcome_stream =
        stream::iter(installer_manifest_paths.into_iter().map(|path| async move {
            task::spawn_blocking(move || parse_installer_manifest(path)).await
        }))
        .buffer_unordered(concurrent_manifest_reads.get());

    while let Some(outcome) = parse_outcome_stream.next().await {
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

    Ok(ManifestScan {
        installer_manifests_found,
        packages_analyzed,
        installer_entries_total: installers_by_url.values().map(Vec::len).sum(),
        unique_urls_total: installers_by_url.len(),
        manifest_errors,
        manifest_panics,
        installers_by_url,
    })
}

fn resolve_resume_winget_pkgs_path(
    command: &AnalyzeWingetPkgs,
    resume_report_path: &Utf8Path,
    report: &InstallerAnalysisReport,
) -> Utf8PathBuf {
    if command.path.as_str() != "." {
        return command.path.clone();
    }

    let report_winget_pkgs_path = Utf8PathBuf::from(report.winget_pkgs_path.as_str());
    if report_winget_pkgs_path.is_absolute() {
        report_winget_pkgs_path
    } else if let Some(parent) = resume_report_path.parent() {
        parent.join(report_winget_pkgs_path)
    } else {
        report_winget_pkgs_path
    }
}

fn prepare_resume_report(
    command: &AnalyzeWingetPkgs,
    mut report: InstallerAnalysisReport,
    mut installers_by_url: HashMap<DecodedUrl, Vec<InstallerReference>>,
    started_at: chrono::DateTime<chrono::Utc>,
    winget_pkgs_path: &Utf8Path,
) -> Result<(
    InstallerAnalysisReport,
    HashMap<DecodedUrl, Vec<InstallerReference>>,
    u128,
    Option<ResumeProgress>,
)> {
    let base_duration_ms = report.duration_ms;
    let mut retained_results = Vec::with_capacity(report.results.len());
    let mut retained_download_failures = Vec::with_capacity(report.download_failures.len());
    let mut removed_cancelled = 0usize;
    let recorded_urls = report
        .download_failures
        .iter()
        .chain(report.results.iter())
        .filter(|result| result.status != AnalysisStatus::DownloadCancelled)
        .filter_map(|result| DecodedUrl::from_str(&result.url).ok())
        .collect::<HashSet<_>>();
    let existing_results = std::mem::take(&mut report.results);
    let existing_download_failures = std::mem::take(&mut report.download_failures);

    installers_by_url.retain(|url, _| !recorded_urls.contains(url));

    for failure in existing_download_failures {
        match failure.status {
            AnalysisStatus::DownloadCancelled => {
                removed_cancelled += 1;
                requeue_cancelled_url(
                    failure,
                    &mut installers_by_url,
                    &recorded_urls,
                    &mut retained_download_failures,
                );
            }
            status if status.is_download_failure() => retained_download_failures.push(failure),
            _ => retained_results.push(failure),
        }
    }

    for result in existing_results {
        match result.status {
            AnalysisStatus::DownloadCancelled => {
                removed_cancelled += 1;
                requeue_cancelled_url(
                    result,
                    &mut installers_by_url,
                    &recorded_urls,
                    &mut retained_download_failures,
                );
            }
            status if status.is_download_failure() => retained_download_failures.push(result),
            _ => retained_results.push(result),
        }
    }

    report.results = retained_results;
    report.results.sort_unstable_by(|a, b| a.url.cmp(&b.url));
    report.download_failures = retained_download_failures;
    report
        .download_failures
        .sort_unstable_by(|a, b| a.url.cmp(&b.url));
    recalculate_report_outcome_totals(&mut report);
    report.started_at = report.started_at.min(started_at);
    report.generated_at = chrono::Utc::now();
    report.duration_ms = base_duration_ms;
    report.report_format_version = CURRENT_REPORT_FORMAT_VERSION;
    report.winget_pkgs_path = winget_pkgs_path.to_string();
    report.settings = ReportSettings {
        concurrent_downloads: command.concurrent_downloads.get(),
        concurrent_analysis: command.concurrent_analysis.get(),
        concurrent_manifest_reads: command.concurrent_manifest_reads.get(),
        slow_download_check_after_secs: command.slow_download_check_after_secs,
        slow_download_max_total_secs: command.slow_download_max_total_secs,
    };

    let resume_progress = ResumeProgress {
        mode: ResumeMode::Resume,
        recorded_urls: recorded_urls.len(),
        retrying_cancelled_urls: removed_cancelled,
        pending_urls: installers_by_url.len(),
    };

    Ok((
        report,
        installers_by_url,
        base_duration_ms,
        Some(resume_progress),
    ))
}

fn prepare_retry_cancelled_report(
    command: &AnalyzeWingetPkgs,
    mut report: InstallerAnalysisReport,
    started_at: chrono::DateTime<chrono::Utc>,
    winget_pkgs_path: &Utf8Path,
) -> Result<(
    InstallerAnalysisReport,
    HashMap<DecodedUrl, Vec<InstallerReference>>,
    u128,
    Option<ResumeProgress>,
)> {
    let base_duration_ms = report.duration_ms;
    let existing_results = std::mem::take(&mut report.results);
    let existing_download_failures = std::mem::take(&mut report.download_failures);

    let mut installers_by_url = HashMap::<DecodedUrl, Vec<InstallerReference>>::new();
    let mut retained_results = Vec::with_capacity(existing_results.len());
    let mut retained_download_failures = Vec::with_capacity(existing_download_failures.len());
    let mut removed_cancelled = 0usize;

    for failure in existing_download_failures {
        match failure.status {
            AnalysisStatus::DownloadCancelled => {
                removed_cancelled += 1;
                requeue_cancelled_url(
                    failure,
                    &mut installers_by_url,
                    &HashSet::new(),
                    &mut retained_download_failures,
                );
            }
            status if status.is_download_failure() => retained_download_failures.push(failure),
            _ => retained_results.push(failure),
        }
    }

    for result in existing_results {
        match result.status {
            AnalysisStatus::DownloadCancelled => {
                removed_cancelled += 1;
                requeue_cancelled_url(
                    result,
                    &mut installers_by_url,
                    &HashSet::new(),
                    &mut retained_download_failures,
                );
            }
            _ => retained_results.push(result),
        }
    }

    report.results = retained_results;
    report.results.sort_unstable_by(|a, b| a.url.cmp(&b.url));
    report.download_failures = retained_download_failures;
    report
        .download_failures
        .sort_unstable_by(|a, b| a.url.cmp(&b.url));
    recalculate_report_outcome_totals(&mut report);
    report.started_at = report.started_at.min(started_at);
    report.generated_at = chrono::Utc::now();
    report.duration_ms = base_duration_ms;
    report.report_format_version = CURRENT_REPORT_FORMAT_VERSION;
    report.winget_pkgs_path = winget_pkgs_path.to_string();
    report.settings = ReportSettings {
        concurrent_downloads: command.concurrent_downloads.get(),
        concurrent_analysis: command.concurrent_analysis.get(),
        concurrent_manifest_reads: command.concurrent_manifest_reads.get(),
        slow_download_check_after_secs: command.slow_download_check_after_secs,
        slow_download_max_total_secs: command.slow_download_max_total_secs,
    };

    let resume_progress = ResumeProgress {
        mode: ResumeMode::RetryCancelled,
        recorded_urls: 0,
        retrying_cancelled_urls: removed_cancelled,
        pending_urls: installers_by_url.len(),
    };

    Ok((
        report,
        installers_by_url,
        base_duration_ms,
        Some(resume_progress),
    ))
}

fn parse_installer_manifest(path: Utf8PathBuf) -> ManifestParseOutcome {
    match catch_unwind(AssertUnwindSafe(|| -> Result<ParsedInstallerManifest> {
        let manifest = io::read_to_string(File::open(&path)?)?;
        let installer_manifest = serde_yaml::from_str::<InstallerManifest>(&manifest)?;

        let package_identifier = installer_manifest.package_identifier.to_string();
        let package_version = installer_manifest.package_version.clone();
        let manifest_path = path.to_string();
        let manifest_installer_type = installer_manifest.r#type.as_ref().map(ToString::to_string);

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
                    installer_type: Some(
                        installer
                            .r#type
                            .as_ref()
                            .map(ToString::to_string)
                            .or_else(|| manifest_installer_type.clone())
                            .unwrap_or_else(|| infer_installer_type_from_url(&url)),
                    ),
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

fn infer_installer_type_from_url(url: &DecodedUrl) -> String {
    let extension = url
        .path_segments()
        .and_then(|mut segments| segments.next_back())
        .and_then(|last_segment| last_segment.rsplit_once('.').map(|(_, ext)| ext))
        .map(|ext| ext.to_ascii_lowercase());

    match extension.as_deref() {
        Some("msix") | Some("msixbundle") => String::from("msix"),
        Some("appx") | Some("appxbundle") => String::from("appx"),
        Some("msi") => String::from("msi"),
        Some("zip") => String::from("zip"),
        Some("exe") => String::from("exe"),
        Some("inno") => String::from("inno"),
        _ => String::from("unknown"),
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
        let installer_types = analyzer.installer_type_labels.clone();

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
    winget_pkgs_path: &Utf8Path,
    started_at: chrono::DateTime<chrono::Utc>,
    duration_ms: u128,
    installer_manifests_found: usize,
    packages_analyzed: usize,
    installer_entries_total: usize,
    unique_urls_total: usize,
    manifest_errors: Vec<ManifestFailure>,
    manifest_panics: Vec<ManifestFailure>,
    mut download_failures: Vec<UrlAnalysisResult>,
    mut results: Vec<UrlAnalysisResult>,
) -> InstallerAnalysisReport {
    download_failures.sort_unstable_by(|a, b| a.url.cmp(&b.url));
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
        download_errors: download_failures
            .iter()
            .filter(|result| result.status == AnalysisStatus::DownloadError)
            .count(),
        download_panics: download_failures
            .iter()
            .filter(|result| result.status == AnalysisStatus::DownloadPanic)
            .count(),
        download_cancelled: download_failures
            .iter()
            .filter(|result| result.status == AnalysisStatus::DownloadCancelled)
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
        report_format_version: CURRENT_REPORT_FORMAT_VERSION,
        generated_at: chrono::Utc::now(),
        started_at,
        duration_ms,
        winget_pkgs_path: winget_pkgs_path.to_string(),
        settings: ReportSettings {
            concurrent_downloads: command.concurrent_downloads.get(),
            concurrent_analysis: command.concurrent_analysis.get(),
            concurrent_manifest_reads: command.concurrent_manifest_reads.get(),
            slow_download_check_after_secs: command.slow_download_check_after_secs,
            slow_download_max_total_secs: command.slow_download_max_total_secs,
        },
        totals,
        manifest_errors,
        manifest_panics,
        download_failures,
        results,
    }
}

fn requeue_cancelled_url(
    cancelled_result: UrlAnalysisResult,
    installers_by_url: &mut HashMap<DecodedUrl, Vec<InstallerReference>>,
    recorded_urls: &HashSet<DecodedUrl>,
    retained_download_failures: &mut Vec<UrlAnalysisResult>,
) {
    match DecodedUrl::from_str(&cancelled_result.url) {
        Ok(url) => {
            if recorded_urls.contains(&url) {
                return;
            }

            let references = cancelled_result.references;
            let pending_references = installers_by_url.entry(url).or_default();
            merge_references(pending_references, references);
        }
        Err(error) => retained_download_failures.push(UrlAnalysisResult {
            url: cancelled_result.url,
            references: cancelled_result.references,
            status: AnalysisStatus::DownloadError,
            message: Some(format!(
                "Failed to parse cancelled URL from resume report: {error}"
            )),
            info: None,
        }),
    }
}

fn merge_references(
    existing_references: &mut Vec<InstallerReference>,
    new_references: Vec<InstallerReference>,
) {
    for reference in new_references {
        if !existing_references.contains(&reference) {
            existing_references.push(reference);
        }
    }
}

fn recalculate_report_outcome_totals(report: &mut InstallerAnalysisReport) {
    report.totals.success = report
        .results
        .iter()
        .filter(|result| result.status == AnalysisStatus::Success)
        .count();
    report.totals.download_errors = report
        .download_failures
        .iter()
        .filter(|result| result.status == AnalysisStatus::DownloadError)
        .count();
    report.totals.download_panics = report
        .download_failures
        .iter()
        .filter(|result| result.status == AnalysisStatus::DownloadPanic)
        .count();
    report.totals.download_cancelled = report
        .download_failures
        .iter()
        .filter(|result| result.status == AnalysisStatus::DownloadCancelled)
        .count();
    report.totals.analysis_errors = report
        .results
        .iter()
        .filter(|result| result.status == AnalysisStatus::AnalysisError)
        .count();
    report.totals.analysis_panics = report
        .results
        .iter()
        .filter(|result| result.status == AnalysisStatus::AnalysisPanic)
        .count();
    report.totals.manifest_errors = report.manifest_errors.len();
    report.totals.manifest_panics = report.manifest_panics.len();
}

fn render_markdown_report(report: &InstallerAnalysisReport) -> String {
    let mut markdown = String::new();

    markdown.push_str("# Installer Analysis Report\n\n");
    markdown.push_str(&format!("Generated at: `{}`\n\n", report.generated_at));
    markdown.push_str("## Summary\n\n");
    markdown.push_str(&format!(
        "- Installer manifests found: {}\n- Packages analyzed: {}\n- Installer entries: {}\n- Unique URLs: {}\n- Success: {}\n- Download panics: {}\n- Analysis errors: {}\n- Analysis panics: {}\n- Manifest errors: {}\n- Manifest panics: {}\n\n",
        report.totals.installer_manifests_found,
        report.totals.packages_analyzed,
        report.totals.installer_entries,
        report.totals.unique_urls,
        report.totals.success,
        report.totals.download_panics,
        report.totals.analysis_errors,
        report.totals.analysis_panics,
        report.totals.manifest_errors,
        report.totals.manifest_panics,
    ));

    if !report.manifest_errors.is_empty() || !report.manifest_panics.is_empty() {
        markdown.push_str("## Manifest Failures\n\n");

        for (heading, failures) in [
            ("Manifest Errors", &report.manifest_errors),
            ("Manifest Panics", &report.manifest_panics),
        ] {
            if failures.is_empty() {
                continue;
            }

            let mut grouped = BTreeMap::<&str, Vec<&ManifestFailure>>::new();
            for failure in failures {
                grouped.entry(&failure.message).or_default().push(failure);
            }

            markdown.push_str(&format!("### {heading}\n\n"));
            for (message, failures) in grouped {
                markdown.push_str(&format!(
                    "#### {} manifests\n\n```\n{}\n```\n\n",
                    failures.len(),
                    message
                ));
                for failure in failures {
                    markdown.push_str(&format!("- `{}`\n", failure.manifest_path));
                }
                markdown.push('\n');
            }
        }
    }

    let grouped_failures = group_url_failures_for_markdown(report);
    if !grouped_failures.is_empty() {
        markdown.push_str("## URL Failures By Installer Type\n\n");

        for (installer_type, failure_groups) in grouped_failures {
            markdown.push_str(&format!("### `{installer_type}`\n\n"));

            for ((status, message), results) in failure_groups {
                markdown.push_str(&format!(
                    "#### {} x `{}`\n\n",
                    results.len(),
                    status.as_str()
                ));
                markdown.push_str("```text\n");
                markdown.push_str(&message);
                markdown.push_str("\n```\n\n");

                for result in results {
                    markdown.push_str(&format!("- `{}`\n", result.url));

                    let references = result
                        .references
                        .iter()
                        .map(|reference| {
                            format!(
                                "{} {} ({})",
                                reference.package_identifier,
                                reference.package_version,
                                reference.architecture
                            )
                        })
                        .collect::<Vec<_>>();
                    if !references.is_empty() {
                        markdown.push_str(&format!("  - {}\n", references.join(", ")));
                    }
                }

                markdown.push('\n');
            }
        }
    }

    markdown
}

fn group_url_failures_for_markdown(
    report: &InstallerAnalysisReport,
) -> BTreeMap<String, BTreeMap<(AnalysisStatus, String), Vec<&UrlAnalysisResult>>> {
    let mut grouped =
        BTreeMap::<String, BTreeMap<(AnalysisStatus, String), Vec<&UrlAnalysisResult>>>::new();

    for result in report
        .download_failures
        .iter()
        .chain(report.results.iter())
        .filter(|result| {
            result.status == AnalysisStatus::DownloadPanic || result.status.is_analysis_failure()
        })
    {
        let installer_type_key = installer_type_bucket(&result.references);
        let message = result
            .message
            .clone()
            .unwrap_or_else(|| String::from("Unknown failure"));
        grouped
            .entry(installer_type_key)
            .or_default()
            .entry((result.status, message))
            .or_default()
            .push(result);
    }

    grouped
}

fn installer_type_bucket(references: &[InstallerReference]) -> String {
    let installer_types = references
        .iter()
        .map(|reference| {
            reference
                .installer_type
                .clone()
                .unwrap_or_else(|| String::from("unknown"))
        })
        .collect::<BTreeSet<_>>();

    if installer_types.is_empty() {
        String::from("unknown")
    } else {
        installer_types.into_iter().collect::<Vec<_>>().join(", ")
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
    println!(
        "Download cancelled: {}",
        report.totals.download_cancelled.yellow()
    );
    println!("Analysis errors: {}", report.totals.analysis_errors.red());
    println!("Analysis panics: {}", report.totals.analysis_panics.red());

    let mut download_failures = report.download_failures.iter().collect::<Vec<_>>();
    download_failures.sort_unstable_by_key(|result| failure_rank(result.status));

    let mut analysis_failures = report
        .results
        .iter()
        .filter(|result| result.status.is_analysis_failure())
        .collect::<Vec<_>>();
    analysis_failures.sort_unstable_by_key(|result| failure_rank(result.status));

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

    if !download_failures.is_empty() {
        println!("{}", "Download failure details:".yellow());
        for failure in download_failures.into_iter().take(max_failure_details) {
            let summary = failure.message.as_deref().unwrap_or("Unknown failure");
            let status = match failure.status {
                AnalysisStatus::DownloadCancelled => failure.status.as_str().yellow().to_string(),
                _ => failure.status.as_str().red().to_string(),
            };
            println!("{} [{}] {}", failure.url.blue(), status, summary);
        }
    }

    if !analysis_failures.is_empty() {
        println!("{}", "Analysis failure details:".yellow());
        for failure in analysis_failures.into_iter().take(max_failure_details) {
            println!(
                "{} [{}] {}",
                failure.url.blue(),
                failure.status.as_str().red(),
                failure.message.as_deref().unwrap_or("Unknown failure"),
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
        _ => {
            let status = match result.status {
                AnalysisStatus::DownloadCancelled => result.status.as_str().yellow().to_string(),
                _ => result.status.as_str().red().to_string(),
            };
            println!(
                "{} [{}] {}",
                result.url.blue(),
                status,
                result.message.as_deref().unwrap_or("Unknown failure"),
            );
        }
    }
}

fn write_report(path: &Utf8PathBuf, report: &InstallerAnalysisReport) -> Result<()> {
    let parent = report_parent_dir(path.as_path());
    let mut temp_report = tempfile::NamedTempFile::new_in(parent)?;

    {
        let mut writer = io::BufWriter::new(temp_report.as_file_mut());
        serde_json::to_writer_pretty(&mut writer, report)?;
        writer.write_all(b"\n")?;
        writer.flush()?;
    }

    temp_report.as_file().sync_all()?;
    temp_report.persist(path.as_std_path())?;

    #[cfg(unix)]
    {
        let parent_directory = File::open(parent.as_std_path())?;
        parent_directory.sync_all()?;
    }

    Ok(())
}

fn report_parent_dir(path: &Utf8Path) -> &Utf8Path {
    path.parent()
        .filter(|parent| !parent.as_str().is_empty())
        .unwrap_or_else(|| Utf8Path::new("."))
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
        AnalysisStatus::DownloadCancelled => 2,
        AnalysisStatus::DownloadError => 3,
        AnalysisStatus::AnalysisError => 4,
        AnalysisStatus::Success => 5,
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

struct ManifestScan {
    installer_manifests_found: usize,
    packages_analyzed: usize,
    installer_entries_total: usize,
    unique_urls_total: usize,
    manifest_errors: Vec<ManifestFailure>,
    manifest_panics: Vec<ManifestFailure>,
    installers_by_url: HashMap<DecodedUrl, Vec<InstallerReference>>,
}

struct ResumeProgress {
    mode: ResumeMode,
    recorded_urls: usize,
    retrying_cancelled_urls: usize,
    pending_urls: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ResumeMode {
    Resume,
    RetryCancelled,
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

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
struct InstallerReference {
    manifest_path: String,
    package_identifier: String,
    package_version: String,
    architecture: String,
    installer_type: Option<String>,
}

#[derive(Deserialize, Serialize)]
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

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
enum AnalysisStatus {
    Success,
    DownloadError,
    DownloadPanic,
    DownloadCancelled,
    AnalysisError,
    AnalysisPanic,
}

impl AnalysisStatus {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::DownloadError => "download_error",
            Self::DownloadPanic => "download_panic",
            Self::DownloadCancelled => "download_cancelled",
            Self::AnalysisError => "analysis_error",
            Self::AnalysisPanic => "analysis_panic",
        }
    }

    const fn is_download_failure(self) -> bool {
        matches!(
            self,
            Self::DownloadError | Self::DownloadPanic | Self::DownloadCancelled
        )
    }

    const fn is_analysis_failure(self) -> bool {
        matches!(self, Self::AnalysisError | Self::AnalysisPanic)
    }
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct UrlAnalysisResult {
    url: String,
    references: Vec<InstallerReference>,
    status: AnalysisStatus,
    message: Option<String>,
    info: Option<AnalysisInfo>,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct ManifestFailure {
    manifest_path: String,
    message: String,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct ReportSettings {
    concurrent_downloads: usize,
    concurrent_analysis: usize,
    concurrent_manifest_reads: usize,
    #[serde(default)]
    slow_download_check_after_secs: u64,
    #[serde(default)]
    slow_download_max_total_secs: u64,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct ReportTotals {
    installer_manifests_found: usize,
    packages_analyzed: usize,
    installer_entries: usize,
    unique_urls: usize,
    success: usize,
    download_errors: usize,
    download_panics: usize,
    download_cancelled: usize,
    analysis_errors: usize,
    analysis_panics: usize,
    manifest_errors: usize,
    manifest_panics: usize,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct InstallerAnalysisReport {
    report_format_version: u8,
    generated_at: chrono::DateTime<chrono::Utc>,
    started_at: chrono::DateTime<chrono::Utc>,
    duration_ms: u128,
    winget_pkgs_path: String,
    settings: ReportSettings,
    totals: ReportTotals,
    manifest_errors: Vec<ManifestFailure>,
    manifest_panics: Vec<ManifestFailure>,
    download_failures: Vec<UrlAnalysisResult>,
    results: Vec<UrlAnalysisResult>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_command() -> AnalyzeWingetPkgs {
        AnalyzeWingetPkgs {
            path: Utf8PathBuf::from("."),
            concurrent_downloads: NonZeroUsize::new(2).unwrap(),
            concurrent_analysis: NonZeroUsize::new(2).unwrap(),
            concurrent_manifest_reads: NonZeroUsize::new(2).unwrap(),
            report: Utf8PathBuf::from("installer-analysis-report.json"),
            max_failure_details: 10,
            slow_download_check_after_secs: 30,
            slow_download_max_total_secs: 300,
            markdown_report: None,
            resume_from: None,
            retry_cancelled_from: None,
        }
    }

    fn test_reference(label: &str) -> InstallerReference {
        InstallerReference {
            manifest_path: format!("manifests/{label}.installer.yaml"),
            package_identifier: format!("Example.{label}"),
            package_version: String::from("1.0.0"),
            architecture: String::from("x64"),
            installer_type: Some(String::from("exe")),
        }
    }

    fn test_result(url: &str, label: &str, status: AnalysisStatus) -> UrlAnalysisResult {
        UrlAnalysisResult {
            url: String::from(url),
            references: vec![test_reference(label)],
            status,
            message: (status != AnalysisStatus::Success).then(|| String::from("failure")),
            info: (status == AnalysisStatus::Success).then(|| AnalysisInfo {
                file_name: format!("{label}.exe"),
                final_url: String::from(url),
                sha_256: String::from("hash"),
                extracted_installers: 1,
                installer_types: vec![String::from("exe")],
                has_nested_zip_installers: false,
                publisher: Some(String::from("Example")),
                package_name: Some(format!("Example {label}")),
                copyright: None,
            }),
        }
    }

    fn test_report(
        report_format_version: u8,
        download_failures: Vec<UrlAnalysisResult>,
        results: Vec<UrlAnalysisResult>,
    ) -> InstallerAnalysisReport {
        InstallerAnalysisReport {
            report_format_version,
            generated_at: chrono::Utc::now(),
            started_at: chrono::Utc::now(),
            duration_ms: 500,
            winget_pkgs_path: String::from("."),
            settings: ReportSettings {
                concurrent_downloads: 2,
                concurrent_analysis: 2,
                concurrent_manifest_reads: 2,
                slow_download_check_after_secs: 30,
                slow_download_max_total_secs: 300,
            },
            totals: ReportTotals {
                installer_manifests_found: 4,
                packages_analyzed: 4,
                installer_entries: 4,
                unique_urls: 4,
                success: results
                    .iter()
                    .filter(|result| result.status == AnalysisStatus::Success)
                    .count(),
                download_errors: download_failures
                    .iter()
                    .filter(|result| result.status == AnalysisStatus::DownloadError)
                    .count(),
                download_panics: download_failures
                    .iter()
                    .filter(|result| result.status == AnalysisStatus::DownloadPanic)
                    .count(),
                download_cancelled: download_failures
                    .iter()
                    .filter(|result| result.status == AnalysisStatus::DownloadCancelled)
                    .count(),
                analysis_errors: results
                    .iter()
                    .filter(|result| result.status == AnalysisStatus::AnalysisError)
                    .count(),
                analysis_panics: results
                    .iter()
                    .filter(|result| result.status == AnalysisStatus::AnalysisPanic)
                    .count(),
                manifest_errors: 0,
                manifest_panics: 0,
            },
            manifest_errors: Vec::new(),
            manifest_panics: Vec::new(),
            download_failures,
            results,
        }
    }

    fn installers_by_url(urls: &[(&str, &str)]) -> HashMap<DecodedUrl, Vec<InstallerReference>> {
        urls.iter()
            .map(|(url, label)| {
                (
                    DecodedUrl::from_str(url).unwrap(),
                    vec![test_reference(label)],
                )
            })
            .collect()
    }

    #[test]
    fn resume_skips_recorded_urls_and_retries_cancelled_urls() {
        let report = test_report(
            CURRENT_REPORT_FORMAT_VERSION,
            vec![
                test_result(
                    "https://example.com/b.exe",
                    "b",
                    AnalysisStatus::DownloadCancelled,
                ),
                test_result(
                    "https://example.com/c.exe",
                    "c",
                    AnalysisStatus::DownloadError,
                ),
            ],
            vec![test_result(
                "https://example.com/a.exe",
                "a",
                AnalysisStatus::Success,
            )],
        );

        let (report, installers_by_url, base_duration_ms, resume_progress) = prepare_resume_report(
            &test_command(),
            report,
            installers_by_url(&[
                ("https://example.com/a.exe", "a"),
                ("https://example.com/b.exe", "b"),
                ("https://example.com/c.exe", "c"),
                ("https://example.com/d.exe", "d"),
            ]),
            chrono::Utc::now(),
            Utf8Path::new("./winget-pkgs"),
        )
        .unwrap();

        let pending_urls = installers_by_url
            .keys()
            .map(ToString::to_string)
            .collect::<HashSet<_>>();
        let resume_progress = resume_progress.unwrap();

        assert_eq!(base_duration_ms, 500);
        assert_eq!(report.report_format_version, CURRENT_REPORT_FORMAT_VERSION);
        assert_eq!(report.winget_pkgs_path, "./winget-pkgs");
        assert_eq!(report.totals.success, 1);
        assert_eq!(report.totals.download_errors, 1);
        assert_eq!(report.totals.download_cancelled, 0);
        assert_eq!(resume_progress.recorded_urls, 2);
        assert_eq!(resume_progress.retrying_cancelled_urls, 1);
        assert_eq!(resume_progress.pending_urls, 2);
        assert!(pending_urls.contains("https://example.com/b.exe"));
        assert!(pending_urls.contains("https://example.com/d.exe"));
        assert!(!pending_urls.contains("https://example.com/a.exe"));
        assert!(!pending_urls.contains("https://example.com/c.exe"));
    }

    #[test]
    fn resume_does_not_retry_cancelled_url_when_success_is_already_recorded() {
        let report = test_report(
            CURRENT_REPORT_FORMAT_VERSION,
            vec![test_result(
                "https://example.com/a.exe",
                "a",
                AnalysisStatus::DownloadCancelled,
            )],
            vec![test_result(
                "https://example.com/a.exe",
                "a",
                AnalysisStatus::Success,
            )],
        );

        let (report, installers_by_url, _base_duration_ms, resume_progress) =
            prepare_resume_report(
                &test_command(),
                report,
                installers_by_url(&[("https://example.com/a.exe", "a")]),
                chrono::Utc::now(),
                Utf8Path::new("."),
            )
            .unwrap();

        let resume_progress = resume_progress.unwrap();

        assert!(installers_by_url.is_empty());
        assert!(report.download_failures.is_empty());
        assert_eq!(report.results.len(), 1);
        assert_eq!(report.results[0].status, AnalysisStatus::Success);
        assert_eq!(resume_progress.recorded_urls, 1);
        assert_eq!(resume_progress.retrying_cancelled_urls, 1);
        assert_eq!(resume_progress.pending_urls, 0);
    }

    #[test]
    fn retry_cancelled_only_requeues_cancelled_urls() {
        let report = test_report(
            CURRENT_REPORT_FORMAT_VERSION,
            vec![
                test_result(
                    "https://example.com/a.exe",
                    "a",
                    AnalysisStatus::DownloadCancelled,
                ),
                test_result(
                    "https://example.com/b.exe",
                    "b",
                    AnalysisStatus::DownloadError,
                ),
            ],
            vec![test_result(
                "https://example.com/c.exe",
                "c",
                AnalysisStatus::Success,
            )],
        );

        let (report, installers_by_url, _base_duration_ms, resume_progress) =
            prepare_retry_cancelled_report(
                &test_command(),
                report,
                chrono::Utc::now(),
                Utf8Path::new("."),
            )
            .unwrap();

        let resume_progress = resume_progress.unwrap();

        assert_eq!(resume_progress.mode, ResumeMode::RetryCancelled);
        assert_eq!(resume_progress.retrying_cancelled_urls, 1);
        assert_eq!(resume_progress.pending_urls, 1);
        assert!(
            installers_by_url
                .contains_key(&DecodedUrl::from_str("https://example.com/a.exe").unwrap())
        );
        assert!(
            !installers_by_url
                .contains_key(&DecodedUrl::from_str("https://example.com/b.exe").unwrap())
        );
        assert_eq!(report.download_failures.len(), 1);
        assert_eq!(
            report.download_failures[0].status,
            AnalysisStatus::DownloadError
        );
        assert_eq!(report.results.len(), 1);
        assert_eq!(report.results[0].status, AnalysisStatus::Success);
    }

    #[test]
    fn markdown_groups_non_error_failures_by_installer_type_and_message() {
        let mut analysis_error = test_result(
            "https://example.com/c.msi",
            "gamma",
            AnalysisStatus::AnalysisError,
        );
        analysis_error.references[0].installer_type = Some(String::from("msi"));

        let report = test_report(
            CURRENT_REPORT_FORMAT_VERSION,
            vec![
                test_result(
                    "https://example.com/a.exe",
                    "alpha",
                    AnalysisStatus::DownloadPanic,
                ),
                test_result(
                    "https://example.com/b.exe",
                    "beta",
                    AnalysisStatus::DownloadPanic,
                ),
            ],
            vec![analysis_error],
        );

        let markdown = render_markdown_report(&report);

        assert!(markdown.contains("## URL Failures By Installer Type"));
        assert!(markdown.contains("### `exe`"));
        assert!(markdown.contains("### `msi`"));
        assert!(markdown.contains("#### 2 x `download_panic`"));
        assert!(markdown.contains("#### 1 x `analysis_error`"));
    }

    #[test]
    fn markdown_omits_download_errors_and_cancellations_from_summary_and_failures() {
        let mut analysis_error = test_result(
            "https://example.com/c.msi",
            "gamma",
            AnalysisStatus::AnalysisError,
        );
        analysis_error.references[0].installer_type = Some(String::from("msi"));

        let report = test_report(
            CURRENT_REPORT_FORMAT_VERSION,
            vec![
                test_result(
                    "https://example.com/a.exe",
                    "alpha",
                    AnalysisStatus::DownloadError,
                ),
                test_result(
                    "https://example.com/b.exe",
                    "beta",
                    AnalysisStatus::DownloadCancelled,
                ),
            ],
            vec![analysis_error],
        );

        let markdown = render_markdown_report(&report);

        assert!(!markdown.contains("Download errors:"));
        assert!(!markdown.contains("Download cancelled:"));
        assert!(!markdown.contains("download_error"));
        assert!(!markdown.contains("download_cancelled"));
        assert!(markdown.contains("#### 1 x `analysis_error`"));
    }

    #[test]
    fn markdown_report_path_uses_md_extension() {
        let markdown_report =
            normalize_markdown_report_path(Utf8Path::new("installer-analysis-report.json"));

        assert_eq!(
            markdown_report,
            Utf8PathBuf::from("installer-analysis-report.md")
        );
    }

    #[test]
    fn report_parent_dir_defaults_to_current_directory_for_relative_filename() {
        let parent = report_parent_dir(Utf8Path::new("installer-analysis-report.json"));

        assert_eq!(parent, Utf8Path::new("."));
    }

    #[test]
    fn write_report_overwrite_keeps_report_parseable() {
        let temp_dir = tempfile::tempdir().unwrap();
        let report_path =
            Utf8PathBuf::from_path_buf(temp_dir.path().join("installer-analysis-report.json"))
                .unwrap();

        let first_report = test_report(
            CURRENT_REPORT_FORMAT_VERSION,
            Vec::new(),
            vec![test_result(
                "https://example.com/a.exe",
                "a",
                AnalysisStatus::Success,
            )],
        );
        write_report(&report_path, &first_report).unwrap();

        let second_report = test_report(
            CURRENT_REPORT_FORMAT_VERSION,
            vec![test_result(
                "https://example.com/b.exe",
                "b",
                AnalysisStatus::DownloadError,
            )],
            vec![test_result(
                "https://example.com/c.exe",
                "c",
                AnalysisStatus::Success,
            )],
        );
        write_report(&report_path, &second_report).unwrap();

        let persisted_report = serde_json::from_slice::<InstallerAnalysisReport>(
            &std::fs::read(report_path.as_std_path()).unwrap(),
        )
        .unwrap();

        assert_eq!(
            persisted_report.report_format_version,
            CURRENT_REPORT_FORMAT_VERSION
        );
        assert_eq!(persisted_report.totals.success, 1);
        assert_eq!(persisted_report.totals.download_errors, 1);
        assert_eq!(persisted_report.results.len(), 1);
        assert_eq!(persisted_report.download_failures.len(), 1);
        assert_eq!(persisted_report.results[0].url, "https://example.com/c.exe");
        assert_eq!(
            persisted_report.download_failures[0].url,
            "https://example.com/b.exe"
        );
    }
}
