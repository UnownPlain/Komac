use std::{
    any::Any,
    borrow::Cow,
    collections::{BTreeMap, BTreeSet, VecDeque},
    fmt::Write as FmtWrite,
    fs::{self, File, OpenOptions},
    io::{self, BufRead, BufReader, Seek, SeekFrom, Write as IoWrite},
    num::NonZeroUsize,
    panic::{self, AssertUnwindSafe},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use anstream::println;
use camino::{Utf8Path, Utf8PathBuf};
use chrono::{DateTime, Utc};
use clap::Parser;
use color_eyre::{
    Result,
    eyre::{self, WrapErr, eyre},
};
use futures_util::{FutureExt, StreamExt, stream::FuturesUnordered};
use indicatif::{ProgressBar, ProgressStyle};
use reqwest::{
    Client,
    header::{CONTENT_DISPOSITION, DNT, HeaderMap, HeaderValue, USER_AGENT},
};
use serde::{Deserialize, Serialize};
use tokio::{
    io::AsyncWriteExt,
    task,
    time::{Instant as TokioInstant, sleep_until},
};
use walkdir::WalkDir;
use winget_types::{
    PackageIdentifier, PackageVersion,
    installer::{Installer, InstallerManifest, InstallerType, VALID_FILE_EXTENSIONS},
};

use crate::analysis::Analyzer;

#[derive(Parser)]
pub struct AnalyzeWinPkgs {
    /// Local clone of microsoft/winget-pkgs, or its manifests directory
    #[arg(value_hint = clap::ValueHint::DirPath)]
    winget_pkgs_path: Utf8PathBuf,

    /// JSONL state file used for resume and report generation
    #[arg(long, default_value = "komac-analyze-winpkgs.jsonl", value_hint = clap::ValueHint::FilePath)]
    state_file: Utf8PathBuf,

    /// Write a markdown report from the run state
    #[arg(long, value_hint = clap::ValueHint::FilePath)]
    report: Option<Utf8PathBuf>,

    /// Only generate the markdown report; do not download or analyze installers
    #[arg(long)]
    report_only: bool,

    /// Only process installers declared as Nullsoft/NSIS in the manifest
    #[arg(long)]
    nullsoft_only: bool,

    /// Re-run installers whose previous terminal state was a cancelled download
    #[arg(long)]
    retry_cancelled_downloads: bool,

    /// Number of installers to download at the same time
    #[arg(long, default_value_t = NonZeroUsize::new(num_cpus::get().saturating_mul(4).max(16)).unwrap())]
    concurrent_downloads: NonZeroUsize,

    /// Number of blocking installer analyses to run at the same time
    #[arg(long, default_value_t = NonZeroUsize::new(num_cpus::get()).unwrap())]
    concurrent_analysis: NonZeroUsize,

    /// After this long, cancel downloads whose projected remaining time is too high
    #[arg(long, default_value = "30s", value_parser = parse_duration)]
    slow_download_check_after: Duration,

    /// Cancel slow downloads when they are projected to need longer than this to finish
    #[arg(long, default_value = "5m", value_parser = parse_duration)]
    slow_download_max_remaining: Duration,

    /// Disable cancellation of extremely slow downloads
    #[arg(long)]
    no_slow_download_cancel: bool,
}

impl AnalyzeWinPkgs {
    pub async fn run(self) -> Result<()> {
        let scan = scan_latest_installers(&self.winget_pkgs_path, self.nullsoft_only)?;
        let replay = StateReplay::read(&self.state_file)?;

        if self.report_only {
            let report = build_report(
                &replay,
                &scan.jobs,
                &self.winget_pkgs_path,
                &self.state_file,
                self.nullsoft_only,
            );
            self.write_or_print_report(&report)?;
            return Ok(());
        }

        let mut live_stats =
            LiveStats::from_replay(&replay, &scan.jobs, self.retry_cancelled_downloads);
        live_stats.manifest_errors = 0;
        let pending_jobs = scan
            .jobs
            .iter()
            .filter(|job| !replay.is_terminal(&job.metadata.key, self.retry_cancelled_downloads))
            .cloned()
            .collect::<VecDeque<_>>();

        let writer = Arc::new(Mutex::new(StateWriter::open(&self.state_file)?));
        record_state(
            &writer,
            StateEventKind::RunStarted {
                winget_pkgs_path: self.winget_pkgs_path.to_string(),
                total_installers: scan.jobs.len(),
                pending_installers: pending_jobs.len(),
                state_version: STATE_VERSION,
            },
        )?;

        for manifest_error in scan.manifest_errors {
            live_stats.manifest_errors += 1;
            record_state(&writer, StateEventKind::ManifestError { manifest_error })?;
        }

        let progress = ProgressBar::new(scan.jobs.len() as u64).with_style(
            ProgressStyle::with_template(
                "{msg}\n{wide_bar:.cyan/blue} {human_pos}/{human_len} {percent}%",
            )?
            .progress_chars("───"),
        );
        progress.set_position(live_stats.completed() as u64);
        progress.set_message(live_stats.message());
        progress.tick();

        let client = Client::builder()
            .default_headers(download_headers())
            .referer(false)
            .build()?;
        let cancellation = Arc::new(AtomicBool::new(false));
        let download_options = DownloadOptions {
            slow_download_cancel: !self.no_slow_download_cancel,
            slow_download_check_after: self.slow_download_check_after,
            slow_download_max_remaining: self.slow_download_max_remaining,
        };

        let mut scheduler = JobScheduler {
            jobs: pending_jobs,
            running: FuturesUnordered::new(),
            client: Arc::new(client),
            writer,
            cancellation: Arc::clone(&cancellation),
            download_options,
            max_running: self.concurrent_downloads.get() + self.concurrent_analysis.get() * 2,
            download_permits: Arc::new(tokio::sync::Semaphore::new(
                self.concurrent_downloads.get(),
            )),
            analysis_permits: Arc::new(tokio::sync::Semaphore::new(self.concurrent_analysis.get())),
        };

        let mut cancelled = false;
        loop {
            scheduler.fill();

            if scheduler.is_finished() {
                break;
            }

            tokio::select! {
                _ = tokio::signal::ctrl_c(), if !cancelled => {
                    cancelled = true;
                    cancellation.store(true, Ordering::Relaxed);
                    progress.set_message("cancelling after in-flight installers finish");
                }
                Some(result) = scheduler.running.next() => {
                    let outcome = result??;
                    live_stats.record(&outcome);
                    progress.set_position(live_stats.completed() as u64);
                    progress.set_message(live_stats.message());
                }
            }
        }

        if cancelled {
            record_state(&scheduler.writer, StateEventKind::RunCancelled)?;
        } else {
            record_state(&scheduler.writer, StateEventKind::RunFinished)?;
        }

        progress.finish_with_message(live_stats.message());
        println!("{}", live_stats.summary_line());

        let replay = StateReplay::read(&self.state_file)?;
        let report = build_report(
            &replay,
            &scan.jobs,
            &self.winget_pkgs_path,
            &self.state_file,
            self.nullsoft_only,
        );
        self.write_report_if_requested(&report)?;

        Ok(())
    }

    fn write_or_print_report(&self, report: &str) -> Result<()> {
        if self.report.is_some() {
            self.write_report_if_requested(report)
        } else {
            print!("{report}");
            Ok(())
        }
    }

    fn write_report_if_requested(&self, report: &str) -> Result<()> {
        let Some(report_path) = &self.report else {
            return Ok(());
        };

        if let Some(parent) = report_path.parent()
            && !parent.as_str().is_empty()
        {
            fs::create_dir_all(parent)?;
        }
        fs::write(report_path, report)?;
        Ok(())
    }
}

struct JobScheduler {
    jobs: VecDeque<InstallerJob>,
    running: FuturesUnordered<tokio::task::JoinHandle<Result<JobOutcome>>>,
    client: Arc<Client>,
    writer: Arc<Mutex<StateWriter>>,
    cancellation: Arc<AtomicBool>,
    download_options: DownloadOptions,
    max_running: usize,
    download_permits: Arc<tokio::sync::Semaphore>,
    analysis_permits: Arc<tokio::sync::Semaphore>,
}

impl JobScheduler {
    fn fill(&mut self) {
        while self.running.len() < self.max_running && !self.cancellation.load(Ordering::Relaxed) {
            let Some(job) = self.jobs.pop_front() else {
                break;
            };

            let client = Arc::clone(&self.client);
            let writer = Arc::clone(&self.writer);
            let cancellation = Arc::clone(&self.cancellation);
            let download_options = self.download_options;
            let download_permits = Arc::clone(&self.download_permits);
            let analysis_permits = Arc::clone(&self.analysis_permits);
            let panic_key = job.metadata.key.clone();
            let panic_installer_type = job.metadata.manifest_type.clone();
            let panic_writer = Arc::clone(&writer);

            self.running.push(tokio::spawn(async move {
                match AssertUnwindSafe(process_job(
                    job,
                    client,
                    writer,
                    cancellation,
                    download_options,
                    download_permits,
                    analysis_permits,
                ))
                .catch_unwind()
                .await
                {
                    Ok(result) => result,
                    Err(panic) => {
                        let error = panic_message(&*panic);
                        let _ = record_state(
                            &panic_writer,
                            StateEventKind::AnalysisFailed {
                                key: panic_key,
                                failure: FailureKind::Panic,
                                installer_type: panic_installer_type,
                                error,
                            },
                        );
                        Ok(JobOutcome::Failed {
                            failure: FailureKind::Panic,
                        })
                    }
                }
            }));
        }
    }

    fn is_finished(&self) -> bool {
        self.jobs.is_empty() && self.running.is_empty()
    }
}

async fn process_job(
    job: InstallerJob,
    client: Arc<Client>,
    writer: Arc<Mutex<StateWriter>>,
    cancellation: Arc<AtomicBool>,
    download_options: DownloadOptions,
    download_permits: Arc<tokio::sync::Semaphore>,
    analysis_permits: Arc<tokio::sync::Semaphore>,
) -> Result<JobOutcome> {
    record_state(
        &writer,
        StateEventKind::InstallerStarted {
            installer: job.metadata.clone(),
        },
    )?;

    if cancellation.load(Ordering::Relaxed) {
        let outcome = JobOutcome::DownloadCancelled;
        record_state(
            &writer,
            StateEventKind::DownloadCancelled {
                key: job.metadata.key,
                reason: "run cancelled".to_owned(),
            },
        )?;
        return Ok(outcome);
    }

    let download_permit = download_permits
        .acquire()
        .await
        .map_err(|_| eyre!("download semaphore was closed"))?;
    let downloaded = match download_installer(
        &client,
        &job.url,
        &job.metadata.manifest_type,
        download_options,
        &cancellation,
    )
    .await
    {
        Ok(downloaded) => downloaded,
        Err(DownloadError::Cancelled(reason)) => {
            let outcome = JobOutcome::DownloadCancelled;
            record_state(
                &writer,
                StateEventKind::DownloadCancelled {
                    key: job.metadata.key,
                    reason,
                },
            )?;
            return Ok(outcome);
        }
        Err(DownloadError::Failed(error)) => {
            let error = error.to_string();
            let outcome = JobOutcome::Failed {
                failure: FailureKind::DownloadError,
            };
            record_state(
                &writer,
                StateEventKind::DownloadFailed {
                    key: job.metadata.key,
                    error,
                },
            )?;
            return Ok(outcome);
        }
    };
    drop(download_permit);

    let analysis = analyze_downloaded_installer(downloaded, analysis_permits).await;
    match analysis {
        AnalysisResult::Succeeded {
            installer_type,
            analyzed_installers,
            limited_arp_data,
        } => {
            let limited_arp_data_count = limited_arp_data.len();
            for arp in limited_arp_data {
                record_state(
                    &writer,
                    StateEventKind::LimitedArpData {
                        key: job.metadata.key.clone(),
                        installer_type: installer_type.clone(),
                        arp,
                    },
                )?;
            }
            let outcome = JobOutcome::Succeeded;
            record_state(
                &writer,
                StateEventKind::InstallerSucceeded {
                    key: job.metadata.key,
                    installer_type,
                    analyzed_installers,
                },
            )?;
            let outcome = if limited_arp_data_count == 0 {
                outcome
            } else {
                JobOutcome::SucceededWithLimitedArp {
                    limited_arp_data: limited_arp_data_count,
                }
            };
            Ok(outcome)
        }
        AnalysisResult::Failed {
            failure,
            installer_type,
            error,
        } => {
            let installer_type =
                resolved_installer_type(&job.metadata.manifest_type, installer_type);
            let outcome = JobOutcome::Failed { failure };
            record_state(
                &writer,
                StateEventKind::AnalysisFailed {
                    key: job.metadata.key,
                    failure,
                    installer_type,
                    error,
                },
            )?;
            Ok(outcome)
        }
    }
}

#[derive(Clone, Copy)]
struct DownloadOptions {
    slow_download_cancel: bool,
    slow_download_check_after: Duration,
    slow_download_max_remaining: Duration,
}

struct DownloadedInstaller {
    file: File,
    file_name: String,
}

enum DownloadError {
    Cancelled(String),
    Failed(eyre::Report),
}

async fn download_installer(
    client: &Client,
    url: &str,
    manifest_type: &str,
    options: DownloadOptions,
    cancellation: &AtomicBool,
) -> std::result::Result<DownloadedInstaller, DownloadError> {
    let parsed_url = url.parse::<url::Url>().map_err(|error| {
        DownloadError::Failed(eyre!("failed to parse installer URL {url:?}: {error}"))
    })?;

    let response = client
        .get(parsed_url.clone())
        .send()
        .await
        .map_err(|error| DownloadError::Failed(error.into()))?;

    let status = response.status();
    if !status.is_success() {
        return Err(DownloadError::Failed(eyre!("{url} returned {status}")));
    }

    let file_name = file_name_from_response(
        &parsed_url,
        response.url(),
        response.headers().get(CONTENT_DISPOSITION),
        fallback_file_name(manifest_type),
    )
    .into_owned();
    let content_length = response.content_length();
    let mut stream = response.bytes_stream();
    let temp_file = tempfile::tempfile().map_err(|error| DownloadError::Failed(error.into()))?;
    let mut file = tokio::fs::File::from_std(
        temp_file
            .try_clone()
            .map_err(|error| DownloadError::Failed(error.into()))?,
    );

    let started = TokioInstant::now();
    let mut next_check = started + options.slow_download_check_after;
    let mut downloaded = 0_u64;

    loop {
        if cancellation.load(Ordering::Relaxed) {
            return Err(DownloadError::Cancelled("run cancelled".to_owned()));
        }

        let check = sleep_until(next_check);
        tokio::pin!(check);

        tokio::select! {
            () = &mut check, if options.slow_download_cancel => {
                if let Some(reason) = slow_download_reason(
                    downloaded,
                    content_length,
                    started.elapsed(),
                    options.slow_download_max_remaining,
                ) {
                    return Err(DownloadError::Cancelled(reason));
                }
                next_check += options.slow_download_check_after;
            }
            chunk = stream.next() => {
                let Some(chunk) = chunk else {
                    break;
                };
                let chunk = chunk.map_err(|error| DownloadError::Failed(error.into()))?;
                downloaded += chunk.len() as u64;
                file.write_all(&chunk)
                    .await
                    .map_err(|error| DownloadError::Failed(error.into()))?;
            }
        }
    }

    file.flush()
        .await
        .map_err(|error| DownloadError::Failed(error.into()))?;
    file.shutdown()
        .await
        .map_err(|error| DownloadError::Failed(error.into()))?;
    drop(file);

    Ok(DownloadedInstaller {
        file: temp_file,
        file_name,
    })
}

fn slow_download_reason(
    downloaded: u64,
    content_length: Option<u64>,
    elapsed: Duration,
    max_remaining: Duration,
) -> Option<String> {
    let content_length = content_length?;
    if downloaded >= content_length {
        return None;
    }

    if downloaded == 0 {
        return Some("download made no progress after the slow-download check window".to_owned());
    }

    let bytes_per_second = downloaded as f64 / elapsed.as_secs_f64();
    if bytes_per_second <= f64::EPSILON {
        return Some("download made no measurable progress".to_owned());
    }

    let remaining_seconds = (content_length - downloaded) as f64 / bytes_per_second;
    (remaining_seconds > max_remaining.as_secs_f64()).then(|| {
        format!(
            "projected remaining download time {:.0}s exceeds {}s",
            remaining_seconds,
            max_remaining.as_secs()
        )
    })
}

enum AnalysisResult {
    Succeeded {
        installer_type: String,
        analyzed_installers: usize,
        limited_arp_data: Vec<LimitedArpRecord>,
    },
    Failed {
        failure: FailureKind,
        installer_type: String,
        error: String,
    },
}

async fn analyze_downloaded_installer(
    downloaded: DownloadedInstaller,
    analysis_permits: Arc<tokio::sync::Semaphore>,
) -> AnalysisResult {
    let permit = analysis_permits.acquire().await;
    let Ok(_permit) = permit else {
        return AnalysisResult::Failed {
            failure: FailureKind::AnalysisError,
            installer_type: UNKNOWN_TYPE.to_owned(),
            error: "analysis semaphore was closed".to_owned(),
        };
    };

    match task::spawn_blocking(move || analyze_downloaded_installer_blocking(downloaded)).await {
        Ok(result) => result,
        Err(error) if error.is_panic() => AnalysisResult::Failed {
            failure: FailureKind::Panic,
            installer_type: UNKNOWN_TYPE.to_owned(),
            error: panic_message(&*error.into_panic()),
        },
        Err(error) => AnalysisResult::Failed {
            failure: FailureKind::AnalysisError,
            installer_type: UNKNOWN_TYPE.to_owned(),
            error: error.to_string(),
        },
    }
}

fn analyze_downloaded_installer_blocking(mut downloaded: DownloadedInstaller) -> AnalysisResult {
    let result = panic::catch_unwind(AssertUnwindSafe(|| {
        downloaded.file.seek(SeekFrom::Start(0))?;
        let analyzer = Analyzer::new(&mut downloaded.file, &downloaded.file_name)?;
        let installer_type = analyzer
            .installer_kind
            .map_or(UNKNOWN_TYPE, |installer_kind| installer_kind.as_str())
            .to_owned();
        let analyzed_installers = analyzer.installers.len();
        let limited_arp_data = limited_nullsoft_arp_data(&analyzer.installers);
        Ok::<_, eyre::Report>((
            installer_type,
            analyzed_installers,
            analyzer.nsis_infinite_loop,
            limited_arp_data,
        ))
    }));

    match result {
        Ok(Ok((installer_type, analyzed_installers, false, limited_arp_data))) => {
            AnalysisResult::Succeeded {
                installer_type,
                analyzed_installers,
                limited_arp_data,
            }
        }
        Ok(Ok((installer_type, _analyzed_installers, true, _limited_arp_data))) => {
            AnalysisResult::Failed {
                failure: FailureKind::NsisInfiniteLoop,
                installer_type,
                error: "nullsoft analysis ran into an infinite loop".to_owned(),
            }
        }
        Ok(Err(error)) => AnalysisResult::Failed {
            failure: FailureKind::AnalysisError,
            installer_type: UNKNOWN_TYPE.to_owned(),
            error: error.to_string(),
        },
        Err(panic) => AnalysisResult::Failed {
            failure: FailureKind::Panic,
            installer_type: UNKNOWN_TYPE.to_owned(),
            error: panic_message(&*panic),
        },
    }
}

fn download_headers() -> HeaderMap {
    const MICROSOFT_DELIVERY_OPTIMIZATION: HeaderValue =
        HeaderValue::from_static("Microsoft-Delivery-Optimization/10.1");
    const SEC_GPC: &str = "Sec-GPC";

    let mut headers = HeaderMap::new();
    headers.insert(USER_AGENT, MICROSOFT_DELIVERY_OPTIMIZATION);
    headers.insert(DNT, HeaderValue::from(1));
    headers.insert(SEC_GPC, HeaderValue::from(1));
    headers
}

fn file_name_from_response<'a>(
    initial_url: &'a url::Url,
    final_url: &'a url::Url,
    content_disposition: Option<&'a HeaderValue>,
    fallback: &'static str,
) -> Cow<'a, str> {
    const FILENAME: &str = "filename";
    const FILENAME_EXT: &str = "filename*";

    if let Some(content_disposition) = content_disposition
        && let Ok(content_disposition) = content_disposition.to_str()
    {
        let mut sections = content_disposition.split(';');
        let _disposition = sections.next();
        let filenames = sections
            .filter_map(|section| {
                section
                    .split_once('=')
                    .map(|(key, value)| (key.trim(), value.trim().trim_matches('"').trim()))
                    .filter(|(key, value)| key.starts_with(FILENAME) && !value.is_empty())
            })
            .collect::<Vec<_>>();

        let filename = filenames
            .iter()
            .find_map(|&(key, value)| (key == FILENAME_EXT).then_some(value))
            .or_else(|| {
                filenames
                    .into_iter()
                    .find_map(|(key, value)| (key == FILENAME).then_some(value))
            });
        if let Some(filename) = filename {
            return Cow::Borrowed(filename);
        }
    }

    url_file_name(initial_url)
        .or_else(|| url_file_name(final_url))
        .map_or(Cow::Borrowed(fallback), Cow::Borrowed)
}

const fn fallback_file_name(manifest_type: &str) -> &'static str {
    match manifest_type.as_bytes() {
        b"appx" => "installer.appx",
        b"msi" | b"wix" => "installer.msi",
        b"msix" => "installer.msix",
        b"zip" => "installer.zip",
        _ => "installer.exe",
    }
}

fn limited_nullsoft_arp_data(installers: &[Installer]) -> Vec<LimitedArpRecord> {
    installers
        .iter()
        .enumerate()
        .filter(|(_index, installer)| {
            installer.r#type == Some(InstallerType::Nullsoft)
                || installer.nested_installer_type.map(InstallerType::from)
                    == Some(InstallerType::Nullsoft)
        })
        .filter_map(|(index, installer)| {
            let arp_entry = installer
                .apps_and_features_entries
                .iter()
                .find(|entry| !entry.is_empty());

            let display_name = arp_entry
                .and_then(|entry| entry.display_name())
                .map(str::to_owned);
            let publisher = arp_entry
                .and_then(|entry| entry.publisher())
                .map(str::to_owned);
            let display_version = arp_entry
                .and_then(|entry| entry.display_version())
                .map(ToString::to_string);
            let product_code = installer
                .product_code
                .as_deref()
                .or_else(|| arp_entry.and_then(|entry| entry.product_code()))
                .map(str::to_owned);

            let mut missing_fields = Vec::new();
            if display_name.is_none() {
                missing_fields.push("DisplayName".to_owned());
            }
            if publisher.is_none() {
                missing_fields.push("Publisher".to_owned());
            }
            if display_version.is_none() {
                missing_fields.push("DisplayVersion".to_owned());
            }
            if product_code.is_none() {
                missing_fields.push("ProductCode".to_owned());
            }

            (!missing_fields.is_empty()).then_some(LimitedArpRecord {
                analyzed_installer_index: index,
                missing_fields,
                display_name,
                publisher,
                display_version,
                product_code,
            })
        })
        .collect()
}

fn url_file_name(url: &url::Url) -> Option<&str> {
    url.path_segments()
        .and_then(|mut segments| segments.next_back())
        .filter(|last_segment| {
            Utf8Path::new(last_segment)
                .extension()
                .is_some_and(|extension| VALID_FILE_EXTENSIONS.contains(&extension))
        })
}

#[derive(Clone)]
struct InstallerJob {
    metadata: InstallerMetadata,
    url: String,
}

struct ScanResult {
    jobs: Vec<InstallerJob>,
    manifest_errors: Vec<ManifestErrorRecord>,
}

#[derive(Clone)]
struct LatestManifest {
    package_identifier: PackageIdentifier,
    package_version: PackageVersion,
    path: Utf8PathBuf,
}

fn scan_latest_installers(winget_pkgs_path: &Utf8Path, nullsoft_only: bool) -> Result<ScanResult> {
    let manifests_root = if winget_pkgs_path.join("manifests").is_dir() {
        winget_pkgs_path.join("manifests")
    } else {
        winget_pkgs_path.to_path_buf()
    };

    let mut latest_manifests = BTreeMap::<PackageIdentifier, LatestManifest>::new();
    let mut manifest_errors = Vec::new();

    for entry in WalkDir::new(&manifests_root) {
        let entry = entry?;
        if !entry.file_type().is_file() {
            continue;
        }

        let path = Utf8PathBuf::from_path_buf(entry.into_path())
            .map_err(|path| eyre!("manifest path is not valid UTF-8: {}", path.display()))?;
        if !path
            .file_name()
            .is_some_and(|file_name| file_name.ends_with(".installer.yaml"))
        {
            continue;
        }

        match latest_manifest_from_path(path.clone()) {
            Ok(candidate) => {
                latest_manifests
                    .entry(candidate.package_identifier.clone())
                    .and_modify(|latest| {
                        if candidate.package_version > latest.package_version {
                            *latest = candidate.clone();
                        }
                    })
                    .or_insert(candidate);
            }
            Err(error) => manifest_errors.push(ManifestErrorRecord {
                path: path.to_string(),
                package_identifier: None,
                package_version: None,
                error: error.to_string(),
            }),
        }
    }

    let mut jobs = Vec::new();
    for latest in latest_manifests.into_values() {
        let manifest = match fs::read_to_string(&latest.path)
            .wrap_err_with(|| format!("failed to read {}", latest.path))
            .and_then(|manifest| {
                serde_yaml::from_str::<InstallerManifest>(&manifest)
                    .wrap_err_with(|| format!("failed to parse {}", latest.path))
            }) {
            Ok(manifest) => manifest,
            Err(error) => {
                manifest_errors.push(ManifestErrorRecord {
                    path: latest.path.to_string(),
                    package_identifier: Some(latest.package_identifier.to_string()),
                    package_version: Some(latest.package_version.to_string()),
                    error: error.to_string(),
                });
                continue;
            }
        };

        let installer_count = manifest.installers.len();
        for (index, installer) in manifest.installers.iter().enumerate() {
            if nullsoft_only && !is_nullsoft_candidate(&manifest, installer) {
                continue;
            }
            jobs.push(installer_job(
                &latest.path,
                &manifest,
                installer,
                index,
                installer_count,
            ));
        }
    }

    Ok(ScanResult {
        jobs,
        manifest_errors,
    })
}

fn is_nullsoft_candidate(manifest: &InstallerManifest, installer: &Installer) -> bool {
    installer.r#type.or(manifest.r#type) == Some(InstallerType::Nullsoft)
        || installer
            .nested_installer_type
            .or(manifest.nested_installer_type)
            .map(InstallerType::from)
            == Some(InstallerType::Nullsoft)
}

fn latest_manifest_from_path(path: Utf8PathBuf) -> Result<LatestManifest> {
    let file_name = path
        .file_name()
        .ok_or_else(|| eyre!("installer manifest path has no file name"))?;
    let package_identifier = file_name
        .strip_suffix(".installer.yaml")
        .ok_or_else(|| eyre!("installer manifest file name has no .installer.yaml suffix"))?
        .parse::<PackageIdentifier>()?;
    let package_version = path
        .parent()
        .and_then(Utf8Path::file_name)
        .ok_or_else(|| eyre!("installer manifest path has no version directory"))?
        .parse::<PackageVersion>()?;

    Ok(LatestManifest {
        package_identifier,
        package_version,
        path,
    })
}

fn installer_job(
    manifest_path: &Utf8Path,
    manifest: &InstallerManifest,
    installer: &Installer,
    installer_index: usize,
    installer_count: usize,
) -> InstallerJob {
    let package_identifier = manifest.package_identifier.to_string();
    let package_version = manifest.package_version.to_string();
    let url = installer.url.to_string();
    let key = format!("{package_identifier}|{package_version}|{installer_index}|{url}");
    let manifest_type = manifest_installer_type(manifest, installer).to_owned();

    InstallerJob {
        metadata: InstallerMetadata {
            key,
            package_identifier,
            package_version,
            manifest_path: manifest_path.to_string(),
            installer_index,
            installer_count,
            url: url.clone(),
            manifest_type,
        },
        url,
    }
}

fn manifest_installer_type(manifest: &InstallerManifest, installer: &Installer) -> &'static str {
    let installer_type = installer.r#type.or(manifest.r#type);
    if installer_type == Some(InstallerType::Zip) {
        return "zip";
    }

    let nested_type = installer
        .nested_installer_type
        .or(manifest.nested_installer_type)
        .map(InstallerType::from);

    installer_type_group(installer_type.or(nested_type))
}

fn installer_type_group(installer_type: Option<InstallerType>) -> &'static str {
    match installer_type {
        Some(InstallerType::Appx) => "appx",
        Some(InstallerType::Burn) => "burn",
        Some(InstallerType::Exe | InstallerType::Portable) => "generic exe",
        Some(InstallerType::Inno) => "inno",
        Some(InstallerType::Msi) => "msi",
        Some(InstallerType::Msix) => "msix",
        Some(InstallerType::Nullsoft) => "nullsoft",
        Some(InstallerType::Wix) => "wix",
        Some(InstallerType::Zip) => "zip",
        Some(InstallerType::Font) => "font",
        Some(InstallerType::Pwa) => "pwa",
        None => MANIFEST_UNSPECIFIED_TYPE,
        Some(_) => UNKNOWN_TYPE,
    }
}

const STATE_VERSION: u8 = 1;
const MANIFEST_UNSPECIFIED_TYPE: &str = "manifest unspecified";
const UNKNOWN_TYPE: &str = "unknown";

fn resolved_installer_type(manifest_type: &str, analyzed_type: String) -> String {
    if analyzed_type == UNKNOWN_TYPE {
        manifest_type.to_owned()
    } else {
        analyzed_type
    }
}

struct StateWriter {
    file: File,
}

impl StateWriter {
    fn open(path: &Utf8Path) -> io::Result<Self> {
        if let Some(parent) = path.parent()
            && !parent.as_str().is_empty()
        {
            fs::create_dir_all(parent)?;
        }

        Ok(Self {
            file: OpenOptions::new().create(true).append(true).open(path)?,
        })
    }

    fn record(&mut self, kind: StateEventKind) -> io::Result<()> {
        serde_json::to_writer(
            &mut self.file,
            &StateEvent {
                at: Utc::now(),
                kind,
            },
        )
        .map_err(io::Error::other)?;
        self.file.write_all(b"\n")?;
        self.file.flush()
    }
}

fn record_state(writer: &Arc<Mutex<StateWriter>>, kind: StateEventKind) -> Result<()> {
    writer
        .lock()
        .map_err(|_| eyre!("state writer lock poisoned"))?
        .record(kind)?;
    Ok(())
}

#[derive(Serialize, Deserialize)]
struct StateEvent {
    at: DateTime<Utc>,
    #[serde(flatten)]
    kind: StateEventKind,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
enum StateEventKind {
    RunStarted {
        winget_pkgs_path: String,
        total_installers: usize,
        pending_installers: usize,
        state_version: u8,
    },
    ManifestError {
        manifest_error: ManifestErrorRecord,
    },
    InstallerStarted {
        installer: InstallerMetadata,
    },
    DownloadCancelled {
        key: String,
        reason: String,
    },
    DownloadFailed {
        key: String,
        error: String,
    },
    AnalysisFailed {
        key: String,
        failure: FailureKind,
        installer_type: String,
        error: String,
    },
    InstallerSucceeded {
        key: String,
        installer_type: String,
        analyzed_installers: usize,
    },
    LimitedArpData {
        key: String,
        installer_type: String,
        arp: LimitedArpRecord,
    },
    RunCancelled,
    RunFinished,
}

#[derive(Clone, Serialize, Deserialize)]
struct InstallerMetadata {
    key: String,
    package_identifier: String,
    package_version: String,
    manifest_path: String,
    installer_index: usize,
    installer_count: usize,
    url: String,
    manifest_type: String,
}

#[derive(Clone, Serialize, Deserialize)]
struct ManifestErrorRecord {
    path: String,
    package_identifier: Option<String>,
    package_version: Option<String>,
    error: String,
}

#[derive(Clone, Serialize, Deserialize)]
struct LimitedArpRecord {
    analyzed_installer_index: usize,
    missing_fields: Vec<String>,
    display_name: Option<String>,
    publisher: Option<String>,
    display_version: Option<String>,
    product_code: Option<String>,
}

impl ManifestErrorRecord {
    fn dedupe_key(&self) -> String {
        format!(
            "{}|{}|{}",
            self.path,
            self.package_identifier.as_deref().unwrap_or_default(),
            self.package_version.as_deref().unwrap_or_default()
        )
    }
}

#[derive(Clone, Copy, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum FailureKind {
    AnalysisError,
    DownloadError,
    NsisInfiniteLoop,
    Panic,
}

impl FailureKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::AnalysisError => "analysis error",
            Self::DownloadError => "download error",
            Self::NsisInfiniteLoop => "nsis infinite loop",
            Self::Panic => "panic",
        }
    }
}

#[derive(Default)]
struct StateReplay {
    total_installers: Option<usize>,
    run_cancelled: bool,
    run_finished: bool,
    installers: BTreeMap<String, InstallerRecord>,
    manifest_errors: BTreeMap<String, ManifestErrorRecord>,
}

impl StateReplay {
    fn read(path: &Utf8Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }

        let file = File::open(path)?;
        let mut replay = Self::default();
        for line in BufReader::new(file).lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            let Ok(event) = serde_json::from_str::<StateEvent>(&line) else {
                continue;
            };
            replay.apply(event.kind);
        }
        Ok(replay)
    }

    fn apply(&mut self, event: StateEventKind) {
        match event {
            StateEventKind::RunStarted {
                total_installers, ..
            } => {
                self.total_installers = Some(total_installers);
                self.manifest_errors.clear();
                self.run_cancelled = false;
                self.run_finished = false;
            }
            StateEventKind::ManifestError { manifest_error } => {
                self.manifest_errors
                    .insert(manifest_error.dedupe_key(), manifest_error);
            }
            StateEventKind::InstallerStarted { installer } => {
                self.installers.insert(
                    installer.key.clone(),
                    InstallerRecord {
                        metadata: installer,
                        status: InstallerStatus::InProgress,
                        limited_arp_data: Vec::new(),
                    },
                );
            }
            StateEventKind::DownloadCancelled { key, reason } => {
                if let Some(record) = self.installers.get_mut(&key) {
                    record.status = InstallerStatus::DownloadCancelled { reason };
                }
            }
            StateEventKind::DownloadFailed { key, error } => {
                if let Some(record) = self.installers.get_mut(&key) {
                    record.status = InstallerStatus::Failed {
                        failure: FailureKind::DownloadError,
                        installer_type: record.metadata.manifest_type.clone(),
                        error,
                    };
                }
            }
            StateEventKind::AnalysisFailed {
                key,
                failure,
                installer_type,
                error,
            } => {
                if let Some(record) = self.installers.get_mut(&key) {
                    record.status = InstallerStatus::Failed {
                        failure,
                        installer_type,
                        error,
                    };
                }
            }
            StateEventKind::InstallerSucceeded {
                key,
                installer_type,
                analyzed_installers: _,
            } => {
                if let Some(record) = self.installers.get_mut(&key) {
                    record.status = InstallerStatus::Succeeded { installer_type };
                }
            }
            StateEventKind::LimitedArpData {
                key,
                installer_type,
                arp,
            } => {
                if let Some(record) = self.installers.get_mut(&key) {
                    record.limited_arp_data.push((installer_type, arp));
                }
            }
            StateEventKind::RunCancelled => self.run_cancelled = true,
            StateEventKind::RunFinished => self.run_finished = true,
        }
    }

    fn is_terminal(&self, key: &str, retry_cancelled_downloads: bool) -> bool {
        self.installers
            .get(key)
            .is_some_and(|record| record.status.is_terminal(retry_cancelled_downloads))
    }
}

struct InstallerRecord {
    metadata: InstallerMetadata,
    status: InstallerStatus,
    limited_arp_data: Vec<(String, LimitedArpRecord)>,
}

enum InstallerStatus {
    InProgress,
    Succeeded {
        installer_type: String,
    },
    DownloadCancelled {
        reason: String,
    },
    Failed {
        failure: FailureKind,
        installer_type: String,
        error: String,
    },
}

impl InstallerStatus {
    const fn is_terminal(&self, retry_cancelled_downloads: bool) -> bool {
        match self {
            Self::InProgress => false,
            Self::DownloadCancelled { .. } => !retry_cancelled_downloads,
            Self::Succeeded { .. } | Self::Failed { .. } => true,
        }
    }
}

enum JobOutcome {
    Succeeded,
    SucceededWithLimitedArp { limited_arp_data: usize },
    DownloadCancelled,
    Failed { failure: FailureKind },
}

#[derive(Default)]
struct LiveStats {
    total: usize,
    success: usize,
    download_cancelled: usize,
    failed: usize,
    download_failed: usize,
    analysis_error: usize,
    panic: usize,
    nsis_infinite_loop: usize,
    limited_arp_data: usize,
    manifest_errors: usize,
}

impl LiveStats {
    fn from_replay(
        replay: &StateReplay,
        jobs: &[InstallerJob],
        retry_cancelled_downloads: bool,
    ) -> Self {
        let mut stats = Self {
            total: jobs.len(),
            manifest_errors: replay.manifest_errors.len(),
            ..Self::default()
        };

        for job in jobs {
            let Some(record) = replay.installers.get(&job.metadata.key) else {
                continue;
            };
            if retry_cancelled_downloads
                && matches!(record.status, InstallerStatus::DownloadCancelled { .. })
            {
                continue;
            }
            stats.record_status(&record.status);
            stats.limited_arp_data += record.limited_arp_data.len();
        }

        stats
    }

    fn record(&mut self, outcome: &JobOutcome) {
        match outcome {
            JobOutcome::Succeeded => self.success += 1,
            JobOutcome::SucceededWithLimitedArp { limited_arp_data } => {
                self.success += 1;
                self.limited_arp_data += limited_arp_data;
            }
            JobOutcome::DownloadCancelled => self.download_cancelled += 1,
            JobOutcome::Failed { failure, .. } => {
                self.failed += 1;
                match failure {
                    FailureKind::AnalysisError => self.analysis_error += 1,
                    FailureKind::DownloadError => self.download_failed += 1,
                    FailureKind::NsisInfiniteLoop => self.nsis_infinite_loop += 1,
                    FailureKind::Panic => self.panic += 1,
                }
            }
        }
    }

    fn record_status(&mut self, status: &InstallerStatus) {
        match status {
            InstallerStatus::Succeeded { .. } => self.success += 1,
            InstallerStatus::DownloadCancelled { .. } => self.download_cancelled += 1,
            InstallerStatus::Failed { failure, .. } => {
                self.failed += 1;
                match failure {
                    FailureKind::AnalysisError => self.analysis_error += 1,
                    FailureKind::DownloadError => self.download_failed += 1,
                    FailureKind::NsisInfiniteLoop => self.nsis_infinite_loop += 1,
                    FailureKind::Panic => self.panic += 1,
                }
            }
            InstallerStatus::InProgress => {}
        }
    }

    const fn completed(&self) -> usize {
        self.success + self.download_cancelled + self.failed
    }

    fn message(&self) -> String {
        format!(
            "installers {} | success {} | cancelled downloads {} | failed {} (download {}, error {}, panic {}, nsis loop {}) | limited arp {} | manifest errors {}",
            self.total,
            self.success,
            self.download_cancelled,
            self.failed,
            self.download_failed,
            self.analysis_error,
            self.panic,
            self.nsis_infinite_loop,
            self.limited_arp_data,
            self.manifest_errors
        )
    }

    fn summary_line(&self) -> String {
        let progress = if self.total == 0 {
            100.0
        } else {
            self.completed() as f64 / self.total as f64 * 100.0
        };
        format!("progress {progress:.2}% | {}", self.message())
    }
}

#[derive(Default)]
struct ReportStats {
    total: usize,
    success: usize,
    download_cancelled: usize,
    failed: usize,
    download_failed: usize,
    analysis_error: usize,
    panic: usize,
    nsis_infinite_loop: usize,
    limited_arp_data: usize,
    in_progress: usize,
    pending: usize,
    manifest_errors: usize,
    by_type: BTreeMap<String, TypeStats>,
    download_issues: Vec<DownloadIssueRow>,
    failures: Vec<FailureRow>,
    limited_arp_rows: Vec<LimitedArpRow>,
}

impl ReportStats {
    fn completed(&self) -> usize {
        self.success + self.download_cancelled + self.failed
    }

    fn progress(&self) -> f64 {
        if self.total == 0 {
            100.0
        } else {
            self.completed() as f64 / self.total as f64 * 100.0
        }
    }
}

#[derive(Default)]
struct TypeStats {
    total: usize,
    success: usize,
    download_cancelled: usize,
    failed: usize,
    download_failed: usize,
    analysis_error: usize,
    panic: usize,
    nsis_infinite_loop: usize,
    limited_arp_data: usize,
    in_progress: usize,
    pending: usize,
}

struct FailureRow {
    installer_type: String,
    metadata: InstallerMetadata,
    failure: FailureKind,
    error: String,
}

struct DownloadIssueRow {
    installer_type: String,
    metadata: InstallerMetadata,
    kind: DownloadIssueKind,
    reason: String,
}

#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd)]
enum DownloadIssueKind {
    Cancelled,
    Error,
}

impl DownloadIssueKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Cancelled => "cancelled",
            Self::Error => "error",
        }
    }
}

struct LimitedArpRow {
    installer_type: String,
    metadata: InstallerMetadata,
    arp: LimitedArpRecord,
}

fn build_report(
    replay: &StateReplay,
    jobs: &[InstallerJob],
    winget_pkgs_path: &Utf8Path,
    state_file: &Utf8Path,
    nullsoft_only: bool,
) -> String {
    let stats = build_report_stats(replay, jobs, !nullsoft_only);
    let run_status = run_status(replay, &stats);

    let mut report = String::new();
    let _ = writeln!(report, "# komac analyze-winpkgs report");
    let _ = writeln!(report);
    let _ = writeln!(report, "- Generated: {}", Utc::now().to_rfc3339());
    let _ = writeln!(report, "- Run status: {run_status}");
    let _ = writeln!(
        report,
        "- Mode: {}",
        if nullsoft_only {
            "nullsoft only"
        } else {
            "all installers"
        }
    );
    let _ = writeln!(report, "- winget-pkgs path: `{}`", winget_pkgs_path);
    let _ = writeln!(report, "- State file: `{state_file}`");
    let _ = writeln!(report);

    let _ = writeln!(report, "## Summary");
    let _ = writeln!(report);
    let _ = writeln!(report, "| Metric | Value |");
    let _ = writeln!(report, "| --- | ---: |");
    let _ = writeln!(report, "| Installers | {} |", stats.total);
    let _ = writeln!(report, "| Progress | {:.2}% |", stats.progress());
    let _ = writeln!(report, "| Success | {} |", stats.success);
    let _ = writeln!(
        report,
        "| Cancelled downloads | {} |",
        stats.download_cancelled
    );
    let _ = writeln!(report, "| Total fail | {} |", stats.failed);
    let _ = writeln!(report, "| Download fail | {} |", stats.download_failed);
    let _ = writeln!(report, "| Analysis error | {} |", stats.analysis_error);
    let _ = writeln!(report, "| Panic | {} |", stats.panic);
    let _ = writeln!(
        report,
        "| NSIS infinite loop | {} |",
        stats.nsis_infinite_loop
    );
    let _ = writeln!(report, "| Limited ARP data | {} |", stats.limited_arp_data);
    let _ = writeln!(report, "| In progress | {} |", stats.in_progress);
    let _ = writeln!(report, "| Pending | {} |", stats.pending);
    let _ = writeln!(report, "| Manifest errors | {} |", stats.manifest_errors);
    let _ = writeln!(report);

    let _ = writeln!(report, "## Installer Types");
    let _ = writeln!(report);
    let _ = writeln!(
        report,
        "| Type | Total | Success | Cancelled download | Failed | Download fail | Analysis error | Panic | NSIS loop | Limited ARP | In progress | Pending |"
    );
    let _ = writeln!(
        report,
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |"
    );
    for (installer_type, type_stats) in &stats.by_type {
        let _ = writeln!(
            report,
            "| {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} |",
            markdown_cell(installer_type),
            type_stats.total,
            type_stats.success,
            type_stats.download_cancelled,
            type_stats.failed,
            type_stats.download_failed,
            type_stats.analysis_error,
            type_stats.panic,
            type_stats.nsis_infinite_loop,
            type_stats.limited_arp_data,
            type_stats.in_progress,
            type_stats.pending
        );
    }
    let _ = writeln!(report);

    let _ = writeln!(report, "## Manifest Errors");
    let _ = writeln!(report);
    if replay.manifest_errors.is_empty() {
        let _ = writeln!(report, "None.");
    } else {
        let _ = writeln!(report, "| Package | Version | Path | Error |");
        let _ = writeln!(report, "| --- | --- | --- | --- |");
        for manifest_error in replay.manifest_errors.values() {
            let _ = writeln!(
                report,
                "| {} | {} | `{}` | {} |",
                markdown_cell(manifest_error.package_identifier.as_deref().unwrap_or("")),
                markdown_cell(manifest_error.package_version.as_deref().unwrap_or("")),
                markdown_cell(&manifest_error.path),
                markdown_cell(&manifest_error.error)
            );
        }
    }
    let _ = writeln!(report);

    let _ = writeln!(report, "## Limited ARP Data");
    let _ = writeln!(report);
    if stats.limited_arp_rows.is_empty() {
        let _ = writeln!(report, "None.");
    } else {
        let _ = writeln!(
            report,
            "| Type | Package | Version | Installer | Missing fields | DisplayName | Publisher | DisplayVersion | ProductCode | URL |"
        );
        let _ = writeln!(
            report,
            "| --- | --- | --- | ---: | --- | --- | --- | --- | --- | --- |"
        );
        for row in &stats.limited_arp_rows {
            let _ = writeln!(
                report,
                "| {} | {} | {} | {}/{} | {} | {} | {} | {} | {} | {} |",
                markdown_cell(&row.installer_type),
                markdown_cell(&row.metadata.package_identifier),
                markdown_cell(&row.metadata.package_version),
                row.metadata.installer_index + 1,
                row.metadata.installer_count,
                markdown_cell(&row.arp.missing_fields.join(", ")),
                markdown_cell(row.arp.display_name.as_deref().unwrap_or("")),
                markdown_cell(row.arp.publisher.as_deref().unwrap_or("")),
                markdown_cell(row.arp.display_version.as_deref().unwrap_or("")),
                markdown_cell(row.arp.product_code.as_deref().unwrap_or("")),
                markdown_link(&row.metadata.url)
            );
        }
    }
    let _ = writeln!(report);

    let _ = writeln!(report, "## Download Issues");
    let _ = writeln!(report);
    if stats.download_issues.is_empty() {
        let _ = writeln!(report, "None.");
    } else {
        let mut grouped_download_issues =
            BTreeMap::<(String, DownloadIssueKind, String), Vec<&DownloadIssueRow>>::new();
        for issue in &stats.download_issues {
            grouped_download_issues
                .entry((
                    issue.installer_type.clone(),
                    issue.kind,
                    issue.reason.clone(),
                ))
                .or_default()
                .push(issue);
        }

        for ((installer_type, kind, reason), issues) in grouped_download_issues {
            let _ = writeln!(
                report,
                "### {} {}: {}",
                markdown_cell(&installer_type),
                kind.as_str(),
                markdown_cell(&reason)
            );
            let _ = writeln!(report);
            let _ = writeln!(report, "| Package | Version | Installer | URL |");
            let _ = writeln!(report, "| --- | --- | ---: | --- |");
            for issue in issues {
                let _ = writeln!(
                    report,
                    "| {} | {} | {}/{} | {} |",
                    markdown_cell(&issue.metadata.package_identifier),
                    markdown_cell(&issue.metadata.package_version),
                    issue.metadata.installer_index + 1,
                    issue.metadata.installer_count,
                    markdown_link(&issue.metadata.url)
                );
            }
            let _ = writeln!(report);
        }
    }
    let _ = writeln!(report);

    let _ = writeln!(report, "## Analysis Failures");
    let _ = writeln!(report);
    if stats.failures.is_empty() {
        let _ = writeln!(report, "None.");
    } else {
        let mut grouped_failures =
            BTreeMap::<(String, FailureKind, String), Vec<&FailureRow>>::new();
        for failure in &stats.failures {
            grouped_failures
                .entry((
                    failure.installer_type.clone(),
                    failure.failure,
                    failure.error.clone(),
                ))
                .or_default()
                .push(failure);
        }

        for ((installer_type, failure_kind, error), failures) in grouped_failures {
            let _ = writeln!(
                report,
                "### {} {}: {}",
                markdown_cell(&installer_type),
                failure_kind.as_str(),
                markdown_cell(&error)
            );
            let _ = writeln!(report);
            let _ = writeln!(report, "| Package | Version | Installer | URL |");
            let _ = writeln!(report, "| --- | --- | ---: | --- |");
            for failure in failures {
                let _ = writeln!(
                    report,
                    "| {} | {} | {}/{} | {} |",
                    markdown_cell(&failure.metadata.package_identifier),
                    markdown_cell(&failure.metadata.package_version),
                    failure.metadata.installer_index + 1,
                    failure.metadata.installer_count,
                    markdown_link(&failure.metadata.url)
                );
            }
            let _ = writeln!(report);
        }
    }

    report
}

fn build_report_stats(
    replay: &StateReplay,
    jobs: &[InstallerJob],
    include_stale: bool,
) -> ReportStats {
    let mut stats = ReportStats {
        total: if include_stale {
            jobs.len()
                .max(replay.total_installers.unwrap_or(replay.installers.len()))
        } else {
            jobs.len()
        },
        manifest_errors: replay.manifest_errors.len(),
        ..ReportStats::default()
    };
    let mut seen = BTreeSet::new();

    for job in jobs {
        seen.insert(job.metadata.key.as_str());
        if let Some(record) = replay.installers.get(&job.metadata.key) {
            add_record_to_report_stats(&mut stats, record);
        } else {
            add_pending_to_report_stats(&mut stats, &job.metadata.manifest_type);
        }
    }

    if include_stale {
        for (key, record) in &replay.installers {
            if seen.contains(key.as_str()) {
                continue;
            }
            add_record_to_report_stats(&mut stats, record);
        }
    }

    stats.pending += stats.total.saturating_sub(
        stats.success + stats.download_cancelled + stats.failed + stats.in_progress + stats.pending,
    );

    stats
}

fn add_record_to_report_stats(stats: &mut ReportStats, record: &InstallerRecord) {
    for (installer_type, arp) in &record.limited_arp_data {
        stats.limited_arp_data += 1;
        stats
            .by_type
            .entry(installer_type.clone())
            .or_default()
            .record_limited_arp_data();
        stats.limited_arp_rows.push(LimitedArpRow {
            installer_type: installer_type.clone(),
            metadata: record.metadata.clone(),
            arp: arp.clone(),
        });
    }

    match &record.status {
        InstallerStatus::InProgress => {
            stats.in_progress += 1;
            stats
                .by_type
                .entry(metadata_installer_type(&record.metadata))
                .or_default()
                .record_in_progress();
        }
        InstallerStatus::Succeeded { installer_type, .. } => {
            let installer_type = recorded_installer_type(record, installer_type);
            stats.success += 1;
            stats
                .by_type
                .entry(installer_type)
                .or_default()
                .record_success();
        }
        InstallerStatus::DownloadCancelled { reason } => {
            stats.download_cancelled += 1;
            let installer_type = metadata_installer_type(&record.metadata);
            stats
                .by_type
                .entry(installer_type.clone())
                .or_default()
                .record_download_cancelled();
            stats.download_issues.push(DownloadIssueRow {
                installer_type,
                metadata: record.metadata.clone(),
                kind: DownloadIssueKind::Cancelled,
                reason: reason.clone(),
            });
        }
        InstallerStatus::Failed {
            failure,
            installer_type,
            error,
        } => {
            let installer_type = recorded_installer_type(record, installer_type);
            stats.failed += 1;
            match failure {
                FailureKind::AnalysisError => stats.analysis_error += 1,
                FailureKind::DownloadError => stats.download_failed += 1,
                FailureKind::NsisInfiniteLoop => stats.nsis_infinite_loop += 1,
                FailureKind::Panic => stats.panic += 1,
            }
            stats
                .by_type
                .entry(installer_type.clone())
                .or_default()
                .record_failed(*failure);
            if *failure == FailureKind::DownloadError {
                stats.download_issues.push(DownloadIssueRow {
                    installer_type,
                    metadata: record.metadata.clone(),
                    kind: DownloadIssueKind::Error,
                    reason: error.clone(),
                });
            } else {
                stats.failures.push(FailureRow {
                    installer_type,
                    metadata: record.metadata.clone(),
                    failure: *failure,
                    error: error.clone(),
                });
            }
        }
    }
}

fn recorded_installer_type(record: &InstallerRecord, installer_type: &str) -> String {
    if installer_type == UNKNOWN_TYPE {
        metadata_installer_type(&record.metadata)
    } else {
        installer_type.to_owned()
    }
}

fn metadata_installer_type(metadata: &InstallerMetadata) -> String {
    if metadata.manifest_type == UNKNOWN_TYPE {
        MANIFEST_UNSPECIFIED_TYPE.to_owned()
    } else {
        metadata.manifest_type.clone()
    }
}

fn add_pending_to_report_stats(stats: &mut ReportStats, installer_type: &str) {
    stats.pending += 1;
    let installer_type = if installer_type == UNKNOWN_TYPE {
        MANIFEST_UNSPECIFIED_TYPE
    } else {
        installer_type
    };
    stats
        .by_type
        .entry(installer_type.to_owned())
        .or_default()
        .record_pending();
}

impl TypeStats {
    fn record_success(&mut self) {
        self.total += 1;
        self.success += 1;
    }

    fn record_download_cancelled(&mut self) {
        self.total += 1;
        self.download_cancelled += 1;
    }

    fn record_failed(&mut self, failure: FailureKind) {
        self.total += 1;
        self.failed += 1;
        match failure {
            FailureKind::AnalysisError => self.analysis_error += 1,
            FailureKind::DownloadError => self.download_failed += 1,
            FailureKind::NsisInfiniteLoop => self.nsis_infinite_loop += 1,
            FailureKind::Panic => self.panic += 1,
        }
    }

    fn record_in_progress(&mut self) {
        self.total += 1;
        self.in_progress += 1;
    }

    fn record_pending(&mut self) {
        self.total += 1;
        self.pending += 1;
    }

    fn record_limited_arp_data(&mut self) {
        self.limited_arp_data += 1;
    }
}

fn run_status(replay: &StateReplay, stats: &ReportStats) -> &'static str {
    if replay.run_finished {
        "completed"
    } else if replay.run_cancelled {
        "cancelled"
    } else if stats.in_progress > 0 {
        "in progress or crashed"
    } else if stats.completed() < stats.total {
        "incomplete or crashed"
    } else {
        "completed without finish marker"
    }
}

fn markdown_cell(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('|', "\\|")
        .replace('\n', "<br>")
}

fn markdown_link(url: &str) -> String {
    format!("[link]({})", url.replace(')', "%29"))
}

fn parse_duration(value: &str) -> Result<Duration, String> {
    let (number, multiplier) = value
        .strip_suffix("ms")
        .map(|number| (number, 0.001))
        .or_else(|| value.strip_suffix('s').map(|number| (number, 1.0)))
        .or_else(|| value.strip_suffix('m').map(|number| (number, 60.0)))
        .or_else(|| value.strip_suffix('h').map(|number| (number, 60.0 * 60.0)))
        .unwrap_or((value, 1.0));

    let number = number
        .parse::<f64>()
        .map_err(|error| format!("invalid duration {value:?}: {error}"))?;
    if !number.is_finite() || number <= 0.0 {
        return Err(format!("duration must be greater than zero: {value:?}"));
    }

    Ok(Duration::from_secs_f64(number * multiplier))
}

fn panic_message(panic: &(dyn Any + Send)) -> String {
    if let Some(message) = panic.downcast_ref::<&str>() {
        (*message).to_owned()
    } else if let Some(message) = panic.downcast_ref::<String>() {
        message.clone()
    } else {
        "non-string panic payload".to_owned()
    }
}
