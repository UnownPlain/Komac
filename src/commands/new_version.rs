use std::{
    collections::BTreeSet,
    mem,
    num::{NonZeroU32, NonZeroUsize},
    str::FromStr,
};

use anstream::println;
use camino::Utf8PathBuf;
use clap::{Parser, ValueEnum};
use color_eyre::eyre::{Result, bail, eyre};
use indicatif::ProgressBar;
use inquire::CustomType;
use ordinal::Ordinal;
use owo_colors::OwoColorize;
use secrecy::SecretString;
use winget_types::{
    LanguageTag, ManifestType, ManifestVersion, PackageIdentifier, PackageVersion,
    installer::{
        Command, FileExtension, InstallModes, InstallerManifest, InstallerSuccessCode,
        InstallerType, NestedInstallerFiles, NestedInstallerType, Protocol, UpgradeBehavior,
        switches::{CustomSwitch, InstallerSwitches, SilentSwitch, SilentWithProgressSwitch},
    },
    locale::{
        Author, Copyright, DefaultLocaleManifest, Description, License, Moniker, PackageName,
        Publisher, ShortDescription, Tag,
    },
    url::{
        CopyrightUrl, DecodedUrl, LicenseUrl, PackageUrl, PublisherSupportUrl, PublisherUrl,
        ReleaseNotesUrl,
    },
    utils::ValidFileExtensions,
    version::VersionManifest,
};

use crate::{
    commands::utils::{
        SPINNER_TICK_RATE, SubmitOption, check_package_type, prompt_existing_pull_request,
        write_changes_to_dir,
    },
    download::Downloader,
    download_file::process_files,
    github::{
        GITHUB_HOST,
        client::GitHub,
        utils::{PackagePath, pull_request::pr_changes},
    },
    manifests::{Manifests, Url},
    prompts::{
        check_prompt, handle_inquire_error,
        list::list_prompt,
        radio_prompt,
        text::{TextPrompt, confirm_prompt, optional_prompt, required_prompt},
    },
    token::TokenManager,
};

/// Create a new package from scratch
#[expect(clippy::struct_excessive_bools, reason = "CLI flags")]
#[derive(Parser)]
pub struct NewVersion {
    /// The package's unique identifier
    #[arg()]
    package_identifier: Option<PackageIdentifier>,

    /// The package's version
    #[arg(short = 'v', long = "version")]
    package_version: Option<PackageVersion>,

    /// The list of package installers
    #[arg(short, long, num_args = 1.., value_hint = clap::ValueHint::Url)]
    urls: Vec<Url>,

    #[arg(long)]
    package_locale: Option<LanguageTag>,

    #[arg(long)]
    publisher: Option<Publisher>,

    #[arg(long, value_hint = clap::ValueHint::Url)]
    publisher_url: Option<PublisherUrl>,

    #[arg(long, value_hint = clap::ValueHint::Url)]
    publisher_support_url: Option<PublisherSupportUrl>,

    #[arg(long)]
    package_name: Option<PackageName>,

    #[arg(long, value_hint = clap::ValueHint::Url)]
    package_url: Option<PackageUrl>,

    #[arg(long)]
    moniker: Option<Moniker>,

    #[arg(long)]
    author: Option<Author>,

    #[arg(long)]
    license: Option<License>,

    #[arg(long, value_hint = clap::ValueHint::Url)]
    license_url: Option<LicenseUrl>,

    #[arg(long)]
    copyright: Option<Copyright>,

    #[arg(long, value_hint = clap::ValueHint::Url)]
    copyright_url: Option<CopyrightUrl>,

    #[arg(long)]
    short_description: Option<ShortDescription>,

    #[arg(long)]
    description: Option<Description>,

    #[arg(long, value_hint = clap::ValueHint::Url)]
    release_notes_url: Option<ReleaseNotesUrl>,

    /// Run without prompting
    #[arg(long)]
    non_interactive: bool,

    /// Treat detected exe installers as portable
    #[arg(long)]
    portable: bool,

    /// Silent switch for exe installers
    #[arg(long)]
    silent: Option<SilentSwitch>,

    /// Silent-with-progress switch for exe installers
    #[arg(long)]
    silent_with_progress: Option<SilentWithProgressSwitch>,

    /// Custom switch for portable installers
    #[arg(long)]
    custom: Option<CustomSwitch>,

    /// Install modes for the package
    #[arg(long = "install-mode")]
    install_modes: Vec<InstallModeCli>,

    /// Additional installer success codes
    #[arg(long = "success-code")]
    success_codes: Vec<InstallerSuccessCode>,

    /// Upgrade behavior for the package
    #[arg(long)]
    upgrade_behavior: Option<UpgradeBehavior>,

    /// Commands or aliases exposed by the package
    #[arg(long = "command")]
    commands: Vec<Command>,

    /// Protocol handlers exposed by the package
    #[arg(long = "protocol")]
    protocols: Vec<Protocol>,

    /// File extensions exposed by the package
    #[arg(long = "file-extension")]
    file_extensions: Vec<FileExtension>,

    /// Tags to include in the default locale manifest
    #[arg(long = "tag")]
    tags: Vec<Tag>,

    /// Number of installers to download at the same time
    #[arg(long, default_value_t = NonZeroUsize::new(num_cpus::get()).unwrap())]
    concurrent_downloads: NonZeroUsize,

    /// List of issues that adding this package or version would resolve
    #[arg(long)]
    resolves: Vec<NonZeroU32>,

    /// Automatically submit a pull request
    #[arg(short, long)]
    submit: bool,

    /// Name of external tool that invoked Komac
    #[arg(long, env = "KOMAC_CREATED_WITH")]
    created_with: Option<String>,

    /// URL to external tool that invoked Komac
    #[arg(long, env = "KOMAC_CREATED_WITH_URL", value_hint = clap::ValueHint::Url)]
    created_with_url: Option<DecodedUrl>,

    /// Directory to output the manifests to
    #[arg(short, long, env = "OUTPUT_DIRECTORY", value_hint = clap::ValueHint::DirPath)]
    output: Option<Utf8PathBuf>,

    /// Open pull request link automatically
    #[arg(long, env = "OPEN_PR")]
    open_pr: bool,

    /// Run without submitting
    #[arg(long, env = "DRY_RUN")]
    dry_run: bool,

    /// Skip checking for existing pull requests
    #[arg(long, env)]
    skip_pr_check: bool,

    /// Look for the package under fonts instead of probing manifests first
    #[arg(long)]
    font: bool,

    /// GitHub personal access token with the `public_repo` scope
    #[arg(short, long, env = "GITHUB_TOKEN", hide_env_values = true)]
    token: Option<SecretString>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum InstallModeCli {
    Interactive,
    Silent,
    SilentWithProgress,
}

impl InstallModeCli {
    const fn into_flag(self) -> InstallModes {
        match self {
            Self::Interactive => InstallModes::INTERACTIVE,
            Self::Silent => InstallModes::SILENT,
            Self::SilentWithProgress => InstallModes::SILENT_WITH_PROGRESS,
        }
    }
}

impl NewVersion {
    pub async fn run(mut self) -> Result<()> {
        let non_interactive = self.non_interactive;
        let dry_run = self.dry_run || (non_interactive && !self.submit);

        let token_manager = TokenManager::handle(self.token.take()).await?;
        let github = GitHub::new(token_manager)?;

        let package_identifier = resolve_required(
            self.package_identifier.take(),
            None::<&str>,
            non_interactive,
            "--package-identifier",
        )?;

        let (versions, font) = github
            .get_versions(&package_identifier, self.font.then_some(true))
            .await
            .ok()
            .map_or((None, false), |(versions, font)| (Some(versions), font));

        let latest_version = versions.as_ref().and_then(BTreeSet::last);

        if let Some(latest_version) = latest_version {
            println!("Latest version of {package_identifier}: {latest_version}");
        }

        let manifests =
            latest_version.map(|version| github.get_manifests(&package_identifier, version, font));

        let package_version = resolve_required(
            self.package_version.take(),
            None::<&str>,
            non_interactive,
            "--version",
        )?;

        if !self.skip_pr_check
            && !dry_run
            && let Some(pull_request) = github
                .get_existing_pull_request(&package_identifier, &package_version)
                .await?
        {
            if non_interactive
                || !prompt_existing_pull_request(
                    &package_identifier,
                    &package_version,
                    &pull_request,
                )?
            {
                return Ok(());
            }
        }

        let mut urls = mem::take(&mut self.urls);
        if urls.is_empty() {
            if non_interactive {
                bail!("Missing required option --urls");
            }
            while urls.len() < 1024 {
                let message = format!("{} Installer URL", Ordinal(urls.len() + 1));
                let url_prompt =
                    CustomType::new(&message).with_error_message("Please enter a valid URL");
                let installer_url = if urls.len() + 1 == 1 {
                    Some(url_prompt.prompt().map_err(handle_inquire_error)?)
                } else {
                    url_prompt
                        .with_help_message("Press ESC if you do not have any more URLs")
                        .prompt_skippable()
                        .map_err(handle_inquire_error)?
                };
                if let Some(url) = installer_url {
                    urls.push(url);
                } else {
                    break;
                }
            }
        }

        let github_values = tokio::spawn({
            let github = github.clone();
            let github_url = urls
                .iter()
                .find(|url| url.host_str() == Some(GITHUB_HOST))
                .cloned();
            async move {
                github_url
                    .map(|url| github.get_all_values_from_url(url.into_inner()))
                    .unwrap_or_default()
                    .await
            }
        });

        let downloader = Downloader::new_with_concurrent(self.concurrent_downloads)?;
        let mut files = downloader.download(urls.iter().cloned()).await?;
        let mut download_results = process_files(&mut files).await?;

        let mut installers = Vec::new();
        for analyzer in &mut download_results.values_mut() {
            let mut silent = None;
            let mut silent_with_progress = None;
            let mut custom = None;
            if analyzer
                .installers
                .iter()
                .any(|installer| installer.r#type == Some(InstallerType::Exe))
            {
                let is_portable = self.portable
                    || resolve_confirm(
                        false,
                        non_interactive,
                        &format!("Is {} a portable exe?", analyzer.file_name),
                    )?;
                if is_portable {
                    for installer in &mut analyzer.installers {
                        installer.r#type = Some(InstallerType::Portable);
                    }
                } else if non_interactive {
                    ensure_exe_switches(self.silent.as_ref(), self.silent_with_progress.as_ref())?;
                }
                if non_interactive {
                    silent.clone_from(&self.silent);
                    silent_with_progress.clone_from(&self.silent_with_progress);
                } else {
                    silent = Some(resolve_required(
                        self.silent.clone(),
                        None::<&str>,
                        non_interactive,
                        "--silent",
                    )?);
                    silent_with_progress = Some(resolve_required(
                        self.silent_with_progress.clone(),
                        None::<&str>,
                        non_interactive,
                        "--silent-with-progress",
                    )?);
                }
            }
            if analyzer
                .installers
                .iter()
                .any(|installer| installer.r#type == Some(InstallerType::Portable))
            {
                custom = resolve_optional(self.custom.clone(), None::<&str>, non_interactive)?;
            }
            if let Some(zip) = &mut analyzer.zip {
                if non_interactive {
                    if !zip.possible_installer_files.is_empty() {
                        let nested_installer_files = zip
                            .possible_installer_files
                            .iter()
                            .cloned()
                            .map(|relative_file_path| NestedInstallerFiles {
                                relative_file_path,
                                portable_command_alias: None,
                            })
                            .collect::<BTreeSet<_>>();
                        let nested_installer_type = zip
                            .possible_installer_files
                            .iter()
                            .find_map(nested_installer_type_from_path);

                        for installer in &mut zip.installers {
                            if installer.nested_installer_type.is_none() {
                                installer.nested_installer_type = nested_installer_type;
                            }
                            installer
                                .nested_installer_files
                                .clone_from(&nested_installer_files);
                        }
                    }
                } else {
                    zip.prompt()?;
                }
                for (analyzer_installer, zip_installer) in
                    analyzer.installers.iter_mut().zip(zip.installers.iter())
                {
                    analyzer_installer.nested_installer_type = zip_installer.nested_installer_type;
                    analyzer_installer
                        .nested_installer_files
                        .clone_from(&zip_installer.nested_installer_files);
                }
            }
            let switches = InstallerSwitches::builder()
                .maybe_silent(silent)
                .maybe_silent_with_progress(silent_with_progress)
                .maybe_custom(custom)
                .build();
            let mut analyzer_installers = mem::take(&mut analyzer.installers);
            for installer in &mut analyzer_installers {
                if !switches.is_empty() {
                    installer.switches = switches.clone();
                }
            }
            installers.extend(analyzer_installers);
        }

        let default_locale = resolve_required(
            self.package_locale.take(),
            Some("en-US"),
            non_interactive,
            "--package-locale",
        )?;
        let mut installer_manifest = InstallerManifest {
            package_identifier: package_identifier.clone(),
            package_version: package_version.clone(),
            installers,
            manifest_type: ManifestType::Installer,
            ..InstallerManifest::default()
        };

        let is_font = check_package_type(&installer_manifest)?;

        if !is_font {
            installer_manifest.install_modes = if installer_manifest
                .installers
                .iter()
                .any(|installer| installer.r#type == Some(InstallerType::Inno))
            {
                InstallModes::all()
            } else if self.install_modes.is_empty() && !non_interactive {
                check_prompt::<InstallModes>()?
            } else {
                self.install_modes
                    .iter()
                    .fold(InstallModes::empty(), |modes, mode| {
                        modes | mode.into_flag()
                    })
            };
            installer_manifest.success_codes = resolve_list(
                mem::take(&mut self.success_codes),
                non_interactive,
                list_prompt::<InstallerSuccessCode>,
            )?;
            installer_manifest.upgrade_behavior = resolve_radio(
                self.upgrade_behavior.take(),
                non_interactive,
                radio_prompt::<UpgradeBehavior>,
            )?;
            installer_manifest.commands = resolve_list(
                mem::take(&mut self.commands),
                non_interactive,
                list_prompt::<Command>,
            )?;
            installer_manifest.protocols = resolve_list(
                mem::take(&mut self.protocols),
                non_interactive,
                list_prompt::<Protocol>,
            )?;
            installer_manifest.file_extensions = if installer_manifest
                .installers
                .iter()
                .all(|installer| installer.file_extensions.is_empty())
            {
                resolve_list(
                    mem::take(&mut self.file_extensions),
                    non_interactive,
                    list_prompt::<FileExtension>,
                )?
            } else {
                BTreeSet::new()
            };
        }

        let mut github_values = match github_values.await? {
            Some(future) => Some(future?),
            None => None,
        };

        let default_locale_manifest = DefaultLocaleManifest {
            package_identifier: package_identifier.clone(),
            package_version: package_version.clone(),
            package_locale: default_locale.clone(),
            publisher: resolve_required(
                self.publisher.take(),
                download_results
                    .values()
                    .find(|analyzer| analyzer.publisher.is_some())
                    .and_then(|analyzer| analyzer.publisher.as_ref())
                    .or_else(|| {
                        github_values
                            .as_ref()
                            .and_then(|values| values.publisher.as_ref())
                    }),
                non_interactive,
                "--publisher",
            )?,
            publisher_url: resolve_optional(
                self.publisher_url.take(),
                github_values.as_ref().map(|values| &values.publisher_url),
                non_interactive,
            )?,
            publisher_support_url: resolve_optional(
                self.publisher_support_url.take(),
                github_values
                    .as_ref()
                    .and_then(|values| values.issues_url.as_ref()),
                non_interactive,
            )?,
            author: resolve_optional(self.author.take(), None::<&str>, non_interactive)?,
            package_name: resolve_required(
                self.package_name.take(),
                download_results
                    .values()
                    .find(|analyzer| analyzer.package_name.is_some())
                    .and_then(|analyzer| analyzer.package_name.as_ref()),
                non_interactive,
                "--package-name",
            )?,
            package_url: resolve_optional(
                self.package_url.take(),
                github_values.as_ref().map(|values| &values.package_url),
                non_interactive,
            )?,
            license: resolve_required(
                self.license.take(),
                github_values
                    .as_ref()
                    .and_then(|values| values.license.as_ref()),
                non_interactive,
                "--license",
            )?,
            license_url: resolve_optional(
                self.license_url.take(),
                github_values
                    .as_ref()
                    .and_then(|values| values.license_url.as_ref()),
                non_interactive,
            )?,
            copyright: resolve_optional(
                self.copyright.take(),
                download_results
                    .values()
                    .find(|analyzer| analyzer.copyright.is_some())
                    .and_then(|analyzer| analyzer.copyright.as_ref()),
                non_interactive,
            )?,
            copyright_url: resolve_optional(
                self.copyright_url.take(),
                None::<&str>,
                non_interactive,
            )?,
            short_description: resolve_required(
                self.short_description.take(),
                github_values
                    .as_ref()
                    .and_then(|values| values.description.as_ref()),
                non_interactive,
                "--short-description",
            )?,
            description: resolve_optional(self.description.take(), None::<&str>, non_interactive)?,
            moniker: resolve_optional(self.moniker.take(), None::<&str>, non_interactive)?,
            tags: match github_values
                .as_mut()
                .map(|values| mem::take(&mut values.topics))
            {
                Some(topics) => topics,
                None => resolve_list(
                    mem::take(&mut self.tags),
                    non_interactive,
                    list_prompt::<Tag>,
                )?,
            },
            release_notes: github_values
                .as_mut()
                .and_then(|values| values.release_notes.take()),
            release_notes_url: resolve_optional(
                self.release_notes_url.take(),
                github_values
                    .as_ref()
                    .and_then(|values| values.release_notes_url.as_ref()),
                non_interactive,
            )?,
            manifest_type: ManifestType::DefaultLocale,
            ..DefaultLocaleManifest::default()
        };

        installer_manifest
            .installers
            .iter_mut()
            .flat_map(|installer| &mut installer.apps_and_features_entries)
            .for_each(|entry| entry.deduplicate(&default_locale_manifest));

        installer_manifest.optimize();

        let version_manifest = VersionManifest {
            package_identifier: package_identifier.clone(),
            package_version: package_version.clone(),
            default_locale,
            manifest_type: ManifestType::Version,
            manifest_version: ManifestVersion::default(),
        };

        let manifests = match manifests {
            Some(manifests) => Some(manifests.await?),
            None => None,
        };

        let manifests = Manifests {
            installer: installer_manifest,
            default_locale: default_locale_manifest,
            locales: manifests
                .map(|manifests| manifests.locales)
                .unwrap_or_default(),
            version: version_manifest,
        };

        let package_path =
            PackagePath::new(&package_identifier, Some(&package_version), None, is_font);
        let mut changes = pr_changes()
            .package_identifier(&package_identifier)
            .manifests(&manifests)
            .package_path(&package_path)
            .maybe_created_with(self.created_with.as_deref())
            .create()?;

        let submit_option = SubmitOption::prompt(
            &mut changes,
            &package_identifier,
            &package_version,
            self.submit,
            dry_run,
        )?;

        if let Some(output) = self
            .output
            .as_ref()
            .map(|out| out.join(package_path.as_str()))
        {
            write_changes_to_dir(&changes, output.as_path()).await?;
            println!(
                "{} written all manifest files to {output}",
                "Successfully".green()
            );
        }

        if submit_option.is_exit() {
            return Ok(());
        }

        // Create an indeterminate progress bar to show as a pull request is being created
        let pr_progress = ProgressBar::new_spinner().with_message(format!(
            "Creating a pull request for {package_identifier} {package_version}"
        ));
        pr_progress.enable_steady_tick(SPINNER_TICK_RATE);

        let pull_request = github
            .add_version()
            .identifier(&package_identifier)
            .version(&package_version)
            .maybe_versions(versions.as_ref())
            .changes(changes)
            .issue_resolves(&self.resolves)
            .maybe_created_with(self.created_with.as_deref())
            .maybe_created_with_url(self.created_with_url.as_ref())
            .send()
            .await?;

        pr_progress.finish_and_clear();

        pull_request.print_success();

        if self.open_pr {
            open::that(pull_request.url().as_str())?;
        }

        Ok(())
    }
}

fn nested_installer_type_from_path(path: &Utf8PathBuf) -> Option<NestedInstallerType> {
    let extension = path.extension()?.parse::<ValidFileExtensions>().ok()?;

    Some(match extension {
        ValidFileExtensions::Msix | ValidFileExtensions::MsixBundle => NestedInstallerType::Msix,
        ValidFileExtensions::Msi => NestedInstallerType::Msi,
        ValidFileExtensions::Appx | ValidFileExtensions::AppxBundle => NestedInstallerType::Appx,
        ValidFileExtensions::Exe => NestedInstallerType::Exe,
        ValidFileExtensions::Fnt
        | ValidFileExtensions::Otc
        | ValidFileExtensions::Otf
        | ValidFileExtensions::Ttc
        | ValidFileExtensions::Ttf => NestedInstallerType::Font,
        ValidFileExtensions::Zip => return None,
    })
}

fn ensure_exe_switches(
    silent: Option<&SilentSwitch>,
    silent_with_progress: Option<&SilentWithProgressSwitch>,
) -> Result<()> {
    if silent.is_none() {
        bail!("Missing required option --silent for exe installers");
    }
    if silent_with_progress.is_none() {
        bail!("Missing required option --silent-with-progress for exe installers");
    }
    Ok(())
}

fn resolve_confirm(value: bool, non_interactive: bool, message: &str) -> Result<bool> {
    if non_interactive {
        Ok(value)
    } else {
        Ok(confirm_prompt(message)?)
    }
}

fn resolve_required<T, U>(
    parameter: Option<T>,
    default: Option<U>,
    non_interactive: bool,
    option_name: &str,
) -> Result<T>
where
    T: FromStr + TextPrompt,
    <T as FromStr>::Err: std::fmt::Display + ToString + std::fmt::Debug + Sync + Send + 'static,
    U: AsRef<str>,
{
    match parameter {
        Some(value) => Ok(value),
        None if non_interactive => default
            .map(|value| {
                value
                    .as_ref()
                    .parse::<T>()
                    .map_err(|err| eyre!(err.to_string()))
            })
            .transpose()?
            .ok_or_else(|| eyre!("Missing required option {option_name}")),
        None => Ok(required_prompt(None, default)?),
    }
}

fn resolve_optional<T, U>(
    parameter: Option<T>,
    default: Option<U>,
    non_interactive: bool,
) -> Result<Option<T>>
where
    T: FromStr + TextPrompt,
    <T as FromStr>::Err: std::fmt::Display + std::fmt::Debug + Sync + Send + 'static,
    U: AsRef<str>,
{
    match parameter {
        Some(value) => Ok(Some(value)),
        None if non_interactive => default
            .map(|value| {
                value
                    .as_ref()
                    .parse::<T>()
                    .map_err(|err| eyre!(err.to_string()))
            })
            .transpose(),
        None => Ok(optional_prompt(None, default)?),
    }
}

fn resolve_list<T, F>(
    items: Vec<T>,
    non_interactive: bool,
    interactive_prompt: F,
) -> Result<BTreeSet<T>>
where
    T: Ord,
    F: FnOnce() -> Result<BTreeSet<T>>,
{
    if items.is_empty() {
        if non_interactive {
            Ok(BTreeSet::new())
        } else {
            interactive_prompt()
        }
    } else {
        Ok(items.into_iter().collect())
    }
}

fn resolve_radio<T, F>(
    value: Option<T>,
    non_interactive: bool,
    interactive_prompt: F,
) -> Result<Option<T>>
where
    F: FnOnce() -> inquire::error::InquireResult<T>,
{
    match value {
        Some(value) => Ok(Some(value)),
        None if non_interactive => Ok(None),
        None => Ok(Some(interactive_prompt()?)),
    }
}
