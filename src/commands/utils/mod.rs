pub mod environment;
mod rate_limit;
mod submit_option;

use std::time::Duration;

use anstream::println;
use camino::Utf8Path;
use chrono::Local;
use color_eyre::{Result, eyre::bail};
use futures_util::{StreamExt, TryStreamExt, stream};
use inquire::error::InquireResult;
use owo_colors::OwoColorize;
pub use rate_limit::RateLimit;
pub use submit_option::SubmitOption;
use tokio::{fs, fs::File, io::AsyncWriteExt};
use winget_types::{
    PackageIdentifier, PackageVersion,
    installer::{Installer, InstallerManifest, InstallerType, NestedInstallerType},
};

use crate::{
    commands::utils::environment::CI, github::graphql::get_existing_pull_request::PullRequest,
    prompts::text::confirm_prompt,
};

pub const SPINNER_TICK_RATE: Duration = Duration::from_millis(50);

pub const SPINNER_SLOW_TICK_RATE: Duration = Duration::from_millis(100);

pub fn prompt_existing_pull_request(
    identifier: &PackageIdentifier,
    version: &PackageVersion,
    pull_request: &PullRequest,
) -> InquireResult<bool> {
    let created_at = pull_request.created_at.with_timezone(&Local);
    println!(
        "There is already {} pull request for {identifier} {version} that was created on {} at {}",
        pull_request.state,
        created_at.date_naive(),
        created_at.time()
    );
    println!("{}", pull_request.url.blue());
    if *CI {
        // Exit instead of proceeding in CI environments
        Ok(false)
    } else {
        confirm_prompt("Would you like to proceed?")
    }
}

pub async fn write_changes_to_dir(changes: &[(String, String)], output: &Utf8Path) -> Result<()> {
    fs::create_dir_all(output).await?;
    stream::iter(changes.iter())
        .map(|(path, content)| async move {
            if let Some(file_name) = Utf8Path::new(path).file_name() {
                let mut file = File::create(output.join(file_name)).await?;
                file.write_all(content.as_bytes()).await?;
            }
            Ok::<(), color_eyre::eyre::Error>(())
        })
        .buffer_unordered(2)
        .try_collect()
        .await
}

pub fn inherit_manifest_properties(
    manifest: &InstallerManifest,
) -> impl Iterator<Item = Installer> + '_ {
    manifest.installers.iter().cloned().map(|mut installer| {
        if manifest.r#type.is_some() {
            installer.r#type = manifest.r#type;
        }
        if manifest.nested_installer_type.is_some() {
            installer.nested_installer_type = manifest.nested_installer_type;
        }
        if manifest.scope.is_some() {
            installer.scope = manifest.scope;
        }
        installer
    })
}

pub fn check_package_type(manifest: &InstallerManifest) -> Result<bool> {
    let installers: Vec<_> = inherit_manifest_properties(manifest).collect();

    let is_font = |installer: &Installer| {
        installer.r#type == Some(InstallerType::Font)
            || installer.nested_installer_type == Some(NestedInstallerType::Font)
    };

    let has_font = installers.iter().any(is_font);
    let has_installer = installers.iter().any(|installer| !is_font(installer));

    if has_font && has_installer {
        bail!("Application and font installers cannot be mixed in the same manifest");
    }

    Ok(has_font)
}
