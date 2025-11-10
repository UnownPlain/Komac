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
    installer::{InstallerManifest, InstallerType, NestedInstallerType},
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

pub fn check_package_type(manifest: &InstallerManifest) -> Result<bool> {
    let root_type = manifest.r#type;
    let root_nested_type = manifest.nested_installer_type;

    let mut has_font = false;
    let mut has_installer = false;

    for installer in &manifest.installers {
        // Use installer-level type if specified, otherwise inherit from root
        let effective_type = installer.r#type.or(root_type);
        let effective_nested_type = installer.nested_installer_type.or(root_nested_type);

        let is_font = effective_type == Some(InstallerType::Font)
            || effective_nested_type == Some(NestedInstallerType::Font);

        if is_font {
            has_font = true;
        } else {
            has_installer = true;
        }
    }

    if has_font && has_installer {
        bail!("Font and non-font installers cannot be mixed in the same manifest");
    }

    Ok(has_font)
}
