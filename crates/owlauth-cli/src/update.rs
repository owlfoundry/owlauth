use std::{
    env,
    io::Write as _,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::Duration,
};

use clap::Args;
use semver::Version;
use serde::Deserialize;
use thiserror::Error;

const DEFAULT_REPOSITORY: &str = "owlfoundry/owlauth";
const RELEASE_TAG_PREFIX: &str = "cli-v";
#[cfg(not(windows))]
const INSTALLER_SH: &str = include_str!("../assets/install.sh");
#[cfg(windows)]
const INSTALLER_PS1: &str = include_str!("../assets/install.ps1");

#[derive(Debug, Args)]
pub struct UpdateArgs {
    /// Install a specific CLI version instead of the latest stable release.
    #[arg(long, value_name = "SEMVER")]
    version: Option<String>,
    /// Print the selected update without installing it.
    #[arg(long)]
    dry_run: bool,
    /// Reinstall or downgrade even when the selected version is not newer.
    #[arg(short, long)]
    force: bool,
    /// Override the directory containing the installed owlauth binary.
    #[arg(long, value_name = "DIRECTORY")]
    install_dir: Option<PathBuf>,
}

#[derive(Debug, Error)]
pub enum UpdateError {
    #[error("invalid CLI release version {value}: {source}")]
    InvalidVersion {
        value: String,
        source: semver::Error,
    },
    #[error("failed to query CLI releases: {0}")]
    ReleaseQuery(String),
    #[error("no stable CLI release was found")]
    NoRelease,
    #[error("cannot determine the current executable directory: {0}")]
    ExecutableDirectory(std::io::Error),
    #[error(
        "selected version {selected} is not newer than {current}; use --force to reinstall or downgrade"
    )]
    NotNewer { current: Version, selected: Version },
    #[error("failed to start the installer: {0}")]
    InstallerStart(std::io::Error),
    #[error("failed to send the bundled installer: {0}")]
    InstallerInput(std::io::Error),
    #[error("installer exited with {status}: {stderr}")]
    InstallerFailed { status: String, stderr: String },
    #[cfg(windows)]
    #[error("timed out while waiting for the Windows installer to stage the update")]
    InstallerTimeout,
    #[error(transparent)]
    Output(#[from] std::io::Error),
}

#[derive(Debug, Deserialize)]
struct Release {
    tag_name: String,
    draft: bool,
    prerelease: bool,
}

pub fn run(args: &UpdateArgs) -> Result<(), UpdateError> {
    let current = Version::parse(env!("CARGO_PKG_VERSION")).expect("package version is SemVer");
    let selected = match &args.version {
        Some(value) => parse_release_version(value)?,
        None => latest_stable_release()?,
    };
    let install_dir = match &args.install_dir {
        Some(path) => path.clone(),
        None => current_executable_directory()?,
    };

    if !args.force && selected <= current {
        if selected == current {
            println!("owlauth {current} is already installed");
            return Ok(());
        }
        return Err(UpdateError::NotNewer { current, selected });
    }

    println!("owlauth {current} -> {selected}");
    println!("install directory: {}", install_dir.display());
    if args.dry_run {
        println!("status: dry-run");
        return Ok(());
    }

    run_installer(&selected, &install_dir)?;
    #[cfg(windows)]
    println!("update staged; replacement will finish after this process exits");
    #[cfg(not(windows))]
    println!("updated owlauth to {selected}");
    Ok(())
}

fn parse_release_version(value: &str) -> Result<Version, UpdateError> {
    let normalized = value
        .strip_prefix(RELEASE_TAG_PREFIX)
        .or_else(|| value.strip_prefix('v'))
        .unwrap_or(value);
    Version::parse(normalized).map_err(|source| UpdateError::InvalidVersion {
        value: value.to_owned(),
        source,
    })
}

fn latest_stable_release() -> Result<Version, UpdateError> {
    let repository =
        env::var("OWLAUTH_GITHUB_REPO").unwrap_or_else(|_| DEFAULT_REPOSITORY.to_owned());
    let api_base =
        env::var("OWLAUTH_GITHUB_API_URL").unwrap_or_else(|_| "https://api.github.com".to_owned());
    let url = format!(
        "{}/repos/{repository}/releases?per_page=100",
        api_base.trim_end_matches('/')
    );
    let response = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|error| UpdateError::ReleaseQuery(error.to_string()))?
        .get(url)
        .header(reqwest::header::USER_AGENT, "owlauth-cli")
        .send()
        .and_then(reqwest::blocking::Response::error_for_status)
        .map_err(|error| UpdateError::ReleaseQuery(error.to_string()))?;
    let releases = response
        .json::<Vec<Release>>()
        .map_err(|error| UpdateError::ReleaseQuery(error.to_string()))?;
    select_latest_stable(&releases).ok_or(UpdateError::NoRelease)
}

fn select_latest_stable(releases: &[Release]) -> Option<Version> {
    releases
        .iter()
        .filter(|release| !release.draft && !release.prerelease)
        .filter_map(|release| {
            let value = release.tag_name.strip_prefix(RELEASE_TAG_PREFIX)?;
            Version::parse(value).ok()
        })
        .filter(|version| version.pre.is_empty())
        .max()
}

fn current_executable_directory() -> Result<PathBuf, UpdateError> {
    let executable = env::current_exe().map_err(UpdateError::ExecutableDirectory)?;
    executable.parent().map(Path::to_path_buf).ok_or_else(|| {
        UpdateError::ExecutableDirectory(std::io::Error::other("the executable path has no parent"))
    })
}

#[cfg(not(windows))]
fn run_installer(version: &Version, install_dir: &Path) -> Result<(), UpdateError> {
    let mut child = installer_command("sh", version, install_dir)
        .spawn()
        .map_err(UpdateError::InstallerStart)?;
    child
        .stdin
        .take()
        .expect("installer stdin is piped")
        .write_all(INSTALLER_SH.as_bytes())
        .map_err(UpdateError::InstallerInput)?;
    let output = child
        .wait_with_output()
        .map_err(UpdateError::InstallerStart)?;
    if output.status.success() {
        print!("{}", String::from_utf8_lossy(&output.stdout));
        Ok(())
    } else {
        Err(UpdateError::InstallerFailed {
            status: output.status.to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_owned(),
        })
    }
}

#[cfg(windows)]
fn run_installer(version: &Version, install_dir: &Path) -> Result<(), UpdateError> {
    let process_id = std::process::id();
    let ready_file = env::temp_dir().join(format!("owlauth-update-{process_id}.ready"));
    match std::fs::remove_file(&ready_file) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(UpdateError::InstallerStart(error)),
    }
    let mut child = installer_command("powershell", version, install_dir)
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            "-",
        ])
        .env("OWLAUTH_UPDATER_PID", process_id.to_string())
        .env("OWLAUTH_UPDATE_READY_FILE", &ready_file)
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(UpdateError::InstallerStart)?;
    child
        .stdin
        .take()
        .expect("installer stdin is piped")
        .write_all(INSTALLER_PS1.as_bytes())
        .map_err(UpdateError::InstallerInput)?;

    for _ in 0..600 {
        if ready_file.is_file() {
            std::fs::remove_file(&ready_file).map_err(UpdateError::InstallerStart)?;
            return Ok(());
        }
        if let Some(status) = child.try_wait().map_err(UpdateError::InstallerStart)? {
            return Err(UpdateError::InstallerFailed {
                status: status.to_string(),
                stderr: "see installer diagnostics above".to_owned(),
            });
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    Err(UpdateError::InstallerTimeout)
}

fn installer_command(program: &str, version: &Version, install_dir: &Path) -> Command {
    let mut command = Command::new(program);
    command
        .env("OWLAUTH_VERSION", version.to_string())
        .env("OWLAUTH_INSTALL_DIR", install_dir)
        .stdin(Stdio::piped());
    command
}

#[cfg(test)]
mod tests {
    use super::*;

    fn release(tag_name: &str, draft: bool, prerelease: bool) -> Release {
        Release {
            tag_name: tag_name.to_owned(),
            draft,
            prerelease,
        }
    }

    #[test]
    fn parses_plain_and_prefixed_versions() {
        assert_eq!(
            parse_release_version("0.0.2").unwrap(),
            Version::new(0, 0, 2)
        );
        assert_eq!(
            parse_release_version("v0.0.2").unwrap(),
            Version::new(0, 0, 2)
        );
        assert_eq!(
            parse_release_version("cli-v0.0.2").unwrap(),
            Version::new(0, 0, 2)
        );
        assert!(parse_release_version("latest").is_err());
    }

    #[test]
    fn selects_highest_stable_cli_release() {
        let releases = vec![
            release("server-v9.0.0", false, false),
            release("cli-v0.0.2", false, false),
            release("cli-v0.0.4", true, false),
            release("cli-v0.0.3-rc.1", false, true),
            release("cli-v0.0.3", false, false),
        ];

        assert_eq!(select_latest_stable(&releases), Some(Version::new(0, 0, 3)));
    }
}
