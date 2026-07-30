#![forbid(unsafe_code)]

mod remote;
mod update;

use std::{error::Error, process::ExitCode};

use clap::{Args, CommandFactory, Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(
    name = "owlauth",
    version,
    about = "Command-line interface for OwlAuth"
)]
struct Cli {
    /// Saved endpoint profile used by remote commands.
    #[arg(long, global = true)]
    profile: Option<String>,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Discover, pin, and select remote endpoint profiles.
    Profile(ProfileArgs),
    /// Read authenticated self-hosted system capabilities.
    System,
    /// Update this CLI from an `OwlAuth` GitHub Release.
    Update(update::UpdateArgs),
}

#[derive(Debug, Args)]
struct ProfileArgs {
    #[command(subcommand)]
    command: ProfileCommand,
}

#[derive(Debug, Subcommand)]
enum ProfileCommand {
    /// Discover an endpoint and save its confirmed identity pin.
    Add {
        name: String,
        #[arg(long)]
        endpoint: String,
        /// Environment variable that will provide the credential, never the credential itself.
        #[arg(long)]
        credential_env: Option<String>,
        /// Confirm the displayed discovery result.
        #[arg(long)]
        yes: bool,
    },
    /// Show a saved profile without reading its credential.
    Inspect {
        /// Profile name; defaults to the selected profile.
        name: Option<String>,
    },
    /// Validate current discovery against a saved identity pin.
    Check {
        /// Profile name; defaults to the selected profile.
        name: Option<String>,
    },
    /// Validate and select a saved profile as the default.
    Use { name: String },
    /// Explicitly replace an endpoint identity pin and credential reference.
    Rebind {
        name: String,
        #[arg(long)]
        endpoint: String,
        /// Environment variable that will provide the new credential.
        #[arg(long)]
        credential_env: Option<String>,
        /// Confirm the displayed old and new identities.
        #[arg(long)]
        yes: bool,
    },
}

fn run(cli: Cli) -> Result<(), Box<dyn Error>> {
    match cli.command {
        Some(Command::Profile(arguments)) => match arguments.command {
            ProfileCommand::Add {
                name,
                endpoint,
                credential_env,
                yes,
            } => remote::add_profile(&name, &endpoint, credential_env.as_deref(), yes)?,
            ProfileCommand::Inspect { name } => {
                remote::inspect_profile(name.as_deref().or(cli.profile.as_deref()))?;
            }
            ProfileCommand::Check { name } => {
                remote::check_profile(name.as_deref().or(cli.profile.as_deref()))?;
            }
            ProfileCommand::Use { name } => remote::use_profile(&name)?,
            ProfileCommand::Rebind {
                name,
                endpoint,
                credential_env,
                yes,
            } => remote::rebind_profile(&name, &endpoint, credential_env.as_deref(), yes)?,
        },
        Some(Command::System) => remote::system(cli.profile.as_deref())?,
        Some(Command::Update(args)) => update::run(&args)?,
        None => {
            Cli::command().print_help()?;
            println!();
        }
    }
    Ok(())
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("owlauth: {error}");
            ExitCode::FAILURE
        }
    }
}
