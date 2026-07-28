#![forbid(unsafe_code)]

mod update;

use std::process::ExitCode;

use clap::{CommandFactory, Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(
    name = "owlauth",
    version,
    about = "Command-line interface for OwlAuth"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Update this CLI from an `OwlAuth` GitHub Release.
    Update(update::UpdateArgs),
}

fn run(cli: Cli) -> Result<(), update::UpdateError> {
    match cli.command {
        Some(Command::Update(args)) => update::run(&args),
        None => {
            Cli::command().print_help()?;
            println!();
            Ok(())
        }
    }
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
