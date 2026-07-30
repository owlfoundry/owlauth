#![forbid(unsafe_code)]

use std::{env, error::Error, io::Write, process::ExitCode};

use owlauth_types::export::{OpenApiPlane, to_pretty_json};

fn run() -> Result<(), Box<dyn Error>> {
    let mut arguments = env::args().skip(1);
    let plane = arguments
        .next()
        .ok_or("usage: owlauth-export-openapi <runtime|control> [output-file]")?
        .parse::<OpenApiPlane>()?;
    let output = arguments.next();
    if arguments.next().is_some() {
        return Err("too many arguments".into());
    }

    let mut document = to_pretty_json(plane)?;
    document.push('\n');
    match output {
        Some(path) => std::fs::write(path, document)?,
        None => std::io::stdout().write_all(document.as_bytes())?,
    }
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("OpenAPI export failed: {error}");
            ExitCode::FAILURE
        }
    }
}
