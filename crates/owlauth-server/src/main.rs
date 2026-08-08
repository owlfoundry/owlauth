#![forbid(unsafe_code)]

use std::{env, error::Error};

use owlauth_server::{
    config::ServerConfig,
    maintenance::{PruneOptions, prune},
};
use tracing_subscriber::EnvFilter;

const USAGE: &str = "usage: owlauth-server [--openapi <runtime|server|control> | maintenance prune [--batch-size <1..=10000>]]";

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    let arguments: Vec<_> = env::args().skip(1).collect();
    if arguments.first().map(String::as_str) == Some("--openapi") {
        let [_, plane] = arguments.as_slice() else {
            return Err("usage: owlauth-server --openapi <runtime|server|control>".into());
        };
        let document = owlauth_types::export::to_pretty_json(plane.parse()?)?;
        println!("{document}");
        return Ok(());
    }
    if arguments.first().map(String::as_str) == Some("maintenance") {
        let options = parse_prune_options(&arguments)?;
        let database_url = env::var("OWLAUTH_POSTGRES_URL")
            .map_err(|_| "OWLAUTH_POSTGRES_URL is required for maintenance")?;
        let report = prune(&database_url, options).await?;
        println!("{}", serde_json::to_string(&report)?);
        return Ok(());
    }
    if !arguments.is_empty() {
        return Err(USAGE.into());
    }

    // Configuration validates and loads the operator key before telemetry starts. Errors
    // are bounded and secret wrappers never implement revealing formatting.
    let config = ServerConfig::from_env()?;
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .json()
        .with_current_span(false)
        .with_span_list(false)
        .try_init()?;
    Box::pin(owlauth_server::run(config)).await?;
    Ok(())
}

fn parse_prune_options(arguments: &[String]) -> Result<PruneOptions, Box<dyn Error + Send + Sync>> {
    match arguments {
        [maintenance, prune] if maintenance == "maintenance" && prune == "prune" => {
            Ok(PruneOptions::default())
        }
        [maintenance, prune, option, value]
            if maintenance == "maintenance" && prune == "prune" && option == "--batch-size" =>
        {
            let batch_size = value
                .parse::<u32>()
                .map_err(|_| "maintenance batch size must be an integer between 1 and 10000")?;
            Ok(PruneOptions { batch_size })
        }
        _ => Err(USAGE.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::parse_prune_options;

    #[test]
    fn maintenance_arguments_are_closed_and_bounded() {
        let defaults = parse_prune_options(&["maintenance".to_owned(), "prune".to_owned()])
            .expect("default maintenance command");
        assert_eq!(defaults.batch_size, 1_000);

        let explicit = parse_prune_options(&[
            "maintenance".to_owned(),
            "prune".to_owned(),
            "--batch-size".to_owned(),
            "250".to_owned(),
        ])
        .expect("explicit maintenance batch");
        assert_eq!(explicit.batch_size, 250);

        assert!(
            parse_prune_options(&[
                "maintenance".to_owned(),
                "prune".to_owned(),
                "--unknown".to_owned(),
                "250".to_owned(),
            ])
            .is_err()
        );
    }
}
