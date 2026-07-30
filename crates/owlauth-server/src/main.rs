#![forbid(unsafe_code)]

use std::{env, error::Error};

use owlauth_server::config::ServerConfig;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    let arguments: Vec<_> = env::args().skip(1).collect();
    if arguments.first().map(String::as_str) == Some("--openapi") {
        let [_, plane] = arguments.as_slice() else {
            return Err("usage: owlauth-server --openapi <runtime|control>".into());
        };
        let document = owlauth_types::export::to_pretty_json(plane.parse()?)?;
        println!("{document}");
        return Ok(());
    }
    if !arguments.is_empty() {
        return Err("owlauth-server accepts no command arguments while serving".into());
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
    owlauth_server::run(config).await?;
    Ok(())
}
