#![forbid(unsafe_code)]

use std::{env, error::Error};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    if env::args().nth(1).as_deref() == Some("--openapi") {
        let document = owlauth_types::openapi().to_pretty_json()?;
        println!("{document}");
        return Ok(());
    }

    let address = env::var("OWLAUTH_ADDR").unwrap_or_else(|_| "127.0.0.1:8080".to_owned());
    let listener = tokio::net::TcpListener::bind(&address).await?;
    println!(
        "OwlAuth server {} listening on {}",
        env!("CARGO_PKG_VERSION"),
        listener.local_addr()?
    );
    axum::serve(listener, owlauth_server::app()).await?;
    Ok(())
}
