#![forbid(unsafe_code)]

use std::{env, error::Error};

use axum::{Json, Router, routing::get};
use owlauth_protocol::HealthResponse;

fn app() -> Router {
    Router::new().route("/health", get(health))
}

async fn health() -> Json<HealthResponse> {
    Json(owlauth_protocol::get_health())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    if env::args().nth(1).as_deref() == Some("--openapi") {
        let document = owlauth_protocol::openapi().to_pretty_json()?;
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
    axum::serve(listener, app()).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use axum::{
        body::{Body, to_bytes},
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;

    use super::app;

    #[tokio::test]
    async fn serves_documented_health_endpoint() {
        let response = app()
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .expect("health request should build"),
            )
            .await
            .expect("health request should succeed");

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), 1024)
            .await
            .expect("health response should be readable");
        assert_eq!(&body[..], br#"{"status":"ok"}"#);
    }
}
