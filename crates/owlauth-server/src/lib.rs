#![forbid(unsafe_code)]

use axum::{Json, Router, routing::get};
use owlauth_types::HealthResponse;

/// Builds the public HTTP application.
pub fn app() -> Router {
    Router::new().route("/health", get(health))
}

async fn health() -> Json<HealthResponse> {
    Json(owlauth_types::get_health())
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
