#![forbid(unsafe_code)]

use std::fmt;

use serde::Serialize;
use utoipa::{OpenApi, ToSchema};

/// OAuth error codes exposed by `OwlAuth`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
#[schema(rename_all = "snake_case")]
pub enum OAuthErrorCode {
    /// The request is missing a required parameter or is otherwise malformed.
    InvalidRequest,
    /// Client authentication failed.
    InvalidClient,
    /// The authorization grant is invalid or expired.
    InvalidGrant,
}

impl fmt::Display for OAuthErrorCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = match self {
            Self::InvalidRequest => "invalid_request",
            Self::InvalidClient => "invalid_client",
            Self::InvalidGrant => "invalid_grant",
        };
        formatter.write_str(value)
    }
}

/// Response returned by the server health endpoint.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, ToSchema)]
pub struct HealthResponse {
    /// Stable health status. Healthy servers return `ok`.
    pub status: String,
}

#[utoipa::path(
    get,
    path = "/health",
    responses(
        (status = 200, description = "The server is healthy", body = HealthResponse)
    )
)]
#[doc(hidden)]
#[must_use]
pub fn get_health() -> HealthResponse {
    HealthResponse {
        status: "ok".to_owned(),
    }
}

#[derive(OpenApi)]
#[openapi(
    info(
        title = "OwlAuth API",
        description = "Public HTTP API for the OwlAuth server"
    ),
    paths(get_health),
    components(schemas(HealthResponse, OAuthErrorCode))
)]
struct ApiDoc;

/// Generates the current server `OpenAPI` document from Rust protocol definitions.
#[must_use]
pub fn openapi() -> utoipa::openapi::OpenApi {
    ApiDoc::openapi()
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::openapi;

    #[test]
    fn generated_openapi_matches_wire_values() {
        let document = serde_json::to_value(openapi()).expect("generated OpenAPI should serialize");

        assert!(document["paths"]["/health"].is_object());
        assert_eq!(document["info"]["version"], env!("CARGO_PKG_VERSION"));
        assert_eq!(
            document["components"]["schemas"]["OAuthErrorCode"]["enum"],
            json!(["invalid_request", "invalid_client", "invalid_grant"])
        );
    }
}
