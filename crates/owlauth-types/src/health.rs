use serde::Serialize;
use utoipa::ToSchema;

/// Minimal response returned by listener liveness and readiness probes.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, ToSchema)]
pub struct HealthResponse {
    /// Stable probe status. Successful probes return `ok`.
    pub status: String,
}

impl HealthResponse {
    /// Creates a successful probe response.
    #[must_use]
    pub fn ok() -> Self {
        Self {
            status: "ok".to_owned(),
        }
    }

    /// Creates a failed readiness response.
    #[must_use]
    pub fn unavailable() -> Self {
        Self {
            status: "unavailable".to_owned(),
        }
    }
}

#[utoipa::path(
    get,
    path = "/health",
    responses(
        (status = 200, description = "The listener event loop is responsive", body = HealthResponse)
    )
)]
#[doc(hidden)]
#[must_use]
pub fn get_liveness() -> HealthResponse {
    HealthResponse::ok()
}

#[utoipa::path(
    get,
    path = "/ready",
    responses(
        (status = 200, description = "The listener can admit business traffic", body = HealthResponse),
        (status = 503, description = "A listener-critical dependency is unavailable", body = HealthResponse)
    )
)]
#[doc(hidden)]
#[must_use]
pub fn get_readiness() -> HealthResponse {
    HealthResponse::ok()
}
