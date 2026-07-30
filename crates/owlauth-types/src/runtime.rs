use utoipa::OpenApi;

use crate::health::HealthResponse;

#[derive(OpenApi)]
#[openapi(
    info(
        title = "OwlAuth Runtime API",
        description = "Project Auth Runtime API"
    ),
    paths(crate::health::get_liveness, crate::health::get_readiness),
    components(schemas(HealthResponse))
)]
struct RuntimeApiDoc;

/// Generates the complete Runtime-plane `OpenAPI` document.
#[must_use]
pub fn openapi() -> utoipa::openapi::OpenApi {
    RuntimeApiDoc::openapi()
}
