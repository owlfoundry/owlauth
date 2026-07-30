use serde::{Deserialize, Serialize};
use utoipa::{OpenApi, ToSchema};

use crate::health::HealthResponse;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ProviderKind {
    Oidc,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
pub enum JwkKeyType {
    #[serde(rename = "OKP")]
    Okp,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
pub enum JwkCurve {
    Ed25519,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
pub enum SigningAlgorithm {
    #[serde(rename = "EdDSA")]
    EdDsa,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
pub enum JwkUse {
    #[serde(rename = "sig")]
    Signature,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct PublicJwk {
    pub kty: JwkKeyType,
    pub crv: JwkCurve,
    pub alg: SigningAlgorithm,
    #[serde(rename = "use")]
    pub key_use: JwkUse,
    #[schema(max_length = 128)]
    pub kid: String,
    #[schema(max_length = 64)]
    pub x: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
pub struct PublicProvider {
    #[schema(max_length = 64)]
    pub key: String,
    #[schema(max_length = 128)]
    pub display_name: String,
    pub kind: ProviderKind,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
pub struct PublicApplicationConfig {
    #[schema(max_length = 96)]
    pub project_public_id: String,
    #[schema(max_length = 128)]
    pub project_display_name: String,
    #[schema(max_length = 96)]
    pub application_public_id: String,
    #[schema(max_length = 128)]
    pub application_display_name: String,
    #[schema(max_items = 50)]
    pub publishable_keys: Vec<String>,
    #[schema(max_items = 50)]
    pub providers: Vec<PublicProvider>,
    pub login_available: bool,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize, ToSchema)]
pub struct JwksDocument {
    #[schema(max_items = 100)]
    pub keys: Vec<PublicJwk>,
    pub revision: i64,
    pub signing_epoch: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
pub struct RuntimeError {
    pub code: String,
    pub message: String,
    pub request_id: String,
}

#[utoipa::path(
    get,
    path = "/v1/projects/{project_public_id}/auth/config",
    params(
        ("project_public_id" = String, Path),
        ("application_id" = String, Query)
    ),
    responses(
        (status = 200, description = "Exact public application configuration", body = PublicApplicationConfig),
        (status = 400, description = "Invalid request", body = RuntimeError),
        (status = 404, description = "Public Project or Application not found", body = RuntimeError),
        (status = 503, description = "Runtime authority unavailable", body = RuntimeError)
    )
)]
#[doc(hidden)]
pub fn get_public_application_config() {}

#[utoipa::path(
    get,
    path = "/projects/{project_public_id}/.well-known/jwks.json",
    params(("project_public_id" = String, Path)),
    responses(
        (status = 200, description = "Project verification key set", body = JwksDocument),
        (status = 400, description = "Credentials are not accepted on public Runtime endpoints", body = RuntimeError),
        (status = 404, description = "Public Project or key ring not found", body = RuntimeError),
        (status = 503, description = "Runtime authority unavailable", body = RuntimeError)
    )
)]
#[doc(hidden)]
pub fn get_project_jwks() {}

#[derive(OpenApi)]
#[openapi(
    info(
        title = "OwlAuth Runtime API",
        description = "Project Auth Runtime API"
    ),
    paths(
        crate::health::get_liveness,
        crate::health::get_readiness,
        get_public_application_config,
        get_project_jwks
    ),
    components(schemas(
        HealthResponse,
        ProviderKind,
        JwkKeyType,
        JwkCurve,
        SigningAlgorithm,
        JwkUse,
        PublicJwk,
        PublicProvider,
        PublicApplicationConfig,
        JwksDocument,
        RuntimeError
    ))
)]
struct RuntimeApiDoc;

/// Generates the complete Runtime-plane `OpenAPI` document.
#[must_use]
pub fn openapi() -> utoipa::openapi::OpenApi {
    RuntimeApiDoc::openapi()
}
