use serde::{Deserialize, Serialize};
use utoipa::openapi::security::{Http, HttpAuthScheme, SecurityScheme};
use utoipa::{Modify, OpenApi, ToSchema};

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
#[serde(deny_unknown_fields)]
pub struct LoginStartRequest {
    #[schema(max_length = 96)]
    pub application_id: String,
    #[schema(max_length = 128)]
    pub publishable_key: String,
    #[schema(max_length = 2048)]
    pub redirect_uri: String,
    #[schema(min_length = 43, max_length = 43)]
    pub pkce_challenge: String,
    #[schema(min_length = 1, max_length = 1024)]
    pub state: String,
    #[schema(max_length = 64)]
    pub presentation_hint: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
pub struct LoginStartResponse {
    #[schema(max_length = 512)]
    pub hosted_url: String,
    #[schema(max_length = 64)]
    pub expires_at: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum HostedApplicationType {
    Web,
    Native,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum HostedInteractionStatus {
    AwaitingMethodSelection,
    ProviderAuthorizationStarted,
    ProviderExchangeInProgress,
    Authenticated,
    HandoffIssued,
    Completed,
    Failed,
    Expired,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
pub struct HostedProvider {
    #[schema(max_length = 64)]
    pub key: String,
    #[schema(max_length = 128)]
    pub display_name: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
pub struct HostedInteractionResponse {
    #[schema(max_length = 96)]
    pub project_id: String,
    #[schema(max_length = 128)]
    pub project_display_name: String,
    #[schema(max_length = 96)]
    pub application_id: String,
    #[schema(max_length = 128)]
    pub application_display_name: String,
    pub application_type: HostedApplicationType,
    pub status: HostedInteractionStatus,
    pub revision: i64,
    pub session_reuse_available: bool,
    #[schema(max_length = 64)]
    pub presentation_hint: Option<String>,
    #[schema(max_items = 50)]
    pub providers: Vec<HostedProvider>,
    #[schema(max_length = 64)]
    pub csrf: String,
    #[schema(max_length = 64)]
    pub expires_at: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct SelectProviderRequest {
    pub expected_revision: i64,
    #[schema(max_length = 64)]
    pub csrf: String,
    #[schema(max_length = 64)]
    pub provider_key: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
pub struct NavigationResponse {
    #[schema(max_length = 4096)]
    pub url: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ConfirmSessionReuseRequest {
    pub expected_revision: i64,
    #[schema(max_length = 64)]
    pub csrf: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct HandoffExchangeRequest {
    #[schema(max_length = 96)]
    pub application_id: String,
    #[schema(max_length = 128)]
    pub publishable_key: String,
    #[schema(max_length = 256)]
    pub handoff: String,
    #[schema(min_length = 43, max_length = 128)]
    pub pkce_verifier: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct RefreshRequest {
    #[schema(max_length = 96)]
    pub application_id: String,
    #[schema(max_length = 128)]
    pub publishable_key: String,
    #[schema(max_length = 256)]
    pub refresh_token: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct UserProjection {
    #[schema(max_length = 96)]
    pub user_id: String,
    pub user_revision: i64,
    #[schema(max_length = 64)]
    pub projection_schema: String,
    pub projection_revision: i64,
    #[schema(max_length = 128)]
    pub display_name: Option<String>,
    #[schema(max_length = 2048)]
    pub picture_url: Option<String>,
    #[schema(max_length = 32)]
    pub status: String,
    #[schema(max_length = 64)]
    pub created_at: String,
    #[schema(max_length = 64)]
    pub updated_at: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CredentialPairResponse {
    #[schema(max_length = 96)]
    pub project_id: String,
    #[schema(max_length = 96)]
    pub application_id: String,
    #[schema(max_length = 96)]
    pub user_id: String,
    #[schema(max_length = 64)]
    pub session_id: String,
    pub refresh_generation: i64,
    #[schema(max_length = 16384)]
    pub access_token: String,
    #[schema(max_length = 256)]
    pub refresh_token: String,
    pub token_type: String,
    pub expires_in: i64,
    pub projection: UserProjection,
    pub projection_revision: i64,
    #[schema(max_length = 64)]
    pub session_expires_at: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CurrentUserResponse {
    #[schema(max_length = 96)]
    pub project_id: String,
    #[schema(max_length = 96)]
    pub application_id: String,
    #[schema(max_length = 96)]
    pub user_id: String,
    pub projection: UserProjection,
    pub projection_revision: i64,
    #[schema(max_length = 64)]
    pub authenticated_at: String,
    #[schema(max_length = 64)]
    pub session_expires_at: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
pub struct BrowserLogoutPreparationResponse {
    #[schema(max_length = 512)]
    pub hosted_url: String,
    #[schema(max_length = 64)]
    pub expires_at: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
pub struct BrowserLogoutResponse {
    #[schema(max_length = 96)]
    pub project_id: String,
    pub revision: i64,
    #[schema(max_length = 64)]
    pub csrf: String,
    #[schema(max_length = 64)]
    pub expires_at: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ConfirmBrowserLogoutRequest {
    pub expected_revision: i64,
    #[schema(max_length = 64)]
    pub csrf: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
pub struct CompletionResponse {
    pub completed: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct RuntimeError {
    #[schema(max_length = 64)]
    pub code: String,
    #[schema(max_length = 256)]
    pub message: String,
    #[schema(max_length = 128)]
    pub request_id: String,
}

#[utoipa::path(
    get,
    path = "/v1/projects/{project_public_id}/auth/config",
    params(("project_public_id" = String, Path), ("application_id" = String, Query)),
    responses(
        (status = 200, body = PublicApplicationConfig),
        (status = 400, body = RuntimeError),
        (status = 404, body = RuntimeError),
        (status = 429, body = RuntimeError, headers(("Retry-After" = u64, description = "Required delay in whole seconds before retrying"))),
        (status = 503, body = RuntimeError)
    )
)]
#[doc(hidden)]
pub fn get_public_application_config() {}

#[utoipa::path(
    get,
    path = "/projects/{project_public_id}/.well-known/jwks.json",
    params(("project_public_id" = String, Path)),
    responses((status = 200, body = JwksDocument), (status = 404, body = RuntimeError), (status = 503, body = RuntimeError), (status = 429, body = RuntimeError, headers(("Retry-After" = u64, description = "Required delay in whole seconds before retrying"))))
)]
#[doc(hidden)]
pub fn get_project_jwks() {}

#[utoipa::path(
    post,
    path = "/v1/projects/{project_public_id}/auth/login/start",
    params(("project_public_id" = String, Path)),
    request_body = LoginStartRequest,
    responses((status = 201, body = LoginStartResponse), (status = 400, body = RuntimeError), (status = 404, body = RuntimeError), (status = 503, body = RuntimeError), (status = 429, body = RuntimeError, headers(("Retry-After" = u64, description = "Required delay in whole seconds before retrying"))))
)]
#[doc(hidden)]
pub fn start_login() {}

#[utoipa::path(
    get,
    path = "/auth/interactions/{interaction}",
    params(("interaction" = String, Path)),
    responses((status = 200, description = "Hosted Authentication HTML"), (status = 404, body = RuntimeError), (status = 409, body = RuntimeError), (status = 429, body = RuntimeError, headers(("Retry-After" = u64, description = "Required delay in whole seconds before retrying"))))
)]
#[doc(hidden)]
pub fn get_hosted_interaction() {}

#[utoipa::path(
    post,
    path = "/v1/projects/{project_public_id}/auth/interactions/{interaction}/method",
    params(("project_public_id" = String, Path), ("interaction" = String, Path)),
    request_body = SelectProviderRequest,
    responses((status = 200, body = NavigationResponse), (status = 400, body = RuntimeError), (status = 403, body = RuntimeError), (status = 409, body = RuntimeError), (status = 429, body = RuntimeError, headers(("Retry-After" = u64, description = "Required delay in whole seconds before retrying"))))
)]
#[doc(hidden)]
pub fn select_provider() {}

#[utoipa::path(
    post,
    path = "/v1/projects/{project_public_id}/auth/interactions/{interaction}/session/reuse",
    params(("project_public_id" = String, Path), ("interaction" = String, Path)),
    request_body = ConfirmSessionReuseRequest,
    responses((status = 200, body = NavigationResponse), (status = 403, body = RuntimeError), (status = 409, body = RuntimeError), (status = 429, body = RuntimeError, headers(("Retry-After" = u64, description = "Required delay in whole seconds before retrying"))))
)]
#[doc(hidden)]
pub fn confirm_session_reuse() {}

#[utoipa::path(
    get,
    path = "/projects/{project_public_id}/auth/callback/{provider_key}",
    params(
        ("project_public_id" = String, Path),
        ("provider_key" = String, Path),
        ("code" = String, Query),
        ("state" = String, Query)
    ),
    responses(
        (status = 303, description = "Redirect to the exact stored Application callback"),
        (status = 400, body = RuntimeError),
        (status = 404, body = RuntimeError),
        (status = 409, body = RuntimeError),
        (status = 429, body = RuntimeError, headers(("Retry-After" = u64, description = "Required delay in whole seconds before retrying"))),
        (status = 503, body = RuntimeError)
    )
)]
#[doc(hidden)]
pub fn complete_provider_callback() {}

#[utoipa::path(
    post,
    path = "/v1/projects/{project_public_id}/auth/handoff/exchange",
    params(("project_public_id" = String, Path)),
    request_body = HandoffExchangeRequest,
    responses((status = 200, body = CredentialPairResponse), (status = 400, body = RuntimeError), (status = 409, body = RuntimeError), (status = 503, body = RuntimeError), (status = 429, body = RuntimeError, headers(("Retry-After" = u64, description = "Required delay in whole seconds before retrying"))))
)]
#[doc(hidden)]
pub fn exchange_handoff() {}

#[utoipa::path(
    post,
    path = "/v1/projects/{project_public_id}/auth/sessions/refresh",
    params(("project_public_id" = String, Path)),
    request_body = RefreshRequest,
    responses((status = 200, body = CredentialPairResponse), (status = 400, body = RuntimeError), (status = 409, body = RuntimeError), (status = 503, body = RuntimeError), (status = 429, body = RuntimeError, headers(("Retry-After" = u64, description = "Required delay in whole seconds before retrying"))))
)]
#[doc(hidden)]
pub fn refresh_session() {}

#[utoipa::path(
    get,
    path = "/v1/projects/{project_public_id}/auth/users/me",
    params(("project_public_id" = String, Path)),
    responses((status = 200, body = CurrentUserResponse), (status = 401, body = RuntimeError), (status = 503, body = RuntimeError), (status = 429, body = RuntimeError, headers(("Retry-After" = u64, description = "Required delay in whole seconds before retrying")))),
    security(("project_bearer" = []))
)]
#[doc(hidden)]
pub fn get_current_user() {}

#[utoipa::path(
    post,
    path = "/v1/projects/{project_public_id}/auth/sessions/logout",
    params(("project_public_id" = String, Path)),
    responses((status = 200, body = CompletionResponse), (status = 401, body = RuntimeError), (status = 503, body = RuntimeError), (status = 429, body = RuntimeError, headers(("Retry-After" = u64, description = "Required delay in whole seconds before retrying")))),
    security(("project_bearer" = []))
)]
#[doc(hidden)]
pub fn logout_application_session() {}

#[utoipa::path(
    post,
    path = "/v1/projects/{project_public_id}/auth/browser-logout/prepare",
    params(("project_public_id" = String, Path)),
    responses((status = 201, body = BrowserLogoutPreparationResponse), (status = 401, body = RuntimeError), (status = 503, body = RuntimeError), (status = 429, body = RuntimeError, headers(("Retry-After" = u64, description = "Required delay in whole seconds before retrying")))),
    security(("project_bearer" = []))
)]
#[doc(hidden)]
pub fn prepare_browser_logout() {}

#[utoipa::path(
    get,
    path = "/auth/browser-logout/{preparation}",
    params(("preparation" = String, Path)),
    responses((status = 200, description = "Hosted browser-logout confirmation HTML"), (status = 404, body = RuntimeError), (status = 409, body = RuntimeError), (status = 429, body = RuntimeError, headers(("Retry-After" = u64, description = "Required delay in whole seconds before retrying"))))
)]
#[doc(hidden)]
pub fn get_browser_logout() {}

#[utoipa::path(
    post,
    path = "/v1/projects/{project_public_id}/auth/browser-logout/{preparation}/confirm",
    params(("project_public_id" = String, Path), ("preparation" = String, Path)),
    request_body = ConfirmBrowserLogoutRequest,
    responses((status = 200, body = CompletionResponse), (status = 403, body = RuntimeError), (status = 409, body = RuntimeError), (status = 429, body = RuntimeError, headers(("Retry-After" = u64, description = "Required delay in whole seconds before retrying"))))
)]
#[doc(hidden)]
pub fn confirm_browser_logout() {}

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

#[derive(OpenApi)]
#[openapi(
    info(title = "OwlAuth Runtime API", description = "Project Auth Runtime API"),
    paths(
        start_login,
        get_hosted_interaction,
        select_provider,
        confirm_session_reuse,
        complete_provider_callback,
        exchange_handoff,
        refresh_session,
        get_current_user,
        logout_application_session,
        prepare_browser_logout,
        get_browser_logout,
        confirm_browser_logout
    ),
    components(
        schemas(
            LoginStartRequest,
            LoginStartResponse,
            HostedApplicationType,
            HostedInteractionStatus,
            HostedProvider,
            HostedInteractionResponse,
            SelectProviderRequest,
            NavigationResponse,
            ConfirmSessionReuseRequest,
            HandoffExchangeRequest,
            RefreshRequest,
            UserProjection,
            CredentialPairResponse,
            CurrentUserResponse,
            BrowserLogoutPreparationResponse,
            BrowserLogoutResponse,
            ConfirmBrowserLogoutRequest,
            CompletionResponse,
            RuntimeError
        )
    ),
    modifiers(&RuntimeSecurity)
)]
struct FederatedProjectAuthApiDoc;

struct RuntimeSecurity;

impl Modify for RuntimeSecurity {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        openapi
            .components
            .get_or_insert_default()
            .add_security_scheme(
                "project_bearer",
                SecurityScheme::Http(Http::new(HttpAuthScheme::Bearer)),
            );
    }
}

/// Generates the complete Runtime-plane `OpenAPI` document.
#[must_use]
pub fn openapi() -> utoipa::openapi::OpenApi {
    let mut document = RuntimeApiDoc::openapi();
    if crate::FEDERATED_PROJECT_AUTH_AVAILABLE {
        document.merge(FederatedProjectAuthApiDoc::openapi());
    }
    document
}
