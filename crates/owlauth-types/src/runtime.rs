use serde::{Deserialize, Deserializer, Serialize};
use utoipa::openapi::security::{Http, HttpAuthScheme, SecurityScheme};
use utoipa::{Modify, OpenApi, ToSchema};

use crate::health::HealthResponse;

fn deserialize_required_nullable<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    Option::<String>::deserialize(deserializer)
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ProviderKind {
    Oidc,
    Google,
    Github,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum IdentityKind {
    Provider,
    Email,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum IdentityMutationMethodKind {
    Provider,
    Email,
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
#[allow(
    clippy::struct_excessive_bools,
    reason = "the public wire contract exposes orthogonal current capability facts"
)]
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
    /// True only while this Runtime can complete the durable email flow.
    pub email_available: bool,
    pub email_otp_enabled: bool,
    pub email_magic_link_enabled: bool,
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
    EmailAddressEntry,
    EmailChallengePending,
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
    pub kind: ProviderKind,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
pub struct HostedPendingEmailChallenge {
    #[schema(min_length = 1, max_length = 96)]
    pub challenge_id: String,
    #[schema(minimum = 1)]
    pub generation: i16,
    #[schema(min_items = 1, max_items = 2)]
    pub proof_modes: Vec<EmailProofMode>,
    #[schema(max_length = 64)]
    pub expires_at: String,
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
    pub email_available: bool,
    #[schema(max_items = 2)]
    pub email_proof_modes: Vec<EmailProofMode>,
    pub pending_email_challenge: Option<HostedPendingEmailChallenge>,
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
pub struct SelectIdentityMutationMethodRequest {
    #[schema(minimum = 1)]
    pub expected_revision: i64,
    #[schema(min_length = 1, max_length = 64)]
    pub csrf: String,
    /// Assertion of the immutable method selected by Control for this exact proof slot.
    pub method_kind: IdentityMutationMethodKind,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum IdentityMutationProofState {
    EmailAddressEntry,
    EmailChallengePending,
    ProviderAuthorizationStarted,
    ProviderExchangeInProgress,
    Proved,
    Expired,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
pub struct IdentityMutationProofStateResponse {
    #[schema(minimum = 1)]
    pub revision: i64,
    pub state: IdentityMutationProofState,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(tag = "method_kind", content = "result", rename_all = "snake_case")]
pub enum IdentityMutationMethodResponse {
    Provider(NavigationResponse),
    Email(IdentityMutationProofStateResponse),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct BeginIdentityMutationEmailChallengeRequest {
    #[schema(minimum = 1)]
    pub expected_revision: i64,
    #[schema(min_length = 1, max_length = 64)]
    pub csrf: String,
    #[schema(min_length = 3, max_length = 254)]
    pub email: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
pub struct IdentityMutationEmailChallengeResponse {
    pub accepted: bool,
    #[schema(minimum = 1)]
    pub revision: i64,
    #[schema(min_length = 1, max_length = 96)]
    pub challenge_id: String,
    #[schema(minimum = 1)]
    pub generation: i16,
    #[schema(min_items = 1, max_items = 2)]
    pub proof_modes: Vec<EmailProofMode>,
    #[schema(max_length = 64)]
    pub expires_at: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct VerifyIdentityMutationEmailOtpRequest {
    #[schema(minimum = 1)]
    pub expected_revision: i64,
    #[schema(min_length = 1, max_length = 64)]
    pub csrf: String,
    #[schema(min_length = 1, max_length = 96)]
    pub challenge_id: String,
    #[schema(minimum = 1)]
    pub generation: i16,
    #[schema(min_length = 6, max_length = 10, pattern = "^[0-9]{6,10}$")]
    pub otp: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct VerifyIdentityMutationEmailLinkRequest {
    #[schema(minimum = 1)]
    pub expected_revision: i64,
    #[schema(min_length = 1, max_length = 64)]
    pub csrf: String,
    #[schema(min_length = 1, max_length = 96)]
    pub challenge_id: String,
    #[schema(minimum = 1)]
    pub generation: i16,
    #[schema(min_length = 22, max_length = 128, pattern = "^[A-Za-z0-9_-]{22,128}$")]
    pub token: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ConfirmHostedIdentityMutationRequest {
    #[schema(minimum = 1)]
    pub expected_revision: i64,
    #[schema(min_length = 1, max_length = 64)]
    pub csrf: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum HostedIdentityMutationStatus {
    PendingProof,
    Ready,
    Expired,
    Cancelled,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
pub struct HostedIdentityMutationResponse {
    #[schema(minimum = 1)]
    pub revision: i64,
    pub status: HostedIdentityMutationStatus,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct SelectEmailRequest {
    pub expected_revision: i64,
    #[schema(max_length = 64)]
    pub csrf: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
pub struct SelectEmailResponse {
    pub status: HostedInteractionStatus,
    #[schema(minimum = 1)]
    pub revision: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct StartManagedReauthorizationRequest {
    #[schema(minimum = 1)]
    pub expected_revision: i64,
    #[schema(max_length = 64)]
    pub csrf: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct BeginEmailChallengeRequest {
    pub expected_revision: i64,
    #[schema(max_length = 64)]
    pub csrf: String,
    #[schema(max_length = 254)]
    pub email: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum EmailProofMode {
    Otp,
    MagicLink,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
pub struct EmailChallengeAcceptedResponse {
    pub accepted: bool,
    pub revision: i64,
    pub challenge_id: String,
    pub generation: i16,
    #[schema(min_items = 1, max_items = 2)]
    pub proof_modes: Vec<EmailProofMode>,
    #[schema(max_length = 64)]
    pub expires_at: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct VerifyEmailOtpRequest {
    pub expected_revision: i64,
    #[schema(max_length = 64)]
    pub csrf: String,
    pub challenge_id: String,
    pub generation: i16,
    #[schema(min_length = 6, max_length = 10, pattern = "^[0-9]{6,10}$")]
    pub otp: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ConfirmEmailMagicRequest {
    pub expected_revision: i64,
    #[schema(max_length = 64)]
    pub csrf: String,
    pub challenge_id: String,
    pub transaction_id: String,
    pub generation: i16,
    #[schema(min_length = 22, max_length = 128, pattern = "^[A-Za-z0-9_-]{22,128}$")]
    pub proof: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
pub struct EmailProofResponse {
    pub completed: bool,
    #[schema(max_length = 4096)]
    pub redirect_url: Option<String>,
    /// Trusted type of the stored Application that owns this exact interaction. Present only on
    /// successful completion and used by Hosted UI to validate the final navigation scheme.
    pub application_type: Option<HostedApplicationType>,
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
    #[serde(deserialize_with = "deserialize_required_nullable")]
    #[schema(max_length = 128, required = true)]
    pub display_name: Option<String>,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    #[schema(max_length = 2048, required = true)]
    pub picture_url: Option<String>,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    #[schema(max_length = 35, required = true)]
    pub locale: Option<String>,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    #[schema(max_length = 320, required = true)]
    pub verified_email: Option<String>,
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
    responses((status = 200, description = "Hosted Authentication HTML", body = String, content_type = "text/html"), (status = 404, body = RuntimeError), (status = 409, body = RuntimeError), (status = 429, body = RuntimeError, headers(("Retry-After" = u64, description = "Required delay in whole seconds before retrying"))))
)]
#[doc(hidden)]
pub fn get_hosted_interaction() {}

#[utoipa::path(
    get,
    path = "/auth/managed-reauthorizations/{interaction}",
    params(("interaction" = String, Path)),
    responses((status = 200, description = "Hosted managed-reauthorization HTML", body = String, content_type = "text/html"), (status = 400, body = RuntimeError), (status = 404, body = RuntimeError), (status = 409, body = RuntimeError), (status = 429, body = RuntimeError, headers(("Retry-After" = u64, description = "Required delay in whole seconds before retrying"))))
)]
#[doc(hidden)]
pub fn get_hosted_managed_reauthorization() {}

#[utoipa::path(
    get,
    path = "/auth/identity-mutations/{intent}",
    params(("intent" = String, Path)),
    responses((status = 200, description = "Hosted identity-mutation HTML", body = String, content_type = "text/html"), (status = 400, body = RuntimeError), (status = 404, body = RuntimeError), (status = 409, body = RuntimeError), (status = 429, body = RuntimeError, headers(("Retry-After" = u64, description = "Required delay in whole seconds before retrying"))))
)]
#[doc(hidden)]
pub fn get_identity_mutation() {}

#[utoipa::path(
    get,
    path = "/auth/identity-mutations/email/confirm/{challenge_id}",
    params(("challenge_id" = String, Path)),
    responses((status = 200, description = "Generic fragment-only identity-mutation magic-link confirmation shell", body = String, content_type = "text/html"), (status = 400, body = RuntimeError), (status = 404, body = RuntimeError), (status = 429, body = RuntimeError, headers(("Retry-After" = u64, description = "Required delay in whole seconds before retrying"))))
)]
#[doc(hidden)]
pub fn get_identity_mutation_magic_confirmation() {}

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
    path = "/v1/projects/{project_public_id}/auth/interactions/{interaction}/email/select",
    params(("project_public_id" = String, Path), ("interaction" = String, Path)),
    request_body = SelectEmailRequest,
    responses((status = 200, body = SelectEmailResponse), (status = 403, body = RuntimeError), (status = 409, body = RuntimeError), (status = 429, body = RuntimeError, headers(("Retry-After" = u64, description = "Required delay in whole seconds before retrying"))))
)]
#[doc(hidden)]
pub fn select_email() {}

#[utoipa::path(
    post,
    path = "/v1/projects/{project_public_id}/auth/interactions/{interaction}/email/challenges",
    params(("project_public_id" = String, Path), ("interaction" = String, Path)),
    request_body = BeginEmailChallengeRequest,
    responses((status = 202, body = EmailChallengeAcceptedResponse), (status = 400, body = RuntimeError), (status = 403, body = RuntimeError), (status = 409, body = RuntimeError), (status = 429, body = RuntimeError, headers(("Retry-After" = u64, description = "Required delay in whole seconds before retrying"))))
)]
#[doc(hidden)]
pub fn begin_email_challenge() {}

#[utoipa::path(
    post,
    path = "/v1/projects/{project_public_id}/auth/interactions/{interaction}/email/resend",
    params(("project_public_id" = String, Path), ("interaction" = String, Path)),
    request_body = BeginEmailChallengeRequest,
    responses((status = 202, body = EmailChallengeAcceptedResponse), (status = 400, body = RuntimeError), (status = 403, body = RuntimeError), (status = 409, body = RuntimeError), (status = 429, body = RuntimeError, headers(("Retry-After" = u64, description = "Required delay in whole seconds before retrying"))))
)]
#[doc(hidden)]
pub fn resend_email_challenge() {}

#[utoipa::path(
    post,
    path = "/v1/projects/{project_public_id}/auth/interactions/{interaction}/email/otp/verify",
    params(("project_public_id" = String, Path), ("interaction" = String, Path)),
    request_body = VerifyEmailOtpRequest,
    responses((status = 200, body = EmailProofResponse), (status = 400, body = RuntimeError), (status = 403, body = RuntimeError), (status = 409, body = RuntimeError), (status = 429, body = RuntimeError, headers(("Retry-After" = u64, description = "Required delay in whole seconds before retrying"))))
)]
#[doc(hidden)]
pub fn verify_email_otp() {}

#[utoipa::path(
    get,
    path = "/auth/email/confirm/{challenge_id}",
    params(("challenge_id" = String, Path)),
    responses((status = 200, description = "Generic fragment-only magic-link confirmation shell", body = String, content_type = "text/html"), (status = 404, body = RuntimeError), (status = 429, body = RuntimeError, headers(("Retry-After" = u64, description = "Required delay in whole seconds before retrying"))))
)]
#[doc(hidden)]
pub fn get_email_magic_confirmation() {}

#[utoipa::path(
    post,
    path = "/v1/projects/{project_public_id}/auth/email/magic/confirm",
    params(("project_public_id" = String, Path)),
    request_body = ConfirmEmailMagicRequest,
    responses((status = 200, body = EmailProofResponse), (status = 400, body = RuntimeError), (status = 403, body = RuntimeError), (status = 409, body = RuntimeError), (status = 429, body = RuntimeError, headers(("Retry-After" = u64, description = "Required delay in whole seconds before retrying"))))
)]
#[doc(hidden)]
pub fn confirm_email_magic() {}

#[utoipa::path(
    post,
    path = "/v1/projects/{project_public_id}/auth/managed-reauthorizations/{interaction}/start",
    params(("project_public_id" = String, Path), ("interaction" = String, Path)),
    request_body = StartManagedReauthorizationRequest,
    responses((status = 200, body = NavigationResponse), (status = 400, body = RuntimeError), (status = 403, body = RuntimeError), (status = 409, body = RuntimeError), (status = 429, body = RuntimeError, headers(("Retry-After" = u64, description = "Required delay in whole seconds before retrying"))))
)]
#[doc(hidden)]
pub fn start_managed_reauthorization() {}

#[utoipa::path(
    post,
    path = "/v1/projects/{project_public_id}/auth/identity-mutations/{intent}/proofs/{proof_slot}/method",
    params(
        ("project_public_id" = String, Path),
        ("intent" = String, Path),
        ("proof_slot" = String, Path)
    ),
    request_body = SelectIdentityMutationMethodRequest,
    responses(
        (status = 200, body = IdentityMutationMethodResponse),
        (status = 400, body = RuntimeError),
        (status = 403, body = RuntimeError),
        (status = 404, body = RuntimeError),
        (status = 409, body = RuntimeError),
        (status = 429, body = RuntimeError, headers(("Retry-After" = u64, description = "Required delay in whole seconds before retrying")))
    )
)]
#[doc(hidden)]
pub fn select_identity_mutation_method() {}

#[utoipa::path(
    post,
    path = "/v1/projects/{project_public_id}/auth/identity-mutations/{intent}/proofs/{proof_slot}/email/challenges",
    params(
        ("project_public_id" = String, Path),
        ("intent" = String, Path),
        ("proof_slot" = String, Path)
    ),
    request_body = BeginIdentityMutationEmailChallengeRequest,
    responses(
        (status = 202, body = IdentityMutationEmailChallengeResponse),
        (status = 400, body = RuntimeError),
        (status = 403, body = RuntimeError),
        (status = 404, body = RuntimeError),
        (status = 409, body = RuntimeError),
        (status = 429, body = RuntimeError, headers(("Retry-After" = u64, description = "Required delay in whole seconds before retrying")))
    )
)]
#[doc(hidden)]
pub fn begin_identity_mutation_email_challenge() {}

#[utoipa::path(
    post,
    path = "/v1/projects/{project_public_id}/auth/identity-mutations/{intent}/proofs/{proof_slot}/email/otp/verify",
    params(
        ("project_public_id" = String, Path),
        ("intent" = String, Path),
        ("proof_slot" = String, Path)
    ),
    request_body = VerifyIdentityMutationEmailOtpRequest,
    responses(
        (status = 200, body = IdentityMutationProofStateResponse),
        (status = 400, body = RuntimeError),
        (status = 403, body = RuntimeError),
        (status = 404, body = RuntimeError),
        (status = 409, body = RuntimeError),
        (status = 429, body = RuntimeError, headers(("Retry-After" = u64, description = "Required delay in whole seconds before retrying")))
    )
)]
#[doc(hidden)]
pub fn verify_identity_mutation_email_otp() {}

#[utoipa::path(
    post,
    path = "/v1/projects/{project_public_id}/auth/identity-mutations/{intent}/proofs/{proof_slot}/email/link/verify",
    params(
        ("project_public_id" = String, Path),
        ("intent" = String, Path),
        ("proof_slot" = String, Path)
    ),
    request_body = VerifyIdentityMutationEmailLinkRequest,
    responses(
        (status = 200, body = IdentityMutationProofStateResponse),
        (status = 400, body = RuntimeError),
        (status = 403, body = RuntimeError),
        (status = 404, body = RuntimeError),
        (status = 409, body = RuntimeError),
        (status = 429, body = RuntimeError, headers(("Retry-After" = u64, description = "Required delay in whole seconds before retrying")))
    )
)]
#[doc(hidden)]
pub fn verify_identity_mutation_email_link() {}

#[utoipa::path(
    post,
    path = "/v1/projects/{project_public_id}/auth/identity-mutations/{intent}/confirm",
    params(
        ("project_public_id" = String, Path),
        ("intent" = String, Path)
    ),
    request_body = ConfirmHostedIdentityMutationRequest,
    responses(
        (status = 200, body = HostedIdentityMutationResponse),
        (status = 400, body = RuntimeError),
        (status = 403, body = RuntimeError),
        (status = 404, body = RuntimeError),
        (status = 409, body = RuntimeError),
        (status = 429, body = RuntimeError, headers(("Retry-After" = u64, description = "Required delay in whole seconds before retrying")))
    )
)]
#[doc(hidden)]
pub fn confirm_identity_mutation() {}

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
    responses((status = 200, body = CurrentUserResponse), (status = 401, body = RuntimeError, headers(("WWW-Authenticate" = String, description = "Bearer authentication challenge"))), (status = 503, body = RuntimeError), (status = 429, body = RuntimeError, headers(("Retry-After" = u64, description = "Required delay in whole seconds before retrying")))),
    security(("project_bearer" = []))
)]
#[doc(hidden)]
pub fn get_current_user() {}

#[utoipa::path(
    post,
    path = "/v1/projects/{project_public_id}/auth/sessions/logout",
    params(("project_public_id" = String, Path)),
    responses((status = 200, body = CompletionResponse), (status = 401, body = RuntimeError, headers(("WWW-Authenticate" = String, description = "Bearer authentication challenge"))), (status = 503, body = RuntimeError), (status = 429, body = RuntimeError, headers(("Retry-After" = u64, description = "Required delay in whole seconds before retrying")))),
    security(("project_bearer" = []))
)]
#[doc(hidden)]
pub fn logout_application_session() {}

#[utoipa::path(
    post,
    path = "/v1/projects/{project_public_id}/auth/browser-logout/prepare",
    params(("project_public_id" = String, Path)),
    responses((status = 201, body = BrowserLogoutPreparationResponse), (status = 401, body = RuntimeError, headers(("WWW-Authenticate" = String, description = "Bearer authentication challenge"))), (status = 503, body = RuntimeError), (status = 429, body = RuntimeError, headers(("Retry-After" = u64, description = "Required delay in whole seconds before retrying")))),
    security(("project_bearer" = []))
)]
#[doc(hidden)]
pub fn prepare_browser_logout() {}

#[utoipa::path(
    get,
    path = "/auth/browser-logout/{preparation}",
    params(("preparation" = String, Path)),
    responses((status = 200, description = "Hosted browser-logout confirmation HTML", body = String, content_type = "text/html"), (status = 404, body = RuntimeError), (status = 409, body = RuntimeError), (status = 429, body = RuntimeError, headers(("Retry-After" = u64, description = "Required delay in whole seconds before retrying"))))
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
        get_hosted_managed_reauthorization,
        get_identity_mutation,
        get_identity_mutation_magic_confirmation,
        select_provider,
        select_email,
        begin_email_challenge,
        resend_email_challenge,
        verify_email_otp,
        get_email_magic_confirmation,
        confirm_email_magic,
        start_managed_reauthorization,
        select_identity_mutation_method,
        begin_identity_mutation_email_challenge,
        verify_identity_mutation_email_otp,
        verify_identity_mutation_email_link,
        confirm_identity_mutation,
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
            HostedPendingEmailChallenge,
            HostedInteractionResponse,
            SelectProviderRequest,
            StartManagedReauthorizationRequest,
            NavigationResponse,
            IdentityKind,
            IdentityMutationMethodKind,
            SelectIdentityMutationMethodRequest,
            IdentityMutationProofState,
            IdentityMutationProofStateResponse,
            IdentityMutationMethodResponse,
            BeginIdentityMutationEmailChallengeRequest,
            IdentityMutationEmailChallengeResponse,
            VerifyIdentityMutationEmailOtpRequest,
            VerifyIdentityMutationEmailLinkRequest,
            ConfirmHostedIdentityMutationRequest,
            HostedIdentityMutationStatus,
            HostedIdentityMutationResponse,
            SelectEmailRequest,
            SelectEmailResponse,
            BeginEmailChallengeRequest,
            EmailProofMode,
            EmailChallengeAcceptedResponse,
            VerifyEmailOtpRequest,
            ConfirmEmailMagicRequest,
            EmailProofResponse,
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

#[cfg(test)]
mod identity_mutation_contract_tests {
    use serde_json::json;

    use super::{SelectIdentityMutationMethodRequest, VerifyIdentityMutationEmailLinkRequest};

    #[test]
    fn runtime_identity_mutation_routes_and_responses_are_bounded() {
        let document =
            serde_json::to_value(super::openapi()).expect("Runtime OpenAPI should serialize");
        for path in [
            "/v1/projects/{project_public_id}/auth/identity-mutations/{intent}/proofs/{proof_slot}/method",
            "/v1/projects/{project_public_id}/auth/identity-mutations/{intent}/proofs/{proof_slot}/email/challenges",
            "/v1/projects/{project_public_id}/auth/identity-mutations/{intent}/proofs/{proof_slot}/email/otp/verify",
            "/v1/projects/{project_public_id}/auth/identity-mutations/{intent}/proofs/{proof_slot}/email/link/verify",
            "/v1/projects/{project_public_id}/auth/identity-mutations/{intent}/confirm",
        ] {
            assert!(document["paths"][path].is_object(), "missing path: {path}");
        }
        assert!(document["paths"]["/auth/identity-mutations/{intent}"]["get"].is_object());

        for schema in [
            "IdentityMutationMethodResponse",
            "IdentityMutationProofStateResponse",
            "IdentityMutationEmailChallengeResponse",
            "HostedIdentityMutationResponse",
        ] {
            let encoded = document["components"]["schemas"][schema].to_string();
            for forbidden in ["receipt", "subject", "scope", "callback", "purpose"] {
                assert!(
                    !encoded.contains(forbidden),
                    "{schema} leaked forbidden field {forbidden}"
                );
            }
        }
        assert_eq!(
            document["components"]["schemas"]["IdentityMutationMethodResponse"]["oneOf"]
                .as_array()
                .map(Vec::len),
            Some(2)
        );
    }

    #[test]
    fn runtime_identity_mutation_commands_reject_authority_overrides() {
        let method = json!({
            "expected_revision": 2,
            "csrf": "csrf",
            "method_kind": "provider",
            "provider_id": "caller-provider"
        });
        assert!(serde_json::from_value::<SelectIdentityMutationMethodRequest>(method).is_err());

        let magic = json!({
            "expected_revision": 3,
            "csrf": "csrf",
            "challenge_id": "challenge",
            "generation": 1,
            "token": "abcdefghijklmnopqrstuv",
            "application_id": "caller-application"
        });
        assert!(serde_json::from_value::<VerifyIdentityMutationEmailLinkRequest>(magic).is_err());
    }

    #[test]
    fn user_projection_nullable_fields_are_explicit_and_required() {
        let projection = json!({
            "user_id": "usr_example",
            "user_revision": 1,
            "projection_schema": "owlauth.user.v1",
            "projection_revision": 1,
            "display_name": null,
            "picture_url": null,
            "locale": null,
            "verified_email": null,
            "status": "active",
            "created_at": "2026-08-02T00:00:00Z",
            "updated_at": "2026-08-02T00:00:00Z"
        });
        assert!(serde_json::from_value::<super::UserProjection>(projection.clone()).is_ok());

        let mut missing = projection.clone();
        missing.as_object_mut().unwrap().remove("locale");
        assert!(serde_json::from_value::<super::UserProjection>(missing).is_err());
        let mut unknown = projection;
        unknown["unexpected"] = json!(true);
        assert!(serde_json::from_value::<super::UserProjection>(unknown).is_err());

        let document = serde_json::to_value(super::openapi()).unwrap();
        let required = document["components"]["schemas"]["UserProjection"]["required"]
            .as_array()
            .unwrap();
        for field in ["display_name", "picture_url", "locale", "verified_email"] {
            assert!(required.iter().any(|required| required == field));
        }
    }
}
