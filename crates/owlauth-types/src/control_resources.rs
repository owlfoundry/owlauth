use serde::{Deserialize, Deserializer, Serialize};
use utoipa::ToSchema;

pub use crate::runtime::{IdentityKind, IdentityMutationMethodKind};
use crate::runtime::{ProviderKind, PublicJwk, SigningAlgorithm};

fn deserialize_required_nullable_string<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    Option::<String>::deserialize(deserializer)
}

fn deserialize_required_nullable_project_server_key<'de, D>(
    deserializer: D,
) -> Result<Option<ProjectServerKey>, D::Error>
where
    D: Deserializer<'de>,
{
    Option::<ProjectServerKey>::deserialize(deserializer)
}

fn deserialize_required_nullable_project_user<'de, D>(
    deserializer: D,
) -> Result<Option<ProjectUser>, D::Error>
where
    D: Deserializer<'de>,
{
    Option::<ProjectUser>::deserialize(deserializer)
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ProjectStatus {
    Active,
    Disabled,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ApplicationType {
    Web,
    Native,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ApplicationStatus {
    Active,
    Disabled,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum SigningKeyState {
    Provisioning,
    Published,
    Active,
    Retiring,
    Retired,
    Revoked,
    Abandoned,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ProviderStatus {
    Provisioning,
    Active,
    Disabled,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
pub struct ProblemDetails {
    #[serde(rename = "type")]
    pub type_uri: String,
    pub code: String,
    pub title: String,
    pub status: u16,
    pub detail: String,
    pub request_id: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
pub struct Project {
    pub id: String,
    pub public_id: String,
    #[schema(max_length = 128)]
    pub display_name: String,
    #[schema(max_length = 256)]
    pub belongs_to: Option<String>,
    pub status: ProjectStatus,
    pub metadata_revision: i64,
    pub security_revision: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
pub struct ProjectList {
    #[schema(max_items = 100)]
    pub items: Vec<Project>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ProjectOverviewSummary {
    pub project_id: String,
    pub applications: ProjectOverviewApplicationCounts,
    pub providers: ProjectOverviewProviderCounts,
    pub users: ProjectOverviewUserCounts,
    pub project_server_keys: ProjectOverviewServerKeyCounts,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ProjectOverviewApplicationCounts {
    #[schema(minimum = 0)]
    pub total: u64,
    #[schema(minimum = 0)]
    pub active: u64,
    #[schema(minimum = 0)]
    pub configured: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ProjectOverviewProviderCounts {
    #[schema(minimum = 0)]
    pub total: u64,
    #[schema(minimum = 0)]
    pub active: u64,
    #[schema(minimum = 0)]
    pub active_assignments: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ProjectOverviewUserCounts {
    #[schema(minimum = 0)]
    pub total: u64,
    #[schema(minimum = 0)]
    pub active: u64,
    #[schema(minimum = 0)]
    pub disabled: u64,
    #[schema(minimum = 0)]
    pub merged: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ProjectOverviewServerKeyCounts {
    #[schema(minimum = 0)]
    pub total: u64,
    #[schema(minimum = 0)]
    pub active: u64,
    #[schema(minimum = 0)]
    pub revoked: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CreateProjectRequest {
    #[schema(min_length = 1, max_length = 128)]
    pub display_name: String,
    #[schema(max_length = 256)]
    pub belongs_to: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct UpdateProjectRequest {
    #[schema(min_length = 1, max_length = 128)]
    pub display_name: String,
    #[schema(max_length = 256)]
    pub belongs_to: Option<String>,
    #[schema(minimum = 1)]
    pub expected_metadata_revision: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
pub struct ProjectPolicy {
    pub project_id: String,
    #[schema(minimum = 60, maximum = 3600)]
    pub access_token_lifetime_seconds: i32,
    pub browser_session_reuse: bool,
    #[schema(minimum = 1)]
    pub claims_revision: i64,
    #[schema(minimum = 1)]
    pub session_revision: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct UpdateProjectPolicyRequest {
    #[schema(minimum = 60, maximum = 3600)]
    pub access_token_lifetime_seconds: i32,
    pub browser_session_reuse: bool,
    #[schema(minimum = 1)]
    pub expected_claims_revision: i64,
    #[schema(minimum = 1)]
    pub expected_session_revision: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ExpectedSecurityRevision {
    #[schema(minimum = 1)]
    pub expected_security_revision: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
pub struct ApplicationConfiguration {
    #[schema(max_items = 50)]
    pub redirect_uris: Vec<String>,
    #[schema(max_items = 50)]
    pub allowed_origins: Vec<String>,
    #[schema(max_items = 50)]
    pub publishable_keys: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
pub struct Application {
    pub id: String,
    pub project_id: String,
    pub public_id: String,
    #[schema(max_length = 128)]
    pub display_name: String,
    pub application_type: ApplicationType,
    pub status: ApplicationStatus,
    pub metadata_revision: i64,
    pub security_revision: i64,
    pub configuration: ApplicationConfiguration,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
pub struct ApplicationList {
    #[schema(max_items = 100)]
    pub items: Vec<Application>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CreateApplicationRequest {
    #[schema(min_length = 1, max_length = 128)]
    pub display_name: String,
    pub application_type: ApplicationType,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct UpdateApplicationRequest {
    #[schema(min_length = 1, max_length = 128)]
    pub display_name: String,
    #[schema(minimum = 1)]
    pub expected_metadata_revision: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ReplaceApplicationConfigurationRequest {
    #[schema(max_items = 50)]
    pub redirect_uris: Vec<String>,
    #[schema(max_items = 50)]
    pub allowed_origins: Vec<String>,
    #[schema(minimum = 1)]
    pub expected_security_revision: i64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum WebhookEndpointStatus {
    Pending,
    Active,
    Disabled,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
pub enum ApplicationUserEventType {
    #[serde(rename = "user.projection.created")]
    Created,
    #[serde(rename = "user.projection.updated")]
    Updated,
    #[serde(rename = "user.projection.disabled")]
    Disabled,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum WebhookDeliveryState {
    Pending,
    Leased,
    Delivered,
    Terminal,
    Cancelled,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum WebhookDeliveryOutcomeClass {
    Accepted,
    Transient,
    Ambiguous,
    Permanent,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
pub struct WebhookEndpoint {
    pub id: String,
    pub public_id: String,
    pub project_id: String,
    pub application_id: String,
    pub url: String,
    #[schema(max_items = 3)]
    pub subscribed_event_types: Vec<ApplicationUserEventType>,
    pub status: WebhookEndpointStatus,
    #[schema(minimum = 1)]
    pub revision: i64,
    pub current_secret_generation: Option<i32>,
    pub overlap_secret_generation: Option<i32>,
    pub overlap_expires_at: Option<String>,
    pub consecutive_failure_count: i32,
    pub last_delivery_at: Option<String>,
    pub last_success_at: Option<String>,
    pub last_failure_class: Option<String>,
    pub last_tested_at: Option<String>,
    pub last_test_succeeded_at: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
pub struct WebhookEndpointList {
    #[schema(max_items = 100)]
    pub items: Vec<WebhookEndpoint>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CreateWebhookEndpointRequest {
    pub url: String,
    #[schema(min_items = 1, max_items = 3)]
    pub subscribed_event_types: Vec<ApplicationUserEventType>,
    #[schema(min_length = 32, max_length = 128, write_only)]
    pub secret: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct UpdateWebhookEndpointRequest {
    #[schema(min_items = 1, max_items = 3)]
    pub subscribed_event_types: Vec<ApplicationUserEventType>,
    #[schema(minimum = 1)]
    pub expected_revision: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ExpectedWebhookEndpointRevision {
    #[schema(minimum = 1)]
    pub expected_revision: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct PrepareWebhookSecretRotationRequest {
    #[schema(min_length = 32, max_length = 128, write_only)]
    pub secret: String,
    #[schema(minimum = 1)]
    pub expected_revision: i64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum WebhookSecretPreparationStatus {
    Pending,
    Provisioned,
    Terminal,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
pub struct PreparedWebhookSecretRotation {
    pub endpoint: WebhookEndpoint,
    #[schema(minimum = 1)]
    pub generation: i32,
    pub preparation_status: WebhookSecretPreparationStatus,
    pub already_active: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ActivateWebhookSecretRotationRequest {
    #[schema(minimum = 1)]
    pub expected_revision: i64,
    #[schema(minimum = 300, maximum = 86400)]
    pub overlap_seconds: i64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize, ToSchema)]
pub struct ApplicationUserEvent {
    pub event_id: String,
    pub project_id: String,
    pub application_id: String,
    pub user_id: String,
    pub event_type: ApplicationUserEventType,
    pub user_revision: i64,
    pub projection_revision: i64,
    pub projection_schema: String,
    pub safe_body: serde_json::Value,
    pub occurred_at: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize, ToSchema)]
pub struct ApplicationUserEventList {
    #[schema(max_items = 100)]
    pub items: Vec<ApplicationUserEvent>,
    pub next_cursor: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
pub struct WebhookDelivery {
    pub id: String,
    pub endpoint_id: String,
    pub event_id: String,
    pub replay_sequence: i32,
    pub replay_of_delivery_id: Option<String>,
    pub state: WebhookDeliveryState,
    pub attempt_count: i32,
    pub next_attempt_at: String,
    pub last_outcome_class: Option<WebhookDeliveryOutcomeClass>,
    pub last_http_status: Option<i32>,
    pub delivered_at: Option<String>,
    pub terminal_at: Option<String>,
    pub created_at: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
pub struct WebhookDeliveryList {
    #[schema(max_items = 100)]
    pub items: Vec<WebhookDelivery>,
    pub next_cursor: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ReplayWebhookDeliveryRequest {
    pub confirm: bool,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize, ToSchema)]
pub struct SigningKey {
    pub id: String,
    pub project_id: String,
    pub kid: String,
    pub algorithm: SigningAlgorithm,
    pub state: SigningKeyState,
    pub ring_revision: i64,
    pub signing_epoch: i64,
    pub sign_not_before: Option<String>,
    pub verify_not_after: Option<String>,
    /// Absent until the external signer material has been reconciled.
    pub public_jwk: Option<PublicJwk>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize, ToSchema)]
pub struct SigningKeyList {
    #[schema(max_items = 100)]
    pub items: Vec<SigningKey>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ProjectServerKeyStatus {
    Active,
    Revoked,
}

/// Safe Control inventory metadata. No credential digest or secret component is exposed.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ProjectServerKey {
    #[schema(max_length = 36)]
    pub id: String,
    #[schema(max_length = 36)]
    pub project_id: String,
    #[schema(min_length = 22, max_length = 22, pattern = "^[A-Za-z0-9_-]{22}$")]
    pub public_key_id: String,
    #[schema(min_length = 1, max_length = 64)]
    pub label: String,
    pub status: ProjectServerKeyStatus,
    #[schema(minimum = 1)]
    pub digest_key_version: i32,
    #[schema(
        min_length = 36,
        max_length = 36,
        pattern = "^owl_server_v1\\.[A-Za-z0-9_-]{22}$"
    )]
    pub display_prefix: String,
    #[schema(minimum = 1)]
    pub revision: i64,
    #[schema(max_length = 64)]
    pub created_at: String,
    /// Set only after an operator explicitly confirms durable secret-manager storage.
    #[serde(deserialize_with = "deserialize_required_nullable_string")]
    #[schema(max_length = 64, required = true)]
    pub credential_acknowledged_at: Option<String>,
    #[schema(max_length = 64)]
    pub last_used_at: Option<String>,
    #[schema(max_length = 64)]
    pub revoked_at: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ProjectServerKeyList {
    #[schema(max_items = 100)]
    pub items: Vec<ProjectServerKey>,
    #[serde(default)]
    #[schema(max_length = 64)]
    pub next_cursor: Option<String>,
    /// Bounded, secret-free creation gate authority independent of paginated history size.
    #[serde(deserialize_with = "deserialize_required_nullable_project_server_key")]
    #[schema(required = true)]
    pub active_unacknowledged_key: Option<ProjectServerKey>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CreateProjectServerKeyRequest {
    #[schema(min_length = 1, max_length = 64)]
    pub label: String,
}

/// Original successful create response. The credential is never durable and is redacted in Debug.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CreateProjectServerKeyResponse {
    pub key: ProjectServerKey,
    #[schema(
        min_length = 80,
        max_length = 80,
        pattern = "^owl_server_v1\\.[A-Za-z0-9_-]{22}\\.[A-Za-z0-9_-]{43}$",
        read_only
    )]
    pub credential: String,
}

impl std::fmt::Debug for CreateProjectServerKeyResponse {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CreateProjectServerKeyResponse")
            .field("key", &self.key)
            .field("credential", &"[REDACTED]")
            .finish()
    }
}

impl Drop for CreateProjectServerKeyResponse {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.credential);
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct AcknowledgeProjectServerKeyDeliveryRequest {
    #[schema(minimum = 1)]
    pub expected_revision: i64,
    /// Explicit assertion that the one-time credential is stored outside `OwlAuth`.
    pub confirm_stored: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct RevokeProjectServerKeyRequest {
    #[schema(minimum = 1)]
    pub expected_revision: i64,
    /// Explicit acknowledgement that revocation is immediate and irreversible.
    pub confirm: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct RotateSigningKeyRequest {
    #[schema(minimum = 1)]
    pub expected_project_revision: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct KeyTransitionRequest {
    #[schema(minimum = 1)]
    pub expected_ring_revision: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "generated wire capability flags are independently meaningful and additive"
)]
pub struct ProviderManagedProfileCapability {
    pub supported: bool,
    pub enabled: bool,
    #[schema(max_items = 16)]
    pub exact_scopes: Vec<String>,
    pub profile_schema: String,
    pub read_retry_safe: bool,
    pub renewal_idempotent_replay: bool,
    pub supports_revocation: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
pub struct Provider {
    pub id: String,
    pub project_id: String,
    #[schema(max_length = 64)]
    pub provider_key: String,
    pub kind: ProviderKind,
    #[schema(max_length = 128)]
    pub display_name: String,
    pub issuer: String,
    pub client_id: String,
    pub callback_url: String,
    pub status: ProviderStatus,
    pub revision: i64,
    /// Whether this adapter can be selected for ordinary Runtime login.
    pub login_supported: bool,
    /// Whether this adapter can serve as an identity-mutation proof authority.
    pub identity_proof_supported: bool,
    pub managed_profile: ProviderManagedProfileCapability,
    /// Whether a durable protected-secret replacement awaits reconciliation or abandonment.
    pub secret_replacement_pending: bool,
    #[schema(max_items = 100)]
    pub assigned_application_ids: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
pub struct ProviderList {
    #[schema(max_items = 100)]
    pub items: Vec<Provider>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ProviderEgressMode {
    AllowAll,
    ExactOrigins,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
pub struct ProviderEgressPolicy {
    pub project_id: String,
    pub mode: ProviderEgressMode,
    #[schema(max_items = 1024)]
    pub exact_origins: Vec<String>,
    #[schema(minimum = 1)]
    pub revision: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct UpdateProviderEgressPolicyRequest {
    pub mode: ProviderEgressMode,
    #[schema(max_items = 1024)]
    pub exact_origins: Vec<String>,
    #[schema(minimum = 1)]
    pub expected_revision: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct OidcPreflightRequest {
    #[schema(min_length = 1, max_length = 64)]
    pub provider_key: String,
    #[schema(min_length = 8, max_length = 2048)]
    pub issuer: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "the public diagnostic reports four independent reviewed OIDC capabilities"
)]
pub struct OidcPreflightResult {
    pub canonical_issuer: String,
    pub callback_url: String,
    pub callback_guidance: ProviderCallbackGuidance,
    #[schema(max_items = 8)]
    pub admitted_endpoint_origins: Vec<String>,
    #[schema(max_items = 8)]
    pub exact_scopes: Vec<String>,
    pub authorization_code_supported: bool,
    pub pkce_s256_supported: bool,
    pub rs256_id_tokens_supported: bool,
    pub managed_profile_supported: bool,
    pub policy_mode: ProviderEgressMode,
    #[schema(minimum = 1)]
    pub policy_revision: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct NamedProviderPreflightRequest {
    /// Named server-owned adapter profile. Custom OIDC is rejected.
    pub kind: ProviderKind,
    #[schema(min_length = 1, max_length = 64)]
    pub provider_key: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ProviderCallbackGuidance {
    RegisterExactRedirectUri,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ProviderConsentBehavior {
    Standard,
    ExplicitOfflineConsent,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
pub struct FixedProviderAuthorizationPolicy {
    #[schema(max_items = 8)]
    pub exact_scopes: Vec<String>,
    pub consent_behavior: ProviderConsentBehavior,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
pub struct NamedProviderPreflightResult {
    pub kind: ProviderKind,
    pub issuer: String,
    pub callback_url: String,
    pub callback_guidance: ProviderCallbackGuidance,
    pub login: FixedProviderAuthorizationPolicy,
    pub managed_profile: Option<FixedProviderAuthorizationPolicy>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CreateProviderRequest {
    /// Closed server-owned adapter profile.
    pub kind: ProviderKind,
    #[schema(min_length = 1, max_length = 64)]
    pub provider_key: String,
    #[schema(min_length = 1, max_length = 128)]
    pub display_name: String,
    /// Required for Custom OIDC and forbidden for named profiles.
    #[schema(min_length = 8, max_length = 2048)]
    pub issuer: Option<String>,
    #[schema(min_length = 1, max_length = 512)]
    pub client_id: String,
    #[schema(write_only, min_length = 1, max_length = 4096)]
    pub client_secret: String,
    /// Enables only adapter-declared fixed least scopes; callers cannot supply scopes.
    #[serde(default)]
    pub managed_profile_enabled: bool,
    #[schema(minimum = 1)]
    pub expected_project_revision: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct UpdateProviderRequest {
    #[schema(min_length = 1, max_length = 128)]
    pub display_name: String,
    #[schema(min_length = 1, max_length = 512)]
    pub client_id: String,
    #[schema(minimum = 1)]
    pub expected_provider_revision: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ReplaceProviderSecretRequest {
    #[schema(min_length = 1, max_length = 128)]
    pub display_name: String,
    #[schema(min_length = 1, max_length = 512)]
    pub client_id: String,
    #[schema(write_only, min_length = 1, max_length = 4096)]
    pub client_secret: String,
    #[schema(minimum = 1)]
    pub expected_provider_revision: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ReconcileProviderRequest {
    #[schema(write_only, min_length = 1, max_length = 4096)]
    pub client_secret: String,
    #[schema(minimum = 1)]
    pub expected_project_revision: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ReconcileProviderSecretReplacementRequest {
    #[schema(write_only, min_length = 1, max_length = 4096)]
    pub client_secret: String,
    #[schema(minimum = 1)]
    pub expected_provider_revision: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ProviderRevisionRequest {
    #[schema(minimum = 1)]
    pub expected_provider_revision: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ProviderAssignmentRequest {
    #[schema(minimum = 1)]
    pub expected_application_revision: i64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum SmtpTlsMode {
    ImplicitTls,
    StarttlsRequired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum SmtpGenerationStatus {
    Reconciled,
    Pending,
    Active,
    Retained,
    Disabled,
    Compromised,
    Retired,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "generated Control policy DTO preserves explicit independent switches"
)]
pub struct EmailMethodPolicy {
    pub project_id: String,
    pub enabled: bool,
    pub policy_revision: i64,
    pub security_revision: i64,
    pub otp_enabled: bool,
    pub magic_link_enabled: bool,
    #[schema(minimum = 6, maximum = 10)]
    pub otp_digits: i16,
    #[schema(minimum = 30, maximum = 600)]
    pub otp_validity_seconds: i32,
    #[schema(minimum = 1, maximum = 5)]
    pub otp_max_attempts: i16,
    #[schema(minimum = 30, maximum = 600)]
    pub resend_after_seconds: i32,
    #[schema(minimum = 1, maximum = 5)]
    pub max_generations: i16,
    #[schema(minimum = 30, maximum = 600)]
    pub magic_validity_seconds: i32,
    pub signup_enabled: bool,
    pub transferred_magic_link_enabled: bool,
    pub allow_deployment_default: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(deny_unknown_fields)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "generated Control policy DTO preserves explicit independent switches"
)]
pub struct UpdateEmailMethodPolicyRequest {
    pub enabled: bool,
    pub otp_enabled: bool,
    pub magic_link_enabled: bool,
    pub otp_digits: i16,
    pub otp_validity_seconds: i32,
    pub otp_max_attempts: i16,
    pub resend_after_seconds: i32,
    pub max_generations: i16,
    pub magic_validity_seconds: i32,
    pub signup_enabled: bool,
    pub transferred_magic_link_enabled: bool,
    pub allow_deployment_default: bool,
    pub expected_policy_revision: i64,
    pub expected_security_revision: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct EmailAssignmentRequest {
    pub enabled: bool,
    pub expected_application_security_revision: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
pub struct EmailAssignment {
    pub project_id: String,
    pub application_id: String,
    pub enabled: bool,
    #[schema(minimum = 1)]
    pub security_revision: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
pub struct EmailAssignmentList {
    #[schema(max_items = 100)]
    pub items: Vec<EmailAssignment>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
pub struct SmtpConfiguration {
    pub id: String,
    pub project_id: String,
    pub generation: i32,
    pub revision: i64,
    pub security_eligibility_revision: i64,
    pub status: SmtpGenerationStatus,
    #[schema(max_length = 253)]
    pub host: String,
    pub port: u16,
    pub tls_mode: SmtpTlsMode,
    #[schema(max_length = 254)]
    pub sender_address: String,
    #[schema(max_length = 128)]
    pub sender_name: Option<String>,
    #[schema(max_length = 254)]
    pub reply_to: Option<String>,
    #[schema(max_length = 64)]
    pub retained_until: Option<String>,
    #[schema(max_length = 64)]
    pub safe_fingerprint: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
pub struct DeploymentSmtpGeneration {
    pub generation: i32,
    pub revision: i64,
    pub security_eligibility_revision: i64,
    pub status: SmtpGenerationStatus,
    #[schema(max_length = 253)]
    pub host: String,
    pub port: u16,
    pub tls_mode: SmtpTlsMode,
    #[schema(max_length = 254)]
    pub sender_address: String,
    #[schema(max_length = 64)]
    pub retained_until: Option<String>,
    #[schema(max_length = 64)]
    pub safe_fingerprint: String,
    #[schema(max_items = 16)]
    pub explicitly_allowed_private_ips: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
pub struct DeploymentSmtpGenerationList {
    #[schema(max_items = 32)]
    pub items: Vec<DeploymentSmtpGeneration>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
pub struct SmtpConfigurationList {
    #[schema(max_items = 32)]
    pub items: Vec<SmtpConfiguration>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ReconcileDeploymentSmtpRequest {
    #[schema(write_only, min_length = 2, max_length = 4096)]
    pub credential: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CreateSmtpConfigurationRequest {
    #[schema(max_length = 253)]
    pub host: String,
    pub port: u16,
    pub tls_mode: SmtpTlsMode,
    #[schema(max_length = 254)]
    pub sender_address: String,
    #[schema(max_length = 128)]
    pub sender_name: Option<String>,
    #[schema(max_length = 254)]
    pub reply_to: Option<String>,
    #[schema(write_only, min_length = 2, max_length = 4096)]
    pub credential: String,
    pub expected_project_security_revision: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct SmtpRevisionRequest {
    pub expected_revision: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct TestSmtpConfigurationRequest {
    #[schema(max_length = 254)]
    pub recipient: String,
    pub expected_revision: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
pub struct SmtpTestOperation {
    pub id: String,
    pub project_id: String,
    pub smtp_configuration_id: String,
    pub status: String,
    pub outcome: Option<String>,
    pub created_at: String,
    pub completed_at: Option<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ManagedProviderConnectionState {
    Active,
    ReauthRequired,
    Revoked,
    Disconnected,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
pub struct ManagedProviderConnection {
    pub id: String,
    pub project_id: String,
    pub provider_id: String,
    pub identity_id: String,
    pub user_id: String,
    pub state: ManagedProviderConnectionState,
    pub revision: i64,
    pub generation: i64,
    pub credential_generation: i64,
    pub capability_key: String,
    #[schema(max_items = 16)]
    pub required_scopes: Vec<String>,
    pub source_schema: String,
    pub supports_revocation: bool,
    #[schema(max_items = 100)]
    pub reauthorization_application_ids: Vec<String>,
    pub last_safe_outcome: String,
    pub last_synchronized_at: Option<String>,
    pub next_synchronize_at: Option<String>,
    pub next_renewal_at: Option<String>,
    pub consecutive_failures: i32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
pub struct ManagedProviderConnectionList {
    #[schema(max_items = 100)]
    pub items: Vec<ManagedProviderConnection>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ManagedProviderConnectionActionRequest {
    #[schema(minimum = 1)]
    pub expected_revision: i64,
    #[schema(minimum = 1)]
    pub expected_generation: i64,
    /// Required for destructive disconnect/revoke actions.
    #[serde(default)]
    pub confirm: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ManagedReauthorizationStatus {
    AwaitingBrowserBinding,
    AwaitingProviderStart,
    ProviderAuthorizationStarted,
    ProviderExchangeInProgress,
    Completed,
    ProviderExchangeFailed,
    Expired,
    Cancelled,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
pub struct ManagedReauthorization {
    pub id: String,
    pub project_id: String,
    pub user_id: String,
    pub connection_id: String,
    pub provider_key: String,
    pub application_id: String,
    pub status: ManagedReauthorizationStatus,
    #[schema(minimum = 1)]
    pub revision: i64,
    pub expires_at: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CreateManagedReauthorizationRequest {
    pub application_id: String,
    #[schema(minimum = 1)]
    pub expected_connection_revision: i64,
    #[schema(minimum = 1)]
    pub expected_connection_generation: i64,
    #[schema(minimum = 1)]
    pub expected_credential_generation: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
pub struct CreateManagedReauthorizationResponse {
    #[serde(flatten)]
    pub interaction: ManagedReauthorization,
    /// Present only on create or identical idempotency replay through expiry.
    pub hosted_target: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CancelManagedReauthorizationRequest {
    #[schema(minimum = 1)]
    pub expected_revision: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct IdentityMutationUserTarget {
    pub user_id: String,
    #[schema(minimum = 1)]
    pub expected_user_revision: i64,
    #[schema(minimum = 1)]
    pub expected_user_security_revision: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(tag = "identity_kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ExistingIdentityReference {
    Provider {
        identity_id: String,
        #[schema(minimum = 1)]
        expected_identity_revision: i64,
    },
    Email {
        identity_id: String,
        #[schema(minimum = 1)]
        expected_identity_revision: i64,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(tag = "method_kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum IdentityMutationProofAuthority {
    Provider {
        application_id: String,
        provider_id: String,
    },
    Email {
        application_id: String,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(tag = "disposition", rename_all = "snake_case", deny_unknown_fields)]
pub enum UnlinkPrimarySourceDisposition {
    Preserve,
    Clear,
    Provider {
        identity_id: String,
        #[schema(minimum = 1)]
        expected_identity_revision: i64,
    },
    Email {
        identity_id: String,
        #[schema(minimum = 1)]
        expected_identity_revision: i64,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(tag = "identity_kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum MergePrimarySource {
    Provider {
        identity_id: String,
        #[schema(minimum = 1)]
        expected_identity_revision: i64,
    },
    Email {
        identity_id: String,
        #[schema(minimum = 1)]
        expected_identity_revision: i64,
    },
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum MergeSessionsDisposition {
    LoserRevoked,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum MergeBindingsDisposition {
    WinnerPreferred,
}

/// A typed identity mutation plan. Mandatory proof slots and all authority revisions are derived
/// by the server; callers can neither provide slots nor override their purposes.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(tag = "operation_kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum CreateIdentityMutationIntentRequest {
    Link {
        destination: IdentityMutationUserTarget,
        destination_identity: ExistingIdentityReference,
        candidate_identity_kind: IdentityKind,
        destination_proof_authority: IdentityMutationProofAuthority,
        candidate_proof_authority: IdentityMutationProofAuthority,
    },
    Unlink {
        owner: IdentityMutationUserTarget,
        identity: ExistingIdentityReference,
        proof_authority: IdentityMutationProofAuthority,
        primary_source_disposition: UnlinkPrimarySourceDisposition,
    },
    Merge {
        winner: IdentityMutationUserTarget,
        winner_identity: ExistingIdentityReference,
        winner_proof_authority: IdentityMutationProofAuthority,
        loser: IdentityMutationUserTarget,
        loser_identity: ExistingIdentityReference,
        loser_proof_authority: IdentityMutationProofAuthority,
        primary_source: MergePrimarySource,
        sessions_disposition: MergeSessionsDisposition,
        bindings_disposition: MergeBindingsDisposition,
    },
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum IdentityMutationOperationKind {
    Link,
    Unlink,
    Merge,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum IdentityMutationIntentStatus {
    PendingProof,
    Ready,
    Completed,
    Expired,
    Cancelled,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum IdentityMutationProofRole {
    DestinationOwner,
    CandidateIdentity,
    IdentityOwner,
    WinnerOwner,
    LoserOwner,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
pub struct IdentityMutationProofSlot {
    pub id: String,
    pub role: IdentityMutationProofRole,
    pub identity_kind: IdentityKind,
    pub method_kind: IdentityMutationMethodKind,
    pub proved: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
pub struct IdentityMutationIntent {
    pub id: String,
    pub project_id: String,
    pub operation_kind: IdentityMutationOperationKind,
    pub status: IdentityMutationIntentStatus,
    #[schema(minimum = 1)]
    pub revision: i64,
    #[schema(max_length = 64)]
    pub effective_expires_at: String,
    #[schema(min_items = 1, max_items = 2)]
    pub slots: Vec<IdentityMutationProofSlot>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
pub struct CreateIdentityMutationIntentResponse {
    #[serde(flatten)]
    pub intent: IdentityMutationIntent,
    /// Present only on create or identical idempotency replay through effective expiry.
    #[schema(max_length = 512)]
    pub hosted_target: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CancelIdentityMutationIntentRequest {
    #[schema(minimum = 1)]
    pub expected_revision: i64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum LinkIdentityMutationConfirmation {
    LinkIdentity,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum UnlinkIdentityMutationConfirmation {
    UnlinkIdentity,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum MergeIdentityMutationConfirmation {
    MergeUsers,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(tag = "operation_kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ConfirmIdentityMutationIntentRequest {
    Link {
        #[schema(minimum = 1)]
        expected_revision: i64,
        confirmation: LinkIdentityMutationConfirmation,
    },
    Unlink {
        #[schema(minimum = 1)]
        expected_revision: i64,
        confirmation: UnlinkIdentityMutationConfirmation,
    },
    Merge {
        #[schema(minimum = 1)]
        expected_revision: i64,
        confirmation: MergeIdentityMutationConfirmation,
    },
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ProjectUserStatus {
    Active,
    Disabled,
    Merged,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ProjectUserSort {
    CreatedNewest,
    CreatedOldest,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ProjectUserIdentityFilter {
    Provider,
    Email,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ManagedSessionStatus {
    Active,
    Revoked,
    Expired,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
pub struct ProjectUser {
    pub id: String,
    pub project_id: String,
    #[schema(max_length = 96)]
    pub public_id: String,
    pub status: ProjectUserStatus,
    #[schema(minimum = 1)]
    pub user_revision: i64,
    #[schema(minimum = 1)]
    pub security_revision: i64,
    #[schema(max_length = 256)]
    pub display_name: Option<String>,
    #[schema(max_length = 2048)]
    pub picture_url: Option<String>,
    #[schema(max_length = 64)]
    pub created_at: String,
    #[schema(max_length = 64)]
    pub updated_at: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
pub struct ProjectUserList {
    #[schema(max_items = 100)]
    pub items: Vec<ProjectUser>,
    #[schema(max_length = 36)]
    pub next_cursor: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ProjectUserEmailLookupRequest {
    #[schema(min_length = 3, max_length = 320)]
    pub email: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ProjectUserLookup {
    #[serde(deserialize_with = "deserialize_required_nullable_project_user")]
    #[schema(required = true)]
    pub user: Option<ProjectUser>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ProjectUserIdentityStatus {
    Active,
    Disabled,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum RedactedEmailMarker {
    Redacted,
}

/// Safe presentation only. `provider_key` is immutable creation provenance, not current provider
/// authority. Email presentation is a fixed marker and never an address or reversible material.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(tag = "identity_kind", rename_all = "snake_case")]
pub enum ProjectUserIdentityPresentation {
    Provider {
        #[schema(max_length = 64)]
        provider_key: String,
    },
    Email {
        address: RedactedEmailMarker,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
pub struct ProjectUserIdentity {
    pub id: String,
    pub project_id: String,
    pub user_id: String,
    pub status: ProjectUserIdentityStatus,
    #[schema(minimum = 1)]
    pub identity_revision: i64,
    pub is_primary_source: bool,
    #[serde(flatten)]
    pub presentation: ProjectUserIdentityPresentation,
    #[schema(max_length = 64)]
    pub verified_or_observed_at: String,
    #[schema(max_length = 64)]
    pub created_at: String,
    #[schema(max_length = 64)]
    pub updated_at: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
pub struct ProjectUserIdentityList {
    #[schema(max_items = 100)]
    pub items: Vec<ProjectUserIdentity>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
pub struct ApplicationSession {
    pub id: String,
    pub project_id: String,
    pub user_id: String,
    pub application_id: String,
    #[schema(max_length = 96)]
    pub application_public_id: String,
    #[schema(max_length = 128)]
    pub application_display_name: String,
    pub browser_session_id: Option<String>,
    pub status: ManagedSessionStatus,
    #[schema(minimum = 1)]
    pub session_revision: i64,
    #[schema(max_length = 64)]
    pub authenticated_at: String,
    #[schema(max_length = 64)]
    pub absolute_expires_at: String,
    #[schema(max_length = 64)]
    pub revoked_at: Option<String>,
    #[schema(max_length = 64)]
    pub created_at: String,
    #[schema(max_length = 64)]
    pub updated_at: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
pub struct BrowserSession {
    pub id: String,
    pub project_id: String,
    pub user_id: String,
    pub status: ManagedSessionStatus,
    #[schema(minimum = 1)]
    pub session_revision: i64,
    #[schema(max_length = 64)]
    pub authenticated_at: String,
    #[schema(max_length = 64)]
    pub last_activity_at: String,
    #[schema(max_length = 64)]
    pub idle_expires_at: String,
    #[schema(max_length = 64)]
    pub absolute_expires_at: String,
    #[schema(max_length = 64)]
    pub terminated_at: Option<String>,
    #[schema(max_length = 64)]
    pub created_at: String,
    #[schema(max_length = 64)]
    pub updated_at: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
pub struct ProjectUserSessions {
    #[schema(max_items = 100)]
    pub application_sessions: Vec<ApplicationSession>,
    #[schema(max_items = 100)]
    pub browser_sessions: Vec<BrowserSession>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ExpectedSessionRevision {
    /// Exact current revision. A terminal session with this revision is returned unchanged;
    /// a stale revision conflicts.
    #[schema(minimum = 1)]
    pub expected_session_revision: i64,
}

macro_rules! control_path {
    ($name:ident, $method:ident, $path:literal, $response:ty, $summary:literal $(, body = $body:ty)? $(, params($($params:tt)*))?) => {
        #[utoipa::path(
            $method,
            path = $path,
            $(request_body = $body,)?
            responses(
                (status = 200, description = $summary, body = $response),
                (status = 400, description = "Invalid request", body = ProblemDetails, content_type = "application/problem+json"),
                (status = 401, description = "Missing or invalid operator API key", body = ProblemDetails, content_type = "application/problem+json", headers(("WWW-Authenticate" = String, description = "Bearer authentication challenge"))),
                (status = 404, description = "Resource not found", body = ProblemDetails, content_type = "application/problem+json"),
                (status = 409, description = "Revision, state, idempotency, or capacity conflict", body = ProblemDetails, content_type = "application/problem+json"),
                (status = 500, description = "Stored authority data violated an invariant", body = ProblemDetails, content_type = "application/problem+json"),
                (status = 503, description = "Required authority unavailable", body = ProblemDetails, content_type = "application/problem+json")
            ),
            $(params($($params)*),)?
            security(("operator_api_key" = []))
        )]
        #[doc(hidden)]
        pub fn $name() {}
    };
}

macro_rules! control_preflight_path {
    ($name:ident, $path:literal, $response:ty, $summary:literal, $body:ty) => {
        #[utoipa::path(
            post,
            path = $path,
            request_body = $body,
            responses(
                (status = 200, description = $summary, body = $response),
                (status = 400, description = "Invalid request", body = ProblemDetails, content_type = "application/problem+json"),
                (status = 401, description = "Missing or invalid operator API key", body = ProblemDetails, content_type = "application/problem+json", headers(("WWW-Authenticate" = String, description = "Bearer authentication challenge"))),
                (status = 404, description = "Resource not found", body = ProblemDetails, content_type = "application/problem+json"),
                (status = 409, description = "Revision, state, idempotency, or capacity conflict", body = ProblemDetails, content_type = "application/problem+json"),
                (status = 422, description = "Provider metadata or policy rejected", body = ProblemDetails, content_type = "application/problem+json"),
                (status = 500, description = "Stored authority data violated an invariant", body = ProblemDetails, content_type = "application/problem+json"),
                (status = 503, description = "Required authority unavailable", body = ProblemDetails, content_type = "application/problem+json")
            ),
            params(("project_id" = String, Path)),
            security(("operator_api_key" = []))
        )]
        #[doc(hidden)]
        pub fn $name() {}
    };
}

#[utoipa::path(
    post,
    path = "/v1/projects/{project_id}/smtp-configurations/{smtp_id}/test",
    request_body = TestSmtpConfigurationRequest,
    responses(
        (
            status = 202,
            description = "Enqueued bounded SMTP test",
            body = SmtpTestOperation,
            headers(("Location" = String, description = "Exact Control path for the SMTP test operation"))
        ),
        (status = 400, description = "Invalid request", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "Missing or invalid operator API key", body = ProblemDetails, content_type = "application/problem+json", headers(("WWW-Authenticate" = String, description = "Bearer authentication challenge"))),
        (status = 404, description = "Resource not found", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "Revision, state, idempotency, or capacity conflict", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 500, description = "Stored authority data violated an invariant", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "Required authority unavailable", body = ProblemDetails, content_type = "application/problem+json")
    ),
    params(
        ("project_id" = String, Path),
        ("smtp_id" = String, Path),
        ("Idempotency-Key" = String, Header)
    ),
    security(("operator_api_key" = []))
)]
#[doc(hidden)]
pub fn test_smtp_configuration() {}

control_path!(
    list_projects,
    get,
    "/v1/projects",
    ProjectList,
    "Projects",
    params(("belongs_to" = Option<String>, Query))
);
control_path!(
    create_project,
    post,
    "/v1/projects",
    Project,
    "Created or authoritatively replayed project",
    body = CreateProjectRequest,
    params(("Idempotency-Key" = String, Header))
);
control_path!(
    get_project,
    get,
    "/v1/projects/{project_id}",
    Project,
    "Project",
    params(("project_id" = String, Path))
);
control_path!(
    update_project,
    patch,
    "/v1/projects/{project_id}",
    Project,
    "Updated project",
    body = UpdateProjectRequest,
    params(("project_id" = String, Path))
);
control_path!(
    get_project_overview,
    get,
    "/v1/projects/{project_id}/overview",
    ProjectOverviewSummary,
    "Project resource overview",
    params(("project_id" = String, Path))
);
control_path!(
    get_project_policy,
    get,
    "/v1/projects/{project_id}/policy",
    ProjectPolicy,
    "Project policy",
    params(("project_id" = String, Path))
);
control_path!(
    update_project_policy,
    put,
    "/v1/projects/{project_id}/policy",
    ProjectPolicy,
    "Updated Project policy",
    body = UpdateProjectPolicyRequest,
    params(("project_id" = String, Path))
);
control_path!(
    disable_project,
    post,
    "/v1/projects/{project_id}/disable",
    Project,
    "Disabled project",
    body = ExpectedSecurityRevision,
    params(("project_id" = String, Path))
);
control_path!(
    list_project_server_keys,
    get,
    "/v1/projects/{project_id}/server-keys",
    ProjectServerKeyList,
    "Safe Project server-key metadata",
    params(
        ("project_id" = String, Path),
        ("cursor" = Option<String>, Query),
        ("limit" = Option<usize>, Query, minimum = 1, maximum = 100)
    )
);
control_path!(
    get_project_server_key,
    get,
    "/v1/projects/{project_id}/server-keys/{key_id}",
    ProjectServerKey,
    "Safe metadata for one Project server key",
    params(("project_id" = String, Path), ("key_id" = String, Path))
);

#[utoipa::path(
    post,
    path = "/v1/projects/{project_id}/server-keys",
    request_body = CreateProjectServerKeyRequest,
    responses(
        (status = 201, description = "Created Project server key with one-time credential reveal", body = CreateProjectServerKeyResponse, headers(("Location" = String, description = "Exact Control path for the created Project server key"))),
        (status = 400, description = "Invalid request", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "Missing or invalid operator API key", body = ProblemDetails, content_type = "application/problem+json", headers(("WWW-Authenticate" = String, description = "Bearer authentication challenge"))),
        (status = 404, description = "Resource not found", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "Unacknowledged delivery, key limit, idempotency conflict, or secret unavailable on replay", body = ProblemDetails),
        (status = 500, description = "Stored authority data violated an invariant", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "Required Server verifier fleet is not ready", body = ProblemDetails)
    ),
    params(
        ("project_id" = String, Path),
        ("Idempotency-Key" = String, Header)
    ),
    security(("operator_api_key" = []))
)]
#[doc(hidden)]
pub fn create_project_server_key() {}

control_path!(
    acknowledge_project_server_key_delivery,
    post,
    "/v1/projects/{project_id}/server-keys/{key_id}/acknowledge",
    ProjectServerKey,
    "Project server-key delivery acknowledged",
    body = AcknowledgeProjectServerKeyDeliveryRequest,
    params(
        ("project_id" = String, Path),
        ("key_id" = String, Path),
        ("Idempotency-Key" = String, Header)
    )
);
control_path!(
    revoke_project_server_key,
    post,
    "/v1/projects/{project_id}/server-keys/{key_id}/revoke",
    ProjectServerKey,
    "Revoked Project server key",
    body = RevokeProjectServerKeyRequest,
    params(
        ("project_id" = String, Path),
        ("key_id" = String, Path),
        ("Idempotency-Key" = String, Header)
    )
);
control_path!(
    list_applications,
    get,
    "/v1/projects/{project_id}/applications",
    ApplicationList,
    "Applications",
    params(("project_id" = String, Path))
);
control_path!(
    create_application,
    post,
    "/v1/projects/{project_id}/applications",
    Application,
    "Created or authoritatively replayed application",
    body = CreateApplicationRequest,
    params(
        ("project_id" = String, Path),
        ("Idempotency-Key" = String, Header)
    )
);
control_path!(
    get_application,
    get,
    "/v1/projects/{project_id}/applications/{application_id}",
    Application,
    "Application",
    params(
        ("project_id" = String, Path),
        ("application_id" = String, Path)
    )
);
control_path!(
    update_application,
    patch,
    "/v1/projects/{project_id}/applications/{application_id}",
    Application,
    "Updated application",
    body = UpdateApplicationRequest,
    params(
        ("project_id" = String, Path),
        ("application_id" = String, Path)
    )
);
control_path!(
    replace_application_configuration,
    put,
    "/v1/projects/{project_id}/applications/{application_id}/configuration",
    Application,
    "Replaced exact application configuration",
    body = ReplaceApplicationConfigurationRequest,
    params(
        ("project_id" = String, Path),
        ("application_id" = String, Path)
    )
);
control_path!(
    disable_application,
    post,
    "/v1/projects/{project_id}/applications/{application_id}/disable",
    Application,
    "Disabled application",
    body = ExpectedSecurityRevision,
    params(
        ("project_id" = String, Path),
        ("application_id" = String, Path)
    )
);
control_path!(
    list_webhook_endpoints,
    get,
    "/v1/projects/{project_id}/applications/{application_id}/webhook-endpoints",
    WebhookEndpointList,
    "Webhook endpoints",
    params(
        ("project_id" = String, Path),
        ("application_id" = String, Path)
    )
);
control_path!(
    create_webhook_endpoint,
    post,
    "/v1/projects/{project_id}/applications/{application_id}/webhook-endpoints",
    WebhookEndpoint,
    "Created or authoritatively replayed pending webhook endpoint",
    body = CreateWebhookEndpointRequest,
    params(
        ("project_id" = String, Path),
        ("application_id" = String, Path),
        ("Idempotency-Key" = String, Header)
    )
);
control_path!(
    get_webhook_endpoint,
    get,
    "/v1/projects/{project_id}/applications/{application_id}/webhook-endpoints/{endpoint_id}",
    WebhookEndpoint,
    "Webhook endpoint",
    params(
        ("project_id" = String, Path),
        ("application_id" = String, Path),
        ("endpoint_id" = String, Path)
    )
);
control_path!(
    update_webhook_endpoint,
    put,
    "/v1/projects/{project_id}/applications/{application_id}/webhook-endpoints/{endpoint_id}",
    WebhookEndpoint,
    "Updated webhook endpoint subscriptions",
    body = UpdateWebhookEndpointRequest,
    params(
        ("project_id" = String, Path),
        ("application_id" = String, Path),
        ("endpoint_id" = String, Path)
    )
);
control_path!(
    test_webhook_endpoint,
    post,
    "/v1/projects/{project_id}/applications/{application_id}/webhook-endpoints/{endpoint_id}/test",
    WebhookEndpoint,
    "Validated webhook endpoint DNS and destination policy",
    body = ExpectedWebhookEndpointRevision,
    params(
        ("project_id" = String, Path),
        ("application_id" = String, Path),
        ("endpoint_id" = String, Path)
    )
);
control_path!(
    activate_webhook_endpoint,
    post,
    "/v1/projects/{project_id}/applications/{application_id}/webhook-endpoints/{endpoint_id}/activate",
    WebhookEndpoint,
    "Activated a tested webhook endpoint",
    body = ExpectedWebhookEndpointRevision,
    params(
        ("project_id" = String, Path),
        ("application_id" = String, Path),
        ("endpoint_id" = String, Path)
    )
);
control_path!(
    disable_webhook_endpoint,
    post,
    "/v1/projects/{project_id}/applications/{application_id}/webhook-endpoints/{endpoint_id}/disable",
    WebhookEndpoint,
    "Disabled webhook endpoint",
    body = ExpectedWebhookEndpointRevision,
    params(
        ("project_id" = String, Path),
        ("application_id" = String, Path),
        ("endpoint_id" = String, Path)
    )
);
control_path!(
    prepare_webhook_secret_rotation,
    post,
    "/v1/projects/{project_id}/applications/{application_id}/webhook-endpoints/{endpoint_id}/secret-rotations",
    PreparedWebhookSecretRotation,
    "Prepared a write-only webhook secret generation",
    body = PrepareWebhookSecretRotationRequest,
    params(
        ("project_id" = String, Path),
        ("application_id" = String, Path),
        ("endpoint_id" = String, Path),
        ("Idempotency-Key" = String, Header)
    )
);
control_path!(
    activate_webhook_secret_rotation,
    post,
    "/v1/projects/{project_id}/applications/{application_id}/webhook-endpoints/{endpoint_id}/secret-rotations/{generation}/activate",
    WebhookEndpoint,
    "Activated a prepared webhook secret generation",
    body = ActivateWebhookSecretRotationRequest,
    params(
        ("project_id" = String, Path),
        ("application_id" = String, Path),
        ("endpoint_id" = String, Path),
        ("generation" = i32, Path)
    )
);
control_path!(
    list_application_user_events,
    get,
    "/v1/projects/{project_id}/applications/{application_id}/user-events",
    ApplicationUserEventList,
    "Immutable Application user events",
    params(
        ("project_id" = String, Path),
        ("application_id" = String, Path),
        ("cursor" = Option<String>, Query),
        ("limit" = Option<usize>, Query, minimum = 1, maximum = 100)
    )
);
control_path!(
    list_webhook_deliveries,
    get,
    "/v1/projects/{project_id}/applications/{application_id}/webhook-deliveries",
    WebhookDeliveryList,
    "Webhook delivery history",
    params(
        ("project_id" = String, Path),
        ("application_id" = String, Path),
        ("endpoint_id" = Option<String>, Query),
        ("cursor" = Option<String>, Query),
        ("limit" = Option<usize>, Query, minimum = 1, maximum = 100)
    )
);
control_path!(
    get_webhook_delivery,
    get,
    "/v1/projects/{project_id}/applications/{application_id}/webhook-deliveries/{delivery_id}",
    WebhookDelivery,
    "One retained webhook delivery",
    params(
        ("project_id" = String, Path),
        ("application_id" = String, Path),
        ("delivery_id" = String, Path)
    )
);
#[utoipa::path(
    post,
    path = "/v1/projects/{project_id}/applications/{application_id}/webhook-deliveries/{delivery_id}/replay",
    request_body = ReplayWebhookDeliveryRequest,
    responses(
        (status = 201, description = "Created a new delivery for the same immutable event and endpoint", body = WebhookDelivery, headers(("Location" = String, description = "Exact Control path for the created webhook delivery"))),
        (status = 400, description = "Invalid request", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "Missing or invalid operator API key", body = ProblemDetails, content_type = "application/problem+json", headers(("WWW-Authenticate" = String, description = "Bearer authentication challenge"))),
        (status = 404, description = "Resource not found", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "Revision, state, idempotency, or capacity conflict", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 500, description = "Stored authority data violated an invariant", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "Required authority unavailable", body = ProblemDetails, content_type = "application/problem+json")
    ),
    params(
        ("project_id" = String, Path),
        ("application_id" = String, Path),
        ("delivery_id" = String, Path)
    ),
    security(("operator_api_key" = []))
)]
#[doc(hidden)]
pub fn replay_webhook_delivery() {}
control_path!(
    list_signing_keys,
    get,
    "/v1/projects/{project_id}/signing-keys",
    SigningKeyList,
    "Signing keys",
    params(("project_id" = String, Path))
);
control_path!(
    rotate_signing_key,
    post,
    "/v1/projects/{project_id}/signing-keys/rotate",
    SigningKey,
    "Accepted a durable signing key rotation",
    body = RotateSigningKeyRequest,
    params(
        ("project_id" = String, Path),
        ("Idempotency-Key" = String, Header)
    )
);
control_path!(
    revoke_signing_key,
    post,
    "/v1/projects/{project_id}/signing-keys/{key_id}/revoke",
    SigningKey,
    "Emergency-revoked signing key",
    body = KeyTransitionRequest,
    params(("project_id" = String, Path), ("key_id" = String, Path))
);
control_path!(
    get_provider_egress_policy,
    get,
    "/v1/projects/{project_id}/provider-egress-policy",
    ProviderEgressPolicy,
    "Project Custom OIDC egress policy",
    params(("project_id" = String, Path))
);
control_path!(
    update_provider_egress_policy,
    put,
    "/v1/projects/{project_id}/provider-egress-policy",
    ProviderEgressPolicy,
    "Updated Project Custom OIDC egress policy",
    body = UpdateProviderEgressPolicyRequest,
    params(("project_id" = String, Path))
);
control_preflight_path!(
    preflight_oidc_provider,
    "/v1/projects/{project_id}/providers/oidc/preflight",
    OidcPreflightResult,
    "Advisory Custom OIDC discovery preflight",
    OidcPreflightRequest
);
control_preflight_path!(
    preflight_named_provider,
    "/v1/projects/{project_id}/providers/named/preflight",
    NamedProviderPreflightResult,
    "Advisory named-provider registration preflight",
    NamedProviderPreflightRequest
);
control_path!(
    list_providers,
    get,
    "/v1/projects/{project_id}/providers",
    ProviderList,
    "Providers",
    params(("project_id" = String, Path))
);
control_path!(
    create_provider,
    post,
    "/v1/projects/{project_id}/providers",
    Provider,
    "Configured or authoritatively replayed provider",
    body = CreateProviderRequest,
    params(
        ("project_id" = String, Path),
        ("Idempotency-Key" = String, Header)
    )
);
control_path!(
    update_provider,
    patch,
    "/v1/projects/{project_id}/providers/{provider_id}",
    Provider,
    "Updated provider metadata",
    body = UpdateProviderRequest,
    params(
        ("project_id" = String, Path),
        ("provider_id" = String, Path)
    )
);
control_path!(
    replace_provider_secret,
    post,
    "/v1/projects/{project_id}/providers/{provider_id}/replace-secret",
    Provider,
    "Replaced provider protected client secret",
    body = ReplaceProviderSecretRequest,
    params(
        ("project_id" = String, Path),
        ("provider_id" = String, Path),
        ("Idempotency-Key" = String, Header)
    )
);
control_path!(
    reconcile_provider_secret_replacement,
    post,
    "/v1/projects/{project_id}/providers/{provider_id}/replace-secret/reconcile",
    Provider,
    "Reconciled a pending provider protected-secret replacement",
    body = ReconcileProviderSecretReplacementRequest,
    params(
        ("project_id" = String, Path),
        ("provider_id" = String, Path)
    )
);
control_path!(
    abandon_provider_secret_replacement,
    post,
    "/v1/projects/{project_id}/providers/{provider_id}/replace-secret/abandon",
    Provider,
    "Abandoned a pending provider protected-secret replacement",
    body = ProviderRevisionRequest,
    params(
        ("project_id" = String, Path),
        ("provider_id" = String, Path)
    )
);
control_path!(
    reconcile_provider,
    post,
    "/v1/projects/{project_id}/providers/{provider_id}/reconcile",
    Provider,
    "Reconciled provider secret provisioning",
    body = ReconcileProviderRequest,
    params(
        ("project_id" = String, Path),
        ("provider_id" = String, Path)
    )
);
control_path!(
    disable_provider,
    post,
    "/v1/projects/{project_id}/providers/{provider_id}/disable",
    Provider,
    "Disabled provider",
    body = ProviderRevisionRequest,
    params(
        ("project_id" = String, Path),
        ("provider_id" = String, Path)
    )
);
control_path!(
    assign_provider,
    put,
    "/v1/projects/{project_id}/providers/{provider_id}/assignments/{application_id}",
    Provider,
    "Assigned provider",
    body = ProviderAssignmentRequest,
    params(
        ("project_id" = String, Path),
        ("provider_id" = String, Path),
        ("application_id" = String, Path)
    )
);
control_path!(
    unassign_provider,
    post,
    "/v1/projects/{project_id}/providers/{provider_id}/assignments/{application_id}/unassign",
    Provider,
    "Unassigned provider",
    body = ProviderAssignmentRequest,
    params(
        ("project_id" = String, Path),
        ("provider_id" = String, Path),
        ("application_id" = String, Path)
    )
);

control_path!(
    get_email_method_policy,
    get,
    "/v1/projects/{project_id}/email-method",
    EmailMethodPolicy,
    "Passwordless email policy",
    params(("project_id" = String, Path))
);
control_path!(
    update_email_method_policy,
    put,
    "/v1/projects/{project_id}/email-method",
    EmailMethodPolicy,
    "Updated passwordless email policy",
    body = UpdateEmailMethodPolicyRequest,
    params(("project_id" = String, Path))
);
control_path!(
    list_email_assignments,
    get,
    "/v1/projects/{project_id}/email-method/assignments",
    EmailAssignmentList,
    "Application email assignments",
    params(("project_id" = String, Path))
);
control_path!(
    assign_email_method,
    put,
    "/v1/projects/{project_id}/applications/{application_id}/email-method",
    EmailMethodPolicy,
    "Updated Application email assignment",
    body = EmailAssignmentRequest,
    params(
        ("project_id" = String, Path),
        ("application_id" = String, Path)
    )
);
control_path!(
    list_deployment_smtp_generations,
    get,
    "/v1/system/smtp-default-generations",
    DeploymentSmtpGenerationList,
    "Deployment SMTP generations"
);
control_path!(
    reconcile_deployment_smtp_generation,
    post,
    "/v1/system/smtp-default-generations",
    DeploymentSmtpGeneration,
    "Reconciled deployment SMTP generation",
    body = ReconcileDeploymentSmtpRequest,
    params(("Idempotency-Key" = String, Header))
);
control_path!(
    disable_deployment_smtp_generation,
    post,
    "/v1/system/smtp-default-generations/{generation}/disable",
    DeploymentSmtpGeneration,
    "Disabled deployment SMTP generation",
    body = SmtpRevisionRequest,
    params(("generation" = i32, Path))
);
control_path!(
    compromise_deployment_smtp_generation,
    post,
    "/v1/system/smtp-default-generations/{generation}/compromise",
    DeploymentSmtpGeneration,
    "Compromised deployment SMTP generation",
    body = SmtpRevisionRequest,
    params(("generation" = i32, Path))
);
control_path!(
    list_smtp_configurations,
    get,
    "/v1/projects/{project_id}/smtp-configurations",
    SmtpConfigurationList,
    "SMTP generations",
    params(("project_id" = String, Path))
);
control_path!(
    create_smtp_configuration,
    post,
    "/v1/projects/{project_id}/smtp-configurations",
    SmtpConfiguration,
    "Created or authoritatively replayed pending SMTP generation",
    body = CreateSmtpConfigurationRequest,
    params(
        ("project_id" = String, Path),
        ("Idempotency-Key" = String, Header)
    )
);
control_path!(
    get_smtp_test_operation,
    get,
    "/v1/projects/{project_id}/smtp-configurations/{smtp_id}/tests/{operation_id}",
    SmtpTestOperation,
    "SMTP test operation status",
    params(
        ("project_id" = String, Path),
        ("smtp_id" = String, Path),
        ("operation_id" = String, Path)
    )
);
control_path!(
    activate_smtp_configuration,
    post,
    "/v1/projects/{project_id}/smtp-configurations/{smtp_id}/activate",
    SmtpConfiguration,
    "Activated SMTP generation",
    body = SmtpRevisionRequest,
    params(("project_id" = String, Path), ("smtp_id" = String, Path))
);
control_path!(
    disable_smtp_configuration,
    post,
    "/v1/projects/{project_id}/smtp-configurations/{smtp_id}/disable",
    SmtpConfiguration,
    "Disabled SMTP generation",
    body = SmtpRevisionRequest,
    params(("project_id" = String, Path), ("smtp_id" = String, Path))
);
control_path!(
    compromise_smtp_configuration,
    post,
    "/v1/projects/{project_id}/smtp-configurations/{smtp_id}/compromise",
    SmtpConfiguration,
    "Marked SMTP generation compromised",
    body = SmtpRevisionRequest,
    params(("project_id" = String, Path), ("smtp_id" = String, Path))
);

control_path!(
    list_project_users,
    get,
    "/v1/projects/{project_id}/users",
    ProjectUserList,
    "Project users",
    params(
        ("project_id" = String, Path),
        ("status" = Option<ProjectUserStatus>, Query),
        ("search" = Option<String>, Query, min_length = 1, max_length = 128),
        ("identity_kind" = Option<ProjectUserIdentityFilter>, Query),
        ("provider_key" = Option<String>, Query, min_length = 1, max_length = 64),
        ("sort" = Option<ProjectUserSort>, Query),
        ("cursor" = Option<String>, Query, max_length = 36, description = "Cursor returned by a previous page with the same status, search, identity, provider, and sort criteria"),
        ("limit" = Option<usize>, Query, minimum = 1, maximum = 100)
    )
);
control_path!(
    lookup_project_user_by_email,
    post,
    "/v1/projects/{project_id}/users/lookup",
    ProjectUserLookup,
    "Exact canonical email Project user lookup",
    body = ProjectUserEmailLookupRequest,
    params(("project_id" = String, Path))
);
control_path!(
    get_project_user,
    get,
    "/v1/projects/{project_id}/users/{user_id}",
    ProjectUser,
    "Project user",
    params(("project_id" = String, Path), ("user_id" = String, Path))
);
control_path!(
    list_project_user_identities,
    get,
    "/v1/projects/{project_id}/users/{user_id}/identities",
    ProjectUserIdentityList,
    "Bounded safe mixed provider and email identity inventory",
    params(("project_id" = String, Path), ("user_id" = String, Path))
);
control_path!(
    disable_project_user,
    post,
    "/v1/projects/{project_id}/users/{user_id}/disable",
    ProjectUser,
    "Disabled Project user",
    body = ExpectedSecurityRevision,
    params(("project_id" = String, Path), ("user_id" = String, Path))
);
control_path!(
    enable_project_user,
    post,
    "/v1/projects/{project_id}/users/{user_id}/enable",
    ProjectUser,
    "Enabled Project user",
    body = ExpectedSecurityRevision,
    params(("project_id" = String, Path), ("user_id" = String, Path))
);
control_path!(
    list_project_user_sessions,
    get,
    "/v1/projects/{project_id}/users/{user_id}/sessions",
    ProjectUserSessions,
    "Project user sessions",
    params(("project_id" = String, Path), ("user_id" = String, Path))
);
control_path!(
    revoke_application_session,
    post,
    "/v1/projects/{project_id}/users/{user_id}/application-sessions/{session_id}/revoke",
    ApplicationSession,
    "Revoked Application session",
    body = ExpectedSessionRevision,
    params(
        ("project_id" = String, Path),
        ("user_id" = String, Path),
        ("session_id" = String, Path)
    )
);
control_path!(
    revoke_browser_session,
    post,
    "/v1/projects/{project_id}/users/{user_id}/browser-sessions/{session_id}/revoke",
    BrowserSession,
    "Revoked Project browser session",
    body = ExpectedSessionRevision,
    params(
        ("project_id" = String, Path),
        ("user_id" = String, Path),
        ("session_id" = String, Path)
    )
);

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{
        CreateIdentityMutationIntentRequest, IdentityMutationProofAuthority,
        NamedProviderPreflightRequest, OidcPreflightRequest,
    };

    #[test]
    fn provider_preflight_requests_reject_secret_and_callback_authority() {
        assert!(
            serde_json::from_value::<OidcPreflightRequest>(json!({
                "provider_key": "custom-main",
                "issuer": "https://identity.example",
            }))
            .is_ok()
        );
        for forbidden in ["client_secret", "callback_url", "project_public_id"] {
            let mut request = json!({
                "provider_key": "custom-main",
                "issuer": "https://identity.example",
            });
            request[forbidden] = json!("caller-owned");
            assert!(serde_json::from_value::<OidcPreflightRequest>(request).is_err());
        }
        for forbidden in ["client_secret", "callback_url", "issuer"] {
            let mut request = json!({
                "kind": "google",
                "provider_key": "google-main",
            });
            request[forbidden] = json!("caller-owned");
            assert!(serde_json::from_value::<NamedProviderPreflightRequest>(request).is_err());
        }
    }

    #[test]
    fn user_and_session_lifecycle_contract_is_bounded_and_control_only() {
        let document = serde_json::to_value(crate::control::openapi())
            .expect("Control OpenAPI should serialize");
        for path in [
            "/v1/projects/{project_id}/users",
            "/v1/projects/{project_id}/users/{user_id}",
            "/v1/projects/{project_id}/users/{user_id}/disable",
            "/v1/projects/{project_id}/users/{user_id}/sessions",
            "/v1/projects/{project_id}/users/{user_id}/application-sessions/{session_id}/revoke",
            "/v1/projects/{project_id}/users/{user_id}/browser-sessions/{session_id}/revoke",
        ] {
            assert!(document["paths"][path].is_object(), "missing path: {path}");
        }
        let user = &document["components"]["schemas"]["ProjectUser"]["properties"];
        assert!(user.get("provider_credentials").is_none());
        assert!(user.get("source_payload").is_none());
        assert_eq!(
            document["components"]["schemas"]["ProjectUserList"]["properties"]["items"]["maxItems"],
            100
        );
    }

    #[test]
    fn identity_mutation_control_contract_is_typed_and_safe() {
        let document = serde_json::to_value(crate::control::openapi())
            .expect("Control OpenAPI should serialize");
        let collection = "/v1/projects/{project_id}/identity-mutation-intents";
        for path in [
            collection,
            "/v1/projects/{project_id}/identity-mutation-intents/{intent_id}",
            "/v1/projects/{project_id}/identity-mutation-intents/{intent_id}/cancel",
            "/v1/projects/{project_id}/identity-mutation-intents/{intent_id}/confirm",
        ] {
            assert!(document["paths"][path].is_object(), "missing path: {path}");
        }
        assert!(
            document["paths"][collection]["post"]["parameters"]
                .as_array()
                .expect("create parameters")
                .iter()
                .any(|parameter| parameter["name"] == "Idempotency-Key")
        );

        let intent = &document["components"]["schemas"]["IdentityMutationIntent"];
        assert_eq!(intent["properties"]["slots"]["maxItems"], 2);
        for forbidden in [
            "raw_state",
            "receipt",
            "evidence",
            "subject",
            "email",
            "address",
            "provider_secret",
        ] {
            assert!(intent["properties"].get(forbidden).is_none());
        }
        let create_schema =
            &document["components"]["schemas"]["CreateIdentityMutationIntentRequest"];
        let variants = create_schema["oneOf"]
            .as_array()
            .expect("typed create variants");
        assert_eq!(variants.len(), 3);
        assert!(
            document["paths"]["/v1/projects/{project_id}/identity-mutation-intents"]
                ["post"]["responses"]
                .get("201")
                .is_some()
        );
        assert!(
            document["paths"]["/v1/projects/{project_id}/identity-mutation-intents"]
                ["post"]["responses"]
                .get("200")
                .is_some()
        );
        assert!(
            variants
                .iter()
                .all(|variant| variant["properties"].get("slots").is_none())
        );
    }

    #[test]
    fn identity_mutation_commands_reject_caller_derived_authority() {
        let link = json!({
            "operation_kind": "link",
            "destination": {
                "user_id": "user-1",
                "expected_user_revision": 3,
                "expected_user_security_revision": 4
            },
            "destination_identity": {
                "identity_kind": "provider",
                "identity_id": "identity-1",
                "expected_identity_revision": 5
            },
            "candidate_identity_kind": "email",
            "destination_proof_authority": {
                "method_kind": "provider",
                "application_id": "application-1",
                "provider_id": "provider-1"
            },
            "candidate_proof_authority": {
                "method_kind": "email",
                "application_id": "application-1"
            },
            "slots": []
        });
        assert!(serde_json::from_value::<CreateIdentityMutationIntentRequest>(link).is_err());

        let authority = json!({
            "method_kind": "provider",
            "application_id": "application-1",
            "provider_id": "provider-1",
            "scopes": ["openid"],
            "callback": "https://attacker.example/callback"
        });
        assert!(serde_json::from_value::<IdentityMutationProofAuthority>(authority).is_err());
    }
}

control_path!(
    list_managed_provider_connections,
    get,
    "/v1/projects/{project_id}/users/{user_id}/managed-provider-connections",
    ManagedProviderConnectionList,
    "Safe managed provider connection metadata",
    params(("project_id" = String, Path), ("user_id" = String, Path))
);
control_path!(
    synchronize_managed_provider_connection,
    post,
    "/v1/projects/{project_id}/users/{user_id}/managed-provider-connections/{connection_id}/synchronize",
    ManagedProviderConnection,
    "Scheduled guarded profile synchronization",
    body = ManagedProviderConnectionActionRequest,
    params(
        ("project_id" = String, Path),
        ("user_id" = String, Path),
        ("connection_id" = String, Path)
    )
);
#[utoipa::path(
    post,
    path = "/v1/projects/{project_id}/users/{user_id}/managed-provider-connections/{connection_id}/reauthorizations",
    request_body = CreateManagedReauthorizationRequest,
    responses(
        (status = 201, description = "Created one exact managed reauthorization interaction", body = CreateManagedReauthorizationResponse, headers(("Location" = String, description = "Exact Control path for the created managed reauthorization"))),
        (status = 200, description = "Authoritative idempotent replay of the managed reauthorization", body = CreateManagedReauthorizationResponse),
        (status = 400, description = "Invalid request", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "Missing or invalid operator API key", body = ProblemDetails, content_type = "application/problem+json", headers(("WWW-Authenticate" = String, description = "Bearer authentication challenge"))),
        (status = 404, description = "Resource not found", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "Revision, state, idempotency, or capacity conflict", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 500, description = "Stored authority data violated an invariant", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "Required authority unavailable", body = ProblemDetails, content_type = "application/problem+json")
    ),
    params(
        ("project_id" = String, Path),
        ("user_id" = String, Path),
        ("connection_id" = String, Path),
        ("Idempotency-Key" = String, Header)
    ),
    security(("operator_api_key" = []))
)]
#[doc(hidden)]
pub fn create_managed_reauthorization() {}
control_path!(
    get_managed_reauthorization,
    get,
    "/v1/projects/{project_id}/users/{user_id}/managed-provider-connections/{connection_id}/reauthorizations/{interaction_id}",
    ManagedReauthorization,
    "Read bounded managed reauthorization status without Hosted target",
    params(
        ("project_id" = String, Path),
        ("user_id" = String, Path),
        ("connection_id" = String, Path),
        ("interaction_id" = String, Path)
    )
);
control_path!(
    cancel_managed_reauthorization,
    post,
    "/v1/projects/{project_id}/users/{user_id}/managed-provider-connections/{connection_id}/reauthorizations/{interaction_id}/cancel",
    ManagedReauthorization,
    "Cancelled one current managed reauthorization interaction",
    body = CancelManagedReauthorizationRequest,
    params(
        ("project_id" = String, Path),
        ("user_id" = String, Path),
        ("connection_id" = String, Path),
        ("interaction_id" = String, Path)
    )
);
control_path!(
    revoke_managed_provider_connection,
    post,
    "/v1/projects/{project_id}/users/{user_id}/managed-provider-connections/{connection_id}/revoke",
    ManagedProviderConnection,
    "Provider revocation when the adapter can prove it",
    body = ManagedProviderConnectionActionRequest,
    params(
        ("project_id" = String, Path),
        ("user_id" = String, Path),
        ("connection_id" = String, Path)
    )
);
control_path!(
    disconnect_managed_provider_connection,
    post,
    "/v1/projects/{project_id}/users/{user_id}/managed-provider-connections/{connection_id}/disconnect",
    ManagedProviderConnection,
    "Locally disconnected and destroyed renewable credential",
    body = ManagedProviderConnectionActionRequest,
    params(
        ("project_id" = String, Path),
        ("user_id" = String, Path),
        ("connection_id" = String, Path)
    )
);

#[utoipa::path(
    post,
    path = "/v1/projects/{project_id}/identity-mutation-intents",
    request_body = CreateIdentityMutationIntentRequest,
    responses(
        (status = 201, description = "Created one typed identity mutation intent", body = CreateIdentityMutationIntentResponse, headers(("Location" = String, description = "Exact Control path for the created identity mutation intent"))),
        (status = 200, description = "Authoritative idempotent replay of the identity mutation intent", body = CreateIdentityMutationIntentResponse),
        (status = 400, description = "Invalid request", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "Missing or invalid operator API key", body = ProblemDetails, content_type = "application/problem+json", headers(("WWW-Authenticate" = String, description = "Bearer authentication challenge"))),
        (status = 404, description = "Resource not found", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "Revision, state, idempotency, or capacity conflict", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 500, description = "Stored authority data violated an invariant", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "Required authority unavailable", body = ProblemDetails, content_type = "application/problem+json")
    ),
    params(
        ("project_id" = String, Path),
        ("Idempotency-Key" = String, Header)
    ),
    security(("operator_api_key" = []))
)]
#[doc(hidden)]
pub fn create_identity_mutation_intent() {}
control_path!(
    get_identity_mutation_intent,
    get,
    "/v1/projects/{project_id}/identity-mutation-intents/{intent_id}",
    IdentityMutationIntent,
    "Read safe identity mutation intent readiness",
    params(("project_id" = String, Path), ("intent_id" = String, Path))
);
control_path!(
    cancel_identity_mutation_intent,
    post,
    "/v1/projects/{project_id}/identity-mutation-intents/{intent_id}/cancel",
    IdentityMutationIntent,
    "Cancelled one current identity mutation intent",
    body = CancelIdentityMutationIntentRequest,
    params(("project_id" = String, Path), ("intent_id" = String, Path))
);
control_path!(
    confirm_identity_mutation_intent,
    post,
    "/v1/projects/{project_id}/identity-mutation-intents/{intent_id}/confirm",
    IdentityMutationIntent,
    "Confirmed one ready identity mutation intent",
    body = ConfirmIdentityMutationIntentRequest,
    params(("project_id" = String, Path), ("intent_id" = String, Path))
);

#[cfg(test)]
mod project_server_key_contract_tests {
    use super::*;

    fn metadata() -> ProjectServerKey {
        ProjectServerKey {
            id: "00000000-0000-0000-0000-000000000001".to_owned(),
            project_id: "00000000-0000-0000-0000-000000000002".to_owned(),
            public_key_id: "AAAAAAAAAAAAAAAAAAAAAA".to_owned(),
            label: "production backend".to_owned(),
            status: ProjectServerKeyStatus::Active,
            digest_key_version: 1,
            display_prefix: "owl_server_v1.AAAAAAAAAAAAAAAAAAAAAA".to_owned(),
            revision: 1,
            created_at: "2026-08-05T00:00:00Z".to_owned(),
            credential_acknowledged_at: None,
            last_used_at: None,
            revoked_at: None,
        }
    }

    #[test]
    fn one_time_credential_is_redacted_from_debug() {
        let response = CreateProjectServerKeyResponse {
            key: metadata(),
            credential: format!("owl_server_v1.AAAAAAAAAAAAAAAAAAAAAA.{}", "B".repeat(43)),
        };
        let debug = format!("{response:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains(&"B".repeat(43)));
    }

    #[test]
    fn acknowledgement_status_is_explicit_and_required_in_inventory() {
        let mut encoded = serde_json::to_value(metadata()).expect("server-key metadata");
        encoded
            .as_object_mut()
            .expect("server-key metadata object")
            .remove("credential_acknowledged_at");
        assert!(serde_json::from_value::<ProjectServerKey>(encoded).is_err());

        assert!(
            serde_json::from_value::<ProjectServerKeyList>(serde_json::json!({
                "items": [],
                "next_cursor": null
            }))
            .is_err()
        );
        assert!(
            serde_json::from_value::<ProjectServerKeyList>(serde_json::json!({
                "items": [],
                "next_cursor": null,
                "active_unacknowledged_key": null
            }))
            .is_ok()
        );
    }

    #[test]
    fn lifecycle_commands_reject_unknown_authority_fields() {
        assert!(
            serde_json::from_value::<CreateProjectServerKeyRequest>(serde_json::json!({
                "label": "backend",
                "scopes": ["users:read"]
            }))
            .is_err()
        );
        assert!(
            serde_json::from_value::<RevokeProjectServerKeyRequest>(serde_json::json!({
                "expected_revision": 1,
                "confirm": true,
                "enable": false
            }))
            .is_err()
        );
        assert!(
            serde_json::from_value::<AcknowledgeProjectServerKeyDeliveryRequest>(
                serde_json::json!({
                    "expected_revision": 1,
                    "confirm_stored": true,
                    "credential": "must-never-be-accepted"
                })
            )
            .is_err()
        );
    }
}
