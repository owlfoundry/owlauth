use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

pub use crate::runtime::{IdentityKind, IdentityMutationMethodKind};
use crate::runtime::{ProviderKind, PublicJwk, SigningAlgorithm};

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
pub struct CreateProjectRequest {
    #[schema(min_length = 1, max_length = 128)]
    pub display_name: String,
    #[schema(max_length = 256)]
    pub belongs_to: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
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
pub struct CreateApplicationRequest {
    #[schema(min_length = 1, max_length = 128)]
    pub display_name: String,
    pub application_type: ApplicationType,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
pub struct UpdateApplicationRequest {
    #[schema(min_length = 1, max_length = 128)]
    pub display_name: String,
    #[schema(minimum = 1)]
    pub expected_metadata_revision: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
pub struct ReplaceApplicationConfigurationRequest {
    #[schema(max_items = 50)]
    pub redirect_uris: Vec<String>,
    #[schema(max_items = 50)]
    pub allowed_origins: Vec<String>,
    #[schema(minimum = 1)]
    pub expected_security_revision: i64,
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

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
pub struct CreateSigningKeyRequest {
    #[schema(minimum = 1)]
    pub expected_project_revision: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
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
    pub managed_profile: ProviderManagedProfileCapability,
    #[schema(max_items = 100)]
    pub assigned_application_ids: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
pub struct ProviderList {
    #[schema(max_items = 100)]
    pub items: Vec<Provider>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
pub struct CreateProviderRequest {
    #[schema(min_length = 1, max_length = 64)]
    pub provider_key: String,
    #[schema(min_length = 1, max_length = 128)]
    pub display_name: String,
    #[schema(min_length = 8, max_length = 2048)]
    pub issuer: String,
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
pub struct ReconcileSigningKeyRequest {
    #[schema(minimum = 1)]
    pub expected_project_revision: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
pub struct ReconcileProviderRequest {
    #[schema(write_only, min_length = 1, max_length = 4096)]
    pub client_secret: String,
    #[schema(minimum = 1)]
    pub expected_project_revision: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
pub struct ProviderRevisionRequest {
    #[schema(minimum = 1)]
    pub expected_provider_revision: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
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
    pub safe_fingerprint: String,
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
                (status = 400, description = "Invalid request", body = ProblemDetails),
                (status = 401, description = "Missing or invalid operator API key", body = ProblemDetails),
                (status = 404, description = "Resource not found", body = ProblemDetails),
                (status = 409, description = "Revision, state, or idempotency conflict", body = ProblemDetails),
                (status = 500, description = "Stored authority data violated an invariant", body = ProblemDetails),
                (status = 503, description = "Required authority unavailable", body = ProblemDetails)
            ),
            $(params($($params)*),)?
            security(("operator_api_key" = []))
        )]
        #[doc(hidden)]
        pub fn $name() {}
    };
}

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
    "Created project",
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
    "Created application",
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
    list_signing_keys,
    get,
    "/v1/projects/{project_id}/signing-keys",
    SigningKeyList,
    "Signing keys",
    params(("project_id" = String, Path))
);
control_path!(
    create_signing_key,
    post,
    "/v1/projects/{project_id}/signing-keys",
    SigningKey,
    "Provisioned and published signing key",
    body = CreateSigningKeyRequest,
    params(
        ("project_id" = String, Path),
        ("Idempotency-Key" = String, Header)
    )
);
control_path!(
    reconcile_signing_key,
    post,
    "/v1/projects/{project_id}/signing-keys/{key_id}/reconcile",
    SigningKey,
    "Reconciled signing key provisioning",
    body = ReconcileSigningKeyRequest,
    params(("project_id" = String, Path), ("key_id" = String, Path))
);
control_path!(
    activate_signing_key,
    post,
    "/v1/projects/{project_id}/signing-keys/{key_id}/activate",
    SigningKey,
    "Activated signing key",
    body = KeyTransitionRequest,
    params(("project_id" = String, Path), ("key_id" = String, Path))
);
control_path!(
    retire_signing_key,
    post,
    "/v1/projects/{project_id}/signing-keys/{key_id}/retire",
    SigningKey,
    "Retired signing key",
    body = KeyTransitionRequest,
    params(("project_id" = String, Path), ("key_id" = String, Path))
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
    "Configured provider",
    body = CreateProviderRequest,
    params(
        ("project_id" = String, Path),
        ("Idempotency-Key" = String, Header)
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
    delete,
    "/v1/projects/{project_id}/providers/{provider_id}/assignments/{application_id}",
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
    "Created pending SMTP generation",
    body = CreateSmtpConfigurationRequest,
    params(
        ("project_id" = String, Path),
        ("Idempotency-Key" = String, Header)
    )
);
control_path!(
    test_smtp_configuration,
    post,
    "/v1/projects/{project_id}/smtp-configurations/{smtp_id}/test",
    SmtpTestOperation,
    "Enqueued bounded SMTP test",
    body = TestSmtpConfigurationRequest,
    params(
        ("project_id" = String, Path),
        ("smtp_id" = String, Path),
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

    use super::{CreateIdentityMutationIntentRequest, IdentityMutationProofAuthority};

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
                .is_none()
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
control_path!(
    create_managed_reauthorization,
    post,
    "/v1/projects/{project_id}/users/{user_id}/managed-provider-connections/{connection_id}/reauthorizations",
    CreateManagedReauthorizationResponse,
    "Created one exact managed reauthorization interaction",
    body = CreateManagedReauthorizationRequest,
    params(
        ("project_id" = String, Path),
        ("user_id" = String, Path),
        ("connection_id" = String, Path),
        ("Idempotency-Key" = String, Header)
    )
);
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
        (status = 201, description = "Created one typed identity mutation intent", body = CreateIdentityMutationIntentResponse),
        (status = 400, description = "Invalid request", body = ProblemDetails),
        (status = 401, description = "Missing or invalid operator API key", body = ProblemDetails),
        (status = 404, description = "Resource not found", body = ProblemDetails),
        (status = 409, description = "Revision, state, or idempotency conflict", body = ProblemDetails),
        (status = 500, description = "Stored authority data violated an invariant", body = ProblemDetails),
        (status = 503, description = "Required authority unavailable", body = ProblemDetails)
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
