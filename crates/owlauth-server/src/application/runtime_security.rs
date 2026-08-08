use std::collections::BTreeSet;

use async_trait::async_trait;
use serde_json::Value;
use time::OffsetDateTime;
use uuid::Uuid;
use zeroize::Zeroizing;

use super::{ApplicationError, ProtectedValue, VersionedDigest};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OpaquePurpose {
    Interaction,
    BrowserBinding,
    InteractionCsrf,
    UpstreamState,
    OidcNonce,
    HandoffTicket,
    BrowserSession,
    RefreshToken,
    BrowserLogout,
    EmailIdentityLookup,
    EmailOtpProof,
    EmailMagicProof,
    EmailMagicTransferContext,
    EmailMagicTransferCsrf,
    ManagedReauthorization,
    ManagedReauthorizationBrowser,
    ManagedReauthorizationCsrf,
    ManagedReauthorizationState,
    ManagedReauthorizationNonce,
    IdentityMutationIntent,
    IdentityMutationBrowser,
    IdentityMutationCsrf,
    IdentityMutationMagicTransferContext,
    IdentityMutationMagicTransferCsrf,
    IdentityMutationProviderState,
    IdentityMutationNonce,
    IdentityMutationCandidateEvidenceDigest,
    IdentityMutationReceipt,
}

impl OpaquePurpose {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Interaction => "interaction",
            Self::BrowserBinding => "browser_binding",
            Self::InteractionCsrf => "interaction_csrf",
            Self::UpstreamState => "upstream_state",
            Self::OidcNonce => "oidc_nonce",
            Self::HandoffTicket => "handoff_ticket",
            Self::BrowserSession => "browser_session",
            Self::RefreshToken => "refresh_token",
            Self::BrowserLogout => "browser_logout",
            Self::EmailIdentityLookup => "email_identity_lookup_v1",
            Self::EmailOtpProof => "email_otp_proof_v1",
            Self::EmailMagicProof => "email_magic_proof_v1",
            Self::EmailMagicTransferContext => "email_magic_transfer_context_v1",
            Self::EmailMagicTransferCsrf => "email_magic_transfer_csrf_v1",
            Self::ManagedReauthorization => "managed_reauthorization",
            Self::ManagedReauthorizationBrowser => "managed_reauthorization_browser",
            Self::ManagedReauthorizationCsrf => "managed_reauthorization_csrf",
            Self::ManagedReauthorizationState => "managed_reauthorization_state",
            Self::ManagedReauthorizationNonce => "managed_reauthorization_nonce",
            Self::IdentityMutationIntent => "identity_mutation_intent_v1",
            Self::IdentityMutationBrowser => "identity_mutation_browser_v1",
            Self::IdentityMutationCsrf => "identity_mutation_csrf_v1",
            Self::IdentityMutationMagicTransferContext => {
                "identity_mutation_magic_transfer_context_v1"
            }
            Self::IdentityMutationMagicTransferCsrf => "identity_mutation_magic_transfer_csrf_v1",
            Self::IdentityMutationProviderState => "identity_mutation_provider_state_v1",
            Self::IdentityMutationNonce => "identity_mutation_nonce_v1",
            Self::IdentityMutationCandidateEvidenceDigest => {
                "identity_mutation_candidate_evidence_digest_v1"
            }
            Self::IdentityMutationReceipt => "identity_mutation_receipt_v1",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProtectedPurpose {
    ApplicationState,
    ProviderPkce,
    EmailChallengeAddress,
    EmailOutboxEnvelope,
    EmailOutboxBody,
    EmailIdentityAddress,
    ManagedProviderCredential,
    ManagedReauthorizationPkce,
    ManagedReauthorizationCreateResult,
    IdentityMutationProviderPkce,
    IdentityMutationCallbackContinuation,
    IdentityMutationCandidateEvidence,
    IdentityMutationCreateResult,
}

impl ProtectedPurpose {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::ApplicationState => "application_state",
            Self::ProviderPkce => "provider_pkce",
            Self::EmailChallengeAddress => "email_challenge_address_v1",
            Self::EmailOutboxEnvelope => "email_outbox_envelope_v1",
            Self::EmailOutboxBody => "email_outbox_body_v1",
            Self::EmailIdentityAddress => "email_identity_address_v1",
            Self::ManagedProviderCredential => "managed_provider_credential",
            Self::ManagedReauthorizationPkce => "managed_reauthorization_pkce",
            Self::ManagedReauthorizationCreateResult => "managed_reauthorization_create_result",
            Self::IdentityMutationProviderPkce => "identity_mutation_provider_pkce_v1",
            Self::IdentityMutationCallbackContinuation => {
                "identity_mutation_callback_continuation_v1"
            }
            Self::IdentityMutationCandidateEvidence => "identity_mutation_candidate_evidence_v1",
            Self::IdentityMutationCreateResult => "identity_mutation_create_result_v1",
        }
    }
}

/// Decrypt-only capability for one exact durable email identity. Callers cannot choose a purpose,
/// associated data, lookup digest, or encryption operation.
pub(crate) trait DurableEmailAddressReader: Send + Sync {
    fn read_durable_address(
        &self,
        project_id: uuid::Uuid,
        identity_id: uuid::Uuid,
        value: &ProtectedValue,
    ) -> Result<Zeroizing<String>, ApplicationError>;
}

/// Purpose- and context-limited protection for Application projection verified email. This ring is
/// physically distinct from generic Runtime and durable email-identity roots.
pub(crate) trait ProjectionVerifiedEmailProtector: Send + Sync {
    fn write_version(&self) -> i32;
    fn readable_versions(&self) -> BTreeSet<i32>;
    fn protect_verified_email(
        &self,
        project_id: uuid::Uuid,
        application_id: uuid::Uuid,
        user_id: uuid::Uuid,
        projection_revision: i64,
        email: &[u8],
    ) -> Result<ProtectedValue, ApplicationError>;
    fn unprotect_verified_email(
        &self,
        project_id: uuid::Uuid,
        application_id: uuid::Uuid,
        user_id: uuid::Uuid,
        projection_revision: i64,
        value: &ProtectedValue,
    ) -> Result<Zeroizing<String>, ApplicationError>;
}

pub(crate) trait RuntimeProtector: Send + Sync {
    /// Active key version for short-lived transactions, challenges, sessions, and outbox data.
    fn active_version(&self) -> i32;

    /// Independently retained active version for durable email identity lookup and PII.
    fn email_identity_active_version(&self) -> i32 {
        self.active_version()
    }

    /// Immutable process-local key inventory for short-lived Runtime material.
    fn readable_key_versions(&self) -> BTreeSet<i32>;

    /// Immutable process-local key inventory for durable email lookup aliases and ciphertext.
    fn email_identity_readable_key_versions(&self) -> BTreeSet<i32> {
        self.readable_key_versions()
    }

    fn random_opaque(&self, bytes: usize) -> Result<Zeroizing<String>, ApplicationError>;

    fn digest(
        &self,
        purpose: OpaquePurpose,
        context: &[u8],
        value: &[u8],
    ) -> Result<VersionedDigest, ApplicationError>;

    fn digest_at(
        &self,
        purpose: OpaquePurpose,
        context: &[u8],
        value: &[u8],
        key_version: i32,
    ) -> Result<VersionedDigest, ApplicationError>;

    fn derive_opaque(
        &self,
        purpose: OpaquePurpose,
        context: &[u8],
        key_version: Option<i32>,
    ) -> Result<Zeroizing<String>, ApplicationError>;

    fn protect(
        &self,
        purpose: ProtectedPurpose,
        context: &[u8],
        value: &[u8],
    ) -> Result<ProtectedValue, ApplicationError>;

    fn unprotect(
        &self,
        purpose: ProtectedPurpose,
        context: &[u8],
        value: &ProtectedValue,
    ) -> Result<Zeroizing<Vec<u8>>, ApplicationError>;
}

#[async_trait]
pub(crate) trait RuntimeSigner: Send + Sync {
    async fn sign(
        &self,
        signing_material_id: Uuid,
        signing_input: &[u8],
    ) -> Result<Vec<u8>, ApplicationError>;

    fn verify(
        &self,
        public_jwk: &Value,
        signing_input: &[u8],
        signature: &[u8],
    ) -> Result<(), ApplicationError>;
}

#[async_trait]
pub(crate) trait ProviderSecretResolver: Send + Sync {
    async fn resolve(
        &self,
        secret_material_id: Uuid,
    ) -> Result<Zeroizing<String>, ApplicationError>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProviderRequestProfile {
    Login,
    ManagedProfile,
    IdentityProof,
}

impl ProviderRequestProfile {
    pub(crate) const fn is_managed_profile(self) -> bool {
        matches!(self, Self::ManagedProfile)
    }
}

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct ProviderAuthorizationRequest {
    pub kind: crate::domain::ProviderKind,
    pub issuer: String,
    pub client_id: String,
    pub callback_url: String,
    pub state: String,
    pub nonce: String,
    pub pkce_challenge: String,
    pub profile: ProviderRequestProfile,
    pub egress_policy: Option<crate::domain::ProviderEgressPolicy>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ProviderAuthorization {
    pub url: String,
    pub managed_supports_revocation: Option<bool>,
}

pub(crate) struct ProviderCallbackRequest {
    pub kind: crate::domain::ProviderKind,
    pub issuer: String,
    pub client_id: String,
    pub client_secret: Zeroizing<String>,
    pub callback_url: String,
    pub code: Zeroizing<String>,
    pub pkce_verifier: Zeroizing<String>,
    pub expected_nonce: Zeroizing<String>,
    pub now: OffsetDateTime,
    pub allowed_clock_skew_seconds: i64,
    pub profile: ProviderRequestProfile,
    pub egress_policy: Option<crate::domain::ProviderEgressPolicy>,
}

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct RenewableProviderCredential {
    pub value: Zeroizing<Vec<u8>>,
    pub granted_scopes: Vec<String>,
    pub supports_revocation: bool,
}

impl std::fmt::Debug for RenewableProviderCredential {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RenewableProviderCredential")
            .field("value", &"[REDACTED]")
            .field("granted_scope_count", &self.granted_scopes.len())
            .field("supports_revocation", &self.supports_revocation)
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ProviderIdentity {
    pub issuer: String,
    pub subject: String,
    pub display_name: Option<String>,
    pub picture_url: Option<String>,
    pub renewable_credential: Option<RenewableProviderCredential>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProviderExchangeError {
    Rejected,
    InvalidProof,
    UnavailableBeforeDispatch,
    AmbiguousAfterDispatch,
}

#[async_trait]
pub(crate) trait UpstreamProviderClient: Send + Sync {
    fn issuer_allowed(&self, kind: crate::domain::ProviderKind, issuer: &str) -> bool;

    async fn authorization_url(
        &self,
        request: ProviderAuthorizationRequest,
    ) -> Result<ProviderAuthorization, ProviderExchangeError>;

    async fn exchange_code(
        &self,
        request: ProviderCallbackRequest,
    ) -> Result<ProviderIdentity, ProviderExchangeError>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LoginStartContext {
    pub project_id: Uuid,
    pub project_public_id: String,
    pub project_display_name: String,
    pub project_metadata_revision: i64,
    pub project_security_revision: i64,
    pub application_id: Uuid,
    pub application_public_id: String,
    pub application_display_name: String,
    pub application_security_revision: i64,
    pub claims_revision: i64,
    pub session_revision: i64,
    pub admitted_providers: Vec<super::AdmittedProviderMethod>,
    pub admitted_email: Option<super::AdmittedEmailMethod>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct HostedProviderMethod {
    pub key: String,
    pub display_name: String,
    pub kind: crate::domain::ProviderKind,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct HostedPendingEmailChallenge {
    pub challenge_id: Uuid,
    pub generation: i16,
    pub otp_available: bool,
    pub magic_link_available: bool,
    pub expires_at: OffsetDateTime,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct HostedInteraction {
    pub transaction_id: Uuid,
    pub project_id: Uuid,
    pub project_public_id: String,
    pub project_display_name: String,
    pub application_id: Uuid,
    pub application_public_id: String,
    pub application_display_name: String,
    pub application_type: crate::domain::ApplicationType,
    pub status: crate::domain::LoginTransactionStatus,
    pub transaction_revision: i64,
    pub csrf_key_version: Option<i32>,
    pub presentation_hint: Option<String>,
    pub providers: Vec<HostedProviderMethod>,
    pub email_available: bool,
    pub email_otp_enabled: bool,
    pub email_magic_link_enabled: bool,
    pub pending_email_challenge: Option<HostedPendingEmailChallenge>,
    pub expires_at: OffsetDateTime,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ProviderRuntimeContext {
    pub project_id: Uuid,
    pub provider_kind: crate::domain::ProviderKind,
    pub transaction_id: Uuid,
    pub provider_id: Uuid,
    pub provider_key: String,
    pub issuer: String,
    pub client_id: String,
    pub callback_url: String,
    pub secret_material_id: Uuid,
    pub managed_profile_enabled: bool,
    pub managed_profile_revision: i64,
    pub egress_policy: Option<crate::domain::ProviderEgressPolicy>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AccessTokenSessionLookup {
    pub project_id: Uuid,
    pub application_public_id: String,
    pub user_public_id: String,
    pub application_session_id: Uuid,
    pub claims_revision: i64,
    pub now: OffsetDateTime,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct CurrentSession {
    pub project_id: Uuid,
    pub project_public_id: String,
    pub application_id: Uuid,
    pub application_public_id: String,
    pub user_id: Uuid,
    pub user_public_id: String,
    pub application_session_id: Uuid,
    pub browser_session_id: Uuid,
    pub claims_revision: i64,
    pub projection_revision: i64,
    pub projection_document: Value,
    pub authenticated_at: OffsetDateTime,
    pub absolute_expires_at: OffsetDateTime,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct VerificationKey {
    pub project_id: Uuid,
    pub project_public_id: String,
    pub issuer: String,
    pub public_jwk: Value,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct BrowserLogoutContext {
    pub project_id: Uuid,
    pub project_public_id: String,
    pub interaction_revision: i64,
    pub expires_at: OffsetDateTime,
}

#[async_trait]
pub(crate) trait RuntimeAuthorityRepository: Send + Sync {
    async fn prepare_login_start(
        &self,
        project_public_id: &str,
        application_public_id: &str,
        publishable_key: &str,
        redirect_uri: &str,
    ) -> Result<LoginStartContext, ApplicationError>;

    async fn hosted_interaction(
        &self,
        interaction: &VersionedDigest,
        browser_binding: Option<&VersionedDigest>,
        now: OffsetDateTime,
    ) -> Result<HostedInteraction, ApplicationError>;

    async fn provider_runtime_context(
        &self,
        project_id: Uuid,
        transaction_id: Uuid,
        provider_key: &str,
    ) -> Result<ProviderRuntimeContext, ApplicationError>;

    async fn resolve_application(
        &self,
        project_public_id: &str,
        application_public_id: &str,
        publishable_key: &str,
    ) -> Result<(Uuid, Uuid), ApplicationError>;

    async fn resolve_public_application(
        &self,
        project_public_id: &str,
        application_public_id: &str,
    ) -> Result<(Uuid, Uuid), ApplicationError>;

    async fn exact_application_origin(
        &self,
        project_id: Uuid,
        application_id: Uuid,
        origin: &str,
    ) -> Result<bool, ApplicationError>;

    async fn project_origin_allowed(
        &self,
        project_public_id: &str,
        origin: &str,
    ) -> Result<bool, ApplicationError>;

    async fn browser_session_reuse_available(
        &self,
        project_id: Uuid,
        browser_credential: &VersionedDigest,
        now: OffsetDateTime,
    ) -> Result<bool, ApplicationError>;

    async fn verification_key(
        &self,
        project_public_id: &str,
        kid: &str,
        now: OffsetDateTime,
    ) -> Result<VerificationKey, ApplicationError>;

    async fn current_session(
        &self,
        lookup: AccessTokenSessionLookup,
        allow_revoked: bool,
    ) -> Result<CurrentSession, ApplicationError>;

    async fn browser_logout_context(
        &self,
        preparation: &VersionedDigest,
        now: OffsetDateTime,
    ) -> Result<BrowserLogoutContext, ApplicationError>;
}
