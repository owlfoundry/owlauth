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
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProtectedPurpose {
    ApplicationState,
    ProviderPkce,
}

impl ProtectedPurpose {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::ApplicationState => "application_state",
            Self::ProviderPkce => "provider_pkce",
        }
    }
}

pub(crate) trait RuntimeProtector: Send + Sync {
    fn active_version(&self) -> i32;

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
        signer_ref: &str,
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
    async fn resolve(&self, secret_ref: &str) -> Result<Zeroizing<String>, ApplicationError>;
}

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct ProviderAuthorizationRequest {
    pub issuer: String,
    pub client_id: String,
    pub callback_url: String,
    pub state: String,
    pub nonce: String,
    pub pkce_challenge: String,
}

pub(crate) struct ProviderCallbackRequest {
    pub issuer: String,
    pub client_id: String,
    pub client_secret: Zeroizing<String>,
    pub callback_url: String,
    pub code: Zeroizing<String>,
    pub pkce_verifier: Zeroizing<String>,
    pub expected_nonce: Zeroizing<String>,
    pub now: OffsetDateTime,
    pub allowed_clock_skew_seconds: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ProviderIdentity {
    pub issuer: String,
    pub subject: String,
    pub display_name: Option<String>,
    pub picture_url: Option<String>,
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
    fn issuer_allowed(&self, issuer: &str) -> bool;

    async fn authorization_url(
        &self,
        request: ProviderAuthorizationRequest,
    ) -> Result<String, ProviderExchangeError>;

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
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct HostedProviderMethod {
    pub key: String,
    pub display_name: String,
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
    pub expires_at: OffsetDateTime,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ProviderRuntimeContext {
    pub project_id: Uuid,
    pub transaction_id: Uuid,
    pub provider_id: Uuid,
    pub provider_key: String,
    pub issuer: String,
    pub client_id: String,
    pub callback_url: String,
    pub secret_ref: String,
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
