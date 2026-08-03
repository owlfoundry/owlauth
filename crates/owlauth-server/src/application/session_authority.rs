use async_trait::async_trait;
use serde_json::Value;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::domain::{
    ManagedProfileCapability, ProfileDisplayName, ProfileLocale, ProfilePictureUrl, ProviderIssuer,
    ProviderSubject,
};

use super::{ApplicationError, ProtectedValue, RenewableProviderCredential, VersionedDigest};

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ManagedCredentialCapability {
    pub adapter_key: String,
    pub adapter_revision: i64,
    pub exact_scopes: Vec<String>,
    pub supports_revocation: bool,
}

impl ManagedCredentialCapability {
    pub(crate) fn from_adapter(
        capability: &ManagedProfileCapability,
        supports_revocation: bool,
    ) -> Result<Self, ApplicationError> {
        capability.validate().map_err(ApplicationError::from)?;
        Ok(Self {
            adapter_key: capability.adapter_key.to_owned(),
            adapter_revision: capability.adapter_revision,
            exact_scopes: capability
                .exact_scopes
                .iter()
                .map(ToString::to_string)
                .collect(),
            supports_revocation: capability.supports_revocation && supports_revocation,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct VerifiedProviderIdentity {
    pub issuer: ProviderIssuer,
    pub subject: ProviderSubject,
    pub display_name: Option<ProfileDisplayName>,
    pub picture_url: Option<ProfilePictureUrl>,
    pub locale: Option<ProfileLocale>,
    pub renewable_credential: Option<RenewableProviderCredential>,
    /// Exact adapter-owned capability validated by Runtime for this callback. Repositories may
    /// freeze this snapshot but must never manufacture capability constants of their own.
    pub managed_capability: Option<ManagedCredentialCapability>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum AuthenticatedIdentityEvidence {
    Provider(VerifiedProviderIdentity),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CompleteAuthenticatedIdentity {
    pub project_id: Uuid,
    pub transaction_id: Uuid,
    pub expected_transaction_revision: i64,
    pub evidence: AuthenticatedIdentityEvidence,
    pub new_user_id: Uuid,
    pub new_user_public_id: String,
    pub new_identity_id: Uuid,
    pub browser_session_id: Uuid,
    pub existing_browser_credential: Option<VersionedDigest>,
    pub browser_credential: VersionedDigest,
    pub handoff_id: Uuid,
    pub handoff_ticket: VersionedDigest,
    pub now: OffsetDateTime,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ConfirmBrowserSessionReuse {
    pub project_id: Uuid,
    pub transaction_id: Uuid,
    pub expected_transaction_revision: i64,
    pub browser_binding: VersionedDigest,
    pub csrf: VersionedDigest,
    pub browser_credential: VersionedDigest,
    pub handoff_id: Uuid,
    pub handoff_ticket: VersionedDigest,
    pub now: OffsetDateTime,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct IssuedHandoff {
    pub project_id: Uuid,
    pub application_id: Uuid,
    pub user_id: Uuid,
    pub user_public_id: String,
    pub browser_session_id: Uuid,
    pub handoff_id: Uuid,
    pub redirect_uri: String,
    pub application_state: ProtectedValue,
    pub expires_at: OffsetDateTime,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PrepareHandoffExchange {
    pub project_id: Uuid,
    pub application_id: Uuid,
    pub handoff_ticket: VersionedDigest,
    pub application_pkce_challenge: String,
    pub now: OffsetDateTime,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct HandoffPreparation {
    pub ticket_id: Uuid,
    pub project_public_id: String,
    pub project_issuer: String,
    pub application_public_id: String,
    pub user_id: Uuid,
    pub user_public_id: String,
    pub user_revision: i64,
    pub user_security_revision: i64,
    pub project_security_revision: i64,
    pub application_security_revision: i64,
    pub claims_revision: i64,
    pub session_revision: i64,
    pub project_projection_revision: i64,
    pub application_projection_revision: i64,
    pub projection_revision: i64,
    pub projection_document: Value,
    pub signing_ring_id: Uuid,
    pub signing_key_id: Uuid,
    pub signing_kid: String,
    pub signer_ref: String,
    pub signing_epoch: i64,
    pub access_token_lifetime_seconds: i64,
    pub authenticated_at: OffsetDateTime,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct CommitHandoffExchange {
    pub project_id: Uuid,
    pub application_id: Uuid,
    pub handoff_ticket: VersionedDigest,
    pub application_pkce_challenge: String,
    pub preparation: HandoffPreparation,
    pub binding_id: Uuid,
    pub projection_id: Uuid,
    pub application_session_id: Uuid,
    pub refresh_family_id: Uuid,
    pub refresh_generation_id: Uuid,
    pub refresh_token: VersionedDigest,
    pub allowed_clock_skew_seconds: i64,
    pub now: OffsetDateTime,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct HandoffSessionRecord {
    pub project_id: Uuid,
    pub application_id: Uuid,
    pub user_id: Uuid,
    pub user_public_id: String,
    pub binding_id: Uuid,
    pub projection_revision: i64,
    pub application_session_id: Uuid,
    pub refresh_family_id: Uuid,
    pub refresh_generation: i64,
    pub absolute_expires_at: OffsetDateTime,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PrepareRefreshRotation {
    pub project_id: Uuid,
    pub application_id: Uuid,
    pub presented_token: VersionedDigest,
    pub now: OffsetDateTime,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct RefreshPreparation {
    pub generation_id: Uuid,
    pub family_id: Uuid,
    pub project_public_id: String,
    pub project_issuer: String,
    pub application_public_id: String,
    pub family_revision: i64,
    pub generation: i64,
    pub application_session_id: Uuid,
    pub session_revision: i64,
    pub binding_id: Uuid,
    pub binding_revision: i64,
    pub user_id: Uuid,
    pub user_public_id: String,
    pub user_revision: i64,
    pub claims_revision: i64,
    pub project_projection_revision: i64,
    pub application_projection_revision: i64,
    pub projection_revision: i64,
    pub projection_document: Value,
    pub signing_ring_id: Uuid,
    pub signing_key_id: Uuid,
    pub signing_kid: String,
    pub signer_ref: String,
    pub signing_epoch: i64,
    pub access_token_lifetime_seconds: i64,
    pub authenticated_at: OffsetDateTime,
    pub absolute_expires_at: OffsetDateTime,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) enum RefreshPreparationResult {
    Ready(Box<RefreshPreparation>),
    ReplayRevoked { family_id: Uuid },
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct RotateRefreshToken {
    pub project_id: Uuid,
    pub application_id: Uuid,
    pub presented_token: VersionedDigest,
    pub preparation: RefreshPreparation,
    pub successor_generation_id: Uuid,
    pub successor_token: VersionedDigest,
    pub now: OffsetDateTime,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum RefreshRotationResult {
    Rotated {
        user_id: Uuid,
        application_session_id: Uuid,
        family_id: Uuid,
        generation: i64,
        absolute_expires_at: OffsetDateTime,
    },
    ReplayRevoked {
        family_id: Uuid,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RecoverProviderExchanges {
    pub abandoned_before: OffsetDateTime,
    pub limit: u64,
    pub now: OffsetDateTime,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LogoutApplicationSession {
    pub project_id: Uuid,
    pub application_id: Uuid,
    pub user_id: Uuid,
    pub application_session_id: Uuid,
    pub now: OffsetDateTime,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PrepareBrowserLogout {
    pub id: Uuid,
    pub project_id: Uuid,
    pub application_id: Uuid,
    pub user_id: Uuid,
    pub application_session_id: Uuid,
    pub browser_session_id: Uuid,
    pub preparation: VersionedDigest,
    pub now: OffsetDateTime,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct BindBrowserLogout {
    pub preparation: VersionedDigest,
    pub browser_credential: VersionedDigest,
    pub expected_interaction_revision: i64,
    pub csrf: VersionedDigest,
    pub now: OffsetDateTime,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ConfirmBrowserLogout {
    pub preparation: VersionedDigest,
    pub browser_credential: VersionedDigest,
    pub csrf: VersionedDigest,
    pub expected_interaction_revision: i64,
    pub now: OffsetDateTime,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct BrowserLogoutRecord {
    pub id: Uuid,
    pub project_id: Uuid,
    pub browser_session_id: Uuid,
    pub interaction_revision: i64,
    pub expires_at: OffsetDateTime,
}

#[async_trait]
pub(crate) trait SessionAuthorityRepository: Send + Sync {
    async fn complete_authenticated_identity(
        &self,
        command: CompleteAuthenticatedIdentity,
    ) -> Result<IssuedHandoff, ApplicationError>;

    async fn confirm_browser_session_reuse(
        &self,
        command: ConfirmBrowserSessionReuse,
    ) -> Result<IssuedHandoff, ApplicationError>;

    async fn prepare_handoff_exchange(
        &self,
        command: PrepareHandoffExchange,
    ) -> Result<HandoffPreparation, ApplicationError>;

    async fn commit_handoff_exchange(
        &self,
        command: CommitHandoffExchange,
    ) -> Result<HandoffSessionRecord, ApplicationError>;

    async fn prepare_refresh_rotation(
        &self,
        command: PrepareRefreshRotation,
    ) -> Result<RefreshPreparationResult, ApplicationError>;

    async fn rotate_refresh_token(
        &self,
        command: RotateRefreshToken,
    ) -> Result<RefreshRotationResult, ApplicationError>;

    async fn recover_abandoned_provider_exchanges(
        &self,
        command: RecoverProviderExchanges,
    ) -> Result<u64, ApplicationError>;

    async fn logout_application_session(
        &self,
        command: LogoutApplicationSession,
    ) -> Result<(), ApplicationError>;

    async fn prepare_browser_logout(
        &self,
        command: PrepareBrowserLogout,
    ) -> Result<BrowserLogoutRecord, ApplicationError>;

    async fn bind_browser_logout(
        &self,
        command: BindBrowserLogout,
    ) -> Result<BrowserLogoutRecord, ApplicationError>;

    async fn confirm_browser_logout(
        &self,
        command: ConfirmBrowserLogout,
    ) -> Result<BrowserLogoutRecord, ApplicationError>;
}
