use std::collections::BTreeSet;

use async_trait::async_trait;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::domain::LoginTransactionStatus;

use super::ApplicationError;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct VersionedDigest {
    pub value: [u8; 32],
    pub key_version: i32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ProtectedValue {
    pub ciphertext: Vec<u8>,
    pub key_version: i32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(
    clippy::struct_field_names,
    reason = "explicit revision ownership prevents Project/Application policy confusion"
)]
pub(crate) struct LoginRevisionSnapshot {
    pub project_metadata_revision: i64,
    pub project_security_revision: i64,
    pub application_security_revision: i64,
    pub claims_revision: i64,
    pub session_revision: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AdmittedProviderMethod {
    pub method_key: String,
    pub provider_id: Uuid,
    pub display_name: String,
    pub issuer: String,
    pub provider_revision: i64,
    pub assignment_security_revision: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CreateLoginTransaction {
    pub id: Uuid,
    pub project_id: Uuid,
    pub application_id: Uuid,
    pub interaction: VersionedDigest,
    pub redirect_uri: String,
    pub application_pkce_challenge: String,
    pub application_state: ProtectedValue,
    pub presentation_hint: Option<String>,
    pub revisions: LoginRevisionSnapshot,
    pub created_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
    pub admitted_providers: Vec<AdmittedProviderMethod>,
    pub admitted_email: Option<super::AdmittedEmailMethod>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LoginTransactionRecord {
    pub id: Uuid,
    pub project_id: Uuid,
    pub application_id: Uuid,
    pub status: LoginTransactionStatus,
    pub transaction_revision: i64,
    pub expires_at: OffsetDateTime,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct BindHostedBrowser {
    pub interaction: VersionedDigest,
    pub expected_transaction_revision: i64,
    pub browser_binding: VersionedDigest,
    pub csrf: VersionedDigest,
    pub now: OffsetDateTime,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SelectProviderMethod {
    pub project_id: Uuid,
    pub transaction_id: Uuid,
    pub expected_transaction_revision: i64,
    pub method_key: String,
    pub provider_id: Uuid,
    pub browser_binding: VersionedDigest,
    pub csrf: VersionedDigest,
    pub callback_url: String,
    pub upstream_state: VersionedDigest,
    pub oidc_nonce: VersionedDigest,
    pub provider_pkce: ProtectedValue,
    pub now: OffsetDateTime,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ClaimProviderCallback {
    pub transaction_id: Uuid,
    pub project_public_id: String,
    pub provider_key: String,
    pub upstream_state: VersionedDigest,
    pub browser_binding: VersionedDigest,
    /// Immutable Runtime key inventory. The repository compares both frozen nonce and PKCE
    /// versions under the transaction lock before persisting the callback claim.
    pub readable_key_versions: BTreeSet<i32>,
    pub now: OffsetDateTime,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DenyProviderCallback {
    pub transaction_id: Uuid,
    pub project_public_id: String,
    pub provider_key: String,
    pub upstream_state: VersionedDigest,
    pub browser_binding: VersionedDigest,
    pub safe_outcome: &'static str,
    pub now: OffsetDateTime,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct FailProviderExchange {
    pub project_id: Uuid,
    pub transaction_id: Uuid,
    pub expected_transaction_revision: i64,
    pub now: OffsetDateTime,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ClaimedProviderExchange {
    pub transaction: LoginTransactionRecord,
    pub provider_id: Uuid,
    pub callback_url: String,
    pub oidc_nonce: VersionedDigest,
    pub provider_pkce: ProtectedValue,
}

#[async_trait]
pub(crate) trait AuthenticationRepository: Send + Sync {
    async fn create_login_transaction(
        &self,
        command: CreateLoginTransaction,
    ) -> Result<LoginTransactionRecord, ApplicationError>;

    async fn bind_hosted_browser(
        &self,
        command: BindHostedBrowser,
    ) -> Result<LoginTransactionRecord, ApplicationError>;

    async fn select_provider_method(
        &self,
        command: SelectProviderMethod,
    ) -> Result<LoginTransactionRecord, ApplicationError>;

    async fn claim_provider_callback(
        &self,
        command: ClaimProviderCallback,
    ) -> Result<ClaimedProviderExchange, ApplicationError>;

    async fn deny_provider_callback(
        &self,
        command: DenyProviderCallback,
    ) -> Result<LoginTransactionRecord, ApplicationError>;

    async fn fail_provider_exchange(
        &self,
        command: FailProviderExchange,
    ) -> Result<LoginTransactionRecord, ApplicationError>;
}
