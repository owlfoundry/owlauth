use async_trait::async_trait;
use time::OffsetDateTime;
use uuid::Uuid;

use super::{ApplicationError, ProtectedValue, VersionedDigest};

#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "persisted email policy snapshot keeps independent switches explicit"
)]
pub(crate) struct AdmittedEmailMethod {
    pub policy_revision: i64,
    pub security_revision: i64,
    pub assignment_security_revision: i64,
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
    pub smtp_selection_kind: String,
    pub smtp_configuration_id: Option<Uuid>,
    pub smtp_generation: i32,
    pub smtp_security_eligibility_revision: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct EmailMethodSelection {
    pub status: crate::domain::LoginTransactionStatus,
    pub transaction_revision: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SelectEmailMethod {
    pub project_id: Uuid,
    pub transaction_id: Uuid,
    pub expected_transaction_revision: i64,
    pub browser_binding: VersionedDigest,
    pub csrf: VersionedDigest,
    pub now: OffsetDateTime,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct EmailGenerationPreparation {
    pub project_id: Uuid,
    pub application_id: Uuid,
    pub transaction_id: Uuid,
    pub next_generation: i16,
    pub transaction_expires_at: OffsetDateTime,
    pub policy: AdmittedEmailMethod,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CommitEmailGeneration {
    pub project_id: Uuid,
    pub application_id: Uuid,
    pub transaction_id: Uuid,
    pub expected_transaction_revision: i64,
    pub expected_generation: i16,
    pub challenge_id: Uuid,
    pub outbox_id: Uuid,
    pub canonicalization_version: i32,
    pub lookup_digest: VersionedDigest,
    /// Active and retained canonical-recipient digests used only for durable delivery suppression.
    pub recipient_digests: Vec<VersionedDigest>,
    pub address: ProtectedValue,
    pub otp_digest: Option<VersionedDigest>,
    pub magic_digest: Option<VersionedDigest>,
    pub envelope: ProtectedValue,
    pub body: ProtectedValue,
    pub message_id: String,
    pub issued_at: OffsetDateTime,
    pub otp_expires_at: Option<OffsetDateTime>,
    pub magic_expires_at: Option<OffsetDateTime>,
    pub expires_at: OffsetDateTime,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum EmailProofKind {
    Otp,
    MagicLink,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct VerifyEmailProof {
    pub project_id: Uuid,
    pub transaction_id: Uuid,
    pub challenge_id: Uuid,
    pub proof_kind: EmailProofKind,
    pub proof_digest: VersionedDigest,
    pub browser_binding: Option<VersionedDigest>,
    pub csrf: VersionedDigest,
    pub transfer_context: Option<VersionedDigest>,
    pub expected_transaction_revision: i64,
    pub now: OffsetDateTime,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct EstablishMagicTransferContext {
    pub id: Uuid,
    pub challenge_id: Uuid,
    pub context: VersionedDigest,
    pub csrf: VersionedDigest,
    pub now: OffsetDateTime,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ResolveMagicTransferContext {
    pub challenge_id: Uuid,
    pub project_public_id: String,
    pub transaction_id: Uuid,
    pub context: VersionedDigest,
    pub csrf: VersionedDigest,
    pub now: OffsetDateTime,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ResolvedMagicTransferContext {
    pub project_id: Uuid,
    pub project_public_id: String,
    pub transaction_id: Uuid,
    pub application_type: crate::domain::ApplicationType,
    pub browser_binding_required: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum EmailProofDecision {
    Accepted(VerifiedEmailChallenge),
    Invalid,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct VerifiedEmailChallenge {
    pub project_id: Uuid,
    pub application_id: Uuid,
    pub transaction_id: Uuid,
    pub challenge_id: Uuid,
    pub address: ProtectedValue,
    pub canonicalization_version: i32,
    pub lookup_digest: VersionedDigest,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CompleteEmailProof {
    pub verification: VerifyEmailProof,
    pub new_user_id: Uuid,
    pub new_user_public_id: String,
    pub new_identity_id: Uuid,
    pub durable_address: ProtectedValue,
    /// The challenge-local lookup authority re-derived from the decrypted candidate at the
    /// exact persisted key version. This is independent of the current durable alias roster.
    pub verified_challenge_lookup: VersionedDigest,
    pub lookup_aliases: Vec<VersionedDigest>,
    pub active_alias: VersionedDigest,
    pub alias_authority_revision: i64,
    pub browser_session_id: Uuid,
    pub existing_browser_credential: Option<VersionedDigest>,
    pub browser_credential: VersionedDigest,
    pub handoff_id: Uuid,
    pub handoff_ticket: VersionedDigest,
}

#[async_trait]
pub(crate) trait PasswordlessEmailRepository: Send + Sync {
    async fn select_email_method(
        &self,
        command: SelectEmailMethod,
    ) -> Result<EmailMethodSelection, ApplicationError>;

    async fn prepare_email_generation(
        &self,
        project_id: Uuid,
        transaction_id: Uuid,
        expected_transaction_revision: i64,
        browser_binding: &VersionedDigest,
        csrf: &VersionedDigest,
        now: OffsetDateTime,
    ) -> Result<EmailGenerationPreparation, ApplicationError>;

    async fn commit_email_generation(
        &self,
        command: CommitEmailGeneration,
    ) -> Result<(), ApplicationError>;

    async fn establish_magic_transfer_context(
        &self,
        command: EstablishMagicTransferContext,
    ) -> Result<(), ApplicationError>;

    async fn resolve_magic_transfer_context(
        &self,
        command: ResolveMagicTransferContext,
    ) -> Result<ResolvedMagicTransferContext, ApplicationError>;

    async fn email_proof_key_version(
        &self,
        project_id: Uuid,
        transaction_id: Uuid,
        challenge_id: Uuid,
        proof_kind: EmailProofKind,
    ) -> Result<Option<i32>, ApplicationError>;

    async fn verify_email_proof(
        &self,
        command: VerifyEmailProof,
    ) -> Result<EmailProofDecision, ApplicationError>;

    async fn complete_email_proof(
        &self,
        command: CompleteEmailProof,
    ) -> Result<super::IssuedHandoff, ApplicationError>;
}
