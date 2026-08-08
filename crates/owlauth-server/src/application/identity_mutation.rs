use std::{collections::BTreeSet, sync::Arc};

use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::{Duration, OffsetDateTime};
use url::Url;
use uuid::Uuid;
use zeroize::Zeroizing;

use super::{
    AdmittedEmailMethod, ApplicationError, Clock, EmailProofKind, OpaquePurpose, ProtectedPurpose,
    ProtectedValue, ProviderAuthorizationRequest, ProviderCallbackRequest, ProviderExchangeError,
    ProviderIdentity, ProviderRequestProfile, ProviderSecretResolver, RuntimeProtector,
    UpstreamProviderClient, VersionedDigest,
};
use crate::domain::{
    IdentityKind, IdentityMutationKind, IdentityMutationSlotRole, IdentityMutationSlotState,
    IdentityMutationStatus, ProviderKey, ProviderProofCapabilitySnapshot, PublicId,
    TrustedRuntimeProviderCallback,
};

const IDENTITY_MUTATION_LIFETIME: Duration = Duration::minutes(10);
const CALLBACK_CLOCK_SKEW_SECONDS: i64 = 60;
const MAX_HANDLE_BYTES: usize = 256;
const MAX_CALLBACK_CODE_BYTES: usize = 4096;
const CONTROLLED_OIDC_PROOF_ADAPTER_KEY: &str = "controlled_oidc_profile_v1";
const GOOGLE_OIDC_PROOF_ADAPTER_KEY: &str = "google_oidc_profile_v1";
const OIDC_PROOF_ADAPTER_REVISION: i64 = 1;
#[cfg(test)]
const CONTROLLED_OIDC_PROOF_ADAPTER_REVISION: i64 = OIDC_PROOF_ADAPTER_REVISION;
const CONTROLLED_OIDC_PROOF_SCOPES: &[&str] = &["openid", "profile"];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum IdentityMutationProofMethodKind {
    Provider,
    Email,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(
    clippy::struct_field_names,
    reason = "expected revision names remain explicit at the persistence CAS boundary"
)]
pub(crate) struct ExpectedIdentity {
    pub identity_kind: IdentityKind,
    pub identity_id: Uuid,
    pub expected_identity_revision: i64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(
    clippy::struct_field_names,
    reason = "expected revision names remain explicit at the persistence CAS boundary"
)]
pub(crate) struct ExpectedUser {
    pub user_id: Uuid,
    pub expected_user_revision: i64,
    pub expected_user_security_revision: i64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum IdentityMutationProofAuthoritySelection {
    Provider {
        application_id: Uuid,
        provider_configuration_id: Uuid,
    },
    Email {
        application_id: Uuid,
    },
}

impl IdentityMutationProofAuthoritySelection {
    pub(crate) const fn method_kind(self) -> IdentityMutationProofMethodKind {
        match self {
            Self::Provider { .. } => IdentityMutationProofMethodKind::Provider,
            Self::Email { .. } => IdentityMutationProofMethodKind::Email,
        }
    }

    const fn application_id(self) -> Uuid {
        match self {
            Self::Provider { application_id, .. } | Self::Email { application_id } => {
                application_id
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum IdentityMutationPrimarySourceDisposition {
    Preserve,
    Provider(ExpectedIdentity),
    Email(ExpectedIdentity),
    Clear,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum IdentityMutationSessionsDisposition {
    LoserRevoked,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum IdentityMutationBindingsDisposition {
    WinnerPreferred,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum IdentityMutationCreateOperation {
    Link {
        destination: ExpectedUser,
        destination_identity: ExpectedIdentity,
        candidate_kind: IdentityKind,
        destination_authority: IdentityMutationProofAuthoritySelection,
        candidate_authority: IdentityMutationProofAuthoritySelection,
    },
    Unlink {
        owner: ExpectedUser,
        identity: ExpectedIdentity,
        authority: IdentityMutationProofAuthoritySelection,
        primary_source: IdentityMutationPrimarySourceDisposition,
    },
    Merge {
        winner: ExpectedUser,
        winner_identity: ExpectedIdentity,
        loser: ExpectedUser,
        loser_identity: ExpectedIdentity,
        winner_authority: IdentityMutationProofAuthoritySelection,
        loser_authority: IdentityMutationProofAuthoritySelection,
        primary_source: IdentityMutationPrimarySourceDisposition,
        sessions: IdentityMutationSessionsDisposition,
        bindings: IdentityMutationBindingsDisposition,
    },
}

impl IdentityMutationCreateOperation {
    pub(crate) const fn kind(&self) -> IdentityMutationKind {
        match self {
            Self::Link { .. } => IdentityMutationKind::Link,
            Self::Unlink { .. } => IdentityMutationKind::Unlink,
            Self::Merge { .. } => IdentityMutationKind::Merge,
        }
    }

    #[cfg(test)]
    pub(crate) fn derived_roles(&self) -> &'static [IdentityMutationSlotRole] {
        match self {
            Self::Link { .. } => &[
                IdentityMutationSlotRole::DestinationOwner,
                IdentityMutationSlotRole::CandidateIdentity,
            ],
            Self::Unlink { .. } => &[IdentityMutationSlotRole::IdentityOwner],
            Self::Merge { .. } => &[
                IdentityMutationSlotRole::WinnerOwner,
                IdentityMutationSlotRole::LoserOwner,
            ],
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CreateIdentityMutation {
    pub project_id: Uuid,
    pub operation: IdentityMutationCreateOperation,
    pub idempotency_key: String,
    pub correlation_id: Uuid,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct IdentityMutationProviderCapability {
    adapter_key: String,
    adapter_revision: i64,
    exact_nonrenewable_scopes: Vec<String>,
    provider_pkce_required: bool,
    oidc_nonce_required: bool,
}

impl IdentityMutationProviderCapability {
    pub(crate) fn controlled_oidc() -> Self {
        Self::oidc(CONTROLLED_OIDC_PROOF_ADAPTER_KEY)
    }

    fn google_oidc() -> Self {
        Self::oidc(GOOGLE_OIDC_PROOF_ADAPTER_KEY)
    }

    fn oidc(adapter_key: &'static str) -> Self {
        Self {
            adapter_key: adapter_key.to_owned(),
            adapter_revision: OIDC_PROOF_ADAPTER_REVISION,
            exact_nonrenewable_scopes: CONTROLLED_OIDC_PROOF_SCOPES
                .iter()
                .map(ToString::to_string)
                .collect(),
            provider_pkce_required: true,
            oidc_nonce_required: true,
        }
    }

    pub(crate) fn snapshot(
        &self,
        runtime_base: &str,
        project_public_id: &str,
        provider_key: &str,
    ) -> Result<ProviderProofCapabilitySnapshot, ApplicationError> {
        let project_public_id = PublicId::parse(project_public_id.to_owned())?;
        let provider_key = ProviderKey::parse(provider_key.to_owned())?;
        let callback = TrustedRuntimeProviderCallback::derive(
            runtime_base,
            &project_public_id,
            &provider_key,
        )?;
        ProviderProofCapabilitySnapshot::from_reviewed_adapter(
            self.adapter_key.clone(),
            self.adapter_revision,
            self.exact_nonrenewable_scopes.clone(),
            callback,
            self.provider_pkce_required,
            self.oidc_nonce_required,
        )
        .map_err(ApplicationError::from)
    }

    #[cfg(test)]
    pub(crate) fn exact_nonrenewable_scopes(&self) -> &[String] {
        &self.exact_nonrenewable_scopes
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct IdentityMutationProviderCapabilities {
    oidc: IdentityMutationProviderCapability,
    google: IdentityMutationProviderCapability,
}

impl IdentityMutationProviderCapabilities {
    pub(crate) fn reviewed() -> Self {
        Self {
            oidc: IdentityMutationProviderCapability::controlled_oidc(),
            google: IdentityMutationProviderCapability::google_oidc(),
        }
    }

    pub(crate) fn for_kind(
        &self,
        kind: crate::domain::ProviderKind,
    ) -> Option<&IdentityMutationProviderCapability> {
        match kind {
            crate::domain::ProviderKind::Oidc => Some(&self.oidc),
            crate::domain::ProviderKind::Google => Some(&self.google),
            crate::domain::ProviderKind::Github => None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct IdentityMutationSafeSlot {
    pub id: Uuid,
    pub role: IdentityMutationSlotRole,
    pub identity_kind: IdentityKind,
    pub method_kind: IdentityMutationProofMethodKind,
    pub state: IdentityMutationSlotState,
    pub proved: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct IdentityMutationView {
    pub id: Uuid,
    pub project_id: Uuid,
    pub project_public_id: String,
    pub kind: IdentityMutationKind,
    pub status: IdentityMutationStatus,
    pub revision: i64,
    pub expires_at: OffsetDateTime,
    pub slots: Vec<IdentityMutationSafeSlot>,
}

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct IdentityMutationProviderSlotAuthority {
    pub provider_configuration_id: Uuid,
    pub provider_kind: crate::domain::ProviderKind,
    pub provider_configuration_revision: i64,
    pub provider_egress_policy_revision: Option<i64>,
    pub egress_policy: Option<crate::domain::ProviderEgressPolicy>,
    pub provider_key: String,
    pub issuer: String,
    pub client_id: String,
    pub secret_material_id: Uuid,
    pub callback_url: String,
    pub adapter_key: String,
    pub adapter_capability_revision: i64,
    pub exact_scopes: Vec<String>,
    pub provider_pkce_required: bool,
    pub oidc_nonce_required: bool,
    pub upstream_state_key_version: Option<i32>,
    pub oidc_nonce: Option<VersionedDigest>,
    pub provider_pkce: Option<ProtectedValue>,
    pub callback_continuation: Option<ProtectedValue>,
}

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct IdentityMutationSlotRecord {
    pub id: Uuid,
    pub role: IdentityMutationSlotRole,
    pub identity_kind: IdentityKind,
    pub method_kind: IdentityMutationProofMethodKind,
    pub state: IdentityMutationSlotState,
    pub revision: i64,
    pub existing_identity_id: Option<Uuid>,
    pub provider: Option<IdentityMutationProviderSlotAuthority>,
}

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct IdentityMutationRecord {
    pub id: Uuid,
    pub project_id: Uuid,
    pub project_public_id: String,
    pub kind: IdentityMutationKind,
    pub status: IdentityMutationStatus,
    pub revision: i64,
    pub browser_binding_key_version: Option<i32>,
    pub csrf_key_version: Option<i32>,
    pub expires_at: OffsetDateTime,
    pub slots: Vec<IdentityMutationSlotRecord>,
}

impl IdentityMutationRecord {
    pub(crate) fn safe_view(&self) -> IdentityMutationView {
        IdentityMutationView {
            id: self.id,
            project_id: self.project_id,
            project_public_id: self.project_public_id.clone(),
            kind: self.kind,
            status: self.status,
            revision: self.revision,
            expires_at: self.expires_at,
            slots: self
                .slots
                .iter()
                .map(|slot| IdentityMutationSafeSlot {
                    id: slot.id,
                    role: slot.role,
                    identity_kind: slot.identity_kind,
                    method_kind: slot.method_kind,
                    state: slot.state,
                    proved: slot.state == IdentityMutationSlotState::Proved,
                })
                .collect(),
        }
    }

    fn slot(&self, id: Uuid) -> Result<&IdentityMutationSlotRecord, ApplicationError> {
        self.slots
            .iter()
            .find(|slot| slot.id == id)
            .ok_or(ApplicationError::NotFound)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum IdentityMutationCreateOutcome {
    Created {
        intent: IdentityMutationView,
        hosted_target: Option<String>,
    },
    Replayed {
        intent: IdentityMutationView,
        hosted_target: Option<String>,
    },
}

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct PreparedIdentityMutationCreate {
    pub command: CreateIdentityMutation,
    pub provider_capabilities: IdentityMutationProviderCapabilities,
    pub runtime_base: String,
    pub intent_id: Uuid,
    pub hosted_handle_digest: VersionedDigest,
    pub request_digest: Vec<u8>,
    pub protected_create_result: ProtectedValue,
    pub created_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
}

pub(crate) enum CreateIdentityMutationResult {
    Created(IdentityMutationRecord),
    Replayed {
        intent: IdentityMutationRecord,
        protected_create_result: Option<ProtectedValue>,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct IdentityMutationDigestVersions {
    pub intent: i32,
    pub browser_binding: Option<i32>,
    pub csrf: Option<i32>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct IdentityMutationProviderDigestVersions {
    pub browser_binding: i32,
    pub upstream_state: i32,
    pub oidc_nonce: Option<i32>,
    pub provider_pkce: Option<i32>,
    pub callback_continuation: Option<i32>,
}

pub(crate) struct IdentityMutationBootstrap {
    pub intent: IdentityMutationView,
    pub browser_binding: Zeroizing<String>,
    pub csrf: Zeroizing<String>,
}

pub(crate) struct StartIdentityMutationMethod {
    pub project_public_id: String,
    pub interaction: String,
    pub proof_slot_id: Uuid,
    pub asserted_method: IdentityMutationProofMethodKind,
    pub browser_binding: String,
    pub csrf: String,
    pub expected_revision: i64,
}

pub(crate) enum StartedIdentityMutationMethod {
    ProviderNavigation { url: String, proof_slot_id: Uuid },
    EmailAddressEntry(IdentityMutationView),
}

pub(crate) struct ConfirmIdentityMutationReady {
    pub project_public_id: String,
    pub interaction: String,
    pub browser_binding: String,
    pub csrf: String,
    pub expected_revision: i64,
}

pub(crate) struct IdentityMutationProviderDenial {
    pub intent_id: Uuid,
    pub proof_slot_id: Uuid,
    pub project_public_id: String,
    pub provider_key: String,
    pub state: String,
    pub browser_binding: String,
    pub safe_outcome: &'static str,
}

pub(crate) struct IdentityMutationProviderCallback {
    pub intent_id: Uuid,
    pub proof_slot_id: Uuid,
    pub project_public_id: String,
    pub provider_key: String,
    pub state: String,
    pub code: String,
    pub browser_binding: String,
}

pub(crate) enum IdentityMutationCallbackOutcome {
    Proved { continuation: Zeroizing<String> },
    Duplicate,
    TerminalizedFailure,
    TerminalizedStaleAuthority,
}

pub(crate) enum ClaimIdentityMutationProvider {
    Claimed(IdentityMutationRecord),
    Duplicate(IdentityMutationRecord),
    TerminalizedStaleAuthority,
}

pub(crate) enum FailIdentityMutationProvider {
    Terminalized(IdentityMutationRecord),
    TerminalWinner(IdentityMutationRecord),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ProviderProofObservation {
    pub issuer: String,
    pub subject: String,
    pub display_name: Option<String>,
    pub picture_url: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum IdentityMutationCandidateKind {
    Provider,
    Email,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct IdentityMutationCandidateEvidenceContext {
    pub project_id: Uuid,
    pub intent_id: Uuid,
    pub proof_slot_id: Uuid,
    pub evidence_id: Uuid,
    pub evidence_revision: i64,
    pub candidate_kind: IdentityMutationCandidateKind,
}

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct CandidateEvidenceMaterial {
    pub context: IdentityMutationCandidateEvidenceContext,
    pub ciphertext: ProtectedValue,
    pub digest: VersionedDigest,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct IdentityMutationProviderRegistrationEvidence {
    pub provider_configuration_id: Uuid,
    pub provider_configuration_revision: i64,
    pub adapter_key: String,
    pub adapter_capability_revision: i64,
    pub issuer: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct IdentityMutationAdmittedProviderProfile {
    pub display_name: Option<String>,
    pub picture_url: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct IdentityMutationProviderCandidate {
    pub issuer: String,
    pub subject: String,
    pub admitted_profile: IdentityMutationAdmittedProviderProfile,
    pub registration: IdentityMutationProviderRegistrationEvidence,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct IdentityMutationEmailCandidate {
    pub identity_id: Uuid,
    pub canonicalization_version: i32,
    pub normalized_address: String,
    pub lookup_aliases: Vec<VersionedDigest>,
    pub active_alias: VersionedDigest,
    pub alias_authority_revision: i64,
    pub durable_address: ProtectedValue,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum IdentityMutationCandidate {
    Provider(IdentityMutationProviderCandidate),
    Email(IdentityMutationEmailCandidate),
}

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct IdentityMutationCandidateEvidenceEnvelope {
    pub context: IdentityMutationCandidateEvidenceContext,
    pub ciphertext: ProtectedValue,
    pub digest: VersionedDigest,
}

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct IdentityMutationControlConfirmationPreparation {
    pub project_id: Uuid,
    pub intent_id: Uuid,
    pub expected_intent_revision: i64,
    pub expected_kind: IdentityMutationKind,
    pub candidate_evidence: Option<IdentityMutationCandidateEvidenceEnvelope>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PreparedIdentityMutationCandidate {
    pub context: IdentityMutationCandidateEvidenceContext,
    pub evidence_digest: VersionedDigest,
    pub candidate: IdentityMutationCandidate,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PreparedIdentityMutationConfirmation {
    pub project_id: Uuid,
    pub intent_id: Uuid,
    pub expected_intent_revision: i64,
    pub expected_kind: IdentityMutationKind,
    pub candidate: Option<PreparedIdentityMutationCandidate>,
    pub correlation_id: Uuid,
    pub now: OffsetDateTime,
}

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct PreparedIdentityMutationProviderCompletion {
    pub claimed: IdentityMutationRecord,
    pub proof_slot_id: Uuid,
    pub observation: ProviderProofObservation,
    pub candidate_evidence: Option<CandidateEvidenceMaterial>,
    pub receipt_id: Uuid,
    pub receipt_digest: VersionedDigest,
    pub now: OffsetDateTime,
}

pub(crate) struct PrepareIdentityMutationEmailGeneration {
    pub project_public_id: String,
    pub interaction: String,
    pub proof_slot_id: Uuid,
    pub browser_binding: String,
    pub csrf: String,
    pub expected_revision: i64,
}

pub(crate) struct BeginIdentityMutationEmailChallenge {
    pub project_public_id: String,
    pub interaction: String,
    pub proof_slot_id: Uuid,
    pub browser_binding: String,
    pub csrf: String,
    pub expected_revision: i64,
    pub email: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct IdentityMutationEmailChallengeAccepted {
    pub revision: i64,
    pub challenge_id: Uuid,
    pub generation: i16,
    pub otp_enabled: bool,
    pub magic_link_enabled: bool,
    pub expires_at: OffsetDateTime,
}

pub(crate) struct VerifyIdentityMutationMagicTransferProof {
    pub project_public_id: String,
    pub interaction: String,
    pub proof_slot_id: Uuid,
    pub challenge_id: Uuid,
    pub generation: i16,
    pub csrf: String,
    pub expected_revision: i64,
    pub proof: Zeroizing<String>,
    pub transfer_context: String,
    pub browser_binding: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct IdentityMutationMagicTransferGate {
    pub context: Zeroizing<String>,
    pub csrf: Zeroizing<String>,
    pub project_public_id: String,
    pub proof_slot_id: Uuid,
    pub generation: i16,
    pub expected_revision: i64,
}

pub(crate) struct VerifyRawIdentityMutationEmailProof {
    pub project_public_id: String,
    pub interaction: String,
    pub proof_slot_id: Uuid,
    pub browser_binding: String,
    pub csrf: String,
    pub expected_revision: i64,
    pub challenge_id: Uuid,
    pub generation: i16,
    pub proof_kind: EmailProofKind,
    pub proof: Zeroizing<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct IdentityMutationEmailGenerationPreparation {
    pub project_id: Uuid,
    pub application_id: Uuid,
    pub intent_id: Uuid,
    pub proof_slot_id: Uuid,
    pub next_generation: i16,
    pub intent_expires_at: OffsetDateTime,
    pub policy: AdmittedEmailMethod,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CommitIdentityMutationEmailGeneration {
    pub project_id: Uuid,
    pub application_id: Uuid,
    pub intent_id: Uuid,
    pub proof_slot_id: Uuid,
    pub expected_intent_revision: i64,
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
    pub admitted_method: AdmittedEmailMethod,
    pub issued_at: OffsetDateTime,
    pub otp_expires_at: Option<OffsetDateTime>,
    pub magic_expires_at: Option<OffsetDateTime>,
    pub expires_at: OffsetDateTime,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct IdentityMutationEmailProofKey {
    pub project_id: Uuid,
    pub intent_id: Uuid,
    pub proof_slot_id: Uuid,
    pub challenge_id: Uuid,
    pub proof_kind: EmailProofKind,
}

pub(crate) struct SubmitIdentityMutationEmailProof {
    pub project_id: Uuid,
    pub intent_id: Uuid,
    pub proof_slot_id: Uuid,
    pub challenge_id: Uuid,
    pub generation: i16,
    pub proof_kind: EmailProofKind,
    pub proof: Zeroizing<String>,
    pub browser_binding: Option<VersionedDigest>,
    pub csrf: VersionedDigest,
    pub transfer_context: Option<VersionedDigest>,
    pub expected_intent_revision: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct VerifyIdentityMutationEmailProof {
    pub project_id: Uuid,
    pub intent_id: Uuid,
    pub proof_slot_id: Uuid,
    pub challenge_id: Uuid,
    pub generation: i16,
    pub proof_kind: EmailProofKind,
    pub proof_digest: VersionedDigest,
    pub browser_binding: Option<VersionedDigest>,
    pub csrf: VersionedDigest,
    pub transfer_context: Option<VersionedDigest>,
    pub expected_intent_revision: i64,
    pub now: OffsetDateTime,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct VerifiedIdentityMutationEmailChallenge {
    pub project_id: Uuid,
    pub application_id: Uuid,
    pub intent_id: Uuid,
    pub proof_slot_id: Uuid,
    pub slot_role: IdentityMutationSlotRole,
    pub challenge_id: Uuid,
    pub generation: i16,
    pub address: ProtectedValue,
    pub canonicalization_version: i32,
    pub lookup_digest: VersionedDigest,
    pub existing_identity_id: Option<Uuid>,
    pub existing_identity_revision: Option<i64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum IdentityMutationEmailProofDecision {
    Accepted(VerifiedIdentityMutationEmailChallenge),
    Invalid,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum IdentityMutationEmailCompletionDecision {
    Completed(IdentityMutationView),
    Invalid,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct IdentityMutationExistingEmailEvidence {
    pub identity_id: Uuid,
    pub identity_revision: i64,
    pub verified_challenge_lookup: VersionedDigest,
    pub lookup_aliases: Vec<VersionedDigest>,
    pub active_alias: VersionedDigest,
    pub alias_authority_revision: i64,
}

#[derive(Clone, Eq, PartialEq)]
pub(crate) enum IdentityMutationEmailProofMaterial {
    Candidate(CandidateEvidenceMaterial),
    Existing(IdentityMutationExistingEmailEvidence),
}

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct CompleteIdentityMutationEmailProof {
    pub verification: VerifyIdentityMutationEmailProof,
    pub verified_challenge_lookup: VersionedDigest,
    pub material: IdentityMutationEmailProofMaterial,
    pub receipt_id: Uuid,
    pub receipt_digest: VersionedDigest,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct IdentityMutationMagicTransferOwner {
    pub project_id: Uuid,
    pub intent_id: Uuid,
    pub proof_slot_id: Uuid,
    pub challenge_id: Uuid,
    pub generation: i16,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct EstablishIdentityMutationMagicTransferContext {
    pub id: Uuid,
    pub challenge_id: Uuid,
    pub context: VersionedDigest,
    pub csrf: VersionedDigest,
    pub now: OffsetDateTime,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct EstablishedIdentityMutationMagicTransferContext {
    pub owner: IdentityMutationMagicTransferOwner,
    pub project_public_id: String,
    pub expected_intent_revision: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ResolveIdentityMutationMagicTransferContext {
    pub challenge_id: Uuid,
    pub project_public_id: String,
    pub intent: VersionedDigest,
    pub context: VersionedDigest,
    pub csrf: VersionedDigest,
    pub now: OffsetDateTime,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ResolvedIdentityMutationMagicTransferContext {
    pub owner: IdentityMutationMagicTransferOwner,
    pub project_public_id: String,
    pub expected_intent_revision: i64,
}

#[async_trait]
#[allow(
    clippy::too_many_arguments,
    reason = "each mutation CAS carries exact intent, slot, browser, CSRF, and revision authority"
)]
pub(crate) trait ControlIdentityMutationRepository: Send + Sync {
    async fn create(
        &self,
        prepared: PreparedIdentityMutationCreate,
    ) -> Result<CreateIdentityMutationResult, ApplicationError>;

    async fn control_read(
        &self,
        project_id: Uuid,
        intent_id: Uuid,
        now: OffsetDateTime,
    ) -> Result<IdentityMutationRecord, ApplicationError>;

    async fn cancel(
        &self,
        project_id: Uuid,
        intent_id: Uuid,
        expected_revision: i64,
        correlation_id: Uuid,
        now: OffsetDateTime,
    ) -> Result<IdentityMutationRecord, ApplicationError>;

    async fn prepare_control_confirmation(
        &self,
        project_id: Uuid,
        intent_id: Uuid,
        expected_revision: i64,
        expected_kind: IdentityMutationKind,
        now: OffsetDateTime,
    ) -> Result<IdentityMutationControlConfirmationPreparation, ApplicationError>;

    async fn confirm_control(
        &self,
        confirmation: PreparedIdentityMutationConfirmation,
    ) -> Result<IdentityMutationRecord, ApplicationError>;
}

#[async_trait]
#[allow(
    clippy::too_many_arguments,
    reason = "each Runtime mutation CAS carries exact intent, slot, browser, CSRF, and revision authority"
)]
pub(crate) trait RuntimeIdentityMutationRepository: Send + Sync {
    async fn digest_versions(
        &self,
        intent_id: Uuid,
        now: OffsetDateTime,
    ) -> Result<IdentityMutationDigestVersions, ApplicationError>;

    async fn provider_digest_versions(
        &self,
        intent_id: Uuid,
        proof_slot_id: Uuid,
        now: OffsetDateTime,
    ) -> Result<IdentityMutationProviderDigestVersions, ApplicationError>;

    async fn bind_browser(
        &self,
        intent: &VersionedDigest,
        browser_binding: &VersionedDigest,
        csrf: &VersionedDigest,
        now: OffsetDateTime,
    ) -> Result<IdentityMutationRecord, ApplicationError>;

    async fn hosted_read(
        &self,
        intent: &VersionedDigest,
        browser_binding: &VersionedDigest,
        now: OffsetDateTime,
    ) -> Result<IdentityMutationRecord, ApplicationError>;

    async fn start_provider(
        &self,
        intent_id: Uuid,
        proof_slot_id: Uuid,
        intent: &VersionedDigest,
        browser_binding: &VersionedDigest,
        csrf: &VersionedDigest,
        expected_revision: i64,
        upstream_state: VersionedDigest,
        oidc_nonce: VersionedDigest,
        provider_pkce: Option<ProtectedValue>,
        callback_continuation: ProtectedValue,
        now: OffsetDateTime,
    ) -> Result<IdentityMutationRecord, ApplicationError>;

    async fn claim_provider_callback(
        &self,
        intent_id: Uuid,
        proof_slot_id: Uuid,
        project_public_id: &str,
        provider_key: &str,
        upstream_state: &VersionedDigest,
        browser_binding: &VersionedDigest,
        now: OffsetDateTime,
    ) -> Result<ClaimIdentityMutationProvider, ApplicationError>;

    async fn deny_provider_callback(
        &self,
        intent_id: Uuid,
        proof_slot_id: Uuid,
        project_public_id: &str,
        provider_key: &str,
        upstream_state: &VersionedDigest,
        browser_binding: &VersionedDigest,
        safe_outcome: &'static str,
        now: OffsetDateTime,
    ) -> Result<IdentityMutationRecord, ApplicationError>;

    async fn complete_provider_callback(
        &self,
        completion: PreparedIdentityMutationProviderCompletion,
    ) -> Result<IdentityMutationRecord, ApplicationError>;

    async fn fail_provider_callback(
        &self,
        claimed: &IdentityMutationRecord,
        proof_slot_id: Uuid,
        safe_outcome: &'static str,
        now: OffsetDateTime,
    ) -> Result<FailIdentityMutationProvider, ApplicationError>;

    async fn begin_email(
        &self,
        intent_id: Uuid,
        proof_slot_id: Uuid,
        intent: &VersionedDigest,
        browser_binding: &VersionedDigest,
        csrf: &VersionedDigest,
        expected_revision: i64,
        now: OffsetDateTime,
    ) -> Result<IdentityMutationRecord, ApplicationError>;

    async fn prepare_email_generation(
        &self,
        intent_id: Uuid,
        proof_slot_id: Uuid,
        intent: &VersionedDigest,
        browser_binding: &VersionedDigest,
        csrf: &VersionedDigest,
        expected_revision: i64,
        now: OffsetDateTime,
    ) -> Result<IdentityMutationEmailGenerationPreparation, ApplicationError>;

    async fn commit_email_generation(
        &self,
        generation: CommitIdentityMutationEmailGeneration,
    ) -> Result<IdentityMutationRecord, ApplicationError>;

    async fn establish_magic_transfer_context(
        &self,
        command: EstablishIdentityMutationMagicTransferContext,
    ) -> Result<EstablishedIdentityMutationMagicTransferContext, ApplicationError>;

    async fn resolve_magic_transfer_context(
        &self,
        command: ResolveIdentityMutationMagicTransferContext,
    ) -> Result<ResolvedIdentityMutationMagicTransferContext, ApplicationError>;

    async fn email_proof_key_version(
        &self,
        key: IdentityMutationEmailProofKey,
    ) -> Result<Option<i32>, ApplicationError>;

    async fn verify_email_proof(
        &self,
        verification: VerifyIdentityMutationEmailProof,
    ) -> Result<IdentityMutationEmailProofDecision, ApplicationError>;

    async fn complete_email_proof(
        &self,
        completion: CompleteIdentityMutationEmailProof,
    ) -> Result<IdentityMutationRecord, ApplicationError>;

    async fn confirm_ready(
        &self,
        intent_id: Uuid,
        intent: &VersionedDigest,
        browser_binding: &VersionedDigest,
        csrf: &VersionedDigest,
        expected_revision: i64,
        now: OffsetDateTime,
    ) -> Result<IdentityMutationRecord, ApplicationError>;
}

pub(crate) trait IdentityMutationTargetIssuer: Send + Sync {
    fn random_handle(&self, bytes: usize) -> Result<Zeroizing<String>, ApplicationError>;
    fn digest_handle(
        &self,
        intent_id: Uuid,
        value: &[u8],
    ) -> Result<VersionedDigest, ApplicationError>;
    fn protect_create_result(
        &self,
        intent_id: Uuid,
        value: &[u8],
    ) -> Result<ProtectedValue, ApplicationError>;
    fn replay_create_result(
        &self,
        intent_id: Uuid,
        value: &ProtectedValue,
    ) -> Result<Zeroizing<Vec<u8>>, ApplicationError>;
}

pub(crate) trait IdentityMutationTargetVerifier: Send + Sync {
    #[cfg(test)]
    fn readable_key_versions(&self) -> BTreeSet<i32>;
    fn digest_handle_at(
        &self,
        intent_id: Uuid,
        value: &[u8],
        key_version: i32,
    ) -> Result<VersionedDigest, ApplicationError>;
}

pub(crate) trait IdentityMutationProofMaterialProtector: Send + Sync {
    fn protect_candidate(
        &self,
        context: IdentityMutationCandidateEvidenceContext,
        plaintext: &[u8],
    ) -> Result<CandidateEvidenceMaterial, ApplicationError>;

    fn issue_receipt_digest(
        &self,
        intent_id: Uuid,
        proof_slot_id: Uuid,
    ) -> Result<VersionedDigest, ApplicationError>;
}

/// Control-plane capability for reading already-issued candidate material. It deliberately cannot
/// protect candidate bytes or mint a proof receipt.
pub(crate) trait IdentityMutationCandidateVerifier: Send + Sync {
    fn unprotect_candidate(
        &self,
        context: &IdentityMutationCandidateEvidenceContext,
        ciphertext: &ProtectedValue,
    ) -> Result<Zeroizing<Vec<u8>>, ApplicationError>;

    fn digest_candidate_at(
        &self,
        context: &IdentityMutationCandidateEvidenceContext,
        plaintext: &[u8],
        key_version: i32,
    ) -> Result<VersionedDigest, ApplicationError>;
}

/// Narrow Runtime-only capability for producing durable email identity material. It exposes no
/// general candidate-evidence or receipt authority.
pub(crate) trait IdentityMutationDurableEmailProtector: Send + Sync {
    fn protect_durable_address(
        &self,
        project_id: Uuid,
        identity_id: Uuid,
        normalized_address: &[u8],
    ) -> Result<ProtectedValue, ApplicationError>;
}

pub(crate) struct IdentityMutationControlService {
    repository: Arc<dyn ControlIdentityMutationRepository>,
    target_issuer: Arc<dyn IdentityMutationTargetIssuer>,
    candidate_verifier: Arc<dyn IdentityMutationCandidateVerifier>,
    clock: Arc<dyn Clock>,
    runtime_base: Url,
    provider_capabilities: IdentityMutationProviderCapabilities,
}

impl IdentityMutationControlService {
    #[cfg(test)]
    pub(crate) async fn repository_control_read(
        &self,
        project_id: Uuid,
        intent_id: Uuid,
        now: OffsetDateTime,
    ) -> Result<IdentityMutationRecord, ApplicationError> {
        self.repository
            .control_read(project_id, intent_id, now)
            .await
    }

    #[cfg(test)]
    pub(crate) async fn repository_confirm_control(
        &self,
        confirmation: PreparedIdentityMutationConfirmation,
    ) -> Result<IdentityMutationRecord, ApplicationError> {
        self.repository.confirm_control(confirmation).await
    }

    pub(crate) fn new(
        repository: Arc<dyn ControlIdentityMutationRepository>,
        target_issuer: Arc<dyn IdentityMutationTargetIssuer>,
        candidate_verifier: Arc<dyn IdentityMutationCandidateVerifier>,
        clock: Arc<dyn Clock>,
        runtime_base: Url,
        provider_capabilities: IdentityMutationProviderCapabilities,
    ) -> Result<Self, ApplicationError> {
        if !matches!(runtime_base.scheme(), "http" | "https") || runtime_base.host_str().is_none() {
            return Err(ApplicationError::InvalidInput);
        }
        Ok(Self {
            repository,
            target_issuer,
            candidate_verifier,
            clock,
            runtime_base,
            provider_capabilities,
        })
    }

    pub(crate) async fn create(
        &self,
        command: CreateIdentityMutation,
    ) -> Result<IdentityMutationCreateOutcome, ApplicationError> {
        validate_create(&command)?;
        let now = self.clock.now();
        let intent_id = Uuid::new_v4();
        let handle = self.credential_with_id(intent_id)?;
        let hosted_handle_digest = self
            .target_issuer
            .digest_handle(intent_id, handle.as_bytes())?;
        let hosted_target = self.hosted_target(&handle)?;
        let protected_create_result = self
            .target_issuer
            .protect_create_result(intent_id, hosted_target.as_bytes())?;
        let result = self
            .repository
            .create(PreparedIdentityMutationCreate {
                request_digest: create_request_digest(&command),
                command,
                provider_capabilities: self.provider_capabilities.clone(),
                runtime_base: self.runtime_base.to_string(),
                intent_id,
                hosted_handle_digest,
                protected_create_result,
                created_at: now,
                expires_at: now + IDENTITY_MUTATION_LIFETIME,
            })
            .await?;
        match result {
            CreateIdentityMutationResult::Created(intent) => {
                Ok(IdentityMutationCreateOutcome::Created {
                    intent: intent.safe_view(),
                    hosted_target: Some(hosted_target),
                })
            }
            CreateIdentityMutationResult::Replayed {
                intent,
                protected_create_result,
            } => {
                let target = protected_create_result
                    .map(|value| self.target_issuer.replay_create_result(intent.id, &value))
                    .transpose()?
                    .map(|value| {
                        String::from_utf8(value.to_vec()).map_err(|_| ApplicationError::Integrity)
                    })
                    .transpose()?;
                Ok(IdentityMutationCreateOutcome::Replayed {
                    intent: intent.safe_view(),
                    hosted_target: target,
                })
            }
        }
    }

    pub(crate) async fn read(
        &self,
        project_id: Uuid,
        intent_id: Uuid,
    ) -> Result<IdentityMutationView, ApplicationError> {
        self.repository
            .control_read(project_id, intent_id, self.clock.now())
            .await
            .map(|record| record.safe_view())
    }

    pub(crate) async fn cancel(
        &self,
        project_id: Uuid,
        intent_id: Uuid,
        expected_revision: i64,
        correlation_id: Uuid,
    ) -> Result<IdentityMutationView, ApplicationError> {
        validate_positive_revision(expected_revision)?;
        self.repository
            .cancel(
                project_id,
                intent_id,
                expected_revision,
                correlation_id,
                self.clock.now(),
            )
            .await
            .map(|record| record.safe_view())
    }

    pub(crate) async fn confirm(
        &self,
        project_id: Uuid,
        intent_id: Uuid,
        expected_revision: i64,
        expected_kind: IdentityMutationKind,
        correlation_id: Uuid,
    ) -> Result<IdentityMutationView, ApplicationError> {
        validate_positive_revision(expected_revision)?;
        if project_id.is_nil() || intent_id.is_nil() || correlation_id.is_nil() {
            return Err(ApplicationError::InvalidInput);
        }
        let now = self.clock.now();
        let preparation = self
            .repository
            .prepare_control_confirmation(
                project_id,
                intent_id,
                expected_revision,
                expected_kind,
                now,
            )
            .await?;
        validate_control_preparation(
            &preparation,
            project_id,
            intent_id,
            expected_revision,
            expected_kind,
        )?;
        let candidate = preparation
            .candidate_evidence
            .as_ref()
            .map(|evidence| self.prepare_candidate(evidence))
            .transpose()?;
        self.repository
            .confirm_control(PreparedIdentityMutationConfirmation {
                project_id,
                intent_id,
                expected_intent_revision: expected_revision,
                expected_kind,
                candidate,
                correlation_id,
                now,
            })
            .await
            .map(|record| record.safe_view())
    }

    fn prepare_candidate(
        &self,
        evidence: &IdentityMutationCandidateEvidenceEnvelope,
    ) -> Result<PreparedIdentityMutationCandidate, ApplicationError> {
        validate_candidate_context(&evidence.context)?;
        let plaintext = self
            .candidate_verifier
            .unprotect_candidate(&evidence.context, &evidence.ciphertext)?;
        let recomputed = self.candidate_verifier.digest_candidate_at(
            &evidence.context,
            plaintext.as_slice(),
            evidence.digest.key_version,
        )?;
        if recomputed != evidence.digest {
            return Err(ApplicationError::Integrity);
        }
        let candidate = decode_candidate(evidence.context.candidate_kind, plaintext.as_slice())?;
        validate_candidate(&candidate)?;
        Ok(PreparedIdentityMutationCandidate {
            context: evidence.context.clone(),
            evidence_digest: evidence.digest.clone(),
            candidate,
        })
    }

    fn credential_with_id(&self, id: Uuid) -> Result<Zeroizing<String>, ApplicationError> {
        let random = self.target_issuer.random_handle(32)?;
        Ok(Zeroizing::new(format!("{id}.{}", random.as_str())))
    }

    fn hosted_target(&self, handle: &str) -> Result<String, ApplicationError> {
        self.runtime_base
            .join(&format!("auth/identity-mutations/{handle}"))
            .map(String::from)
            .map_err(|_| ApplicationError::Integrity)
    }
}

#[async_trait]
pub(crate) trait IdentityMutationRuntimePort: Send + Sync {
    async fn bootstrap(
        &self,
        interaction: &str,
        browser_binding: Option<&str>,
    ) -> Result<IdentityMutationBootstrap, ApplicationError>;

    async fn establish_magic_transfer_context(
        &self,
        challenge_id: Uuid,
    ) -> Result<IdentityMutationMagicTransferGate, ApplicationError>;

    async fn start_method(
        &self,
        command: StartIdentityMutationMethod,
    ) -> Result<StartedIdentityMutationMethod, ApplicationError>;

    async fn begin_email_challenge(
        &self,
        request: BeginIdentityMutationEmailChallenge,
    ) -> Result<IdentityMutationEmailChallengeAccepted, ApplicationError>;

    async fn verify_email_proof(
        &self,
        request: VerifyRawIdentityMutationEmailProof,
    ) -> Result<IdentityMutationEmailCompletionDecision, ApplicationError>;

    async fn verify_magic_transfer(
        &self,
        request: VerifyIdentityMutationMagicTransferProof,
    ) -> Result<IdentityMutationEmailCompletionDecision, ApplicationError>;

    async fn confirm_ready(
        &self,
        command: ConfirmIdentityMutationReady,
    ) -> Result<IdentityMutationView, ApplicationError>;

    async fn deny_provider_callback(
        &self,
        denial: IdentityMutationProviderDenial,
    ) -> Result<IdentityMutationView, ApplicationError>;

    async fn complete_provider_callback(
        &self,
        callback: IdentityMutationProviderCallback,
    ) -> Result<IdentityMutationCallbackOutcome, ApplicationError>;
}

pub(crate) struct IdentityMutationRuntimeService {
    repository: Arc<dyn RuntimeIdentityMutationRepository>,
    protector: Arc<dyn RuntimeProtector>,
    target_verifier: Arc<dyn IdentityMutationTargetVerifier>,
    proof_material: Arc<dyn IdentityMutationProofMaterialProtector>,
    durable_email: Arc<dyn IdentityMutationDurableEmailProtector>,
    provider: Arc<dyn UpstreamProviderClient>,
    provider_secrets: Arc<dyn ProviderSecretResolver>,
    clock: Arc<dyn Clock>,
    runtime_base: Url,
    provider_capabilities: IdentityMutationProviderCapabilities,
}

#[async_trait]
impl IdentityMutationRuntimePort for IdentityMutationRuntimeService {
    async fn bootstrap(
        &self,
        interaction: &str,
        browser_binding: Option<&str>,
    ) -> Result<IdentityMutationBootstrap, ApplicationError> {
        self.bootstrap(interaction, browser_binding).await
    }

    async fn establish_magic_transfer_context(
        &self,
        challenge_id: Uuid,
    ) -> Result<IdentityMutationMagicTransferGate, ApplicationError> {
        self.establish_magic_transfer_context(challenge_id).await
    }

    async fn start_method(
        &self,
        command: StartIdentityMutationMethod,
    ) -> Result<StartedIdentityMutationMethod, ApplicationError> {
        self.start_method(command).await
    }

    async fn begin_email_challenge(
        &self,
        request: BeginIdentityMutationEmailChallenge,
    ) -> Result<IdentityMutationEmailChallengeAccepted, ApplicationError> {
        self.begin_email_challenge(request).await
    }

    async fn verify_email_proof(
        &self,
        request: VerifyRawIdentityMutationEmailProof,
    ) -> Result<IdentityMutationEmailCompletionDecision, ApplicationError> {
        self.verify_email_proof(request).await
    }

    async fn verify_magic_transfer(
        &self,
        request: VerifyIdentityMutationMagicTransferProof,
    ) -> Result<IdentityMutationEmailCompletionDecision, ApplicationError> {
        self.verify_magic_transfer(request).await
    }

    async fn confirm_ready(
        &self,
        command: ConfirmIdentityMutationReady,
    ) -> Result<IdentityMutationView, ApplicationError> {
        self.confirm_ready(command).await
    }

    async fn deny_provider_callback(
        &self,
        denial: IdentityMutationProviderDenial,
    ) -> Result<IdentityMutationView, ApplicationError> {
        self.deny_provider_callback(denial).await
    }

    async fn complete_provider_callback(
        &self,
        callback: IdentityMutationProviderCallback,
    ) -> Result<IdentityMutationCallbackOutcome, ApplicationError> {
        self.complete_provider_callback(callback).await
    }
}

impl IdentityMutationRuntimeService {
    #[cfg(test)]
    pub(crate) async fn repository_digest_versions(
        &self,
        intent_id: Uuid,
        now: OffsetDateTime,
    ) -> Result<IdentityMutationDigestVersions, ApplicationError> {
        self.repository.digest_versions(intent_id, now).await
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        repository: Arc<dyn RuntimeIdentityMutationRepository>,
        protector: Arc<dyn RuntimeProtector>,
        target_verifier: Arc<dyn IdentityMutationTargetVerifier>,
        proof_material: Arc<dyn IdentityMutationProofMaterialProtector>,
        durable_email: Arc<dyn IdentityMutationDurableEmailProtector>,
        provider: Arc<dyn UpstreamProviderClient>,
        provider_secrets: Arc<dyn ProviderSecretResolver>,
        clock: Arc<dyn Clock>,
        runtime_base: Url,
        provider_capabilities: IdentityMutationProviderCapabilities,
    ) -> Self {
        Self {
            repository,
            protector,
            target_verifier,
            proof_material,
            durable_email,
            provider,
            provider_secrets,
            clock,
            runtime_base,
            provider_capabilities,
        }
    }

    pub(crate) async fn bootstrap(
        &self,
        interaction: &str,
        browser_binding: Option<&str>,
    ) -> Result<IdentityMutationBootstrap, ApplicationError> {
        let id = credential_id(interaction)?;
        let now = self.clock.now();
        let versions = self.repository.digest_versions(id, now).await?;
        let intent_digest =
            self.target_verifier
                .digest_handle_at(id, interaction.as_bytes(), versions.intent)?;
        let (record, browser_binding, fresh_csrf) = if let Some(binding) = browser_binding {
            let version = versions
                .browser_binding
                .ok_or(ApplicationError::Integrity)?;
            let browser = self.protector.digest_at(
                OpaquePurpose::IdentityMutationBrowser,
                id.as_bytes(),
                binding.as_bytes(),
                version,
            )?;
            (
                self.repository
                    .hosted_read(&intent_digest, &browser, now)
                    .await?,
                Zeroizing::new(binding.to_owned()),
                None,
            )
        } else {
            let raw = self.credential_with_id(id)?;
            let browser = self.protector.digest(
                OpaquePurpose::IdentityMutationBrowser,
                id.as_bytes(),
                raw.as_bytes(),
            )?;
            let csrf = self.protector.derive_opaque(
                OpaquePurpose::IdentityMutationCsrf,
                id.as_bytes(),
                None,
            )?;
            let csrf_digest = self.protector.digest(
                OpaquePurpose::IdentityMutationCsrf,
                id.as_bytes(),
                csrf.as_bytes(),
            )?;
            let record = self
                .repository
                .bind_browser(&intent_digest, &browser, &csrf_digest, now)
                .await?;
            (record, raw, Some(csrf))
        };
        let csrf = if let Some(csrf) = fresh_csrf {
            csrf
        } else {
            self.protector.derive_opaque(
                OpaquePurpose::IdentityMutationCsrf,
                record.id.as_bytes(),
                record.csrf_key_version,
            )?
        };
        Ok(IdentityMutationBootstrap {
            intent: record.safe_view(),
            browser_binding,
            csrf,
        })
    }

    pub(crate) async fn start_method(
        &self,
        command: StartIdentityMutationMethod,
    ) -> Result<StartedIdentityMutationMethod, ApplicationError> {
        let (id, intent, browser, csrf, current) = self
            .authenticated_intent(
                &command.project_public_id,
                &command.interaction,
                &command.browser_binding,
                &command.csrf,
                command.expected_revision,
            )
            .await?;
        let slot = current.slot(command.proof_slot_id)?;
        if slot.method_kind != command.asserted_method
            || slot.state != IdentityMutationSlotState::Pending
        {
            return Err(ApplicationError::InvalidTransition);
        }
        match command.asserted_method {
            IdentityMutationProofMethodKind::Provider => {
                self.start_provider(command, id, intent, browser, csrf, current)
                    .await
            }
            IdentityMutationProofMethodKind::Email => self
                .repository
                .begin_email(
                    id,
                    command.proof_slot_id,
                    &intent,
                    &browser,
                    &csrf,
                    command.expected_revision,
                    self.clock.now(),
                )
                .await
                .map(|record| StartedIdentityMutationMethod::EmailAddressEntry(record.safe_view())),
        }
    }

    pub(crate) async fn confirm_ready(
        &self,
        command: ConfirmIdentityMutationReady,
    ) -> Result<IdentityMutationView, ApplicationError> {
        let (id, intent, browser, csrf, _current) = self
            .authenticated_intent(
                &command.project_public_id,
                &command.interaction,
                &command.browser_binding,
                &command.csrf,
                command.expected_revision,
            )
            .await?;
        self.repository
            .confirm_ready(
                id,
                &intent,
                &browser,
                &csrf,
                command.expected_revision,
                self.clock.now(),
            )
            .await
            .map(|record| record.safe_view())
    }

    pub(crate) async fn deny_provider_callback(
        &self,
        denial: IdentityMutationProviderDenial,
    ) -> Result<IdentityMutationView, ApplicationError> {
        validate_callback_owner(&denial.state, denial.proof_slot_id)?;
        let versions = self
            .repository
            .provider_digest_versions(denial.intent_id, denial.proof_slot_id, self.clock.now())
            .await?;
        let state = self.protector.digest_at(
            OpaquePurpose::IdentityMutationProviderState,
            denial.proof_slot_id.as_bytes(),
            denial.state.as_bytes(),
            versions.upstream_state,
        )?;
        let browser = self.protector.digest_at(
            OpaquePurpose::IdentityMutationBrowser,
            denial.intent_id.as_bytes(),
            denial.browser_binding.as_bytes(),
            versions.browser_binding,
        )?;
        self.repository
            .deny_provider_callback(
                denial.intent_id,
                denial.proof_slot_id,
                &denial.project_public_id,
                &denial.provider_key,
                &state,
                &browser,
                denial.safe_outcome,
                self.clock.now(),
            )
            .await
            .map(|record| record.safe_view())
    }

    pub(crate) async fn complete_provider_callback(
        &self,
        callback: IdentityMutationProviderCallback,
    ) -> Result<IdentityMutationCallbackOutcome, ApplicationError> {
        if callback.code.is_empty() || callback.code.len() > MAX_CALLBACK_CODE_BYTES {
            return Err(ApplicationError::InvalidInput);
        }
        validate_callback_owner(&callback.state, callback.proof_slot_id)?;
        let versions = self
            .repository
            .provider_digest_versions(callback.intent_id, callback.proof_slot_id, self.clock.now())
            .await?;
        let state = self.protector.digest_at(
            OpaquePurpose::IdentityMutationProviderState,
            callback.proof_slot_id.as_bytes(),
            callback.state.as_bytes(),
            versions.upstream_state,
        )?;
        let browser = self.protector.digest_at(
            OpaquePurpose::IdentityMutationBrowser,
            callback.intent_id.as_bytes(),
            callback.browser_binding.as_bytes(),
            versions.browser_binding,
        )?;
        let claimed = self
            .repository
            .claim_provider_callback(
                callback.intent_id,
                callback.proof_slot_id,
                &callback.project_public_id,
                &callback.provider_key,
                &state,
                &browser,
                self.clock.now(),
            )
            .await?;
        let claimed = match claimed {
            ClaimIdentityMutationProvider::Claimed(record) => record,
            ClaimIdentityMutationProvider::Duplicate(record) => {
                drop(record);
                return Ok(IdentityMutationCallbackOutcome::Duplicate);
            }
            ClaimIdentityMutationProvider::TerminalizedStaleAuthority => {
                return Ok(IdentityMutationCallbackOutcome::TerminalizedStaleAuthority);
            }
        };
        match self.exchange_and_complete(&callback, claimed.clone()).await {
            Ok(outcome) => Ok(outcome),
            Err(_) => resolve_failed_provider(
                self.repository
                    .fail_provider_callback(
                        &claimed,
                        callback.proof_slot_id,
                        "provider_exchange_failed",
                        self.clock.now(),
                    )
                    .await,
            ),
        }
    }

    pub(crate) async fn prepare_email_generation(
        &self,
        command: PrepareIdentityMutationEmailGeneration,
    ) -> Result<IdentityMutationEmailGenerationPreparation, ApplicationError> {
        let (intent_id, intent, browser, csrf, current) = self
            .authenticated_intent(
                &command.project_public_id,
                &command.interaction,
                &command.browser_binding,
                &command.csrf,
                command.expected_revision,
            )
            .await?;
        let slot = current.slot(command.proof_slot_id)?;
        if slot.method_kind != IdentityMutationProofMethodKind::Email
            || !matches!(
                slot.state,
                IdentityMutationSlotState::EmailAddressEntry
                    | IdentityMutationSlotState::EmailChallengePending
            )
        {
            return Err(ApplicationError::InvalidTransition);
        }
        let preparation = self
            .repository
            .prepare_email_generation(
                intent_id,
                command.proof_slot_id,
                &intent,
                &browser,
                &csrf,
                command.expected_revision,
                self.clock.now(),
            )
            .await?;
        validate_email_generation_preparation(&preparation, &current, command.proof_slot_id)?;
        Ok(preparation)
    }

    pub(crate) async fn commit_email_generation(
        &self,
        generation: CommitIdentityMutationEmailGeneration,
    ) -> Result<IdentityMutationView, ApplicationError> {
        validate_email_generation(&generation)?;
        self.repository
            .commit_email_generation(generation)
            .await
            .map(|record| record.safe_view())
    }

    /// HTTP-safe email challenge entry point. Canonicalization, random authority, purpose-bound
    /// digests, encryption and outbox construction all remain inside the Runtime service.
    #[allow(clippy::too_many_lines)]
    pub(crate) async fn begin_email_challenge(
        &self,
        request: BeginIdentityMutationEmailChallenge,
    ) -> Result<IdentityMutationEmailChallengeAccepted, ApplicationError> {
        let canonical = crate::domain::CanonicalEmail::parse_v1(&request.email)
            .map_err(|_| ApplicationError::InvalidInput)?;
        let preparation = self
            .prepare_email_generation(PrepareIdentityMutationEmailGeneration {
                project_public_id: request.project_public_id.clone(),
                interaction: request.interaction.clone(),
                proof_slot_id: request.proof_slot_id,
                browser_binding: request.browser_binding,
                csrf: request.csrf,
                expected_revision: request.expected_revision,
            })
            .await?;
        let challenge_id = Uuid::new_v4();
        let outbox_id = Uuid::new_v4();
        let context = mutation_email_challenge_context(
            preparation.project_id,
            preparation.intent_id,
            preparation.proof_slot_id,
            challenge_id,
            preparation.next_generation,
        );
        let (recipient_digests, lookup_digest) = derive_mutation_email_aliases(
            self.protector.as_ref(),
            preparation.project_id,
            &canonical,
        )?;
        let address = self.protector.protect(
            ProtectedPurpose::EmailChallengeAddress,
            &context,
            canonical.expose().as_bytes(),
        )?;
        let otp = preparation
            .policy
            .otp_enabled
            .then(|| {
                u8::try_from(preparation.policy.otp_digits)
                    .map_err(|_| crate::domain::DomainError::InvalidValue)
                    .and_then(crate::domain::generate_decimal_otp)
            })
            .transpose()
            .map_err(ApplicationError::from)?;
        let magic = preparation
            .policy
            .magic_link_enabled
            .then(|| self.protector.random_opaque(24))
            .transpose()?;
        let otp_digest = otp
            .as_ref()
            .map(|proof| {
                self.protector
                    .digest(OpaquePurpose::EmailOtpProof, &context, proof.as_bytes())
            })
            .transpose()?;
        let magic_digest = magic
            .as_ref()
            .map(|proof| {
                self.protector
                    .digest(OpaquePurpose::EmailMagicProof, &context, proof.as_bytes())
            })
            .transpose()?;
        let now = self.clock.now();
        let otp_expires_at = otp.as_ref().map(|_| {
            std::cmp::min(
                now + Duration::seconds(i64::from(preparation.policy.otp_validity_seconds)),
                preparation.intent_expires_at,
            )
        });
        let magic_expires_at = magic.as_ref().map(|_| {
            std::cmp::min(
                now + Duration::seconds(i64::from(preparation.policy.magic_validity_seconds)),
                preparation.intent_expires_at,
            )
        });
        let expires_at = otp_expires_at
            .into_iter()
            .chain(magic_expires_at)
            .max()
            .ok_or(ApplicationError::Integrity)?;
        if expires_at <= now {
            return Err(ApplicationError::InvalidTransition);
        }
        let magic_url = magic
            .as_ref()
            .map(|proof| {
                self.runtime_base
                    .join(&format!(
                        "auth/identity-mutations/email/confirm/{challenge_id}"
                    ))
                    .map(|mut url| {
                        let fragment = url::form_urlencoded::Serializer::new(String::new())
                            .append_pair("proof", proof.as_str())
                            .append_pair("project", &request.project_public_id)
                            .append_pair("interaction", &request.interaction)
                            .append_pair("slot", &preparation.proof_slot_id.to_string())
                            .append_pair("generation", &preparation.next_generation.to_string())
                            .append_pair("revision", &(request.expected_revision + 1).to_string())
                            .finish();
                        url.set_fragment(Some(&fragment));
                        url.to_string()
                    })
                    .map_err(|_| ApplicationError::Integrity)
            })
            .transpose()?;
        let envelope_plaintext = Zeroizing::new(
            serde_json::to_vec(&serde_json::json!({"to": canonical.expose()}))
                .map_err(|_| ApplicationError::Integrity)?,
        );
        let mut message = String::from(
            "OwlAuth identity verification\r\n\r\nUse only the newest code or link for this identity proof.\r\n",
        );
        if let Some(otp) = otp.as_deref() {
            message.push_str("\r\nOne-time code: ");
            message.push_str(otp);
            message.push_str("\r\n");
        }
        if let Some(magic_url) = magic_url.as_deref() {
            message.push_str("\r\nVerification link: ");
            message.push_str(magic_url);
            message.push_str("\r\n");
        }
        message.push_str("\r\nIf you did not request this proof, ignore this message.\r\n");
        let body_plaintext = Zeroizing::new(message.into_bytes());
        let admitted_method = preparation.policy.clone();
        self.commit_email_generation(CommitIdentityMutationEmailGeneration {
            project_id: preparation.project_id,
            application_id: preparation.application_id,
            intent_id: preparation.intent_id,
            proof_slot_id: preparation.proof_slot_id,
            expected_intent_revision: request.expected_revision,
            expected_generation: preparation.next_generation,
            challenge_id,
            outbox_id,
            canonicalization_version: crate::domain::CanonicalEmail::version(),
            lookup_digest,
            recipient_digests,
            address,
            otp_digest,
            magic_digest,
            envelope: self.protector.protect(
                ProtectedPurpose::EmailOutboxEnvelope,
                &context,
                envelope_plaintext.as_slice(),
            )?,
            body: self.protector.protect(
                ProtectedPurpose::EmailOutboxBody,
                &context,
                body_plaintext.as_slice(),
            )?,
            message_id: format!("<{outbox_id}@mail.owlauth.invalid>"),
            admitted_method,
            issued_at: now,
            otp_expires_at,
            magic_expires_at,
            expires_at,
        })
        .await?;
        Ok(IdentityMutationEmailChallengeAccepted {
            revision: request.expected_revision + 1,
            challenge_id,
            generation: preparation.next_generation,
            otp_enabled: preparation.policy.otp_enabled,
            magic_link_enabled: preparation.policy.magic_link_enabled,
            expires_at,
        })
    }

    pub(crate) async fn establish_magic_transfer_context(
        &self,
        challenge_id: Uuid,
    ) -> Result<IdentityMutationMagicTransferGate, ApplicationError> {
        if challenge_id.is_nil() {
            return Err(ApplicationError::InvalidInput);
        }
        let context = self.protector.random_opaque(32)?;
        let csrf = self.protector.random_opaque(24)?;
        let context_digest = self.protector.digest(
            OpaquePurpose::IdentityMutationMagicTransferContext,
            challenge_id.as_bytes(),
            context.as_bytes(),
        )?;
        let csrf_digest = self.protector.digest(
            OpaquePurpose::IdentityMutationMagicTransferCsrf,
            challenge_id.as_bytes(),
            csrf.as_bytes(),
        )?;
        let established = self
            .repository
            .establish_magic_transfer_context(EstablishIdentityMutationMagicTransferContext {
                id: Uuid::new_v4(),
                challenge_id,
                context: context_digest,
                csrf: csrf_digest,
                now: self.clock.now(),
            })
            .await?;
        Ok(IdentityMutationMagicTransferGate {
            context,
            csrf,
            project_public_id: established.project_public_id,
            proof_slot_id: established.owner.proof_slot_id,
            generation: established.owner.generation,
            expected_revision: established.expected_intent_revision,
        })
    }

    pub(crate) async fn verify_magic_transfer(
        &self,
        request: VerifyIdentityMutationMagicTransferProof,
    ) -> Result<IdentityMutationEmailCompletionDecision, ApplicationError> {
        validate_positive_revision(request.expected_revision)?;
        validate_raw_email_proof(EmailProofKind::MagicLink, request.proof.as_str())?;
        let intent_id = credential_id(&request.interaction)?;
        let versions = self
            .repository
            .digest_versions(intent_id, self.clock.now())
            .await?;
        let intent = self.target_verifier.digest_handle_at(
            intent_id,
            request.interaction.as_bytes(),
            versions.intent,
        )?;
        let context = self.protector.digest(
            OpaquePurpose::IdentityMutationMagicTransferContext,
            request.challenge_id.as_bytes(),
            request.transfer_context.as_bytes(),
        )?;
        let csrf = self.protector.digest(
            OpaquePurpose::IdentityMutationMagicTransferCsrf,
            request.challenge_id.as_bytes(),
            request.csrf.as_bytes(),
        )?;
        let resolved = self
            .repository
            .resolve_magic_transfer_context(ResolveIdentityMutationMagicTransferContext {
                challenge_id: request.challenge_id,
                project_public_id: request.project_public_id.clone(),
                intent,
                context: context.clone(),
                csrf: csrf.clone(),
                now: self.clock.now(),
            })
            .await?;
        if resolved.owner.intent_id != intent_id
            || resolved.owner.proof_slot_id != request.proof_slot_id
            || resolved.owner.challenge_id != request.challenge_id
            || resolved.owner.generation != request.generation
            || resolved.project_public_id != request.project_public_id
            || resolved.expected_intent_revision != request.expected_revision
        {
            return Ok(IdentityMutationEmailCompletionDecision::Invalid);
        }
        let browser_binding = request
            .browser_binding
            .as_deref()
            .map(|binding| {
                self.protector.digest_at(
                    OpaquePurpose::IdentityMutationBrowser,
                    intent_id.as_bytes(),
                    binding.as_bytes(),
                    versions
                        .browser_binding
                        .ok_or(ApplicationError::Integrity)?,
                )
            })
            .transpose()?;
        self.complete_email_proof(SubmitIdentityMutationEmailProof {
            project_id: resolved.owner.project_id,
            intent_id,
            proof_slot_id: request.proof_slot_id,
            challenge_id: request.challenge_id,
            generation: request.generation,
            proof_kind: EmailProofKind::MagicLink,
            proof: request.proof,
            browser_binding,
            csrf,
            transfer_context: Some(context),
            expected_intent_revision: request.expected_revision,
        })
        .await
    }

    /// HTTP-safe OTP/magic verifier. The service derives exact browser and CSRF digests; callers
    /// provide only bounded raw values and public handles.
    pub(crate) async fn verify_email_proof(
        &self,
        request: VerifyRawIdentityMutationEmailProof,
    ) -> Result<IdentityMutationEmailCompletionDecision, ApplicationError> {
        validate_raw_email_proof(request.proof_kind, request.proof.as_str())?;
        let (intent_id, _intent, browser, csrf, current) = self
            .authenticated_intent(
                &request.project_public_id,
                &request.interaction,
                &request.browser_binding,
                &request.csrf,
                request.expected_revision,
            )
            .await?;
        if current.slot(request.proof_slot_id)?.method_kind
            != IdentityMutationProofMethodKind::Email
        {
            return Err(ApplicationError::InvalidTransition);
        }
        self.complete_email_proof(SubmitIdentityMutationEmailProof {
            project_id: current.project_id,
            intent_id,
            proof_slot_id: request.proof_slot_id,
            challenge_id: request.challenge_id,
            generation: request.generation,
            proof_kind: request.proof_kind,
            proof: request.proof,
            browser_binding: Some(browser),
            csrf,
            transfer_context: None,
            expected_intent_revision: request.expected_revision,
        })
        .await
    }

    pub(crate) async fn complete_email_proof(
        &self,
        submission: SubmitIdentityMutationEmailProof,
    ) -> Result<IdentityMutationEmailCompletionDecision, ApplicationError> {
        validate_email_proof_submission(&submission)?;
        let key = IdentityMutationEmailProofKey {
            project_id: submission.project_id,
            intent_id: submission.intent_id,
            proof_slot_id: submission.proof_slot_id,
            challenge_id: submission.challenge_id,
            proof_kind: submission.proof_kind,
        };
        let Some(key_version) = self.repository.email_proof_key_version(key).await? else {
            return Ok(IdentityMutationEmailCompletionDecision::Invalid);
        };
        let owner_context = mutation_email_challenge_context(
            submission.project_id,
            submission.intent_id,
            submission.proof_slot_id,
            submission.challenge_id,
            submission.generation,
        );
        let purpose = match submission.proof_kind {
            EmailProofKind::Otp => OpaquePurpose::EmailOtpProof,
            EmailProofKind::MagicLink => OpaquePurpose::EmailMagicProof,
        };
        let proof_digest = self.protector.digest_at(
            purpose,
            &owner_context,
            submission.proof.as_bytes(),
            key_version,
        )?;
        let verification = VerifyIdentityMutationEmailProof {
            project_id: submission.project_id,
            intent_id: submission.intent_id,
            proof_slot_id: submission.proof_slot_id,
            challenge_id: submission.challenge_id,
            generation: submission.generation,
            proof_kind: submission.proof_kind,
            proof_digest,
            browser_binding: submission.browser_binding,
            csrf: submission.csrf,
            transfer_context: submission.transfer_context,
            expected_intent_revision: submission.expected_intent_revision,
            now: self.clock.now(),
        };
        let decision = self
            .repository
            .verify_email_proof(verification.clone())
            .await?;
        let IdentityMutationEmailProofDecision::Accepted(challenge) = decision else {
            return Ok(IdentityMutationEmailCompletionDecision::Invalid);
        };
        self.complete_verified_email_proof(verification, challenge, &owner_context)
            .await
    }

    async fn complete_verified_email_proof(
        &self,
        verification: VerifyIdentityMutationEmailProof,
        challenge: VerifiedIdentityMutationEmailChallenge,
        owner_context: &[u8],
    ) -> Result<IdentityMutationEmailCompletionDecision, ApplicationError> {
        validate_verified_email_challenge(&verification, &challenge)?;
        let normalized = self.protector.unprotect(
            ProtectedPurpose::EmailChallengeAddress,
            owner_context,
            &challenge.address,
        )?;
        let normalized =
            std::str::from_utf8(normalized.as_slice()).map_err(|_| ApplicationError::Integrity)?;
        let canonical = crate::domain::CanonicalEmail::parse_v1(normalized)
            .map_err(|_| ApplicationError::Integrity)?;
        if challenge.canonicalization_version != crate::domain::CanonicalEmail::version()
            || canonical.expose() != normalized
        {
            return Err(ApplicationError::Integrity);
        }
        let verified_challenge_lookup = verify_mutation_email_challenge_lookup(
            self.protector.as_ref(),
            challenge.project_id,
            &canonical,
            &challenge.lookup_digest,
        )?;
        let (lookup_aliases, active_alias) = derive_mutation_email_aliases(
            self.protector.as_ref(),
            challenge.project_id,
            &canonical,
        )?;
        let material = self.prepare_email_proof_material(
            &challenge,
            canonical.expose(),
            lookup_aliases,
            active_alias,
            1,
            &verified_challenge_lookup,
        )?;
        let receipt_digest = self
            .proof_material
            .issue_receipt_digest(challenge.intent_id, challenge.proof_slot_id)?;
        let completed = self
            .repository
            .complete_email_proof(CompleteIdentityMutationEmailProof {
                verification,
                verified_challenge_lookup,
                material,
                receipt_id: Uuid::new_v4(),
                receipt_digest,
            })
            .await?;
        Ok(IdentityMutationEmailCompletionDecision::Completed(
            completed.safe_view(),
        ))
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "candidate and existing proof material share the same exact alias authority snapshot"
    )]
    fn prepare_email_proof_material(
        &self,
        challenge: &VerifiedIdentityMutationEmailChallenge,
        normalized_address: &str,
        lookup_aliases: Vec<VersionedDigest>,
        active_alias: VersionedDigest,
        alias_authority_revision: i64,
        verified_challenge_lookup: &VersionedDigest,
    ) -> Result<IdentityMutationEmailProofMaterial, ApplicationError> {
        if challenge.slot_role == IdentityMutationSlotRole::CandidateIdentity {
            if challenge.existing_identity_id.is_some()
                || challenge.existing_identity_revision.is_some()
            {
                return Err(ApplicationError::Integrity);
            }
            let identity_id = Uuid::new_v4();
            let durable_address = self.durable_email.protect_durable_address(
                challenge.project_id,
                identity_id,
                normalized_address.as_bytes(),
            )?;
            let candidate = IdentityMutationCandidate::Email(IdentityMutationEmailCandidate {
                identity_id,
                canonicalization_version: challenge.canonicalization_version,
                normalized_address: normalized_address.to_owned(),
                lookup_aliases,
                active_alias,
                alias_authority_revision,
                durable_address,
            });
            let context = IdentityMutationCandidateEvidenceContext {
                project_id: challenge.project_id,
                intent_id: challenge.intent_id,
                proof_slot_id: challenge.proof_slot_id,
                evidence_id: Uuid::new_v4(),
                evidence_revision: 1,
                candidate_kind: IdentityMutationCandidateKind::Email,
            };
            let plaintext = encode_candidate(&candidate)?;
            return self
                .protect_candidate_exact(&context, &plaintext)
                .map(IdentityMutationEmailProofMaterial::Candidate);
        }
        let identity_id = challenge
            .existing_identity_id
            .ok_or(ApplicationError::Integrity)?;
        let identity_revision = challenge
            .existing_identity_revision
            .filter(|revision| *revision > 0)
            .ok_or(ApplicationError::Integrity)?;
        Ok(IdentityMutationEmailProofMaterial::Existing(
            IdentityMutationExistingEmailEvidence {
                identity_id,
                identity_revision,
                verified_challenge_lookup: verified_challenge_lookup.clone(),
                lookup_aliases,
                active_alias,
                alias_authority_revision,
            },
        ))
    }

    async fn start_provider(
        &self,
        command: StartIdentityMutationMethod,
        intent_id: Uuid,
        intent: VersionedDigest,
        browser: VersionedDigest,
        csrf: VersionedDigest,
        current: IdentityMutationRecord,
    ) -> Result<StartedIdentityMutationMethod, ApplicationError> {
        let slot = current.slot(command.proof_slot_id)?;
        let authority = slot.provider.as_ref().ok_or(ApplicationError::Integrity)?;
        let capability = self
            .provider_capabilities
            .for_kind(authority.provider_kind)
            .filter(|capability| capability.adapter_key == authority.adapter_key)
            .ok_or(ApplicationError::RevisionConflict)?;
        if authority.adapter_capability_revision != capability.adapter_revision
            || authority.exact_scopes != capability.exact_nonrenewable_scopes
            || !authority.oidc_nonce_required
        {
            return Err(ApplicationError::RevisionConflict);
        }
        let state = self.credential_with_id(command.proof_slot_id)?;
        let state_digest = self.protector.digest(
            OpaquePurpose::IdentityMutationProviderState,
            command.proof_slot_id.as_bytes(),
            state.as_bytes(),
        )?;
        let nonce = self.protector.derive_opaque(
            OpaquePurpose::IdentityMutationNonce,
            command.proof_slot_id.as_bytes(),
            None,
        )?;
        let nonce_digest = self.protector.digest(
            OpaquePurpose::IdentityMutationNonce,
            command.proof_slot_id.as_bytes(),
            nonce.as_bytes(),
        )?;
        let (pkce_challenge, protected_pkce) = if authority.provider_pkce_required {
            let verifier = self.protector.random_opaque(32)?;
            let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
            let protected = self.protector.protect(
                ProtectedPurpose::IdentityMutationProviderPkce,
                command.proof_slot_id.as_bytes(),
                verifier.as_bytes(),
            )?;
            (challenge, Some(protected))
        } else {
            (String::new(), None)
        };
        let continuation = self.protector.protect(
            ProtectedPurpose::IdentityMutationCallbackContinuation,
            &callback_continuation_context(intent_id, command.proof_slot_id),
            command.interaction.as_bytes(),
        )?;
        let authorization = self
            .provider
            .authorization_url(ProviderAuthorizationRequest {
                kind: authority.provider_kind,
                issuer: authority.issuer.clone(),
                client_id: authority.client_id.clone(),
                callback_url: authority.callback_url.clone(),
                state: state.to_string(),
                nonce: nonce.to_string(),
                pkce_challenge,
                profile: ProviderRequestProfile::IdentityProof,
                egress_policy: authority.egress_policy.clone(),
            })
            .await
            .map_err(map_provider_error)?;
        if authorization.managed_supports_revocation.is_some() {
            return Err(ApplicationError::Integrity);
        }
        self.repository
            .start_provider(
                intent_id,
                command.proof_slot_id,
                &intent,
                &browser,
                &csrf,
                command.expected_revision,
                state_digest,
                nonce_digest,
                protected_pkce,
                continuation,
                self.clock.now(),
            )
            .await?;
        Ok(StartedIdentityMutationMethod::ProviderNavigation {
            url: authorization.url,
            proof_slot_id: command.proof_slot_id,
        })
    }

    #[allow(
        clippy::too_many_lines,
        reason = "provider exchange validates one frozen authority before issuing its exact proof material"
    )]
    async fn exchange_and_complete(
        &self,
        callback: &IdentityMutationProviderCallback,
        claimed: IdentityMutationRecord,
    ) -> Result<IdentityMutationCallbackOutcome, ApplicationError> {
        let slot = claimed.slot(callback.proof_slot_id)?;
        let authority = slot.provider.as_ref().ok_or(ApplicationError::Integrity)?;
        let capability = self
            .provider_capabilities
            .for_kind(authority.provider_kind)
            .filter(|capability| capability.adapter_key == authority.adapter_key)
            .ok_or(ApplicationError::RevisionConflict)?;
        if slot.state != IdentityMutationSlotState::ProviderExchangeInProgress
            || authority.adapter_capability_revision != capability.adapter_revision
            || authority.exact_scopes != capability.exact_nonrenewable_scopes
        {
            return Err(ApplicationError::RevisionConflict);
        }
        let secret = self
            .provider_secrets
            .resolve(authority.secret_material_id)
            .await?;
        let pkce = match &authority.provider_pkce {
            Some(value) => self.protector.unprotect(
                ProtectedPurpose::IdentityMutationProviderPkce,
                callback.proof_slot_id.as_bytes(),
                value,
            )?,
            None if !authority.provider_pkce_required => Zeroizing::new(Vec::new()),
            None => return Err(ApplicationError::Integrity),
        };
        let nonce = self.protector.derive_opaque(
            OpaquePurpose::IdentityMutationNonce,
            callback.proof_slot_id.as_bytes(),
            authority.oidc_nonce.as_ref().map(|value| value.key_version),
        )?;
        let identity = self
            .provider
            .exchange_code(ProviderCallbackRequest {
                kind: authority.provider_kind,
                issuer: authority.issuer.clone(),
                client_id: authority.client_id.clone(),
                client_secret: secret,
                callback_url: authority.callback_url.clone(),
                code: Zeroizing::new(callback.code.clone()),
                pkce_verifier: Zeroizing::new(
                    String::from_utf8(pkce.to_vec()).map_err(|_| ApplicationError::Integrity)?,
                ),
                expected_nonce: nonce,
                now: self.clock.now(),
                allowed_clock_skew_seconds: CALLBACK_CLOCK_SKEW_SECONDS,
                profile: ProviderRequestProfile::IdentityProof,
                egress_policy: authority.egress_policy.clone(),
            })
            .await
            .map_err(map_provider_error)?;
        let observation = nonrenewable_provider_observation(identity)?;
        let candidate_evidence = if slot.role == IdentityMutationSlotRole::CandidateIdentity {
            let candidate =
                IdentityMutationCandidate::Provider(IdentityMutationProviderCandidate {
                    issuer: observation.issuer.clone(),
                    subject: observation.subject.clone(),
                    admitted_profile: IdentityMutationAdmittedProviderProfile {
                        display_name: observation.display_name.clone(),
                        picture_url: observation.picture_url.clone(),
                    },
                    registration: IdentityMutationProviderRegistrationEvidence {
                        provider_configuration_id: authority.provider_configuration_id,
                        provider_configuration_revision: authority.provider_configuration_revision,
                        adapter_key: authority.adapter_key.clone(),
                        adapter_capability_revision: authority.adapter_capability_revision,
                        issuer: authority.issuer.clone(),
                    },
                });
            validate_candidate(&candidate)?;
            let context = IdentityMutationCandidateEvidenceContext {
                project_id: claimed.project_id,
                intent_id: claimed.id,
                proof_slot_id: callback.proof_slot_id,
                evidence_id: Uuid::new_v4(),
                evidence_revision: 1,
                candidate_kind: IdentityMutationCandidateKind::Provider,
            };
            let plaintext = encode_candidate(&candidate)?;
            Some(self.protect_candidate_exact(&context, &plaintext)?)
        } else {
            None
        };
        let receipt_digest = self
            .proof_material
            .issue_receipt_digest(claimed.id, callback.proof_slot_id)?;
        let continuation = authority
            .callback_continuation
            .as_ref()
            .ok_or(ApplicationError::Integrity)
            .and_then(|value| {
                self.protector.unprotect(
                    ProtectedPurpose::IdentityMutationCallbackContinuation,
                    &callback_continuation_context(claimed.id, callback.proof_slot_id),
                    value,
                )
            })
            .and_then(|value| {
                String::from_utf8(value.to_vec())
                    .map(Zeroizing::new)
                    .map_err(|_| ApplicationError::Integrity)
            })?;
        let completed = self
            .repository
            .complete_provider_callback(PreparedIdentityMutationProviderCompletion {
                claimed,
                proof_slot_id: callback.proof_slot_id,
                observation,
                candidate_evidence,
                receipt_id: Uuid::new_v4(),
                receipt_digest,
                now: self.clock.now(),
            })
            .await?;
        let _ = completed;
        Ok(IdentityMutationCallbackOutcome::Proved { continuation })
    }

    #[allow(clippy::type_complexity)]
    async fn authenticated_intent(
        &self,
        project_public_id: &str,
        interaction: &str,
        browser_binding: &str,
        csrf: &str,
        expected_revision: i64,
    ) -> Result<
        (
            Uuid,
            VersionedDigest,
            VersionedDigest,
            VersionedDigest,
            IdentityMutationRecord,
        ),
        ApplicationError,
    > {
        validate_positive_revision(expected_revision)?;
        let id = credential_id(interaction)?;
        let versions = self
            .repository
            .digest_versions(id, self.clock.now())
            .await?;
        let intent =
            self.target_verifier
                .digest_handle_at(id, interaction.as_bytes(), versions.intent)?;
        let browser = self.protector.digest_at(
            OpaquePurpose::IdentityMutationBrowser,
            id.as_bytes(),
            browser_binding.as_bytes(),
            versions
                .browser_binding
                .ok_or(ApplicationError::Integrity)?,
        )?;
        let current = self
            .repository
            .hosted_read(&intent, &browser, self.clock.now())
            .await?;
        if current.project_public_id != project_public_id || current.revision != expected_revision {
            return Err(ApplicationError::RevisionConflict);
        }
        let csrf_digest = self.protector.digest_at(
            OpaquePurpose::IdentityMutationCsrf,
            id.as_bytes(),
            csrf.as_bytes(),
            current
                .csrf_key_version
                .ok_or(ApplicationError::Integrity)?,
        )?;
        Ok((id, intent, browser, csrf_digest, current))
    }

    fn protect_candidate_exact(
        &self,
        context: &IdentityMutationCandidateEvidenceContext,
        plaintext: &[u8],
    ) -> Result<CandidateEvidenceMaterial, ApplicationError> {
        let material = self
            .proof_material
            .protect_candidate(context.clone(), plaintext)?;
        if &material.context != context {
            return Err(ApplicationError::Integrity);
        }
        validate_candidate_context(&material.context)?;
        validate_protected(&material.ciphertext)?;
        validate_digest(&material.digest)?;
        Ok(material)
    }

    fn credential_with_id(&self, id: Uuid) -> Result<Zeroizing<String>, ApplicationError> {
        let random = self.protector.random_opaque(32)?;
        Ok(Zeroizing::new(format!("{id}.{}", random.as_str())))
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProviderCandidateV1 {
    schema: String,
    issuer: String,
    subject: String,
    display_name: Option<String>,
    picture_url: Option<String>,
    provider_configuration_id: Uuid,
    provider_configuration_revision: i64,
    adapter_key: String,
    adapter_capability_revision: i64,
    registration_issuer: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EmailCandidateV1 {
    schema: String,
    identity_id: Uuid,
    canonicalization_version: i32,
    normalized_address: String,
    lookup_aliases: Vec<DigestV1>,
    active_alias: DigestV1,
    alias_authority_revision: i64,
    durable_address: ProtectedV1,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DigestV1 {
    key_version: i32,
    value: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProtectedV1 {
    key_version: i32,
    ciphertext: String,
}

impl From<&VersionedDigest> for DigestV1 {
    fn from(value: &VersionedDigest) -> Self {
        Self {
            key_version: value.key_version,
            value: URL_SAFE_NO_PAD.encode(value.value),
        }
    }
}

impl TryFrom<DigestV1> for VersionedDigest {
    type Error = ApplicationError;

    fn try_from(value: DigestV1) -> Result<Self, Self::Error> {
        let decoded = URL_SAFE_NO_PAD
            .decode(value.value)
            .map_err(|_| ApplicationError::Integrity)?;
        let bytes: [u8; 32] = decoded
            .try_into()
            .map_err(|_| ApplicationError::Integrity)?;
        Ok(Self {
            value: bytes,
            key_version: value.key_version,
        })
    }
}

impl From<&ProtectedValue> for ProtectedV1 {
    fn from(value: &ProtectedValue) -> Self {
        Self {
            key_version: value.key_version,
            ciphertext: URL_SAFE_NO_PAD.encode(&value.ciphertext),
        }
    }
}

impl TryFrom<ProtectedV1> for ProtectedValue {
    type Error = ApplicationError;

    fn try_from(value: ProtectedV1) -> Result<Self, Self::Error> {
        Ok(Self {
            ciphertext: URL_SAFE_NO_PAD
                .decode(value.ciphertext)
                .map_err(|_| ApplicationError::Integrity)?,
            key_version: value.key_version,
        })
    }
}

fn encode_candidate(candidate: &IdentityMutationCandidate) -> Result<Vec<u8>, ApplicationError> {
    match candidate {
        IdentityMutationCandidate::Provider(candidate) => {
            serde_json::to_vec(&ProviderCandidateV1 {
                schema: "owlauth.identity_mutation.provider_candidate.v1".to_owned(),
                issuer: candidate.issuer.clone(),
                subject: candidate.subject.clone(),
                display_name: candidate.admitted_profile.display_name.clone(),
                picture_url: candidate.admitted_profile.picture_url.clone(),
                provider_configuration_id: candidate.registration.provider_configuration_id,
                provider_configuration_revision: candidate
                    .registration
                    .provider_configuration_revision,
                adapter_key: candidate.registration.adapter_key.clone(),
                adapter_capability_revision: candidate.registration.adapter_capability_revision,
                registration_issuer: candidate.registration.issuer.clone(),
            })
        }
        IdentityMutationCandidate::Email(candidate) => serde_json::to_vec(&EmailCandidateV1 {
            schema: "owlauth.identity_mutation.email_candidate.v1".to_owned(),
            identity_id: candidate.identity_id,
            canonicalization_version: candidate.canonicalization_version,
            normalized_address: candidate.normalized_address.clone(),
            lookup_aliases: candidate
                .lookup_aliases
                .iter()
                .map(DigestV1::from)
                .collect(),
            active_alias: DigestV1::from(&candidate.active_alias),
            alias_authority_revision: candidate.alias_authority_revision,
            durable_address: ProtectedV1::from(&candidate.durable_address),
        }),
    }
    .map_err(|_| ApplicationError::Integrity)
}

fn decode_candidate(
    kind: IdentityMutationCandidateKind,
    plaintext: &[u8],
) -> Result<IdentityMutationCandidate, ApplicationError> {
    match kind {
        IdentityMutationCandidateKind::Provider => {
            let value: ProviderCandidateV1 =
                serde_json::from_slice(plaintext).map_err(|_| ApplicationError::Integrity)?;
            if value.schema != "owlauth.identity_mutation.provider_candidate.v1" {
                return Err(ApplicationError::Integrity);
            }
            Ok(IdentityMutationCandidate::Provider(
                IdentityMutationProviderCandidate {
                    issuer: value.issuer,
                    subject: value.subject,
                    admitted_profile: IdentityMutationAdmittedProviderProfile {
                        display_name: value.display_name,
                        picture_url: value.picture_url,
                    },
                    registration: IdentityMutationProviderRegistrationEvidence {
                        provider_configuration_id: value.provider_configuration_id,
                        provider_configuration_revision: value.provider_configuration_revision,
                        adapter_key: value.adapter_key,
                        adapter_capability_revision: value.adapter_capability_revision,
                        issuer: value.registration_issuer,
                    },
                },
            ))
        }
        IdentityMutationCandidateKind::Email => {
            let value: EmailCandidateV1 =
                serde_json::from_slice(plaintext).map_err(|_| ApplicationError::Integrity)?;
            if value.schema != "owlauth.identity_mutation.email_candidate.v1" {
                return Err(ApplicationError::Integrity);
            }
            Ok(IdentityMutationCandidate::Email(
                IdentityMutationEmailCandidate {
                    identity_id: value.identity_id,
                    canonicalization_version: value.canonicalization_version,
                    normalized_address: value.normalized_address,
                    lookup_aliases: value
                        .lookup_aliases
                        .into_iter()
                        .map(VersionedDigest::try_from)
                        .collect::<Result<_, _>>()?,
                    active_alias: value.active_alias.try_into()?,
                    alias_authority_revision: value.alias_authority_revision,
                    durable_address: value.durable_address.try_into()?,
                },
            ))
        }
    }
}

fn validate_control_preparation(
    preparation: &IdentityMutationControlConfirmationPreparation,
    project_id: Uuid,
    intent_id: Uuid,
    expected_revision: i64,
    expected_kind: IdentityMutationKind,
) -> Result<(), ApplicationError> {
    if preparation.project_id != project_id
        || preparation.intent_id != intent_id
        || preparation.expected_intent_revision != expected_revision
        || preparation.expected_kind != expected_kind
    {
        return Err(ApplicationError::Integrity);
    }
    if let Some(evidence) = &preparation.candidate_evidence {
        validate_candidate_context(&evidence.context)?;
        if evidence.context.project_id != project_id || evidence.context.intent_id != intent_id {
            return Err(ApplicationError::Integrity);
        }
        validate_digest(&evidence.digest)?;
        validate_protected(&evidence.ciphertext)?;
    }
    Ok(())
}

fn validate_candidate_context(
    context: &IdentityMutationCandidateEvidenceContext,
) -> Result<(), ApplicationError> {
    if context.project_id.is_nil()
        || context.intent_id.is_nil()
        || context.proof_slot_id.is_nil()
        || context.evidence_id.is_nil()
        || context.evidence_revision <= 0
    {
        return Err(ApplicationError::Integrity);
    }
    Ok(())
}

fn validate_candidate(candidate: &IdentityMutationCandidate) -> Result<(), ApplicationError> {
    match candidate {
        IdentityMutationCandidate::Provider(candidate) => {
            if candidate.issuer.is_empty()
                || candidate.issuer.len() > 2048
                || candidate.subject.is_empty()
                || candidate.subject.len() > 512
                || candidate.registration.provider_configuration_id.is_nil()
                || candidate.registration.provider_configuration_revision <= 0
                || candidate.registration.adapter_key.is_empty()
                || candidate.registration.adapter_key.len() > 128
                || candidate.registration.adapter_capability_revision <= 0
                || candidate.registration.issuer != candidate.issuer
                || candidate
                    .admitted_profile
                    .display_name
                    .as_ref()
                    .is_some_and(|value| value.chars().count() > 128)
                || candidate
                    .admitted_profile
                    .picture_url
                    .as_ref()
                    .is_some_and(|value| value.len() > 2048)
            {
                return Err(ApplicationError::Integrity);
            }
        }
        IdentityMutationCandidate::Email(candidate) => {
            let canonical = crate::domain::CanonicalEmail::parse_v1(&candidate.normalized_address)
                .map_err(|_| ApplicationError::Integrity)?;
            if candidate.identity_id.is_nil()
                || candidate.canonicalization_version != crate::domain::CanonicalEmail::version()
                || canonical.expose() != candidate.normalized_address
                || candidate.lookup_aliases.is_empty()
                || candidate.alias_authority_revision <= 0
                || !candidate.lookup_aliases.contains(&candidate.active_alias)
            {
                return Err(ApplicationError::Integrity);
            }
            validate_digest(&candidate.active_alias)?;
            for alias in &candidate.lookup_aliases {
                validate_digest(alias)?;
            }
            let versions = candidate
                .lookup_aliases
                .iter()
                .map(|alias| alias.key_version)
                .collect::<BTreeSet<_>>();
            if versions.len() != candidate.lookup_aliases.len() {
                return Err(ApplicationError::Integrity);
            }
            validate_protected(&candidate.durable_address)?;
        }
    }
    Ok(())
}

fn validate_digest(value: &VersionedDigest) -> Result<(), ApplicationError> {
    if value.key_version <= 0 || value.value == [0; 32] {
        return Err(ApplicationError::Integrity);
    }
    Ok(())
}

fn validate_protected(value: &ProtectedValue) -> Result<(), ApplicationError> {
    if value.key_version <= 0 || value.ciphertext.is_empty() {
        return Err(ApplicationError::Integrity);
    }
    Ok(())
}

fn validate_email_generation_preparation(
    preparation: &IdentityMutationEmailGenerationPreparation,
    current: &IdentityMutationRecord,
    proof_slot_id: Uuid,
) -> Result<(), ApplicationError> {
    if preparation.project_id != current.project_id
        || preparation.intent_id != current.id
        || preparation.proof_slot_id != proof_slot_id
        || preparation.application_id.is_nil()
        || preparation.next_generation <= 0
        || preparation.intent_expires_at != current.expires_at
    {
        return Err(ApplicationError::Integrity);
    }
    validate_admitted_email_method(&preparation.policy)
}

fn validate_email_generation(
    generation: &CommitIdentityMutationEmailGeneration,
) -> Result<(), ApplicationError> {
    if generation.project_id.is_nil()
        || generation.application_id.is_nil()
        || generation.intent_id.is_nil()
        || generation.proof_slot_id.is_nil()
        || generation.expected_intent_revision <= 0
        || generation.expected_generation <= 0
        || generation.challenge_id.is_nil()
        || generation.outbox_id.is_nil()
        || generation.canonicalization_version != crate::domain::CanonicalEmail::version()
        || generation.message_id.is_empty()
        || generation.message_id.len() > 255
        || generation.expires_at <= generation.issued_at
    {
        return Err(ApplicationError::InvalidInput);
    }
    validate_digest(&generation.lookup_digest)?;
    validate_protected(&generation.address)?;
    validate_protected(&generation.envelope)?;
    validate_protected(&generation.body)?;
    validate_admitted_email_method(&generation.admitted_method)?;
    if generation.admitted_method.otp_enabled != generation.otp_digest.is_some()
        || generation.admitted_method.magic_link_enabled != generation.magic_digest.is_some()
        || generation.admitted_method.otp_enabled != generation.otp_expires_at.is_some()
        || generation.admitted_method.magic_link_enabled != generation.magic_expires_at.is_some()
        || generation.otp_expires_at.is_some_and(|expires| {
            expires <= generation.issued_at || expires > generation.expires_at
        })
        || generation.magic_expires_at.is_some_and(|expires| {
            expires <= generation.issued_at || expires > generation.expires_at
        })
    {
        return Err(ApplicationError::InvalidInput);
    }
    if let Some(digest) = &generation.otp_digest {
        validate_digest(digest)?;
    }
    if let Some(digest) = &generation.magic_digest {
        validate_digest(digest)?;
    }
    Ok(())
}

fn validate_admitted_email_method(policy: &AdmittedEmailMethod) -> Result<(), ApplicationError> {
    if policy.policy_revision <= 0
        || policy.security_revision <= 0
        || policy.assignment_security_revision <= 0
        || (!policy.otp_enabled && !policy.magic_link_enabled)
        || policy.otp_digits <= 0
        || policy.otp_validity_seconds <= 0
        || policy.otp_max_attempts <= 0
        || policy.resend_after_seconds < 0
        || policy.max_generations <= 0
        || policy.magic_validity_seconds <= 0
        || policy.smtp_selection_kind.is_empty()
        || policy.smtp_selection_kind.len() > 64
        || policy.smtp_generation <= 0
        || policy.smtp_security_eligibility_revision <= 0
    {
        return Err(ApplicationError::Integrity);
    }
    Ok(())
}

fn validate_raw_email_proof(kind: EmailProofKind, proof: &str) -> Result<(), ApplicationError> {
    let valid = match kind {
        EmailProofKind::Otp => {
            (6..=10).contains(&proof.len()) && proof.bytes().all(|b| b.is_ascii_digit())
        }
        EmailProofKind::MagicLink => {
            (22..=128).contains(&proof.len())
                && proof
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
        }
    };
    valid.then_some(()).ok_or(ApplicationError::InvalidInput)
}

fn validate_email_proof_submission(
    submission: &SubmitIdentityMutationEmailProof,
) -> Result<(), ApplicationError> {
    if submission.project_id.is_nil()
        || submission.intent_id.is_nil()
        || submission.proof_slot_id.is_nil()
        || submission.challenge_id.is_nil()
        || submission.generation <= 0
        || submission.expected_intent_revision <= 0
        || submission.csrf.key_version <= 0
    {
        return Err(ApplicationError::InvalidInput);
    }
    let proof = submission.proof.as_str();
    let proof_valid = match submission.proof_kind {
        EmailProofKind::Otp => {
            (6..=10).contains(&proof.len())
                && proof.as_bytes().iter().all(u8::is_ascii_digit)
                && submission.browser_binding.is_some()
                && submission.transfer_context.is_none()
        }
        EmailProofKind::MagicLink => {
            (32..=512).contains(&proof.len())
                && ((submission.browser_binding.is_some() && submission.transfer_context.is_none())
                    || (submission.browser_binding.is_none()
                        && submission.transfer_context.is_some()))
        }
    };
    if !proof_valid {
        return Err(ApplicationError::InvalidInput);
    }
    validate_digest(&submission.csrf)?;
    if let Some(binding) = &submission.browser_binding {
        validate_digest(binding)?;
    }
    if let Some(context) = &submission.transfer_context {
        validate_digest(context)?;
    }
    Ok(())
}

fn validate_verified_email_challenge(
    verification: &VerifyIdentityMutationEmailProof,
    challenge: &VerifiedIdentityMutationEmailChallenge,
) -> Result<(), ApplicationError> {
    if challenge.project_id != verification.project_id
        || challenge.intent_id != verification.intent_id
        || challenge.proof_slot_id != verification.proof_slot_id
        || challenge.challenge_id != verification.challenge_id
        || challenge.generation != verification.generation
        || challenge.application_id.is_nil()
    {
        return Err(ApplicationError::Integrity);
    }
    validate_digest(&challenge.lookup_digest)?;
    validate_protected(&challenge.address)
}

fn mutation_email_challenge_context(
    project_id: Uuid,
    intent_id: Uuid,
    proof_slot_id: Uuid,
    challenge_id: Uuid,
    generation: i16,
) -> Vec<u8> {
    let mut context = Vec::with_capacity(32 + 16 * 4 + 2);
    context.extend_from_slice(b"owlauth-identity-mutation-email-challenge-v1\0");
    context.extend_from_slice(project_id.as_bytes());
    context.extend_from_slice(intent_id.as_bytes());
    context.extend_from_slice(proof_slot_id.as_bytes());
    context.extend_from_slice(challenge_id.as_bytes());
    context.extend_from_slice(&generation.to_be_bytes());
    context
}

fn verify_mutation_email_challenge_lookup(
    protector: &dyn RuntimeProtector,
    project_id: Uuid,
    canonical: &crate::domain::CanonicalEmail,
    expected: &VersionedDigest,
) -> Result<VersionedDigest, ApplicationError> {
    let derived = protector.digest_at(
        OpaquePurpose::EmailIdentityLookup,
        project_id.as_bytes(),
        canonical.expose().as_bytes(),
        expected.key_version,
    )?;
    if &derived != expected {
        return Err(ApplicationError::Integrity);
    }
    Ok(derived)
}

fn derive_mutation_email_aliases(
    protector: &dyn RuntimeProtector,
    project_id: Uuid,
    canonical: &crate::domain::CanonicalEmail,
) -> Result<(Vec<VersionedDigest>, VersionedDigest), ApplicationError> {
    let versions = protector.email_identity_readable_key_versions();
    let write_version = protector.email_identity_active_version();
    if versions.is_empty()
        || versions.len() > 16
        || write_version <= 0
        || !versions.contains(&write_version)
    {
        return Err(ApplicationError::Integrity);
    }
    let aliases = versions
        .iter()
        .map(|version| {
            protector.digest_at(
                OpaquePurpose::EmailIdentityLookup,
                project_id.as_bytes(),
                canonical.expose().as_bytes(),
                *version,
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    let active = aliases
        .iter()
        .find(|alias| alias.key_version == write_version)
        .cloned()
        .ok_or(ApplicationError::Integrity)?;
    Ok((aliases, active))
}

fn resolve_failed_provider(
    result: Result<FailIdentityMutationProvider, ApplicationError>,
) -> Result<IdentityMutationCallbackOutcome, ApplicationError> {
    match result? {
        FailIdentityMutationProvider::Terminalized(record)
        | FailIdentityMutationProvider::TerminalWinner(record) => {
            drop(record);
            Ok(IdentityMutationCallbackOutcome::TerminalizedFailure)
        }
    }
}

fn nonrenewable_provider_observation(
    identity: ProviderIdentity,
) -> Result<ProviderProofObservation, ApplicationError> {
    if identity.renewable_credential.is_some() {
        return Err(ApplicationError::Integrity);
    }
    provider_observation(identity)
}

fn provider_observation(
    identity: ProviderIdentity,
) -> Result<ProviderProofObservation, ApplicationError> {
    if identity.issuer.is_empty()
        || identity.issuer.len() > 2048
        || identity.subject.is_empty()
        || identity.subject.len() > 512
        || identity
            .display_name
            .as_ref()
            .is_some_and(|value| value.chars().count() > 128)
        || identity
            .picture_url
            .as_ref()
            .is_some_and(|value| value.len() > 2048)
    {
        return Err(ApplicationError::InvalidInput);
    }
    Ok(ProviderProofObservation {
        issuer: identity.issuer,
        subject: identity.subject,
        display_name: identity.display_name,
        picture_url: identity.picture_url,
    })
}

fn map_provider_error(error: ProviderExchangeError) -> ApplicationError {
    match error {
        ProviderExchangeError::Rejected | ProviderExchangeError::InvalidProof => {
            ApplicationError::InvalidTransition
        }
        ProviderExchangeError::UnavailableBeforeDispatch
        | ProviderExchangeError::AmbiguousAfterDispatch => ApplicationError::ExternalStore,
    }
}

fn validate_callback_owner(state: &str, proof_slot_id: Uuid) -> Result<(), ApplicationError> {
    let state_id = credential_id(state)?;
    if state_id != proof_slot_id {
        return Err(ApplicationError::NotFound);
    }
    Ok(())
}

fn callback_continuation_context(intent_id: Uuid, proof_slot_id: Uuid) -> [u8; 32] {
    let mut context = [0_u8; 32];
    context[..16].copy_from_slice(intent_id.as_bytes());
    context[16..].copy_from_slice(proof_slot_id.as_bytes());
    context
}

fn credential_id(value: &str) -> Result<Uuid, ApplicationError> {
    if value.is_empty() || value.len() > MAX_HANDLE_BYTES {
        return Err(ApplicationError::InvalidInput);
    }
    let (id, secret) = value
        .split_once('.')
        .ok_or(ApplicationError::InvalidInput)?;
    if secret.is_empty() || secret.contains('.') {
        return Err(ApplicationError::InvalidInput);
    }
    Uuid::parse_str(id).map_err(|_| ApplicationError::InvalidInput)
}

fn validate_positive_revision(value: i64) -> Result<(), ApplicationError> {
    if value <= 0 {
        return Err(ApplicationError::InvalidInput);
    }
    Ok(())
}

fn validate_create(command: &CreateIdentityMutation) -> Result<(), ApplicationError> {
    if command.project_id.is_nil()
        || command.correlation_id.is_nil()
        || !(8..=128).contains(&command.idempotency_key.len())
        || !command
            .idempotency_key
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(ApplicationError::InvalidInput);
    }
    match &command.operation {
        IdentityMutationCreateOperation::Link {
            destination,
            destination_identity,
            candidate_kind,
            destination_authority,
            candidate_authority,
        } => {
            validate_user(*destination)?;
            validate_identity(*destination_identity)?;
            if destination_identity.identity_id.is_nil()
                || destination_authority.application_id().is_nil()
                || candidate_authority.application_id().is_nil()
                || destination_identity.identity_kind
                    != method_identity_kind(destination_authority.method_kind())
                || *candidate_kind != method_identity_kind(candidate_authority.method_kind())
            {
                return Err(ApplicationError::InvalidInput);
            }
        }
        IdentityMutationCreateOperation::Unlink {
            owner,
            identity,
            authority,
            primary_source,
        } => {
            validate_user(*owner)?;
            validate_identity(*identity)?;
            validate_primary_source(*primary_source, false)?;
            if authority.application_id().is_nil()
                || identity.identity_kind != method_identity_kind(authority.method_kind())
            {
                return Err(ApplicationError::InvalidInput);
            }
        }
        IdentityMutationCreateOperation::Merge {
            winner,
            winner_identity,
            loser,
            loser_identity,
            winner_authority,
            loser_authority,
            primary_source,
            ..
        } => {
            validate_user(*winner)?;
            validate_user(*loser)?;
            validate_identity(*winner_identity)?;
            validate_identity(*loser_identity)?;
            validate_primary_source(*primary_source, true)?;
            if winner.user_id == loser.user_id
                || winner_identity.identity_id == loser_identity.identity_id
                || winner_authority.application_id().is_nil()
                || loser_authority.application_id().is_nil()
                || winner_identity.identity_kind
                    != method_identity_kind(winner_authority.method_kind())
                || loser_identity.identity_kind
                    != method_identity_kind(loser_authority.method_kind())
            {
                return Err(ApplicationError::InvalidInput);
            }
        }
    }
    Ok(())
}

fn validate_user(user: ExpectedUser) -> Result<(), ApplicationError> {
    if user.user_id.is_nil()
        || user.expected_user_revision <= 0
        || user.expected_user_security_revision <= 0
    {
        return Err(ApplicationError::InvalidInput);
    }
    Ok(())
}

fn validate_identity(identity: ExpectedIdentity) -> Result<(), ApplicationError> {
    if identity.identity_id.is_nil() || identity.expected_identity_revision <= 0 {
        return Err(ApplicationError::InvalidInput);
    }
    Ok(())
}

fn validate_primary_source(
    disposition: IdentityMutationPrimarySourceDisposition,
    merge: bool,
) -> Result<(), ApplicationError> {
    match disposition {
        IdentityMutationPrimarySourceDisposition::Provider(identity)
            if identity.identity_kind != IdentityKind::Provider =>
        {
            Err(ApplicationError::InvalidInput)
        }
        IdentityMutationPrimarySourceDisposition::Email(identity)
            if identity.identity_kind != IdentityKind::Email =>
        {
            Err(ApplicationError::InvalidInput)
        }
        IdentityMutationPrimarySourceDisposition::Provider(identity)
        | IdentityMutationPrimarySourceDisposition::Email(identity)
            if identity.identity_id.is_nil() || identity.expected_identity_revision <= 0 =>
        {
            Err(ApplicationError::InvalidInput)
        }
        IdentityMutationPrimarySourceDisposition::Preserve
        | IdentityMutationPrimarySourceDisposition::Clear
            if merge =>
        {
            Err(ApplicationError::InvalidInput)
        }
        _ => Ok(()),
    }
}

const fn method_identity_kind(method: IdentityMutationProofMethodKind) -> IdentityKind {
    match method {
        IdentityMutationProofMethodKind::Provider => IdentityKind::Provider,
        IdentityMutationProofMethodKind::Email => IdentityKind::Email,
    }
}

fn create_request_digest(command: &CreateIdentityMutation) -> Vec<u8> {
    let mut digest = Sha256::new();
    digest.update(b"owlauth.identity_mutation.create.v1\0");
    digest.update(command.project_id.as_bytes());
    hash_operation(&mut digest, &command.operation);
    digest.finalize().to_vec()
}

fn hash_operation(digest: &mut Sha256, operation: &IdentityMutationCreateOperation) {
    match operation {
        IdentityMutationCreateOperation::Link {
            destination,
            destination_identity,
            candidate_kind,
            destination_authority,
            candidate_authority,
        } => {
            digest.update(b"link\0");
            hash_user(digest, *destination);
            hash_identity(digest, *destination_identity);
            digest.update(candidate_kind.as_str().as_bytes());
            hash_authority(digest, *destination_authority);
            hash_authority(digest, *candidate_authority);
        }
        IdentityMutationCreateOperation::Unlink {
            owner,
            identity,
            authority,
            primary_source,
        } => {
            digest.update(b"unlink\0");
            hash_user(digest, *owner);
            hash_identity(digest, *identity);
            hash_authority(digest, *authority);
            hash_primary_source(digest, *primary_source);
        }
        IdentityMutationCreateOperation::Merge {
            winner,
            winner_identity,
            loser,
            loser_identity,
            winner_authority,
            loser_authority,
            primary_source,
            sessions,
            bindings,
        } => {
            digest.update(b"merge\0");
            hash_user(digest, *winner);
            hash_identity(digest, *winner_identity);
            hash_user(digest, *loser);
            hash_identity(digest, *loser_identity);
            hash_authority(digest, *winner_authority);
            hash_authority(digest, *loser_authority);
            hash_primary_source(digest, *primary_source);
            digest.update(match sessions {
                IdentityMutationSessionsDisposition::LoserRevoked => b"loser_revoked",
            });
            digest.update(match bindings {
                IdentityMutationBindingsDisposition::WinnerPreferred => b"winner_preferred",
            });
        }
    }
}

fn hash_user(digest: &mut Sha256, user: ExpectedUser) {
    digest.update(user.user_id.as_bytes());
    digest.update(user.expected_user_revision.to_be_bytes());
    digest.update(user.expected_user_security_revision.to_be_bytes());
}

fn hash_identity(digest: &mut Sha256, identity: ExpectedIdentity) {
    digest.update(identity.identity_kind.as_str().as_bytes());
    digest.update(identity.identity_id.as_bytes());
    digest.update(identity.expected_identity_revision.to_be_bytes());
}

fn hash_authority(digest: &mut Sha256, authority: IdentityMutationProofAuthoritySelection) {
    match authority {
        IdentityMutationProofAuthoritySelection::Provider {
            application_id,
            provider_configuration_id,
        } => {
            digest.update(b"provider\0");
            digest.update(application_id.as_bytes());
            digest.update(provider_configuration_id.as_bytes());
        }
        IdentityMutationProofAuthoritySelection::Email { application_id } => {
            digest.update(b"email\0");
            digest.update(application_id.as_bytes());
        }
    }
}

fn hash_primary_source(digest: &mut Sha256, disposition: IdentityMutationPrimarySourceDisposition) {
    match disposition {
        IdentityMutationPrimarySourceDisposition::Preserve => digest.update(b"preserve\0"),
        IdentityMutationPrimarySourceDisposition::Provider(identity) => {
            digest.update(b"provider\0");
            hash_identity(digest, identity);
        }
        IdentityMutationPrimarySourceDisposition::Email(identity) => {
            digest.update(b"email\0");
            hash_identity(digest, identity);
        }
        IdentityMutationPrimarySourceDisposition::Clear => digest.update(b"clear\0"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn user(seed: u128) -> ExpectedUser {
        ExpectedUser {
            user_id: Uuid::from_u128(seed),
            expected_user_revision: 2,
            expected_user_security_revision: 3,
        }
    }

    fn identity(seed: u128, kind: IdentityKind) -> ExpectedIdentity {
        ExpectedIdentity {
            identity_kind: kind,
            identity_id: Uuid::from_u128(seed),
            expected_identity_revision: 4,
        }
    }

    fn provider_authority(seed: u128) -> IdentityMutationProofAuthoritySelection {
        IdentityMutationProofAuthoritySelection::Provider {
            application_id: Uuid::from_u128(seed),
            provider_configuration_id: Uuid::from_u128(seed + 1),
        }
    }

    fn command() -> CreateIdentityMutation {
        CreateIdentityMutation {
            project_id: Uuid::from_u128(9),
            operation: IdentityMutationCreateOperation::Unlink {
                owner: user(1),
                identity: identity(2, IdentityKind::Provider),
                authority: provider_authority(3),
                primary_source: IdentityMutationPrimarySourceDisposition::Clear,
            },
            idempotency_key: "identity-mutation-1".to_owned(),
            correlation_id: Uuid::from_u128(10),
        }
    }

    fn record(id: Uuid, status: IdentityMutationStatus, revision: i64) -> IdentityMutationRecord {
        IdentityMutationRecord {
            id,
            project_id: Uuid::from_u128(9),
            project_public_id: "prj_identity_test".to_owned(),
            kind: IdentityMutationKind::Unlink,
            status,
            revision,
            browser_binding_key_version: Some(1),
            csrf_key_version: Some(1),
            expires_at: OffsetDateTime::from_unix_timestamp(1_800_000_600).unwrap(),
            slots: vec![IdentityMutationSlotRecord {
                id: Uuid::from_u128(20),
                role: IdentityMutationSlotRole::IdentityOwner,
                identity_kind: IdentityKind::Provider,
                method_kind: IdentityMutationProofMethodKind::Provider,
                state: if status == IdentityMutationStatus::Ready {
                    IdentityMutationSlotState::Proved
                } else {
                    IdentityMutationSlotState::Pending
                },
                revision: 1,
                existing_identity_id: Some(Uuid::from_u128(2)),
                provider: None,
            }],
        }
    }

    #[derive(Clone, Copy)]
    enum RepositoryBehavior {
        Replay,
        HostedReadFailure,
        Ready,
        EmailResend,
        MagicTransfer,
    }

    struct TestRepository {
        behavior: RepositoryBehavior,
    }

    #[async_trait]
    impl ControlIdentityMutationRepository for TestRepository {
        async fn create(
            &self,
            prepared: PreparedIdentityMutationCreate,
        ) -> Result<CreateIdentityMutationResult, ApplicationError> {
            assert!(matches!(self.behavior, RepositoryBehavior::Replay));
            Ok(CreateIdentityMutationResult::Replayed {
                intent: record(prepared.intent_id, IdentityMutationStatus::PendingProof, 1),
                protected_create_result: Some(prepared.protected_create_result),
            })
        }

        async fn control_read(
            &self,
            _project_id: Uuid,
            intent_id: Uuid,
            _now: OffsetDateTime,
        ) -> Result<IdentityMutationRecord, ApplicationError> {
            Ok(record(intent_id, IdentityMutationStatus::PendingProof, 2))
        }

        async fn cancel(
            &self,
            _project_id: Uuid,
            intent_id: Uuid,
            _expected_revision: i64,
            _correlation_id: Uuid,
            _now: OffsetDateTime,
        ) -> Result<IdentityMutationRecord, ApplicationError> {
            Ok(record(intent_id, IdentityMutationStatus::Cancelled, 3))
        }

        async fn prepare_control_confirmation(
            &self,
            project_id: Uuid,
            intent_id: Uuid,
            expected_revision: i64,
            expected_kind: IdentityMutationKind,
            _now: OffsetDateTime,
        ) -> Result<IdentityMutationControlConfirmationPreparation, ApplicationError> {
            Ok(IdentityMutationControlConfirmationPreparation {
                project_id,
                intent_id,
                expected_intent_revision: expected_revision,
                expected_kind,
                candidate_evidence: None,
            })
        }

        async fn confirm_control(
            &self,
            confirmation: PreparedIdentityMutationConfirmation,
        ) -> Result<IdentityMutationRecord, ApplicationError> {
            Ok(record(
                confirmation.intent_id,
                IdentityMutationStatus::Completed,
                4,
            ))
        }
    }

    #[async_trait]
    impl RuntimeIdentityMutationRepository for TestRepository {
        async fn digest_versions(
            &self,
            _intent_id: Uuid,
            _now: OffsetDateTime,
        ) -> Result<IdentityMutationDigestVersions, ApplicationError> {
            Ok(IdentityMutationDigestVersions {
                intent: 1,
                browser_binding: Some(1),
                csrf: Some(1),
            })
        }

        async fn provider_digest_versions(
            &self,
            _intent_id: Uuid,
            _proof_slot_id: Uuid,
            _now: OffsetDateTime,
        ) -> Result<IdentityMutationProviderDigestVersions, ApplicationError> {
            unreachable!()
        }

        async fn bind_browser(
            &self,
            _intent: &VersionedDigest,
            _browser_binding: &VersionedDigest,
            _csrf: &VersionedDigest,
            _now: OffsetDateTime,
        ) -> Result<IdentityMutationRecord, ApplicationError> {
            unreachable!()
        }

        async fn hosted_read(
            &self,
            _intent: &VersionedDigest,
            _browser_binding: &VersionedDigest,
            _now: OffsetDateTime,
        ) -> Result<IdentityMutationRecord, ApplicationError> {
            match self.behavior {
                RepositoryBehavior::HostedReadFailure => Err(ApplicationError::RevisionConflict),
                RepositoryBehavior::Ready => Ok(record(
                    Uuid::from_u128(30),
                    IdentityMutationStatus::PendingProof,
                    2,
                )),
                RepositoryBehavior::EmailResend => {
                    let mut current =
                        record(Uuid::from_u128(30), IdentityMutationStatus::PendingProof, 2);
                    current.slots[0].identity_kind = IdentityKind::Email;
                    current.slots[0].method_kind = IdentityMutationProofMethodKind::Email;
                    current.slots[0].state = IdentityMutationSlotState::EmailChallengePending;
                    Ok(current)
                }
                RepositoryBehavior::Replay | RepositoryBehavior::MagicTransfer => unreachable!(),
            }
        }

        async fn start_provider(
            &self,
            _intent_id: Uuid,
            _proof_slot_id: Uuid,
            _intent: &VersionedDigest,
            _browser_binding: &VersionedDigest,
            _csrf: &VersionedDigest,
            _expected_revision: i64,
            _upstream_state: VersionedDigest,
            _oidc_nonce: VersionedDigest,
            _provider_pkce: Option<ProtectedValue>,
            _callback_continuation: ProtectedValue,
            _now: OffsetDateTime,
        ) -> Result<IdentityMutationRecord, ApplicationError> {
            unreachable!()
        }

        async fn claim_provider_callback(
            &self,
            _intent_id: Uuid,
            _proof_slot_id: Uuid,
            _project_public_id: &str,
            _provider_key: &str,
            _upstream_state: &VersionedDigest,
            _browser_binding: &VersionedDigest,
            _now: OffsetDateTime,
        ) -> Result<ClaimIdentityMutationProvider, ApplicationError> {
            unreachable!()
        }

        async fn deny_provider_callback(
            &self,
            _intent_id: Uuid,
            _proof_slot_id: Uuid,
            _project_public_id: &str,
            _provider_key: &str,
            _upstream_state: &VersionedDigest,
            _browser_binding: &VersionedDigest,
            _safe_outcome: &'static str,
            _now: OffsetDateTime,
        ) -> Result<IdentityMutationRecord, ApplicationError> {
            unreachable!()
        }

        async fn complete_provider_callback(
            &self,
            _completion: PreparedIdentityMutationProviderCompletion,
        ) -> Result<IdentityMutationRecord, ApplicationError> {
            unreachable!()
        }

        async fn fail_provider_callback(
            &self,
            _claimed: &IdentityMutationRecord,
            _proof_slot_id: Uuid,
            _safe_outcome: &'static str,
            _now: OffsetDateTime,
        ) -> Result<FailIdentityMutationProvider, ApplicationError> {
            unreachable!()
        }

        async fn begin_email(
            &self,
            _intent_id: Uuid,
            _proof_slot_id: Uuid,
            _intent: &VersionedDigest,
            _browser_binding: &VersionedDigest,
            _csrf: &VersionedDigest,
            _expected_revision: i64,
            _now: OffsetDateTime,
        ) -> Result<IdentityMutationRecord, ApplicationError> {
            unreachable!()
        }

        async fn prepare_email_generation(
            &self,
            _intent_id: Uuid,
            _proof_slot_id: Uuid,
            _intent: &VersionedDigest,
            _browser_binding: &VersionedDigest,
            _csrf: &VersionedDigest,
            _expected_revision: i64,
            _now: OffsetDateTime,
        ) -> Result<IdentityMutationEmailGenerationPreparation, ApplicationError> {
            assert!(matches!(self.behavior, RepositoryBehavior::EmailResend));
            Ok(IdentityMutationEmailGenerationPreparation {
                project_id: Uuid::from_u128(9),
                application_id: Uuid::from_u128(60),
                intent_id: Uuid::from_u128(30),
                proof_slot_id: Uuid::from_u128(20),
                next_generation: 2,
                intent_expires_at: OffsetDateTime::from_unix_timestamp(1_800_000_600).unwrap(),
                policy: AdmittedEmailMethod {
                    policy_revision: 2,
                    security_revision: 3,
                    assignment_security_revision: 4,
                    otp_enabled: true,
                    magic_link_enabled: true,
                    otp_digits: 8,
                    otp_validity_seconds: 300,
                    otp_max_attempts: 5,
                    resend_after_seconds: 30,
                    max_generations: 3,
                    magic_validity_seconds: 600,
                    signup_enabled: false,
                    transferred_magic_link_enabled: true,
                    smtp_selection_kind: "deployment_default".to_owned(),
                    smtp_configuration_id: None,
                    smtp_generation: 1,
                    smtp_security_eligibility_revision: 1,
                },
            })
        }

        async fn commit_email_generation(
            &self,
            generation: CommitIdentityMutationEmailGeneration,
        ) -> Result<IdentityMutationRecord, ApplicationError> {
            assert!(matches!(self.behavior, RepositoryBehavior::EmailResend));
            assert_eq!(generation.project_id, Uuid::from_u128(9));
            assert_eq!(generation.application_id, Uuid::from_u128(60));
            assert_eq!(generation.intent_id, Uuid::from_u128(30));
            assert_eq!(generation.proof_slot_id, Uuid::from_u128(20));
            assert_eq!(generation.expected_intent_revision, 2);
            assert_eq!(generation.expected_generation, 2);
            assert_eq!(generation.canonicalization_version, 1);
            assert_eq!(generation.lookup_digest.key_version, 1);
            assert_eq!(generation.address.key_version, 1);
            assert_eq!(generation.address.ciphertext, b"person@example.com");
            assert!(generation.otp_digest.is_some());
            assert!(generation.magic_digest.is_some());
            assert_eq!(generation.envelope.key_version, 1);
            assert_eq!(
                generation.envelope.ciphertext,
                br#"{"to":"person@example.com"}"#
            );
            let body = String::from_utf8(generation.body.ciphertext).expect("mail body is UTF-8");
            assert!(body.contains("One-time code:"));
            assert!(body.contains("Verification link:"));
            assert!(body.contains("#proof=runtime-secret"));
            assert!(body.contains("interaction="));
            assert!(body.contains("revision=3"));
            assert!(!body.contains("intent="));
            assert!(!body.contains("?proof="));
            assert_eq!(generation.issued_at, TestClock.now());
            assert_eq!(
                generation.otp_expires_at,
                Some(TestClock.now() + Duration::seconds(300))
            );
            assert_eq!(
                generation.magic_expires_at,
                Some(TestClock.now() + Duration::seconds(600))
            );
            assert_eq!(
                generation.expires_at,
                TestClock.now() + Duration::seconds(600)
            );
            let mut committed = record(
                generation.intent_id,
                IdentityMutationStatus::PendingProof,
                3,
            );
            committed.slots[0].identity_kind = IdentityKind::Email;
            committed.slots[0].method_kind = IdentityMutationProofMethodKind::Email;
            committed.slots[0].state = IdentityMutationSlotState::EmailChallengePending;
            Ok(committed)
        }

        async fn establish_magic_transfer_context(
            &self,
            command: EstablishIdentityMutationMagicTransferContext,
        ) -> Result<EstablishedIdentityMutationMagicTransferContext, ApplicationError> {
            assert!(matches!(self.behavior, RepositoryBehavior::MagicTransfer));
            assert_eq!(command.challenge_id, Uuid::from_u128(70));
            assert_eq!(command.context.key_version, 1);
            assert_eq!(command.csrf.key_version, 1);
            Ok(EstablishedIdentityMutationMagicTransferContext {
                owner: IdentityMutationMagicTransferOwner {
                    project_id: Uuid::from_u128(9),
                    intent_id: Uuid::from_u128(30),
                    proof_slot_id: Uuid::from_u128(20),
                    challenge_id: command.challenge_id,
                    generation: 2,
                },
                project_public_id: "prj_identity_test".to_owned(),
                expected_intent_revision: 3,
            })
        }

        async fn resolve_magic_transfer_context(
            &self,
            _command: ResolveIdentityMutationMagicTransferContext,
        ) -> Result<ResolvedIdentityMutationMagicTransferContext, ApplicationError> {
            unreachable!()
        }

        async fn email_proof_key_version(
            &self,
            _key: IdentityMutationEmailProofKey,
        ) -> Result<Option<i32>, ApplicationError> {
            unreachable!()
        }

        async fn verify_email_proof(
            &self,
            _verification: VerifyIdentityMutationEmailProof,
        ) -> Result<IdentityMutationEmailProofDecision, ApplicationError> {
            unreachable!()
        }

        async fn complete_email_proof(
            &self,
            _completion: CompleteIdentityMutationEmailProof,
        ) -> Result<IdentityMutationRecord, ApplicationError> {
            unreachable!()
        }

        async fn confirm_ready(
            &self,
            intent_id: Uuid,
            _intent: &VersionedDigest,
            _browser_binding: &VersionedDigest,
            _csrf: &VersionedDigest,
            _expected_revision: i64,
            _now: OffsetDateTime,
        ) -> Result<IdentityMutationRecord, ApplicationError> {
            assert!(matches!(self.behavior, RepositoryBehavior::Ready));
            Ok(record(intent_id, IdentityMutationStatus::Ready, 3))
        }
    }

    struct TestClock;

    impl Clock for TestClock {
        fn now(&self) -> OffsetDateTime {
            OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap()
        }
    }

    struct TestTarget;

    impl IdentityMutationTargetIssuer for TestTarget {
        fn random_handle(&self, _bytes: usize) -> Result<Zeroizing<String>, ApplicationError> {
            Ok(Zeroizing::new("fixed-secret".to_owned()))
        }

        fn digest_handle(
            &self,
            _intent_id: Uuid,
            _value: &[u8],
        ) -> Result<VersionedDigest, ApplicationError> {
            Ok(VersionedDigest {
                value: [1; 32],
                key_version: 1,
            })
        }

        fn protect_create_result(
            &self,
            _intent_id: Uuid,
            value: &[u8],
        ) -> Result<ProtectedValue, ApplicationError> {
            Ok(ProtectedValue {
                ciphertext: value.to_vec(),
                key_version: 1,
            })
        }

        fn replay_create_result(
            &self,
            _intent_id: Uuid,
            value: &ProtectedValue,
        ) -> Result<Zeroizing<Vec<u8>>, ApplicationError> {
            Ok(Zeroizing::new(value.ciphertext.clone()))
        }
    }

    impl IdentityMutationTargetVerifier for TestTarget {
        fn readable_key_versions(&self) -> BTreeSet<i32> {
            BTreeSet::from([1])
        }

        fn digest_handle_at(
            &self,
            _intent_id: Uuid,
            _value: &[u8],
            key_version: i32,
        ) -> Result<VersionedDigest, ApplicationError> {
            Ok(VersionedDigest {
                value: [1; 32],
                key_version,
            })
        }
    }

    struct TestProtector;

    impl RuntimeProtector for TestProtector {
        fn active_version(&self) -> i32 {
            1
        }

        fn readable_key_versions(&self) -> BTreeSet<i32> {
            BTreeSet::from([1])
        }

        fn random_opaque(&self, _bytes: usize) -> Result<Zeroizing<String>, ApplicationError> {
            Ok(Zeroizing::new("runtime-secret".to_owned()))
        }

        fn digest(
            &self,
            _purpose: OpaquePurpose,
            _context: &[u8],
            _value: &[u8],
        ) -> Result<VersionedDigest, ApplicationError> {
            Ok(VersionedDigest {
                value: [2; 32],
                key_version: 1,
            })
        }

        fn digest_at(
            &self,
            _purpose: OpaquePurpose,
            _context: &[u8],
            _value: &[u8],
            key_version: i32,
        ) -> Result<VersionedDigest, ApplicationError> {
            Ok(VersionedDigest {
                value: [2; 32],
                key_version,
            })
        }

        fn derive_opaque(
            &self,
            _purpose: OpaquePurpose,
            _context: &[u8],
            _key_version: Option<i32>,
        ) -> Result<Zeroizing<String>, ApplicationError> {
            Ok(Zeroizing::new("csrf".to_owned()))
        }

        fn protect(
            &self,
            _purpose: ProtectedPurpose,
            _context: &[u8],
            value: &[u8],
        ) -> Result<ProtectedValue, ApplicationError> {
            Ok(ProtectedValue {
                ciphertext: value.to_vec(),
                key_version: 1,
            })
        }

        fn unprotect(
            &self,
            _purpose: ProtectedPurpose,
            _context: &[u8],
            value: &ProtectedValue,
        ) -> Result<Zeroizing<Vec<u8>>, ApplicationError> {
            Ok(Zeroizing::new(value.ciphertext.clone()))
        }
    }

    struct TestProofMaterial;

    impl IdentityMutationProofMaterialProtector for TestProofMaterial {
        fn protect_candidate(
            &self,
            context: IdentityMutationCandidateEvidenceContext,
            plaintext: &[u8],
        ) -> Result<CandidateEvidenceMaterial, ApplicationError> {
            Ok(CandidateEvidenceMaterial {
                context,
                ciphertext: ProtectedValue {
                    ciphertext: plaintext.to_vec(),
                    key_version: 1,
                },
                digest: VersionedDigest {
                    value: [3; 32],
                    key_version: 1,
                },
            })
        }

        fn issue_receipt_digest(
            &self,
            _intent_id: Uuid,
            _proof_slot_id: Uuid,
        ) -> Result<VersionedDigest, ApplicationError> {
            Ok(VersionedDigest {
                value: [4; 32],
                key_version: 1,
            })
        }
    }

    impl IdentityMutationCandidateVerifier for TestProofMaterial {
        fn unprotect_candidate(
            &self,
            _context: &IdentityMutationCandidateEvidenceContext,
            ciphertext: &ProtectedValue,
        ) -> Result<Zeroizing<Vec<u8>>, ApplicationError> {
            Ok(Zeroizing::new(ciphertext.ciphertext.clone()))
        }

        fn digest_candidate_at(
            &self,
            _context: &IdentityMutationCandidateEvidenceContext,
            _plaintext: &[u8],
            key_version: i32,
        ) -> Result<VersionedDigest, ApplicationError> {
            Ok(VersionedDigest {
                value: [3; 32],
                key_version,
            })
        }
    }

    impl IdentityMutationDurableEmailProtector for TestProofMaterial {
        fn protect_durable_address(
            &self,
            _project_id: Uuid,
            _identity_id: Uuid,
            normalized_address: &[u8],
        ) -> Result<ProtectedValue, ApplicationError> {
            Ok(ProtectedValue {
                ciphertext: normalized_address.to_vec(),
                key_version: 1,
            })
        }
    }

    struct TestProvider;

    #[async_trait]
    impl UpstreamProviderClient for TestProvider {
        fn issuer_allowed(&self, _kind: crate::domain::ProviderKind, _issuer: &str) -> bool {
            true
        }

        async fn authorization_url(
            &self,
            _request: ProviderAuthorizationRequest,
        ) -> Result<crate::application::ProviderAuthorization, ProviderExchangeError> {
            unreachable!()
        }

        async fn exchange_code(
            &self,
            _request: ProviderCallbackRequest,
        ) -> Result<ProviderIdentity, ProviderExchangeError> {
            unreachable!()
        }
    }

    struct TestSecrets;

    #[async_trait]
    impl ProviderSecretResolver for TestSecrets {
        async fn resolve(
            &self,
            _secret_material_id: Uuid,
        ) -> Result<Zeroizing<String>, ApplicationError> {
            unreachable!()
        }
    }

    fn runtime_service(behavior: RepositoryBehavior) -> IdentityMutationRuntimeService {
        IdentityMutationRuntimeService::new(
            Arc::new(TestRepository { behavior }),
            Arc::new(TestProtector),
            Arc::new(TestTarget),
            Arc::new(TestProofMaterial),
            Arc::new(TestProofMaterial),
            Arc::new(TestProvider),
            Arc::new(TestSecrets),
            Arc::new(TestClock),
            Url::parse("https://runtime.example/").expect("runtime URL"),
            IdentityMutationProviderCapabilities::reviewed(),
        )
    }

    #[test]
    fn provider_display_name_bound_matches_durable_identity_before_final_link() {
        let candidate = |display_name: String| {
            IdentityMutationCandidate::Provider(IdentityMutationProviderCandidate {
                issuer: "https://issuer.example".to_owned(),
                subject: "subject".to_owned(),
                admitted_profile: IdentityMutationAdmittedProviderProfile {
                    display_name: Some(display_name),
                    picture_url: None,
                },
                registration: IdentityMutationProviderRegistrationEvidence {
                    provider_configuration_id: Uuid::from_u128(42),
                    provider_configuration_revision: 1,
                    adapter_key: CONTROLLED_OIDC_PROOF_ADAPTER_KEY.to_owned(),
                    adapter_capability_revision: CONTROLLED_OIDC_PROOF_ADAPTER_REVISION,
                    issuer: "https://issuer.example".to_owned(),
                },
            })
        };
        assert_eq!(validate_candidate(&candidate("a".repeat(128))), Ok(()));
        assert_eq!(
            validate_candidate(&candidate("a".repeat(129))),
            Err(ApplicationError::Integrity)
        );
        assert_eq!(validate_candidate(&candidate("猫".repeat(128))), Ok(()));
        assert_eq!(
            validate_candidate(&candidate("猫".repeat(129))),
            Err(ApplicationError::Integrity)
        );
        for display_name in ["a".repeat(129), "猫".repeat(129)] {
            let identity = ProviderIdentity {
                issuer: "https://issuer.example".to_owned(),
                subject: "subject".to_owned(),
                display_name: Some(display_name),
                picture_url: None,
                renewable_credential: None,
            };
            assert_eq!(
                provider_observation(identity),
                Err(ApplicationError::InvalidInput)
            );
        }
        let multibyte_boundary = ProviderIdentity {
            issuer: "https://issuer.example".to_owned(),
            subject: "subject".to_owned(),
            display_name: Some("猫".repeat(128)),
            picture_url: None,
            renewable_credential: None,
        };
        assert!(provider_observation(multibyte_boundary).is_ok());
    }

    #[test]
    fn create_operations_derive_only_mandatory_roles() {
        let link = IdentityMutationCreateOperation::Link {
            destination: user(1),
            destination_identity: identity(2, IdentityKind::Provider),
            candidate_kind: IdentityKind::Email,
            destination_authority: provider_authority(3),
            candidate_authority: IdentityMutationProofAuthoritySelection::Email {
                application_id: Uuid::from_u128(5),
            },
        };
        assert_eq!(
            link.derived_roles(),
            &[
                IdentityMutationSlotRole::DestinationOwner,
                IdentityMutationSlotRole::CandidateIdentity
            ]
        );
        let unlink = IdentityMutationCreateOperation::Unlink {
            owner: user(1),
            identity: identity(2, IdentityKind::Provider),
            authority: provider_authority(3),
            primary_source: IdentityMutationPrimarySourceDisposition::Clear,
        };
        assert_eq!(
            unlink.derived_roles(),
            &[IdentityMutationSlotRole::IdentityOwner]
        );
    }

    #[test]
    fn provider_capability_is_fixed_nonrenewable_and_derives_trusted_callback() {
        let capability = IdentityMutationProviderCapability::controlled_oidc();
        assert_eq!(
            capability.exact_nonrenewable_scopes(),
            &["openid", "profile"]
        );
        let snapshot = capability
            .snapshot(
                "https://runtime.example/runtime/",
                "prj_identity_test",
                "oidc-main",
            )
            .unwrap();
        assert_eq!(snapshot.adapter_key(), CONTROLLED_OIDC_PROOF_ADAPTER_KEY);
        assert_eq!(
            snapshot.exact_non_renewable_proof_scopes(),
            &["openid", "profile"]
        );
        assert_eq!(
            snapshot.callback().as_str(),
            "https://runtime.example/runtime/projects/prj_identity_test/auth/callback/oidc-main"
        );

        let capabilities = IdentityMutationProviderCapabilities::reviewed();
        let google = capabilities
            .for_kind(crate::domain::ProviderKind::Google)
            .expect("Google identity proof is reviewed")
            .snapshot(
                "https://runtime.example/runtime/",
                "prj_identity_test",
                "google",
            )
            .unwrap();
        assert_eq!(google.adapter_key(), GOOGLE_OIDC_PROOF_ADAPTER_KEY);
        assert!(
            capabilities
                .for_kind(crate::domain::ProviderKind::Github)
                .is_none()
        );
    }

    #[test]
    fn request_digest_is_operation_specific_and_stable() {
        let command = command();
        assert_eq!(
            create_request_digest(&command),
            create_request_digest(&command)
        );
        assert_eq!(create_request_digest(&command).len(), 32);

        let mut revision_two = command.clone();
        let IdentityMutationCreateOperation::Unlink { primary_source, .. } =
            &mut revision_two.operation
        else {
            unreachable!("test command is unlink")
        };
        *primary_source = IdentityMutationPrimarySourceDisposition::Provider(ExpectedIdentity {
            identity_kind: IdentityKind::Provider,
            identity_id: Uuid::from_u128(40),
            expected_identity_revision: 2,
        });
        let mut revision_three = revision_two.clone();
        let IdentityMutationCreateOperation::Unlink { primary_source, .. } =
            &mut revision_three.operation
        else {
            unreachable!("test command is unlink")
        };
        *primary_source = IdentityMutationPrimarySourceDisposition::Provider(ExpectedIdentity {
            identity_kind: IdentityKind::Provider,
            identity_id: Uuid::from_u128(40),
            expected_identity_revision: 3,
        });
        assert_ne!(
            create_request_digest(&revision_two),
            create_request_digest(&revision_three),
            "primary-source revision is part of idempotency authority"
        );
    }

    #[tokio::test]
    async fn idempotent_create_replays_the_exact_protected_hosted_target() {
        let service = IdentityMutationControlService::new(
            Arc::new(TestRepository {
                behavior: RepositoryBehavior::Replay,
            }),
            Arc::new(TestTarget),
            Arc::new(TestProofMaterial),
            Arc::new(TestClock),
            Url::parse("https://runtime.example/runtime/").unwrap(),
            IdentityMutationProviderCapabilities::reviewed(),
        )
        .unwrap();
        let created = service.create(command()).await.unwrap();
        let IdentityMutationCreateOutcome::Replayed {
            intent,
            hosted_target,
        } = created
        else {
            panic!("the repository replay must remain authoritative at the HTTP boundary");
        };
        let target = hosted_target.expect("live replay returns exact target");
        assert_eq!(
            target,
            format!(
                "https://runtime.example/runtime/auth/identity-mutations/{}.fixed-secret",
                intent.id
            )
        );
    }

    #[tokio::test]
    async fn copied_handle_propagates_browser_binding_authority_failure() {
        let service = runtime_service(RepositoryBehavior::HostedReadFailure);
        let handle = format!("{}.opaque", Uuid::from_u128(30));
        let result = service.bootstrap(&handle, Some("copied-browser")).await;
        assert!(matches!(result, Err(ApplicationError::RevisionConflict)));
    }

    #[tokio::test]
    async fn runtime_service_reaches_authoritative_email_resend_from_pending_challenge() {
        let service = runtime_service(RepositoryBehavior::EmailResend);
        let id = Uuid::from_u128(30);
        let preparation = service
            .prepare_email_generation(PrepareIdentityMutationEmailGeneration {
                project_public_id: "prj_identity_test".to_owned(),
                interaction: format!("{id}.opaque"),
                proof_slot_id: Uuid::from_u128(20),
                browser_binding: "browser".to_owned(),
                csrf: "csrf".to_owned(),
                expected_revision: 2,
            })
            .await
            .expect("pending email challenge must reach repository resend authority");
        assert_eq!(preparation.intent_id, id);
        assert_eq!(preparation.next_generation, 2);
        assert_eq!(
            preparation.intent_expires_at,
            OffsetDateTime::from_unix_timestamp(1_800_000_600).unwrap()
        );
    }

    #[tokio::test]
    async fn raw_email_challenge_builds_bounded_dual_proof_and_outbox_authority() {
        let service = runtime_service(RepositoryBehavior::EmailResend);
        let id = Uuid::from_u128(30);
        let accepted = service
            .begin_email_challenge(BeginIdentityMutationEmailChallenge {
                project_public_id: "prj_identity_test".to_owned(),
                interaction: format!("{id}.opaque"),
                proof_slot_id: Uuid::from_u128(20),
                browser_binding: "browser".to_owned(),
                csrf: "csrf".to_owned(),
                expected_revision: 2,
                email: "person@EXAMPLE.COM".to_owned(),
            })
            .await
            .expect("raw email entry point must own challenge and outbox construction");
        assert_eq!(accepted.revision, 3);
        assert_eq!(accepted.generation, 2);
        assert!(accepted.otp_enabled);
        assert!(accepted.magic_link_enabled);
        assert_eq!(
            accepted.expires_at,
            TestClock.now() + Duration::seconds(600)
        );
    }

    #[tokio::test]
    async fn magic_get_authority_builds_only_a_challenge_scoped_transfer_gate() {
        let service = runtime_service(RepositoryBehavior::MagicTransfer);
        let gate = service
            .establish_magic_transfer_context(Uuid::from_u128(70))
            .await
            .expect("live mutation magic challenge establishes a narrow transfer gate");
        assert_eq!(gate.context.as_str(), "runtime-secret");
        assert_eq!(gate.csrf.as_str(), "runtime-secret");
        assert_eq!(gate.project_public_id, "prj_identity_test");
        assert_eq!(gate.proof_slot_id, Uuid::from_u128(20));
        assert_eq!(gate.generation, 2);
        assert_eq!(gate.expected_revision, 3);
    }

    #[tokio::test]
    async fn hosted_ready_transition_returns_only_safe_readiness() {
        let service = runtime_service(RepositoryBehavior::Ready);
        let id = Uuid::from_u128(30);
        let ready = service
            .confirm_ready(ConfirmIdentityMutationReady {
                project_public_id: "prj_identity_test".to_owned(),
                interaction: format!("{id}.opaque"),
                browser_binding: "browser".to_owned(),
                csrf: "csrf".to_owned(),
                expected_revision: 2,
            })
            .await
            .unwrap();
        assert_eq!(ready.status, IdentityMutationStatus::Ready);
        assert_eq!(ready.revision, 3);
        assert!(ready.slots.iter().all(|slot| slot.proved));
    }

    #[test]
    fn copied_callback_state_cannot_change_its_slot_owner() {
        let slot = Uuid::new_v4();
        let state = format!("{slot}.secret");
        assert_eq!(validate_callback_owner(&state, slot), Ok(()));
        assert_eq!(
            validate_callback_owner(&state, Uuid::new_v4()),
            Err(ApplicationError::NotFound)
        );
    }

    fn digest(byte: u8, key_version: i32) -> VersionedDigest {
        VersionedDigest {
            value: [byte; 32],
            key_version,
        }
    }

    fn provider_candidate() -> IdentityMutationCandidate {
        IdentityMutationCandidate::Provider(IdentityMutationProviderCandidate {
            issuer: "https://issuer.example".to_owned(),
            subject: "subject".to_owned(),
            admitted_profile: IdentityMutationAdmittedProviderProfile {
                display_name: Some("Ada".to_owned()),
                picture_url: Some("https://issuer.example/ada.png".to_owned()),
            },
            registration: IdentityMutationProviderRegistrationEvidence {
                provider_configuration_id: Uuid::from_u128(41),
                provider_configuration_revision: 7,
                adapter_key: CONTROLLED_OIDC_PROOF_ADAPTER_KEY.to_owned(),
                adapter_capability_revision: CONTROLLED_OIDC_PROOF_ADAPTER_REVISION,
                issuer: "https://issuer.example".to_owned(),
            },
        })
    }

    fn candidate_context() -> IdentityMutationCandidateEvidenceContext {
        IdentityMutationCandidateEvidenceContext {
            project_id: Uuid::from_u128(9),
            intent_id: Uuid::from_u128(30),
            proof_slot_id: Uuid::from_u128(20),
            evidence_id: Uuid::from_u128(42),
            evidence_revision: 3,
            candidate_kind: IdentityMutationCandidateKind::Provider,
        }
    }

    fn control_service() -> IdentityMutationControlService {
        IdentityMutationControlService::new(
            Arc::new(TestRepository {
                behavior: RepositoryBehavior::Ready,
            }),
            Arc::new(TestTarget),
            Arc::new(TestProofMaterial),
            Arc::new(TestClock),
            Url::parse("https://runtime.example/runtime/").unwrap(),
            IdentityMutationProviderCapabilities::reviewed(),
        )
        .unwrap()
    }

    #[test]
    fn control_candidate_is_bound_to_exact_evidence_context_revision_and_digest() {
        let context = candidate_context();
        let plaintext = encode_candidate(&provider_candidate()).unwrap();
        let evidence = IdentityMutationCandidateEvidenceEnvelope {
            context: context.clone(),
            ciphertext: ProtectedValue {
                ciphertext: plaintext,
                key_version: 1,
            },
            digest: digest(3, 1),
        };
        let prepared = control_service().prepare_candidate(&evidence).unwrap();
        assert_eq!(prepared.context, context);
        assert_eq!(prepared.evidence_digest, digest(3, 1));
        assert_eq!(prepared.candidate, provider_candidate());
    }

    #[test]
    fn control_candidate_decrypt_digest_schema_and_context_mismatches_fail_closed() {
        let plaintext = encode_candidate(&provider_candidate()).unwrap();
        let mut evidence = IdentityMutationCandidateEvidenceEnvelope {
            context: candidate_context(),
            ciphertext: ProtectedValue {
                ciphertext: plaintext.clone(),
                key_version: 1,
            },
            digest: digest(9, 1),
        };
        assert_eq!(
            control_service().prepare_candidate(&evidence),
            Err(ApplicationError::Integrity)
        );

        evidence.digest = digest(3, 1);
        evidence.context.candidate_kind = IdentityMutationCandidateKind::Email;
        assert_eq!(
            control_service().prepare_candidate(&evidence),
            Err(ApplicationError::Integrity)
        );

        let preparation = IdentityMutationControlConfirmationPreparation {
            project_id: Uuid::from_u128(9),
            intent_id: Uuid::from_u128(30),
            expected_intent_revision: 2,
            expected_kind: IdentityMutationKind::Link,
            candidate_evidence: Some(IdentityMutationCandidateEvidenceEnvelope {
                context: IdentityMutationCandidateEvidenceContext {
                    project_id: Uuid::from_u128(99),
                    candidate_kind: IdentityMutationCandidateKind::Provider,
                    ..candidate_context()
                },
                ciphertext: ProtectedValue {
                    ciphertext: plaintext,
                    key_version: 1,
                },
                digest: digest(3, 1),
            }),
        };
        assert_eq!(
            validate_control_preparation(
                &preparation,
                Uuid::from_u128(9),
                Uuid::from_u128(30),
                2,
                IdentityMutationKind::Link,
            ),
            Err(ApplicationError::Integrity)
        );
    }

    #[tokio::test]
    async fn missing_email_proof_material_cannot_reach_repository_completion() {
        let result = runtime_service(RepositoryBehavior::Ready)
            .complete_email_proof(SubmitIdentityMutationEmailProof {
                project_id: Uuid::from_u128(9),
                intent_id: Uuid::from_u128(30),
                proof_slot_id: Uuid::from_u128(20),
                challenge_id: Uuid::from_u128(50),
                generation: 1,
                proof_kind: EmailProofKind::Otp,
                proof: Zeroizing::new(String::new()),
                browser_binding: Some(digest(2, 1)),
                csrf: digest(2, 1),
                transfer_context: None,
                expected_intent_revision: 2,
            })
            .await;
        assert_eq!(result, Err(ApplicationError::InvalidInput));
    }

    #[test]
    fn email_generation_snapshot_freezes_complete_policy_and_delivery_authority() {
        let policy = AdmittedEmailMethod {
            policy_revision: 2,
            security_revision: 3,
            assignment_security_revision: 4,
            otp_enabled: true,
            magic_link_enabled: true,
            otp_digits: 8,
            otp_validity_seconds: 300,
            otp_max_attempts: 5,
            resend_after_seconds: 30,
            max_generations: 3,
            magic_validity_seconds: 600,
            signup_enabled: false,
            transferred_magic_link_enabled: true,
            smtp_selection_kind: "project".to_owned(),
            smtp_configuration_id: Some(Uuid::from_u128(60)),
            smtp_generation: 6,
            smtp_security_eligibility_revision: 7,
        };
        let issued_at = OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap();
        let generation = CommitIdentityMutationEmailGeneration {
            project_id: Uuid::from_u128(9),
            application_id: Uuid::from_u128(10),
            intent_id: Uuid::from_u128(30),
            proof_slot_id: Uuid::from_u128(20),
            expected_intent_revision: 2,
            expected_generation: 2,
            challenge_id: Uuid::from_u128(50),
            outbox_id: Uuid::from_u128(51),
            canonicalization_version: crate::domain::CanonicalEmail::version(),
            lookup_digest: digest(5, 2),
            recipient_digests: vec![digest(5, 2)],
            address: ProtectedValue {
                ciphertext: vec![1],
                key_version: 2,
            },
            otp_digest: Some(digest(6, 2)),
            magic_digest: Some(digest(7, 2)),
            envelope: ProtectedValue {
                ciphertext: vec![2],
                key_version: 2,
            },
            body: ProtectedValue {
                ciphertext: vec![3],
                key_version: 2,
            },
            message_id: "identity-mutation-50@example.test".to_owned(),
            admitted_method: policy.clone(),
            issued_at,
            otp_expires_at: Some(issued_at + Duration::minutes(5)),
            magic_expires_at: Some(issued_at + Duration::minutes(10)),
            expires_at: issued_at + Duration::minutes(10),
        };
        assert_eq!(validate_email_generation(&generation), Ok(()));
        assert_eq!(generation.admitted_method, policy);
        assert_eq!(generation.message_id, "identity-mutation-50@example.test");
    }

    #[test]
    fn provider_observation_rejects_renewable_material_before_persistence() {
        let identity = ProviderIdentity {
            issuer: "https://issuer.example".to_owned(),
            subject: "subject".to_owned(),
            display_name: None,
            picture_url: None,
            renewable_credential: Some(super::super::RenewableProviderCredential {
                value: Zeroizing::new(b"must-not-survive".to_vec()),
                granted_scopes: vec!["openid".to_owned(), "profile".to_owned()],
                supports_revocation: false,
            }),
        };
        assert_eq!(
            nonrenewable_provider_observation(identity),
            Err(ApplicationError::Integrity)
        );
        assert!(!ProviderRequestProfile::IdentityProof.is_managed_profile());
    }
}
