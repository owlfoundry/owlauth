use std::collections::HashSet;

use time::{Duration, OffsetDateTime};
use url::Url;
use uuid::Uuid;

use super::{DomainError, ProviderKey, project::PublicId};

const MAX_INTENT_LIFETIME: Duration = Duration::minutes(10);
const MAX_RECEIPT_LIFETIME: Duration = Duration::minutes(5);
const MAX_PROVIDER_PROOF_SCOPES: usize = 16;
const INITIAL_BROWSER_BINDING_REVISION: i64 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum IdentityMutationKind {
    Link,
    Unlink,
    Merge,
}

impl IdentityMutationKind {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Link => "link",
            Self::Unlink => "unlink",
            Self::Merge => "merge",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum IdentityMutationStatus {
    PendingProof,
    Ready,
    Completed,
    Expired,
    Cancelled,
}

impl IdentityMutationStatus {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::PendingProof => "pending_proof",
            Self::Ready => "ready",
            Self::Completed => "completed",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
        }
    }

    pub(crate) const fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Expired | Self::Cancelled)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum IdentityMutationSlotRole {
    DestinationOwner,
    CandidateIdentity,
    IdentityOwner,
    WinnerOwner,
    LoserOwner,
}

impl IdentityMutationSlotRole {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::DestinationOwner => "destination_owner",
            Self::CandidateIdentity => "candidate_identity",
            Self::IdentityOwner => "identity_owner",
            Self::WinnerOwner => "winner_owner",
            Self::LoserOwner => "loser_owner",
        }
    }

    pub(crate) const fn purpose(self) -> &'static str {
        match self {
            Self::DestinationOwner => "link.destination_owner",
            Self::CandidateIdentity => "link.candidate_identity",
            Self::IdentityOwner => "unlink.identity_owner",
            Self::WinnerOwner => "merge.winner_owner",
            Self::LoserOwner => "merge.loser_owner",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum IdentityKind {
    Provider,
    Email,
}

impl IdentityKind {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Provider => "provider",
            Self::Email => "email",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ExistingIdentitySnapshot {
    pub project_id: Uuid,
    pub user_id: Uuid,
    pub identity_id: Uuid,
    pub identity_kind: IdentityKind,
    pub expected_user_revision: i64,
    pub expected_user_security_revision: i64,
    pub expected_identity_revision: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct TrustedRuntimeProviderCallback {
    runtime_base: String,
    project_public_id: String,
    provider_key: String,
    value: String,
}

impl TrustedRuntimeProviderCallback {
    pub(crate) fn derive(
        runtime_base: &str,
        project_public_id: &PublicId,
        provider_key: &ProviderKey,
    ) -> Result<Self, DomainError> {
        let base = Url::parse(runtime_base).map_err(|_| DomainError::InvalidValue)?;
        if !matches!(base.scheme(), "http" | "https")
            || base.host_str().is_none()
            || !base.username().is_empty()
            || base.password().is_some()
            || base.query().is_some()
            || base.fragment().is_some()
            || base.cannot_be_a_base()
        {
            return Err(DomainError::InvalidValue);
        }
        let runtime_base = base.to_string();
        let project_public_id = project_public_id.to_string();
        let mut callback = base;
        callback
            .path_segments_mut()
            .map_err(|()| DomainError::InvalidValue)?
            .pop_if_empty()
            .push("projects")
            .push(&project_public_id)
            .push("auth")
            .push("callback")
            .push(provider_key.as_str());
        Ok(Self {
            runtime_base,
            project_public_id,
            provider_key: provider_key.as_str().to_owned(),
            value: callback.into(),
        })
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.value
    }

    fn validate(&self) -> Result<(), DomainError> {
        let project_public_id = PublicId::parse(self.project_public_id.clone())?;
        let provider_key = ProviderKey::parse(self.provider_key.clone())?;
        let derived = Self::derive(&self.runtime_base, &project_public_id, &provider_key)?;
        if derived.value != self.value {
            return Err(DomainError::InvalidValue);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ProviderProofCapabilitySnapshot {
    adapter_key: String,
    adapter_capability_revision: i64,
    exact_non_renewable_proof_scopes: Vec<String>,
    callback: TrustedRuntimeProviderCallback,
    provider_pkce_required: bool,
    oidc_nonce_required: bool,
}

impl ProviderProofCapabilitySnapshot {
    pub(crate) fn from_reviewed_adapter(
        adapter_key: String,
        adapter_capability_revision: i64,
        exact_non_renewable_proof_scopes: Vec<String>,
        callback: TrustedRuntimeProviderCallback,
        provider_pkce_required: bool,
        oidc_nonce_required: bool,
    ) -> Result<Self, DomainError> {
        let snapshot = Self {
            adapter_key,
            adapter_capability_revision,
            exact_non_renewable_proof_scopes,
            callback,
            provider_pkce_required,
            oidc_nonce_required,
        };
        snapshot.validate()?;
        Ok(snapshot)
    }

    pub(crate) fn adapter_key(&self) -> &str {
        &self.adapter_key
    }

    pub(crate) const fn adapter_capability_revision(&self) -> i64 {
        self.adapter_capability_revision
    }

    pub(crate) fn exact_non_renewable_proof_scopes(&self) -> &[String] {
        &self.exact_non_renewable_proof_scopes
    }

    pub(crate) const fn callback(&self) -> &TrustedRuntimeProviderCallback {
        &self.callback
    }

    pub(crate) const fn provider_pkce_required(&self) -> bool {
        self.provider_pkce_required
    }

    pub(crate) const fn oidc_nonce_required(&self) -> bool {
        self.oidc_nonce_required
    }

    fn validate(&self) -> Result<(), DomainError> {
        if self.adapter_key.is_empty()
            || self.adapter_key.len() > 64
            || self.adapter_capability_revision <= 0
            || !self.oidc_nonce_required
            || !valid_exact_scope_set(&self.exact_non_renewable_proof_scopes)
        {
            return Err(DomainError::InvalidValue);
        }
        self.callback.validate()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ProofMethodAuthority {
    Provider {
        project_id: Uuid,
        application_id: Uuid,
        application_security_revision: i64,
        provider_configuration_id: Uuid,
        provider_revision: i64,
        assignment_security_revision: i64,
        proof_scopes: Vec<String>,
        capability: ProviderProofCapabilitySnapshot,
    },
    Email {
        project_id: Uuid,
        application_id: Uuid,
        application_security_revision: i64,
        method_policy_revision: i64,
        method_security_revision: i64,
        assignment_security_revision: i64,
    },
}

impl ProofMethodAuthority {
    pub(crate) const fn project_id(&self) -> Uuid {
        match self {
            Self::Provider { project_id, .. } | Self::Email { project_id, .. } => *project_id,
        }
    }

    pub(crate) const fn application_id(&self) -> Uuid {
        match self {
            Self::Provider { application_id, .. } | Self::Email { application_id, .. } => {
                *application_id
            }
        }
    }

    pub(crate) const fn identity_kind(&self) -> IdentityKind {
        match self {
            Self::Provider { .. } => IdentityKind::Provider,
            Self::Email { .. } => IdentityKind::Email,
        }
    }

    fn validate(&self, project_id: Uuid, target_kind: IdentityKind) -> Result<(), DomainError> {
        if self.project_id() != project_id || self.identity_kind() != target_kind {
            return Err(DomainError::InvalidValue);
        }
        match self {
            Self::Provider {
                application_id,
                application_security_revision,
                provider_configuration_id,
                provider_revision,
                assignment_security_revision,
                proof_scopes,
                capability,
                ..
            } => {
                reject_nil(*application_id)?;
                reject_nil(*provider_configuration_id)?;
                capability.validate()?;
                if [
                    *application_security_revision,
                    *provider_revision,
                    *assignment_security_revision,
                ]
                .into_iter()
                .any(|revision| revision <= 0)
                    || !exact_scope_sets_match(
                        proof_scopes,
                        &capability.exact_non_renewable_proof_scopes,
                    )
                {
                    return Err(DomainError::InvalidValue);
                }
            }
            Self::Email {
                application_id,
                application_security_revision,
                method_policy_revision,
                method_security_revision,
                assignment_security_revision,
                ..
            } => {
                reject_nil(*application_id)?;
                if [
                    *application_security_revision,
                    *method_policy_revision,
                    *method_security_revision,
                    *assignment_security_revision,
                ]
                .into_iter()
                .any(|revision| revision <= 0)
                {
                    return Err(DomainError::InvalidValue);
                }
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum IdentityMutationPlan {
    Link {
        destination_identity: ExistingIdentitySnapshot,
        candidate_kind: IdentityKind,
        destination_authority: ProofMethodAuthority,
        candidate_authority: ProofMethodAuthority,
    },
    Unlink {
        identity: ExistingIdentitySnapshot,
        authority: ProofMethodAuthority,
    },
    Merge {
        winner_identity: ExistingIdentitySnapshot,
        loser_identity: ExistingIdentitySnapshot,
        winner_authority: ProofMethodAuthority,
        loser_authority: ProofMethodAuthority,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum IdentityMutationSlotTarget {
    Existing(ExistingIdentitySnapshot),
    Candidate {
        project_id: Uuid,
        destination_user_id: Uuid,
        expected_user_revision: i64,
        expected_user_security_revision: i64,
        identity_kind: IdentityKind,
    },
}

impl IdentityMutationSlotTarget {
    const fn project_id(self) -> Uuid {
        match self {
            Self::Existing(identity) => identity.project_id,
            Self::Candidate { project_id, .. } => project_id,
        }
    }

    const fn user_id(self) -> Uuid {
        match self {
            Self::Existing(identity) => identity.user_id,
            Self::Candidate {
                destination_user_id,
                ..
            } => destination_user_id,
        }
    }

    const fn expected_user_revision(self) -> i64 {
        match self {
            Self::Existing(identity) => identity.expected_user_revision,
            Self::Candidate {
                expected_user_revision,
                ..
            } => expected_user_revision,
        }
    }

    const fn expected_user_security_revision(self) -> i64 {
        match self {
            Self::Existing(identity) => identity.expected_user_security_revision,
            Self::Candidate {
                expected_user_security_revision,
                ..
            } => expected_user_security_revision,
        }
    }

    const fn identity_kind(self) -> IdentityKind {
        match self {
            Self::Existing(identity) => identity.identity_kind,
            Self::Candidate { identity_kind, .. } => identity_kind,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum IdentityMutationSlotState {
    Pending,
    ProviderAuthorizationStarted,
    ProviderExchangeInProgress,
    ProviderExchangeFailed,
    EmailAddressEntry,
    EmailChallengePending,
    Proved,
    Expired,
}

impl IdentityMutationSlotState {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::ProviderAuthorizationStarted => "provider_authorization_started",
            Self::ProviderExchangeInProgress => "provider_exchange_in_progress",
            Self::ProviderExchangeFailed => "provider_exchange_failed",
            Self::EmailAddressEntry => "email_address_entry",
            Self::EmailChallengePending => "email_challenge_pending",
            Self::Proved => "proved",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct InteractionBrowserBinding {
    pub digest: [u8; 32],
    pub digest_key_version: i32,
    pub revision: i64,
}

impl InteractionBrowserBinding {
    fn validate(self) -> Result<(), DomainError> {
        if self.digest_key_version <= 0 || self.revision != INITIAL_BROWSER_BINDING_REVISION {
            return Err(DomainError::InvalidValue);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum IdentityProofEvidence {
    ExistingIdentity {
        identity_id: Uuid,
        identity_revision: i64,
    },
    CandidateEvidence {
        evidence_id: Uuid,
        evidence_revision: i64,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum IdentityProofReceiptStatus {
    Issued,
    Consumed,
    Expired,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct IdentityProofReceiptSnapshot {
    pub id: Uuid,
    pub project_id: Uuid,
    pub intent_id: Uuid,
    pub slot_id: Uuid,
    pub role: IdentityMutationSlotRole,
    pub purpose: &'static str,
    pub browser_binding: InteractionBrowserBinding,
    pub proof_user_id: Uuid,
    pub proof_user_revision: i64,
    pub proof_user_security_revision: i64,
    pub captured_intent_revision: i64,
    pub evidence: IdentityProofEvidence,
    pub issued_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RestoredIdentityProofReceipt {
    pub snapshot: IdentityProofReceiptSnapshot,
    pub status: IdentityProofReceiptStatus,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RestoredIdentityMutationProofSlot {
    pub id: Uuid,
    pub role: IdentityMutationSlotRole,
    pub ordinal: u8,
    pub target: IdentityMutationSlotTarget,
    pub state: IdentityMutationSlotState,
    pub slot_revision: i64,
    pub receipt: Option<RestoredIdentityProofReceipt>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RestoredIdentityMutationIntent {
    pub id: Uuid,
    pub project_id: Uuid,
    pub kind: IdentityMutationKind,
    pub status: IdentityMutationStatus,
    pub intent_revision: i64,
    pub browser_binding: Option<InteractionBrowserBinding>,
    pub slots: Vec<(RestoredIdentityMutationProofSlot, ProofMethodAuthority)>,
    pub created_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum IdentityMutationEffect {
    Applied,
    Expired,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct IdentityMutationProofSlot {
    id: Uuid,
    role: IdentityMutationSlotRole,
    ordinal: u8,
    target: IdentityMutationSlotTarget,
    authority: ProofMethodAuthority,
    state: IdentityMutationSlotState,
    slot_revision: i64,
    receipt: Option<RestoredIdentityProofReceipt>,
}

impl IdentityMutationProofSlot {
    pub(crate) const fn id(&self) -> Uuid {
        self.id
    }

    pub(crate) const fn role(&self) -> IdentityMutationSlotRole {
        self.role
    }

    pub(crate) const fn ordinal(&self) -> u8 {
        self.ordinal
    }

    pub(crate) const fn target(&self) -> IdentityMutationSlotTarget {
        self.target
    }

    pub(crate) const fn authority(&self) -> &ProofMethodAuthority {
        &self.authority
    }

    pub(crate) const fn state(&self) -> IdentityMutationSlotState {
        self.state
    }

    pub(crate) const fn slot_revision(&self) -> i64 {
        self.slot_revision
    }

    pub(crate) const fn receipt(&self) -> Option<RestoredIdentityProofReceipt> {
        self.receipt
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct IdentityMutationIntent {
    id: Uuid,
    project_id: Uuid,
    kind: IdentityMutationKind,
    status: IdentityMutationStatus,
    intent_revision: i64,
    browser_binding: Option<InteractionBrowserBinding>,
    slots: Vec<IdentityMutationProofSlot>,
    created_at: OffsetDateTime,
    expires_at: OffsetDateTime,
}

impl IdentityMutationIntent {
    pub(crate) fn create(
        id: Uuid,
        project_id: Uuid,
        plan: &IdentityMutationPlan,
        created_at: OffsetDateTime,
        expires_at: OffsetDateTime,
    ) -> Result<Self, DomainError> {
        reject_nil(id)?;
        reject_nil(project_id)?;
        validate_lifetime(created_at, expires_at)?;
        let (kind, slots) = derive_slots(project_id, plan)?;
        Ok(Self {
            id,
            project_id,
            kind,
            status: IdentityMutationStatus::PendingProof,
            intent_revision: 1,
            browser_binding: None,
            slots,
            created_at,
            expires_at,
        })
    }

    pub(crate) fn restore(record: RestoredIdentityMutationIntent) -> Result<Self, DomainError> {
        reject_nil(record.id)?;
        reject_nil(record.project_id)?;
        if let Some(binding) = record.browser_binding {
            binding.validate()?;
        }
        validate_lifetime(record.created_at, record.expires_at)?;
        if record.intent_revision <= 0 {
            return Err(DomainError::InvalidValue);
        }
        let slots = record
            .slots
            .into_iter()
            .map(|(slot, authority)| IdentityMutationProofSlot {
                id: slot.id,
                role: slot.role,
                ordinal: slot.ordinal,
                target: slot.target,
                authority,
                state: slot.state,
                slot_revision: slot.slot_revision,
                receipt: slot.receipt,
            })
            .collect();
        let intent = Self {
            id: record.id,
            project_id: record.project_id,
            kind: record.kind,
            status: record.status,
            intent_revision: record.intent_revision,
            browser_binding: record.browser_binding,
            slots,
            created_at: record.created_at,
            expires_at: record.expires_at,
        };
        intent.validate_restored()?;
        Ok(intent)
    }

    pub(crate) const fn id(&self) -> Uuid {
        self.id
    }

    pub(crate) const fn project_id(&self) -> Uuid {
        self.project_id
    }

    pub(crate) const fn kind(&self) -> IdentityMutationKind {
        self.kind
    }

    pub(crate) const fn status(&self) -> IdentityMutationStatus {
        self.status
    }

    pub(crate) const fn intent_revision(&self) -> i64 {
        self.intent_revision
    }

    pub(crate) const fn browser_binding(&self) -> Option<InteractionBrowserBinding> {
        self.browser_binding
    }

    pub(crate) fn slots(&self) -> &[IdentityMutationProofSlot] {
        &self.slots
    }

    pub(crate) const fn created_at(&self) -> OffsetDateTime {
        self.created_at
    }

    pub(crate) const fn expires_at(&self) -> OffsetDateTime {
        self.expires_at
    }

    pub(crate) fn bind_browser(
        &mut self,
        expected_revision: i64,
        browser_binding: InteractionBrowserBinding,
        now: OffsetDateTime,
    ) -> Result<IdentityMutationEffect, DomainError> {
        browser_binding.validate()?;
        if let Some(outcome) = self.ensure_pending(expected_revision, now)? {
            return Ok(outcome);
        }
        if self.browser_binding.is_some()
            || self.slots.iter().any(|slot| {
                slot.state != IdentityMutationSlotState::Pending || slot.receipt.is_some()
            })
        {
            return Err(DomainError::InvalidTransition);
        }
        self.browser_binding = Some(browser_binding);
        self.intent_revision = next_revision(self.intent_revision)?;
        Ok(IdentityMutationEffect::Applied)
    }

    pub(crate) fn start_provider(
        &mut self,
        role: IdentityMutationSlotRole,
        expected_revision: i64,
        now: OffsetDateTime,
    ) -> Result<IdentityMutationEffect, DomainError> {
        self.transition_slot(role, expected_revision, now, |authority, state| {
            if !matches!(authority, ProofMethodAuthority::Provider { .. })
                || state != IdentityMutationSlotState::Pending
            {
                return Err(DomainError::InvalidTransition);
            }
            Ok(IdentityMutationSlotState::ProviderAuthorizationStarted)
        })
    }

    pub(crate) fn claim_provider_callback(
        &mut self,
        role: IdentityMutationSlotRole,
        expected_revision: i64,
        now: OffsetDateTime,
    ) -> Result<IdentityMutationEffect, DomainError> {
        self.transition_slot(role, expected_revision, now, |authority, state| {
            if !matches!(authority, ProofMethodAuthority::Provider { .. })
                || state != IdentityMutationSlotState::ProviderAuthorizationStarted
            {
                return Err(DomainError::InvalidTransition);
            }
            Ok(IdentityMutationSlotState::ProviderExchangeInProgress)
        })
    }

    pub(crate) fn fail_provider_exchange(
        &mut self,
        role: IdentityMutationSlotRole,
        expected_revision: i64,
        now: OffsetDateTime,
    ) -> Result<IdentityMutationEffect, DomainError> {
        self.transition_slot(role, expected_revision, now, |authority, state| {
            if !matches!(authority, ProofMethodAuthority::Provider { .. })
                || !matches!(
                    state,
                    IdentityMutationSlotState::ProviderAuthorizationStarted
                        | IdentityMutationSlotState::ProviderExchangeInProgress
                )
            {
                return Err(DomainError::InvalidTransition);
            }
            Ok(IdentityMutationSlotState::ProviderExchangeFailed)
        })
    }

    pub(crate) fn begin_email(
        &mut self,
        role: IdentityMutationSlotRole,
        expected_revision: i64,
        now: OffsetDateTime,
    ) -> Result<IdentityMutationEffect, DomainError> {
        self.transition_slot(role, expected_revision, now, |authority, state| {
            if !matches!(authority, ProofMethodAuthority::Email { .. })
                || state != IdentityMutationSlotState::Pending
            {
                return Err(DomainError::InvalidTransition);
            }
            Ok(IdentityMutationSlotState::EmailAddressEntry)
        })
    }

    pub(crate) fn mark_email_challenge_pending(
        &mut self,
        role: IdentityMutationSlotRole,
        expected_revision: i64,
        now: OffsetDateTime,
    ) -> Result<IdentityMutationEffect, DomainError> {
        self.transition_slot(role, expected_revision, now, |authority, state| {
            if !matches!(authority, ProofMethodAuthority::Email { .. })
                || state != IdentityMutationSlotState::EmailAddressEntry
            {
                return Err(DomainError::InvalidTransition);
            }
            Ok(IdentityMutationSlotState::EmailChallengePending)
        })
    }

    pub(crate) fn replace_email_challenge(
        &mut self,
        role: IdentityMutationSlotRole,
        expected_revision: i64,
        now: OffsetDateTime,
    ) -> Result<IdentityMutationEffect, DomainError> {
        self.transition_slot(role, expected_revision, now, |authority, state| {
            if !matches!(authority, ProofMethodAuthority::Email { .. })
                || state != IdentityMutationSlotState::EmailChallengePending
            {
                return Err(DomainError::InvalidTransition);
            }
            Ok(IdentityMutationSlotState::EmailChallengePending)
        })
    }

    pub(crate) fn attach_receipt(
        &mut self,
        expected_revision: i64,
        now: OffsetDateTime,
        receipt: IdentityProofReceiptSnapshot,
    ) -> Result<IdentityMutationEffect, DomainError> {
        if self.status != IdentityMutationStatus::PendingProof
            || self.intent_revision != expected_revision
            || self.browser_binding.is_none()
        {
            return Err(DomainError::InvalidTransition);
        }
        let slot = self.slot(receipt.role)?;
        self.validate_receipt_for_slot(&receipt, slot)?;
        if receipt.captured_intent_revision != expected_revision
            || receipt.issued_at > now
            || now >= receipt.expires_at
        {
            return Err(DomainError::InvalidValue);
        }
        if !matches!(
            slot.state,
            IdentityMutationSlotState::ProviderExchangeInProgress
                | IdentityMutationSlotState::EmailChallengePending
        ) || slot.receipt.is_some()
        {
            return Err(DomainError::InvalidTransition);
        }
        if let Some(outcome) = self.ensure_pending(expected_revision, now)? {
            return Ok(outcome);
        }
        let next_intent_revision = next_revision(self.intent_revision)?;
        let slot = self.slot_mut(receipt.role)?;
        let next_slot_revision = next_revision(slot.slot_revision)?;
        slot.state = IdentityMutationSlotState::Proved;
        slot.receipt = Some(RestoredIdentityProofReceipt {
            snapshot: receipt,
            status: IdentityProofReceiptStatus::Issued,
        });
        slot.slot_revision = next_slot_revision;
        self.intent_revision = next_intent_revision;
        Ok(IdentityMutationEffect::Applied)
    }

    pub(crate) fn confirm_ready(
        &mut self,
        expected_revision: i64,
        now: OffsetDateTime,
    ) -> Result<IdentityMutationEffect, DomainError> {
        if let Some(outcome) = self.ensure_pending(expected_revision, now)? {
            return Ok(outcome);
        }
        if self.slots.iter().any(|slot| {
            slot.state != IdentityMutationSlotState::Proved
                || !matches!(
                    slot.receipt,
                    Some(RestoredIdentityProofReceipt {
                        status: IdentityProofReceiptStatus::Issued,
                        ..
                    })
                )
        }) {
            return Err(DomainError::InvalidTransition);
        }
        self.intent_revision = next_revision(self.intent_revision)?;
        self.status = IdentityMutationStatus::Ready;
        Ok(IdentityMutationEffect::Applied)
    }

    pub(crate) fn complete(
        &mut self,
        expected_revision: i64,
        now: OffsetDateTime,
    ) -> Result<IdentityMutationEffect, DomainError> {
        if self.status != IdentityMutationStatus::Ready || self.intent_revision != expected_revision
        {
            return Err(DomainError::InvalidTransition);
        }
        if now >= self.effective_confirmation_deadline() {
            self.terminalize(IdentityMutationStatus::Expired)?;
            return Ok(IdentityMutationEffect::Expired);
        }
        if self.slots.iter().any(|slot| {
            !matches!(
                slot.receipt,
                Some(RestoredIdentityProofReceipt {
                    status: IdentityProofReceiptStatus::Issued,
                    ..
                })
            )
        }) {
            return Err(DomainError::InvalidTransition);
        }
        let next_intent_revision = next_revision(self.intent_revision)?;
        let next_slot_revisions = next_slot_revisions(&self.slots)?;
        for (slot, next_slot_revision) in self.slots.iter_mut().zip(next_slot_revisions) {
            let receipt = slot
                .receipt
                .as_mut()
                .ok_or(DomainError::InvalidTransition)?;
            receipt.status = IdentityProofReceiptStatus::Consumed;
            slot.slot_revision = next_slot_revision;
        }
        self.status = IdentityMutationStatus::Completed;
        self.intent_revision = next_intent_revision;
        Ok(IdentityMutationEffect::Applied)
    }

    pub(crate) fn cancel(
        &mut self,
        expected_revision: i64,
        now: OffsetDateTime,
    ) -> Result<IdentityMutationEffect, DomainError> {
        if self.status.is_terminal() || self.intent_revision != expected_revision {
            return Err(DomainError::InvalidTransition);
        }
        if now >= self.effective_confirmation_deadline() {
            self.terminalize(IdentityMutationStatus::Expired)?;
            return Ok(IdentityMutationEffect::Expired);
        }
        self.terminalize(IdentityMutationStatus::Cancelled)?;
        Ok(IdentityMutationEffect::Applied)
    }

    pub(crate) fn expire(&mut self, now: OffsetDateTime) -> Result<bool, DomainError> {
        if self.status.is_terminal() || now < self.effective_confirmation_deadline() {
            return Ok(false);
        }
        self.terminalize(IdentityMutationStatus::Expired)?;
        Ok(true)
    }

    pub(crate) fn effective_confirmation_deadline(&self) -> OffsetDateTime {
        self.slots
            .iter()
            .filter_map(|slot| slot.receipt.map(|receipt| receipt.snapshot.expires_at))
            .fold(self.expires_at, std::cmp::min)
    }

    fn transition_slot(
        &mut self,
        role: IdentityMutationSlotRole,
        expected_revision: i64,
        now: OffsetDateTime,
        transition: impl FnOnce(
            &ProofMethodAuthority,
            IdentityMutationSlotState,
        ) -> Result<IdentityMutationSlotState, DomainError>,
    ) -> Result<IdentityMutationEffect, DomainError> {
        if let Some(outcome) = self.ensure_pending(expected_revision, now)? {
            return Ok(outcome);
        }
        if self.browser_binding.is_none() {
            return Err(DomainError::InvalidTransition);
        }
        let next_intent_revision = next_revision(self.intent_revision)?;
        let slot = self.slot_mut(role)?;
        let next_state = transition(&slot.authority, slot.state)?;
        let next_slot_revision = next_revision(slot.slot_revision)?;
        slot.state = next_state;
        slot.slot_revision = next_slot_revision;
        self.intent_revision = next_intent_revision;
        Ok(IdentityMutationEffect::Applied)
    }

    fn ensure_pending(
        &mut self,
        expected_revision: i64,
        now: OffsetDateTime,
    ) -> Result<Option<IdentityMutationEffect>, DomainError> {
        if self.status != IdentityMutationStatus::PendingProof
            || self.intent_revision != expected_revision
        {
            return Err(DomainError::InvalidTransition);
        }
        if now >= self.effective_confirmation_deadline() {
            self.terminalize(IdentityMutationStatus::Expired)?;
            return Ok(Some(IdentityMutationEffect::Expired));
        }
        Ok(None)
    }

    fn validate_receipt_for_slot(
        &self,
        receipt: &IdentityProofReceiptSnapshot,
        slot: &IdentityMutationProofSlot,
    ) -> Result<(), DomainError> {
        reject_nil(receipt.id)?;
        receipt.browser_binding.validate()?;
        if receipt.project_id != self.project_id
            || receipt.intent_id != self.id
            || receipt.slot_id != slot.id
            || receipt.role != slot.role
            || Some(receipt.browser_binding) != self.browser_binding
            || receipt.purpose != slot.role.purpose()
            || receipt.captured_intent_revision <= 0
            || receipt.issued_at < self.created_at
            || receipt.expires_at <= receipt.issued_at
            || receipt.expires_at > receipt.issued_at + MAX_RECEIPT_LIFETIME
            || receipt.expires_at > self.expires_at
            || receipt.proof_user_id != slot.target.user_id()
            || receipt.proof_user_revision != slot.target.expected_user_revision()
            || receipt.proof_user_security_revision != slot.target.expected_user_security_revision()
        {
            return Err(DomainError::InvalidValue);
        }
        match (slot.target, receipt.evidence) {
            (
                IdentityMutationSlotTarget::Existing(identity),
                IdentityProofEvidence::ExistingIdentity {
                    identity_id,
                    identity_revision,
                },
            ) if identity_id == identity.identity_id
                && identity_revision == identity.expected_identity_revision => {}
            (
                IdentityMutationSlotTarget::Candidate { .. },
                IdentityProofEvidence::CandidateEvidence {
                    evidence_id,
                    evidence_revision,
                },
            ) if !evidence_id.is_nil() && evidence_revision > 0 => {}
            _ => return Err(DomainError::InvalidValue),
        }
        Ok(())
    }

    fn terminalize(&mut self, status: IdentityMutationStatus) -> Result<(), DomainError> {
        if !matches!(
            status,
            IdentityMutationStatus::Expired | IdentityMutationStatus::Cancelled
        ) || self.status.is_terminal()
        {
            return Err(DomainError::InvalidTransition);
        }
        let next_intent_revision = next_revision(self.intent_revision)?;
        let next_slot_revisions = next_slot_revisions(&self.slots)?;
        for (slot, next_slot_revision) in self.slots.iter_mut().zip(next_slot_revisions) {
            slot.state = IdentityMutationSlotState::Expired;
            if let Some(receipt) = &mut slot.receipt
                && receipt.status == IdentityProofReceiptStatus::Issued
            {
                receipt.status = IdentityProofReceiptStatus::Expired;
            }
            slot.slot_revision = next_slot_revision;
        }
        self.status = status;
        self.intent_revision = next_intent_revision;
        Ok(())
    }

    fn validate_restored(&self) -> Result<(), DomainError> {
        validate_slot_set(self.project_id, self.kind, &self.slots)?;
        self.validate_browser_binding_state()?;
        let mut slot_ids = HashSet::with_capacity(self.slots.len());
        let mut receipt_ids = HashSet::with_capacity(self.slots.len());
        for slot in &self.slots {
            reject_nil(slot.id)?;
            if slot.slot_revision <= 0
                || !slot_ids.insert(slot.id)
                || slot.target.project_id() != self.project_id
            {
                return Err(DomainError::InvalidValue);
            }
            slot.authority
                .validate(self.project_id, slot.target.identity_kind())?;
            let state_matches_authority = match &slot.authority {
                ProofMethodAuthority::Provider { .. } => !matches!(
                    slot.state,
                    IdentityMutationSlotState::EmailAddressEntry
                        | IdentityMutationSlotState::EmailChallengePending
                ),
                ProofMethodAuthority::Email { .. } => !matches!(
                    slot.state,
                    IdentityMutationSlotState::ProviderAuthorizationStarted
                        | IdentityMutationSlotState::ProviderExchangeInProgress
                        | IdentityMutationSlotState::ProviderExchangeFailed
                ),
            };
            if !state_matches_authority {
                return Err(DomainError::InvalidValue);
            }
            if let Some(receipt) = slot.receipt {
                self.validate_receipt_for_slot(&receipt.snapshot, slot)?;
                if receipt.snapshot.captured_intent_revision >= self.intent_revision
                    || !receipt_ids.insert(receipt.snapshot.id)
                {
                    return Err(DomainError::InvalidValue);
                }
                let valid_state = match receipt.status {
                    IdentityProofReceiptStatus::Issued => {
                        slot.state == IdentityMutationSlotState::Proved
                            && matches!(
                                self.status,
                                IdentityMutationStatus::PendingProof
                                    | IdentityMutationStatus::Ready
                            )
                    }
                    IdentityProofReceiptStatus::Consumed => {
                        slot.state == IdentityMutationSlotState::Proved
                            && self.status == IdentityMutationStatus::Completed
                    }
                    IdentityProofReceiptStatus::Expired => {
                        slot.state == IdentityMutationSlotState::Expired
                            && matches!(
                                self.status,
                                IdentityMutationStatus::Expired | IdentityMutationStatus::Cancelled
                            )
                    }
                };
                if !valid_state {
                    return Err(DomainError::InvalidValue);
                }
            } else if slot.state == IdentityMutationSlotState::Proved
                || (slot.state == IdentityMutationSlotState::Expired
                    && !matches!(
                        self.status,
                        IdentityMutationStatus::Expired | IdentityMutationStatus::Cancelled
                    ))
            {
                return Err(DomainError::InvalidValue);
            }
        }

        let valid_aggregate_state = match self.status {
            IdentityMutationStatus::PendingProof => self
                .slots
                .iter()
                .all(|slot| slot.state != IdentityMutationSlotState::Expired),
            IdentityMutationStatus::Ready => self.slots.iter().all(|slot| {
                slot.state == IdentityMutationSlotState::Proved
                    && slot
                        .receipt
                        .is_some_and(|receipt| receipt.status == IdentityProofReceiptStatus::Issued)
            }),
            IdentityMutationStatus::Completed => self.slots.iter().all(|slot| {
                slot.state == IdentityMutationSlotState::Proved
                    && slot.receipt.is_some_and(|receipt| {
                        receipt.status == IdentityProofReceiptStatus::Consumed
                    })
            }),
            IdentityMutationStatus::Expired | IdentityMutationStatus::Cancelled => self
                .slots
                .iter()
                .all(|slot| slot.state == IdentityMutationSlotState::Expired),
        };
        if !valid_aggregate_state {
            return Err(DomainError::InvalidValue);
        }
        Ok(())
    }

    fn validate_browser_binding_state(&self) -> Result<(), DomainError> {
        if self.browser_binding.is_some() {
            return if self.intent_revision > 1 {
                Ok(())
            } else {
                Err(DomainError::InvalidValue)
            };
        }
        if !matches!(
            self.status,
            IdentityMutationStatus::PendingProof
                | IdentityMutationStatus::Expired
                | IdentityMutationStatus::Cancelled
        ) || self.slots.iter().any(|slot| {
            slot.receipt.is_some()
                || !matches!(
                    slot.state,
                    IdentityMutationSlotState::Pending | IdentityMutationSlotState::Expired
                )
        }) {
            return Err(DomainError::InvalidValue);
        }
        Ok(())
    }

    fn slot(
        &self,
        role: IdentityMutationSlotRole,
    ) -> Result<&IdentityMutationProofSlot, DomainError> {
        let mut matches = self.slots.iter().filter(|slot| slot.role == role);
        let slot = matches.next().ok_or(DomainError::InvalidTransition)?;
        if matches.next().is_some() {
            return Err(DomainError::InvalidTransition);
        }
        Ok(slot)
    }

    fn slot_mut(
        &mut self,
        role: IdentityMutationSlotRole,
    ) -> Result<&mut IdentityMutationProofSlot, DomainError> {
        let mut matches = self.slots.iter_mut().filter(|slot| slot.role == role);
        let slot = matches.next().ok_or(DomainError::InvalidTransition)?;
        if matches.next().is_some() {
            return Err(DomainError::InvalidTransition);
        }
        Ok(slot)
    }
}

fn derive_slots(
    project_id: Uuid,
    plan: &IdentityMutationPlan,
) -> Result<(IdentityMutationKind, Vec<IdentityMutationProofSlot>), DomainError> {
    let (kind, definitions) = match plan {
        IdentityMutationPlan::Link {
            destination_identity,
            candidate_kind,
            destination_authority,
            candidate_authority,
        } => {
            validate_existing(project_id, *destination_identity)?;
            (
                IdentityMutationKind::Link,
                vec![
                    (
                        IdentityMutationSlotRole::DestinationOwner,
                        IdentityMutationSlotTarget::Existing(*destination_identity),
                        destination_authority.clone(),
                    ),
                    (
                        IdentityMutationSlotRole::CandidateIdentity,
                        IdentityMutationSlotTarget::Candidate {
                            project_id,
                            destination_user_id: destination_identity.user_id,
                            expected_user_revision: destination_identity.expected_user_revision,
                            expected_user_security_revision: destination_identity
                                .expected_user_security_revision,
                            identity_kind: *candidate_kind,
                        },
                        candidate_authority.clone(),
                    ),
                ],
            )
        }
        IdentityMutationPlan::Unlink {
            identity,
            authority,
        } => {
            validate_existing(project_id, *identity)?;
            (
                IdentityMutationKind::Unlink,
                vec![(
                    IdentityMutationSlotRole::IdentityOwner,
                    IdentityMutationSlotTarget::Existing(*identity),
                    authority.clone(),
                )],
            )
        }
        IdentityMutationPlan::Merge {
            winner_identity,
            loser_identity,
            winner_authority,
            loser_authority,
        } => {
            validate_existing(project_id, *winner_identity)?;
            validate_existing(project_id, *loser_identity)?;
            if winner_identity.user_id == loser_identity.user_id
                || winner_identity.identity_id == loser_identity.identity_id
            {
                return Err(DomainError::InvalidValue);
            }
            (
                IdentityMutationKind::Merge,
                vec![
                    (
                        IdentityMutationSlotRole::WinnerOwner,
                        IdentityMutationSlotTarget::Existing(*winner_identity),
                        winner_authority.clone(),
                    ),
                    (
                        IdentityMutationSlotRole::LoserOwner,
                        IdentityMutationSlotTarget::Existing(*loser_identity),
                        loser_authority.clone(),
                    ),
                ],
            )
        }
    };

    let slots = definitions
        .into_iter()
        .enumerate()
        .map(|(ordinal, (role, target, authority))| {
            authority.validate(project_id, target.identity_kind())?;
            Ok(IdentityMutationProofSlot {
                id: Uuid::new_v4(),
                role,
                ordinal: u8::try_from(ordinal + 1).map_err(|_| DomainError::InvalidValue)?,
                target,
                authority,
                state: IdentityMutationSlotState::Pending,
                slot_revision: 1,
                receipt: None,
            })
        })
        .collect::<Result<Vec<_>, DomainError>>()?;
    validate_slot_set(project_id, kind, &slots)?;
    Ok((kind, slots))
}

fn validate_slot_set(
    project_id: Uuid,
    kind: IdentityMutationKind,
    slots: &[IdentityMutationProofSlot],
) -> Result<(), DomainError> {
    for slot in slots {
        validate_target(project_id, slot.target)?;
    }

    let expected: &[IdentityMutationSlotRole] = match kind {
        IdentityMutationKind::Link => &[
            IdentityMutationSlotRole::DestinationOwner,
            IdentityMutationSlotRole::CandidateIdentity,
        ],
        IdentityMutationKind::Unlink => &[IdentityMutationSlotRole::IdentityOwner],
        IdentityMutationKind::Merge => &[
            IdentityMutationSlotRole::WinnerOwner,
            IdentityMutationSlotRole::LoserOwner,
        ],
    };
    if slots.len() != expected.len()
        || slots
            .iter()
            .zip(expected)
            .enumerate()
            .any(|(index, (slot, role))| {
                slot.role != *role
                    || usize::from(slot.ordinal) != index + 1
                    || slot.target.project_id() != project_id
            })
    {
        return Err(DomainError::InvalidValue);
    }

    let valid_targets = match kind {
        IdentityMutationKind::Link => match (slots[0].target, slots[1].target) {
            (
                IdentityMutationSlotTarget::Existing(destination),
                IdentityMutationSlotTarget::Candidate {
                    destination_user_id,
                    expected_user_revision,
                    expected_user_security_revision,
                    ..
                },
            ) => {
                destination.user_id == destination_user_id
                    && destination.expected_user_revision == expected_user_revision
                    && destination.expected_user_security_revision
                        == expected_user_security_revision
            }
            _ => false,
        },
        IdentityMutationKind::Unlink => {
            matches!(slots[0].target, IdentityMutationSlotTarget::Existing(_))
        }
        IdentityMutationKind::Merge => match (slots[0].target, slots[1].target) {
            (
                IdentityMutationSlotTarget::Existing(winner),
                IdentityMutationSlotTarget::Existing(loser),
            ) => winner.user_id != loser.user_id && winner.identity_id != loser.identity_id,
            _ => false,
        },
    };
    if !valid_targets {
        return Err(DomainError::InvalidValue);
    }
    Ok(())
}

fn valid_exact_scope_set(scopes: &[String]) -> bool {
    if scopes.is_empty() || scopes.len() > MAX_PROVIDER_PROOF_SCOPES {
        return false;
    }
    let mut unique_scopes = HashSet::with_capacity(scopes.len());
    scopes.iter().all(|scope| {
        !scope.is_empty()
            && scope.len() <= 128
            && scope != "offline_access"
            && scope.bytes().all(|byte| {
                byte == b'!' || (b'#'..=b'[').contains(&byte) || (b']'..=b'~').contains(&byte)
            })
            && unique_scopes.insert(scope.as_str())
    })
}

fn exact_scope_sets_match(requested: &[String], declared: &[String]) -> bool {
    valid_exact_scope_set(requested)
        && valid_exact_scope_set(declared)
        && requested.len() == declared.len()
        && requested.iter().all(|scope| declared.contains(scope))
}

fn validate_target(
    project_id: Uuid,
    target: IdentityMutationSlotTarget,
) -> Result<(), DomainError> {
    match target {
        IdentityMutationSlotTarget::Existing(identity) => validate_existing(project_id, identity),
        IdentityMutationSlotTarget::Candidate {
            project_id: target_project_id,
            destination_user_id,
            expected_user_revision,
            expected_user_security_revision,
            ..
        } => {
            if target_project_id != project_id
                || expected_user_revision <= 0
                || expected_user_security_revision <= 0
            {
                return Err(DomainError::InvalidValue);
            }
            reject_nil(destination_user_id)
        }
    }
}

fn validate_existing(
    project_id: Uuid,
    identity: ExistingIdentitySnapshot,
) -> Result<(), DomainError> {
    if identity.project_id != project_id
        || identity.expected_user_revision <= 0
        || identity.expected_user_security_revision <= 0
        || identity.expected_identity_revision <= 0
    {
        return Err(DomainError::InvalidValue);
    }
    reject_nil(identity.user_id)?;
    reject_nil(identity.identity_id)
}

fn validate_lifetime(
    created_at: OffsetDateTime,
    expires_at: OffsetDateTime,
) -> Result<(), DomainError> {
    if expires_at <= created_at || expires_at > created_at + MAX_INTENT_LIFETIME {
        return Err(DomainError::InvalidValue);
    }
    Ok(())
}

fn next_slot_revisions(slots: &[IdentityMutationProofSlot]) -> Result<Vec<i64>, DomainError> {
    slots
        .iter()
        .map(|slot| next_revision(slot.slot_revision))
        .collect()
}

fn reject_nil(value: Uuid) -> Result<(), DomainError> {
    if value.is_nil() {
        return Err(DomainError::InvalidValue);
    }
    Ok(())
}

fn next_revision(revision: i64) -> Result<i64, DomainError> {
    revision
        .checked_add(1)
        .ok_or(DomainError::InvalidTransition)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(value: u128) -> Uuid {
        Uuid::from_u128(value)
    }

    fn browser_binding() -> InteractionBrowserBinding {
        InteractionBrowserBinding {
            digest: [7; 32],
            digest_key_version: 2,
            revision: INITIAL_BROWSER_BINDING_REVISION,
        }
    }

    fn trusted_callback() -> TrustedRuntimeProviderCallback {
        TrustedRuntimeProviderCallback::derive(
            "https://runtime.example",
            &PublicId::parse("prj_example01".to_owned()).unwrap(),
            &ProviderKey::parse("oidc-main".to_owned()).unwrap(),
        )
        .unwrap()
    }

    fn provider_capability(
        scopes: Vec<String>,
    ) -> Result<ProviderProofCapabilitySnapshot, DomainError> {
        ProviderProofCapabilitySnapshot::from_reviewed_adapter(
            "oidc".to_owned(),
            6,
            scopes,
            trusted_callback(),
            true,
            true,
        )
    }

    fn provider_authority(project_id: Uuid, seed: u128) -> ProofMethodAuthority {
        let proof_scopes = vec!["openid".to_owned(), "profile".to_owned()];
        ProofMethodAuthority::Provider {
            project_id,
            application_id: id(seed),
            application_security_revision: 3,
            provider_configuration_id: id(seed + 1),
            provider_revision: 4,
            assignment_security_revision: 5,
            proof_scopes: proof_scopes.clone(),
            capability: provider_capability(proof_scopes).unwrap(),
        }
    }

    fn email_authority(project_id: Uuid, seed: u128) -> ProofMethodAuthority {
        ProofMethodAuthority::Email {
            project_id,
            application_id: id(seed),
            application_security_revision: 3,
            method_policy_revision: 4,
            method_security_revision: 5,
            assignment_security_revision: 6,
        }
    }

    fn identity(
        project_id: Uuid,
        user_id: Uuid,
        identity_id: Uuid,
        identity_kind: IdentityKind,
    ) -> ExistingIdentitySnapshot {
        ExistingIdentitySnapshot {
            project_id,
            user_id,
            identity_id,
            identity_kind,
            expected_user_revision: 7,
            expected_user_security_revision: 8,
            expected_identity_revision: 9,
        }
    }

    fn times() -> (OffsetDateTime, OffsetDateTime) {
        let created_at = OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();
        (created_at, created_at + Duration::minutes(10))
    }

    fn create_unbound_link() -> IdentityMutationIntent {
        let project_id = id(1);
        let (created_at, expires_at) = times();
        IdentityMutationIntent::create(
            id(100),
            project_id,
            &IdentityMutationPlan::Link {
                destination_identity: identity(project_id, id(2), id(3), IdentityKind::Provider),
                candidate_kind: IdentityKind::Email,
                destination_authority: provider_authority(project_id, 10),
                candidate_authority: email_authority(project_id, 20),
            },
            created_at,
            expires_at,
        )
        .unwrap()
    }

    fn create_link() -> IdentityMutationIntent {
        let (created_at, _) = times();
        let mut intent = create_unbound_link();
        intent
            .bind_browser(1, browser_binding(), created_at)
            .unwrap();
        intent
    }

    fn receipt_for(
        intent: &IdentityMutationIntent,
        role: IdentityMutationSlotRole,
        evidence: IdentityProofEvidence,
        issued_at: OffsetDateTime,
        expires_at: OffsetDateTime,
    ) -> IdentityProofReceiptSnapshot {
        let slot = intent.slot(role).unwrap();
        IdentityProofReceiptSnapshot {
            id: Uuid::new_v4(),
            project_id: intent.project_id(),
            intent_id: intent.id(),
            slot_id: slot.id(),
            role,
            purpose: role.purpose(),
            browser_binding: intent.browser_binding().unwrap(),
            proof_user_id: slot.target().user_id(),
            proof_user_revision: slot.target().expected_user_revision(),
            proof_user_security_revision: slot.target().expected_user_security_revision(),
            captured_intent_revision: intent.intent_revision(),
            evidence,
            issued_at,
            expires_at,
        }
    }

    fn record_for(intent: &IdentityMutationIntent) -> RestoredIdentityMutationIntent {
        RestoredIdentityMutationIntent {
            id: intent.id(),
            project_id: intent.project_id(),
            kind: intent.kind(),
            status: intent.status(),
            intent_revision: intent.intent_revision(),
            browser_binding: intent.browser_binding(),
            slots: intent
                .slots()
                .iter()
                .map(|slot| {
                    (
                        RestoredIdentityMutationProofSlot {
                            id: slot.id(),
                            role: slot.role(),
                            ordinal: slot.ordinal(),
                            target: slot.target(),
                            state: slot.state(),
                            slot_revision: slot.slot_revision(),
                            receipt: slot.receipt(),
                        },
                        slot.authority().clone(),
                    )
                })
                .collect(),
            created_at: intent.created_at(),
            expires_at: intent.expires_at(),
        }
    }

    fn link_with_two_receipts() -> IdentityMutationIntent {
        let (created_at, _) = times();
        let mut intent = create_link();
        intent
            .start_provider(IdentityMutationSlotRole::DestinationOwner, 2, created_at)
            .unwrap();
        intent
            .claim_provider_callback(IdentityMutationSlotRole::DestinationOwner, 3, created_at)
            .unwrap();
        let destination_receipt = receipt_for(
            &intent,
            IdentityMutationSlotRole::DestinationOwner,
            IdentityProofEvidence::ExistingIdentity {
                identity_id: id(3),
                identity_revision: 9,
            },
            created_at,
            created_at + Duration::minutes(5),
        );
        intent
            .attach_receipt(4, created_at, destination_receipt)
            .unwrap();
        intent
            .begin_email(IdentityMutationSlotRole::CandidateIdentity, 5, created_at)
            .unwrap();
        intent
            .mark_email_challenge_pending(
                IdentityMutationSlotRole::CandidateIdentity,
                6,
                created_at,
            )
            .unwrap();
        let candidate_receipt = receipt_for(
            &intent,
            IdentityMutationSlotRole::CandidateIdentity,
            IdentityProofEvidence::CandidateEvidence {
                evidence_id: id(200),
                evidence_revision: 2,
            },
            created_at,
            created_at + Duration::minutes(4),
        );
        intent
            .attach_receipt(7, created_at, candidate_receipt)
            .unwrap();
        intent
    }

    #[test]
    fn plans_derive_only_mandatory_private_slots_in_stable_order() {
        let intent = create_link();
        assert_eq!(intent.kind(), IdentityMutationKind::Link);
        assert_eq!(
            intent
                .slots()
                .iter()
                .map(IdentityMutationProofSlot::role)
                .collect::<Vec<_>>(),
            [
                IdentityMutationSlotRole::DestinationOwner,
                IdentityMutationSlotRole::CandidateIdentity,
            ]
        );
        assert!(matches!(
            intent.slots()[1].target(),
            IdentityMutationSlotTarget::Candidate {
                destination_user_id,
                identity_kind: IdentityKind::Email,
                ..
            } if destination_user_id == id(2)
        ));
    }

    #[test]
    fn control_created_intent_binds_one_browser_before_any_proof() {
        let (created_at, expires_at) = times();
        let mut intent = create_unbound_link();
        assert_eq!(intent.browser_binding(), None);
        assert_eq!(
            intent.start_provider(
                IdentityMutationSlotRole::DestinationOwner,
                intent.intent_revision(),
                created_at,
            ),
            Err(DomainError::InvalidTransition)
        );
        assert_eq!(
            intent.bind_browser(1, browser_binding(), created_at),
            Ok(IdentityMutationEffect::Applied)
        );
        assert_eq!(intent.browser_binding(), Some(browser_binding()));
        assert_eq!(intent.intent_revision(), 2);
        assert_eq!(
            intent.bind_browser(2, browser_binding(), created_at),
            Err(DomainError::InvalidTransition)
        );
        let mut born_bound = record_for(&intent);
        born_bound.intent_revision = 1;
        assert_eq!(
            IdentityMutationIntent::restore(born_bound),
            Err(DomainError::InvalidValue)
        );

        let mut cancelled = create_unbound_link();
        assert_eq!(
            cancelled.cancel(1, created_at),
            Ok(IdentityMutationEffect::Applied)
        );
        assert_eq!(cancelled.browser_binding(), None);
        assert_eq!(
            IdentityMutationIntent::restore(record_for(&cancelled)),
            Ok(cancelled)
        );

        let mut expired = create_unbound_link();
        assert_eq!(
            expired.bind_browser(1, browser_binding(), expires_at),
            Ok(IdentityMutationEffect::Expired)
        );
        assert_eq!(expired.browser_binding(), None);
        assert_eq!(expired.status(), IdentityMutationStatus::Expired);
        assert_eq!(
            IdentityMutationIntent::restore(record_for(&expired)),
            Ok(expired)
        );
    }

    #[test]
    fn restoration_rejects_unbound_progressed_proof() {
        let (created_at, _) = times();
        let mut intent = create_link();
        intent
            .start_provider(IdentityMutationSlotRole::DestinationOwner, 2, created_at)
            .unwrap();
        let mut record = record_for(&intent);
        record.browser_binding = None;
        assert_eq!(
            IdentityMutationIntent::restore(record),
            Err(DomainError::InvalidValue)
        );
    }

    #[test]
    fn validated_restoration_round_trips_private_aggregate_state() {
        let mut intent = create_link();
        let (_, expires_at) = times();
        assert_eq!(
            IdentityMutationIntent::restore(record_for(&intent)),
            Ok(intent.clone())
        );
        assert_eq!(
            intent.cancel(intent.intent_revision(), expires_at),
            Ok(IdentityMutationEffect::Expired)
        );
        assert_eq!(
            IdentityMutationIntent::restore(record_for(&intent)),
            Ok(intent)
        );
    }

    #[test]
    fn restoration_rejects_cross_slot_receipts_duplicate_receipts_and_invalid_targets() {
        let intent = link_with_two_receipts();

        let mut swapped = record_for(&intent);
        let (first, second) = swapped.slots.split_at_mut(1);
        std::mem::swap(&mut first[0].0.receipt, &mut second[0].0.receipt);
        assert_eq!(
            IdentityMutationIntent::restore(swapped),
            Err(DomainError::InvalidValue)
        );

        let mut duplicate = record_for(&intent);
        duplicate.slots[1].0.receipt = duplicate.slots[0].0.receipt;
        assert_eq!(
            IdentityMutationIntent::restore(duplicate),
            Err(DomainError::InvalidValue)
        );

        let mut nil_existing = record_for(&create_link());
        if let IdentityMutationSlotTarget::Existing(identity) = &mut nil_existing.slots[0].0.target
        {
            identity.identity_id = Uuid::nil();
        }
        assert_eq!(
            IdentityMutationIntent::restore(nil_existing),
            Err(DomainError::InvalidValue)
        );

        let mut invalid_candidate = record_for(&create_link());
        if let IdentityMutationSlotTarget::Candidate {
            destination_user_id,
            expected_user_revision,
            ..
        } = &mut invalid_candidate.slots[1].0.target
        {
            *destination_user_id = Uuid::nil();
            *expected_user_revision = 0;
        }
        assert_eq!(
            IdentityMutationIntent::restore(invalid_candidate),
            Err(DomainError::InvalidValue)
        );

        let mut wrong_method_state = record_for(&create_link());
        wrong_method_state.slots[1].0.state =
            IdentityMutationSlotState::ProviderAuthorizationStarted;
        assert_eq!(
            IdentityMutationIntent::restore(wrong_method_state),
            Err(DomainError::InvalidValue)
        );
    }

    #[test]
    fn project_and_method_authority_mismatches_are_rejected() {
        let project_id = id(1);
        let other_project_id = id(99);
        let (created_at, expires_at) = times();
        let provider_identity = identity(project_id, id(2), id(3), IdentityKind::Provider);
        for authority in [
            provider_authority(other_project_id, 10),
            email_authority(project_id, 20),
        ] {
            assert_eq!(
                IdentityMutationIntent::create(
                    id(100),
                    project_id,
                    &IdentityMutationPlan::Unlink {
                        identity: provider_identity,
                        authority,
                    },
                    created_at,
                    expires_at,
                ),
                Err(DomainError::InvalidValue)
            );
        }
        let mut renewable = provider_authority(project_id, 10);
        if let ProofMethodAuthority::Provider { proof_scopes, .. } = &mut renewable {
            proof_scopes.push("offline_access".to_owned());
        }
        assert_eq!(
            IdentityMutationIntent::create(
                id(100),
                project_id,
                &IdentityMutationPlan::Unlink {
                    identity: provider_identity,
                    authority: renewable,
                },
                created_at,
                expires_at,
            ),
            Err(DomainError::InvalidValue)
        );
    }

    #[test]
    fn provider_capability_rejects_caller_shaped_scopes_and_untrusted_callbacks() {
        for scopes in [
            vec!["openid offline_access".to_owned()],
            vec!["openid\tprofile".to_owned()],
            vec!["offline_access".to_owned()],
        ] {
            assert_eq!(provider_capability(scopes), Err(DomainError::InvalidValue));
        }
        let project_public_id = PublicId::parse("prj_example01".to_owned()).unwrap();
        let provider_key = ProviderKey::parse("oidc-main".to_owned()).unwrap();
        for base in [
            "not a URL",
            "ftp://runtime.example",
            "https://user@runtime.example",
            "https://runtime.example?redirect=evil",
        ] {
            assert!(
                TrustedRuntimeProviderCallback::derive(base, &project_public_id, &provider_key)
                    .is_err()
            );
        }
        assert_eq!(
            TrustedRuntimeProviderCallback::derive(
                "https://auth.example/runtime/",
                &project_public_id,
                &provider_key,
            )
            .unwrap()
            .as_str(),
            "https://auth.example/runtime/projects/prj_example01/auth/callback/oidc-main"
        );
        assert_eq!(
            TrustedRuntimeProviderCallback::derive(
                "http://127.0.0.1:8080/",
                &project_public_id,
                &provider_key,
            )
            .unwrap()
            .as_str(),
            "http://127.0.0.1:8080/projects/prj_example01/auth/callback/oidc-main"
        );

        let project_id = id(1);
        let (created_at, expires_at) = times();
        let mut extra_scope = provider_authority(project_id, 10);
        if let ProofMethodAuthority::Provider { proof_scopes, .. } = &mut extra_scope {
            proof_scopes.push("managed.profile.read".to_owned());
        }
        assert_eq!(
            IdentityMutationIntent::create(
                id(100),
                project_id,
                &IdentityMutationPlan::Unlink {
                    identity: identity(project_id, id(2), id(3), IdentityKind::Provider),
                    authority: extra_scope,
                },
                created_at,
                expires_at,
            ),
            Err(DomainError::InvalidValue)
        );

        let mut untrusted_callback = provider_authority(project_id, 10);
        if let ProofMethodAuthority::Provider { capability, .. } = &mut untrusted_callback {
            capability.callback.value =
                "https://evil.example/projects/prj_example01/auth/callback/provider".to_owned();
        }
        assert_eq!(
            IdentityMutationIntent::create(
                id(100),
                project_id,
                &IdentityMutationPlan::Unlink {
                    identity: identity(project_id, id(2), id(3), IdentityKind::Provider),
                    authority: untrusted_callback,
                },
                created_at,
                expires_at,
            ),
            Err(DomainError::InvalidValue)
        );
    }

    #[test]
    fn exact_receipts_gate_ready_and_are_consumed_once() {
        let (created_at, _) = times();
        let mut intent = create_link();
        assert_eq!(
            intent
                .start_provider(IdentityMutationSlotRole::DestinationOwner, 2, created_at)
                .unwrap(),
            IdentityMutationEffect::Applied
        );
        intent
            .claim_provider_callback(IdentityMutationSlotRole::DestinationOwner, 3, created_at)
            .unwrap();
        let destination_receipt = receipt_for(
            &intent,
            IdentityMutationSlotRole::DestinationOwner,
            IdentityProofEvidence::ExistingIdentity {
                identity_id: id(3),
                identity_revision: 9,
            },
            created_at,
            created_at + Duration::minutes(5),
        );
        intent
            .attach_receipt(4, created_at, destination_receipt)
            .unwrap();
        intent
            .begin_email(IdentityMutationSlotRole::CandidateIdentity, 5, created_at)
            .unwrap();
        intent
            .mark_email_challenge_pending(
                IdentityMutationSlotRole::CandidateIdentity,
                6,
                created_at,
            )
            .unwrap();
        assert_eq!(
            intent.replace_email_challenge(
                IdentityMutationSlotRole::CandidateIdentity,
                7,
                created_at,
            ),
            Ok(IdentityMutationEffect::Applied)
        );
        let candidate_receipt = receipt_for(
            &intent,
            IdentityMutationSlotRole::CandidateIdentity,
            IdentityProofEvidence::CandidateEvidence {
                evidence_id: id(200),
                evidence_revision: 2,
            },
            created_at,
            created_at + Duration::minutes(4),
        );
        intent
            .attach_receipt(8, created_at, candidate_receipt)
            .unwrap();
        assert_eq!(
            intent.attach_receipt(9, created_at, candidate_receipt),
            Err(DomainError::InvalidValue)
        );
        intent.confirm_ready(9, created_at).unwrap();
        assert_eq!(intent.status(), IdentityMutationStatus::Ready);
        assert_eq!(
            intent.effective_confirmation_deadline(),
            created_at + Duration::minutes(4)
        );
        intent.complete(10, created_at).unwrap();
        assert_eq!(intent.status(), IdentityMutationStatus::Completed);
        assert!(intent.slots().iter().all(|slot| matches!(
            slot.receipt(),
            Some(RestoredIdentityProofReceipt {
                status: IdentityProofReceiptStatus::Consumed,
                ..
            })
        )));
        assert_eq!(
            intent.complete(11, created_at),
            Err(DomainError::InvalidTransition)
        );
    }

    #[test]
    fn mismatched_receipt_binding_is_rejected_without_partial_mutation() {
        let (created_at, _) = times();
        let mut intent = create_link();
        intent
            .start_provider(IdentityMutationSlotRole::DestinationOwner, 2, created_at)
            .unwrap();
        intent
            .claim_provider_callback(IdentityMutationSlotRole::DestinationOwner, 3, created_at)
            .unwrap();
        let mut receipt = receipt_for(
            &intent,
            IdentityMutationSlotRole::DestinationOwner,
            IdentityProofEvidence::ExistingIdentity {
                identity_id: id(3),
                identity_revision: 9,
            },
            created_at,
            created_at + Duration::minutes(5),
        );
        receipt.browser_binding.digest[0] ^= 1;
        assert_eq!(
            intent.attach_receipt(4, created_at, receipt),
            Err(DomainError::InvalidValue)
        );
        assert_eq!(intent.intent_revision(), 4);
        assert_eq!(
            intent.slots()[0].state(),
            IdentityMutationSlotState::ProviderExchangeInProgress
        );
        assert!(intent.slots()[0].receipt().is_none());
    }

    #[test]
    fn email_resend_invalidates_receipt_captured_at_the_prior_intent_revision() {
        let (created_at, _) = times();
        let mut intent = create_link();
        intent
            .begin_email(IdentityMutationSlotRole::CandidateIdentity, 2, created_at)
            .unwrap();
        intent
            .mark_email_challenge_pending(
                IdentityMutationSlotRole::CandidateIdentity,
                3,
                created_at,
            )
            .unwrap();
        let stale_receipt = receipt_for(
            &intent,
            IdentityMutationSlotRole::CandidateIdentity,
            IdentityProofEvidence::CandidateEvidence {
                evidence_id: id(200),
                evidence_revision: 2,
            },
            created_at,
            created_at + Duration::minutes(4),
        );
        intent
            .replace_email_challenge(IdentityMutationSlotRole::CandidateIdentity, 4, created_at)
            .unwrap();
        assert_eq!(
            intent.attach_receipt(5, created_at, stale_receipt),
            Err(DomainError::InvalidValue)
        );
        assert_eq!(intent.intent_revision(), 5);
        assert!(intent.slots()[1].receipt().is_none());
    }

    #[test]
    fn authoritative_now_and_binding_validation_precede_expiry_terminalization() {
        let (created_at, _) = times();
        let mut future_issued = create_link();
        future_issued
            .begin_email(IdentityMutationSlotRole::CandidateIdentity, 2, created_at)
            .unwrap();
        future_issued
            .mark_email_challenge_pending(
                IdentityMutationSlotRole::CandidateIdentity,
                3,
                created_at,
            )
            .unwrap();
        let future_receipt = receipt_for(
            &future_issued,
            IdentityMutationSlotRole::CandidateIdentity,
            IdentityProofEvidence::CandidateEvidence {
                evidence_id: id(200),
                evidence_revision: 2,
            },
            created_at + Duration::minutes(1),
            created_at + Duration::minutes(4),
        );
        assert_eq!(
            future_issued.attach_receipt(4, created_at, future_receipt),
            Err(DomainError::InvalidValue)
        );
        assert_eq!(future_issued.status(), IdentityMutationStatus::PendingProof);

        let mut intent = create_link();
        intent
            .start_provider(IdentityMutationSlotRole::DestinationOwner, 2, created_at)
            .unwrap();
        intent
            .claim_provider_callback(IdentityMutationSlotRole::DestinationOwner, 3, created_at)
            .unwrap();
        let first_receipt = receipt_for(
            &intent,
            IdentityMutationSlotRole::DestinationOwner,
            IdentityProofEvidence::ExistingIdentity {
                identity_id: id(3),
                identity_revision: 9,
            },
            created_at,
            created_at + Duration::minutes(1),
        );
        intent.attach_receipt(4, created_at, first_receipt).unwrap();
        intent
            .begin_email(IdentityMutationSlotRole::CandidateIdentity, 5, created_at)
            .unwrap();
        intent
            .mark_email_challenge_pending(
                IdentityMutationSlotRole::CandidateIdentity,
                6,
                created_at,
            )
            .unwrap();
        let valid_receipt = receipt_for(
            &intent,
            IdentityMutationSlotRole::CandidateIdentity,
            IdentityProofEvidence::CandidateEvidence {
                evidence_id: id(201),
                evidence_revision: 3,
            },
            created_at + Duration::seconds(30),
            created_at + Duration::minutes(4),
        );
        let mut malformed_receipt = valid_receipt;
        malformed_receipt.slot_id = id(999);
        assert_eq!(
            intent.attach_receipt(7, created_at + Duration::minutes(1), malformed_receipt,),
            Err(DomainError::InvalidValue)
        );
        assert_eq!(intent.status(), IdentityMutationStatus::PendingProof);
        assert_eq!(
            intent.attach_receipt(7, created_at + Duration::minutes(1), valid_receipt),
            Ok(IdentityMutationEffect::Expired)
        );
        assert_eq!(intent.status(), IdentityMutationStatus::Expired);
    }

    #[test]
    fn earliest_receipt_deadline_terminalizes_before_later_effects() {
        let (created_at, _) = times();
        let mut intent = create_link();
        intent
            .start_provider(IdentityMutationSlotRole::DestinationOwner, 2, created_at)
            .unwrap();
        intent
            .claim_provider_callback(IdentityMutationSlotRole::DestinationOwner, 3, created_at)
            .unwrap();
        let receipt = receipt_for(
            &intent,
            IdentityMutationSlotRole::DestinationOwner,
            IdentityProofEvidence::ExistingIdentity {
                identity_id: id(3),
                identity_revision: 9,
            },
            created_at,
            created_at + Duration::minutes(1),
        );
        intent.attach_receipt(4, created_at, receipt).unwrap();
        assert_eq!(
            intent.begin_email(
                IdentityMutationSlotRole::CandidateIdentity,
                5,
                created_at + Duration::minutes(1),
            ),
            Ok(IdentityMutationEffect::Expired)
        );
        assert_eq!(intent.status(), IdentityMutationStatus::Expired);
        assert!(intent.slots().iter().all(|slot| {
            slot.state() == IdentityMutationSlotState::Expired
                && slot
                    .receipt()
                    .is_none_or(|receipt| receipt.status == IdentityProofReceiptStatus::Expired)
        }));
    }

    #[test]
    fn cancel_at_deadline_is_expiry_and_restore_rejects_missing_roles() {
        let (created_at, expires_at) = times();
        let mut intent = create_link();
        assert_eq!(
            intent.cancel(2, expires_at),
            Ok(IdentityMutationEffect::Expired)
        );
        assert_eq!(intent.status(), IdentityMutationStatus::Expired);

        let record = RestoredIdentityMutationIntent {
            id: id(100),
            project_id: id(1),
            kind: IdentityMutationKind::Link,
            status: IdentityMutationStatus::PendingProof,
            intent_revision: 1,
            browser_binding: Some(browser_binding()),
            slots: Vec::new(),
            created_at,
            expires_at,
        };
        assert_eq!(
            IdentityMutationIntent::restore(record),
            Err(DomainError::InvalidValue)
        );
    }

    #[test]
    fn stale_revision_and_provider_failure_are_one_way() {
        let (created_at, _) = times();
        let mut intent = create_link();
        assert_eq!(
            intent.start_provider(IdentityMutationSlotRole::DestinationOwner, 3, created_at),
            Err(DomainError::InvalidTransition)
        );
        intent
            .start_provider(IdentityMutationSlotRole::DestinationOwner, 2, created_at)
            .unwrap();
        let mut denied = intent.clone();
        denied
            .fail_provider_exchange(IdentityMutationSlotRole::DestinationOwner, 3, created_at)
            .unwrap();
        assert_eq!(
            denied.slots()[0].state(),
            IdentityMutationSlotState::ProviderExchangeFailed
        );
        intent
            .claim_provider_callback(IdentityMutationSlotRole::DestinationOwner, 3, created_at)
            .unwrap();
        intent
            .fail_provider_exchange(IdentityMutationSlotRole::DestinationOwner, 4, created_at)
            .unwrap();
        assert_eq!(
            intent.start_provider(IdentityMutationSlotRole::DestinationOwner, 5, created_at),
            Err(DomainError::InvalidTransition)
        );
    }
}
