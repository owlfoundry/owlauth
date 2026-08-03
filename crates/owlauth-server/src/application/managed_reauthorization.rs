use std::{collections::BTreeSet, sync::Arc};

use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest, Sha256};
use time::{Duration, OffsetDateTime};
use url::Url;
use uuid::Uuid;
use zeroize::Zeroizing;

use super::{
    ApplicationError, BoundedManagedProfile, Clock, ConnectionGuard, ManagedConnectionRepository,
    ManagedCredentialContext, ManagedCredentialProtector, OpaquePurpose, ProtectedPurpose,
    ProtectedValue, ProviderAuthorizationRequest, ProviderCallbackRequest, ProviderIdentity,
    ProviderRequestProfile, ProviderSecretResolver, RuntimeProtector, UpstreamProviderClient,
    VersionedDigest,
};
use crate::domain::{
    BoundedProviderProfile, ManagedProfileCapabilities, ManagedProfileCapability,
    ProfileDisplayName, ProfilePictureUrl,
};

const REAUTHORIZATION_LIFETIME: Duration = Duration::minutes(10);
const CALLBACK_CLOCK_SKEW_SECONDS: i64 = 60;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ManagedReauthorizationStatus {
    AwaitingBrowserBinding,
    AwaitingProviderStart,
    ProviderAuthorizationStarted,
    ProviderExchangeInProgress,
    Completed,
    ProviderExchangeFailed,
    Expired,
    Cancelled,
}

impl ManagedReauthorizationStatus {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::AwaitingBrowserBinding => "awaiting_browser_binding",
            Self::AwaitingProviderStart => "awaiting_provider_start",
            Self::ProviderAuthorizationStarted => "provider_authorization_started",
            Self::ProviderExchangeInProgress => "provider_exchange_in_progress",
            Self::Completed => "completed",
            Self::ProviderExchangeFailed => "provider_exchange_failed",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
        }
    }

    pub(crate) fn parse(value: &str) -> Result<Self, ApplicationError> {
        match value {
            "awaiting_browser_binding" => Ok(Self::AwaitingBrowserBinding),
            "awaiting_provider_start" => Ok(Self::AwaitingProviderStart),
            "provider_authorization_started" => Ok(Self::ProviderAuthorizationStarted),
            "provider_exchange_in_progress" => Ok(Self::ProviderExchangeInProgress),
            "completed" => Ok(Self::Completed),
            "provider_exchange_failed" => Ok(Self::ProviderExchangeFailed),
            "expired" => Ok(Self::Expired),
            "cancelled" => Ok(Self::Cancelled),
            _ => Err(ApplicationError::Integrity),
        }
    }

    pub(crate) const fn terminal(self) -> bool {
        matches!(
            self,
            Self::Completed | Self::ProviderExchangeFailed | Self::Expired | Self::Cancelled
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ManagedReauthorizationRecord {
    pub id: Uuid,
    pub project_id: Uuid,
    pub project_public_id: String,
    pub connection_id: Uuid,
    pub linked_identity_id: Uuid,
    pub user_id: Uuid,
    pub provider_configuration_id: Uuid,
    pub provider_key: String,
    pub application_id: Uuid,
    pub expected_connection_generation: i64,
    pub expected_credential_generation: i64,
    pub expected_connection_revision: i64,
    pub provider_kind: crate::domain::ProviderKind,
    pub project_security_revision: i64,
    pub user_security_revision: i64,
    pub identity_revision: i64,
    pub provider_revision: i64,
    pub managed_profile_revision: i64,
    pub application_revision: i64,
    pub assignment_security_revision: i64,
    pub issuer: String,
    pub subject: String,
    pub client_id: String,
    pub secret_ref: String,
    pub callback_url: String,
    pub adapter_key: String,
    pub adapter_capability_revision: i64,
    pub supports_revocation: bool,
    pub required_scopes: Vec<String>,
    pub provider_pkce_required: bool,
    pub oidc_nonce_required: bool,
    pub revision: i64,
    pub status: ManagedReauthorizationStatus,
    pub csrf_key_version: Option<i32>,
    pub oidc_nonce: Option<VersionedDigest>,
    pub provider_pkce: Option<ProtectedValue>,
    pub expires_at: OffsetDateTime,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ManagedReauthorizationView {
    pub id: Uuid,
    pub project_id: Uuid,
    pub project_public_id: String,
    pub user_id: Uuid,
    pub connection_id: Uuid,
    pub provider_key: String,
    pub application_id: Uuid,
    pub status: ManagedReauthorizationStatus,
    pub revision: i64,
    pub expires_at: OffsetDateTime,
}

impl From<&ManagedReauthorizationRecord> for ManagedReauthorizationView {
    fn from(value: &ManagedReauthorizationRecord) -> Self {
        Self {
            id: value.id,
            project_id: value.project_id,
            project_public_id: value.project_public_id.clone(),
            user_id: value.user_id,
            connection_id: value.connection_id,
            provider_key: value.provider_key.clone(),
            application_id: value.application_id,
            status: value.status,
            revision: value.revision,
            expires_at: value.expires_at,
        }
    }
}

pub(crate) struct CreateManagedReauthorization {
    pub project_id: Uuid,
    pub user_id: Uuid,
    pub connection_id: Uuid,
    pub application_id: Uuid,
    pub expected_connection_revision: i64,
    pub expected_connection_generation: i64,
    pub expected_credential_generation: i64,
    pub idempotency_key: String,
    pub correlation_id: Uuid,
}

pub(crate) struct CreatedManagedReauthorization {
    pub interaction: ManagedReauthorizationView,
    pub hosted_target: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ManagedAdapterCapabilitySnapshot {
    pub adapter_key: String,
    pub adapter_revision: i64,
    pub exact_scopes: Vec<String>,
    pub provider_pkce_required: bool,
    pub oidc_nonce_required: bool,
    pub supports_revocation: bool,
}

impl ManagedAdapterCapabilitySnapshot {
    fn from_capability(capability: &ManagedProfileCapability) -> Result<Self, ApplicationError> {
        capability.validate().map_err(ApplicationError::from)?;
        Ok(Self {
            adapter_key: capability.adapter_key.to_owned(),
            adapter_revision: capability.adapter_revision,
            exact_scopes: capability
                .exact_scopes
                .iter()
                .map(ToString::to_string)
                .collect(),
            provider_pkce_required: capability.provider_pkce_required,
            oidc_nonce_required: capability.oidc_nonce_required,
            supports_revocation: capability.supports_revocation,
        })
    }

    fn matches_record(&self, record: &ManagedReauthorizationRecord) -> bool {
        self.adapter_key == record.adapter_key
            && self.adapter_revision == record.adapter_capability_revision
            && self.exact_scopes == record.required_scopes
            && self.provider_pkce_required == record.provider_pkce_required
            && self.oidc_nonce_required == record.oidc_nonce_required
            && (!record.supports_revocation || self.supports_revocation)
    }
}

pub(crate) struct PreparedManagedReauthorizationCreate {
    pub command: CreateManagedReauthorization,
    pub capability: ManagedAdapterCapabilitySnapshot,
    pub interaction_id: Uuid,
    pub interaction_digest: VersionedDigest,
    pub request_digest: Vec<u8>,
    pub protected_create_result: ProtectedValue,
    pub expires_at: OffsetDateTime,
    pub now: OffsetDateTime,
}

pub(crate) enum CreateManagedReauthorizationResult {
    Created(ManagedReauthorizationRecord),
    Replayed {
        interaction: ManagedReauthorizationRecord,
        protected_create_result: Option<ProtectedValue>,
    },
}

pub(crate) struct ManagedReauthorizationBootstrap {
    pub interaction: ManagedReauthorizationView,
    pub browser_binding: Zeroizing<String>,
    pub csrf: Zeroizing<String>,
}

pub(crate) struct StartManagedReauthorization {
    pub project_public_id: String,
    pub interaction: String,
    pub browser_binding: String,
    pub csrf: String,
    pub expected_revision: i64,
}

pub(crate) struct ManagedReauthorizationDenial {
    pub project_public_id: String,
    pub provider_key: String,
    pub state: String,
    pub browser_binding: String,
    pub safe_outcome: &'static str,
}

pub(crate) struct ManagedReauthorizationCallback {
    pub project_public_id: String,
    pub provider_key: String,
    pub state: String,
    pub code: String,
    pub browser_binding: String,
}

pub(crate) enum ManagedReauthorizationCallbackOutcome {
    Completed(ManagedReauthorizationView),
    Duplicate(ManagedReauthorizationView),
    TerminalizedFailure(ManagedReauthorizationView),
    TerminalizedStaleAuthority,
}

pub(crate) struct CompletedManagedReauthorization {
    pub successor: ConnectionGuard,
    pub interaction: ManagedReauthorizationRecord,
}

pub(crate) enum FailManagedReauthorization {
    Terminalized(ManagedReauthorizationRecord),
    TerminalWinner(ManagedReauthorizationRecord),
}

pub(crate) enum ClaimManagedReauthorization {
    Claimed(ManagedReauthorizationRecord),
    Duplicate(ManagedReauthorizationRecord),
    TerminalizedStaleAuthority,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ManagedReauthorizationDigestVersions {
    pub interaction: i32,
    pub browser_binding: Option<i32>,
    pub upstream_state: Option<i32>,
    pub oidc_nonce: Option<i32>,
    pub provider_pkce: Option<i32>,
    pub create_result: Option<i32>,
}

#[async_trait]
#[allow(
    clippy::too_many_arguments,
    reason = "every interaction CAS carries its explicit browser, revision, and frozen authority inputs"
)]
pub(crate) trait ManagedReauthorizationRepository: Send + Sync {
    async fn create(
        &self,
        prepared: PreparedManagedReauthorizationCreate,
    ) -> Result<CreateManagedReauthorizationResult, ApplicationError>;

    async fn control_read(
        &self,
        project_id: Uuid,
        user_id: Uuid,
        connection_id: Uuid,
        interaction_id: Uuid,
        now: OffsetDateTime,
    ) -> Result<ManagedReauthorizationRecord, ApplicationError>;

    async fn cancel(
        &self,
        project_id: Uuid,
        user_id: Uuid,
        connection_id: Uuid,
        interaction_id: Uuid,
        expected_revision: i64,
        correlation_id: Uuid,
        now: OffsetDateTime,
    ) -> Result<ManagedReauthorizationRecord, ApplicationError>;

    async fn digest_versions(
        &self,
        interaction_id: Uuid,
        now: OffsetDateTime,
    ) -> Result<ManagedReauthorizationDigestVersions, ApplicationError>;

    async fn bind_browser(
        &self,
        interaction: &VersionedDigest,
        browser_binding: &VersionedDigest,
        csrf: &VersionedDigest,
        now: OffsetDateTime,
    ) -> Result<ManagedReauthorizationRecord, ApplicationError>;

    async fn hosted_read(
        &self,
        interaction: &VersionedDigest,
        browser_binding: &VersionedDigest,
        now: OffsetDateTime,
    ) -> Result<ManagedReauthorizationRecord, ApplicationError>;

    async fn start_provider(
        &self,
        interaction_id: Uuid,
        interaction: &VersionedDigest,
        browser_binding: &VersionedDigest,
        csrf: &VersionedDigest,
        expected_revision: i64,
        upstream_state: VersionedDigest,
        oidc_nonce: VersionedDigest,
        provider_pkce: Option<ProtectedValue>,
        supports_revocation: bool,
        now: OffsetDateTime,
    ) -> Result<ManagedReauthorizationRecord, ApplicationError>;

    async fn claim_callback(
        &self,
        interaction_id: Uuid,
        project_public_id: &str,
        provider_key: &str,
        upstream_state: &VersionedDigest,
        browser_binding: &VersionedDigest,
        now: OffsetDateTime,
    ) -> Result<ClaimManagedReauthorization, ApplicationError>;

    async fn deny_callback(
        &self,
        project_public_id: &str,
        provider_key: &str,
        upstream_state: &VersionedDigest,
        browser_binding: &VersionedDigest,
        safe_outcome: &'static str,
        now: OffsetDateTime,
    ) -> Result<ManagedReauthorizationRecord, ApplicationError>;

    async fn complete_callback(
        &self,
        claimed: &ManagedReauthorizationRecord,
        protected_successor: ProtectedValue,
        correlation_id: Uuid,
        now: OffsetDateTime,
    ) -> Result<CompletedManagedReauthorization, ApplicationError>;

    async fn fail_callback(
        &self,
        claimed: &ManagedReauthorizationRecord,
        safe_outcome: &'static str,
        now: OffsetDateTime,
    ) -> Result<FailManagedReauthorization, ApplicationError>;
}

/// Control-only capability for issuing target handles and replaying an idempotent create result.
/// No Runtime service accepts this trait.
pub(crate) trait ManagedReauthorizationTargetIssuer: Send + Sync {
    fn random_handle(&self, bytes: usize) -> Result<Zeroizing<String>, ApplicationError>;
    fn digest_handle(
        &self,
        interaction_id: Uuid,
        value: &[u8],
    ) -> Result<VersionedDigest, ApplicationError>;
    fn protect_create_result(
        &self,
        interaction_id: Uuid,
        value: &[u8],
    ) -> Result<ProtectedValue, ApplicationError>;
    fn replay_create_result(
        &self,
        interaction_id: Uuid,
        value: &ProtectedValue,
    ) -> Result<Zeroizing<Vec<u8>>, ApplicationError>;
}

/// Runtime-only capability for verifying a target at its frozen digest-key version.
/// It deliberately has no handle generation, encryption, or replay-decryption methods.
pub(crate) trait ManagedReauthorizationTargetVerifier: Send + Sync {
    fn readable_key_versions(&self) -> BTreeSet<i32>;
    fn digest_handle_at(
        &self,
        interaction_id: Uuid,
        value: &[u8],
        key_version: i32,
    ) -> Result<VersionedDigest, ApplicationError>;
}

pub(crate) struct ManagedReauthorizationControlService {
    repository: Arc<dyn ManagedReauthorizationRepository>,
    target_issuer: Arc<dyn ManagedReauthorizationTargetIssuer>,
    clock: Arc<dyn Clock>,
    runtime_base: Url,
    capabilities: ManagedProfileCapabilities,
}

impl ManagedReauthorizationControlService {
    pub(crate) fn new(
        repository: Arc<dyn ManagedReauthorizationRepository>,
        target_issuer: Arc<dyn ManagedReauthorizationTargetIssuer>,
        clock: Arc<dyn Clock>,
        runtime_base: Url,
        capabilities: impl Into<ManagedProfileCapabilities>,
    ) -> Result<Self, ApplicationError> {
        let capabilities = capabilities.into();
        capabilities.validate().map_err(ApplicationError::from)?;
        Ok(Self {
            repository,
            target_issuer,
            clock,
            runtime_base,
            capabilities,
        })
    }

    pub(crate) async fn create_for_adapter_key(
        &self,
        command: CreateManagedReauthorization,
        adapter_key: &str,
    ) -> Result<CreatedManagedReauthorization, ApplicationError> {
        validate_create(&command)?;
        let capability = self
            .capabilities
            .for_adapter_key(adapter_key)
            .ok_or(ApplicationError::InvalidTransition)?;
        let capability = ManagedAdapterCapabilitySnapshot::from_capability(capability)?;
        let now = self.clock.now();
        let interaction_id = Uuid::new_v4();
        let handle = self.credential_with_id(interaction_id)?;
        let interaction_digest = self
            .target_issuer
            .digest_handle(interaction_id, handle.as_bytes())?;
        let hosted_target = self.hosted_target(&handle)?;
        let protected_create_result = self
            .target_issuer
            .protect_create_result(interaction_id, hosted_target.as_bytes())?;
        let request_digest = create_request_digest(&command);
        let result = self
            .repository
            .create(PreparedManagedReauthorizationCreate {
                command,
                capability,
                interaction_id,
                interaction_digest,
                request_digest,
                protected_create_result,
                expires_at: now + REAUTHORIZATION_LIFETIME,
                now,
            })
            .await?;
        match result {
            CreateManagedReauthorizationResult::Created(interaction) => {
                Ok(CreatedManagedReauthorization {
                    interaction: (&interaction).into(),
                    hosted_target: Some(hosted_target),
                })
            }
            CreateManagedReauthorizationResult::Replayed {
                interaction,
                protected_create_result,
            } => {
                let target = protected_create_result
                    .map(|value| {
                        self.target_issuer
                            .replay_create_result(interaction.id, &value)
                    })
                    .transpose()?
                    .map(|value| {
                        String::from_utf8(value.to_vec()).map_err(|_| ApplicationError::Integrity)
                    })
                    .transpose()?;
                Ok(CreatedManagedReauthorization {
                    interaction: (&interaction).into(),
                    hosted_target: target,
                })
            }
        }
    }

    pub(crate) async fn read(
        &self,
        project_id: Uuid,
        user_id: Uuid,
        connection_id: Uuid,
        interaction_id: Uuid,
    ) -> Result<ManagedReauthorizationView, ApplicationError> {
        self.repository
            .control_read(
                project_id,
                user_id,
                connection_id,
                interaction_id,
                self.clock.now(),
            )
            .await
            .map(|record| (&record).into())
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn cancel(
        &self,
        project_id: Uuid,
        user_id: Uuid,
        connection_id: Uuid,
        interaction_id: Uuid,
        expected_revision: i64,
        correlation_id: Uuid,
    ) -> Result<ManagedReauthorizationView, ApplicationError> {
        self.repository
            .cancel(
                project_id,
                user_id,
                connection_id,
                interaction_id,
                expected_revision,
                correlation_id,
                self.clock.now(),
            )
            .await
            .map(|record| (&record).into())
    }

    fn credential_with_id(&self, id: Uuid) -> Result<Zeroizing<String>, ApplicationError> {
        let random = self.target_issuer.random_handle(32)?;
        Ok(Zeroizing::new(format!("{id}.{}", random.as_str())))
    }

    fn hosted_target(&self, handle: &str) -> Result<String, ApplicationError> {
        self.runtime_base
            .join(&format!("auth/managed-reauthorizations/{handle}"))
            .map(String::from)
            .map_err(|_| ApplicationError::Integrity)
    }
}

pub(crate) struct ManagedReauthorizationRuntimeService {
    repository: Arc<dyn ManagedReauthorizationRepository>,
    connections: Arc<dyn ManagedConnectionRepository>,
    protector: Arc<dyn RuntimeProtector>,
    target_verifier: Arc<dyn ManagedReauthorizationTargetVerifier>,
    credential_protector: Arc<dyn ManagedCredentialProtector>,
    provider: Arc<dyn UpstreamProviderClient>,
    provider_secrets: Arc<dyn ProviderSecretResolver>,
    clock: Arc<dyn Clock>,
    capabilities: ManagedProfileCapabilities,
}

impl ManagedReauthorizationRuntimeService {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        repository: Arc<dyn ManagedReauthorizationRepository>,
        connections: Arc<dyn ManagedConnectionRepository>,
        protector: Arc<dyn RuntimeProtector>,
        target_verifier: Arc<dyn ManagedReauthorizationTargetVerifier>,
        credential_protector: Arc<dyn ManagedCredentialProtector>,
        provider: Arc<dyn UpstreamProviderClient>,
        provider_secrets: Arc<dyn ProviderSecretResolver>,
        clock: Arc<dyn Clock>,
        capabilities: impl Into<ManagedProfileCapabilities>,
    ) -> Result<Self, ApplicationError> {
        let capabilities = capabilities.into();
        capabilities.validate().map_err(ApplicationError::from)?;
        Ok(Self {
            repository,
            connections,
            protector,
            target_verifier,
            credential_protector,
            provider,
            provider_secrets,
            clock,
            capabilities,
        })
    }

    pub(crate) async fn bootstrap(
        &self,
        interaction: &str,
        browser_binding: Option<&str>,
    ) -> Result<ManagedReauthorizationBootstrap, ApplicationError> {
        let id = credential_id(interaction)?;
        let now = self.clock.now();
        let versions = self.repository.digest_versions(id, now).await?;
        let interaction_digest = self.digest_id_at(
            OpaquePurpose::ManagedReauthorization,
            id,
            interaction.as_bytes(),
            versions.interaction,
        )?;
        let (record, browser_binding, bound_csrf) = if let Some(binding) = browser_binding {
            let digest = self.digest_id_at(
                OpaquePurpose::ManagedReauthorizationBrowser,
                id,
                binding.as_bytes(),
                versions
                    .browser_binding
                    .ok_or(ApplicationError::Integrity)?,
            )?;
            (
                self.repository
                    .hosted_read(&interaction_digest, &digest, now)
                    .await?,
                Zeroizing::new(binding.to_owned()),
                None,
            )
        } else {
            let raw = self.credential_with_id(id)?;
            let digest = self.digest_id(
                OpaquePurpose::ManagedReauthorizationBrowser,
                id,
                raw.as_bytes(),
            )?;
            let csrf = self.protector.as_ref().derive_opaque(
                OpaquePurpose::ManagedReauthorizationCsrf,
                id.as_bytes(),
                None,
            )?;
            let csrf_digest = self.digest_id_at(
                OpaquePurpose::ManagedReauthorizationCsrf,
                id,
                csrf.as_bytes(),
                self.protector.as_ref().active_version(),
            )?;
            let record = self
                .repository
                .bind_browser(&interaction_digest, &digest, &csrf_digest, now)
                .await?;
            (record, raw, Some(csrf))
        };
        let csrf = if let Some(csrf) = bound_csrf {
            csrf
        } else {
            let csrf_version = record.csrf_key_version.ok_or(ApplicationError::Integrity)?;
            self.protector.as_ref().derive_opaque(
                OpaquePurpose::ManagedReauthorizationCsrf,
                record.id.as_bytes(),
                Some(csrf_version),
            )?
        };
        Ok(ManagedReauthorizationBootstrap {
            interaction: (&record).into(),
            browser_binding,
            csrf,
        })
    }

    pub(crate) async fn start(
        &self,
        command: StartManagedReauthorization,
    ) -> Result<String, ApplicationError> {
        let id = credential_id(&command.interaction)?;
        let versions = self
            .repository
            .digest_versions(id, self.clock.now())
            .await?;
        let interaction = self.digest_id_at(
            OpaquePurpose::ManagedReauthorization,
            id,
            command.interaction.as_bytes(),
            versions.interaction,
        )?;
        let browser = self.digest_id_at(
            OpaquePurpose::ManagedReauthorizationBrowser,
            id,
            command.browser_binding.as_bytes(),
            versions
                .browser_binding
                .ok_or(ApplicationError::Integrity)?,
        )?;
        let current = self
            .repository
            .hosted_read(&interaction, &browser, self.clock.now())
            .await?;
        if current.project_public_id != command.project_public_id
            || current.status != ManagedReauthorizationStatus::AwaitingProviderStart
            || current.revision != command.expected_revision
        {
            return Err(ApplicationError::RevisionConflict);
        }
        let csrf = self.digest_id_at(
            OpaquePurpose::ManagedReauthorizationCsrf,
            id,
            command.csrf.as_bytes(),
            current
                .csrf_key_version
                .ok_or(ApplicationError::Integrity)?,
        )?;
        let state = self.credential_with_id(id)?;
        let state_digest = self.digest_id(
            OpaquePurpose::ManagedReauthorizationState,
            id,
            state.as_bytes(),
        )?;
        let nonce = self.protector.as_ref().derive_opaque(
            OpaquePurpose::ManagedReauthorizationNonce,
            id.as_bytes(),
            None,
        )?;
        let nonce_digest = self.protector.as_ref().digest(
            OpaquePurpose::ManagedReauthorizationNonce,
            id.as_bytes(),
            nonce.as_bytes(),
        )?;
        let (verifier, challenge, protected_verifier) = if current.provider_pkce_required {
            let verifier = self.protector.as_ref().random_opaque(32)?;
            let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
            let protected = self.protector.as_ref().protect(
                ProtectedPurpose::ManagedReauthorizationPkce,
                id.as_bytes(),
                verifier.as_bytes(),
            )?;
            (Some(verifier), challenge, Some(protected))
        } else {
            (None, String::new(), None)
        };
        // Provider discovery is a bounded read-only preflight: it sends no client secret, code,
        // refresh token, or interaction digest. Keeping it before the start CAS means a transient
        // discovery failure leaves `awaiting_provider_start` retryable; the exact revision and
        // browser/CSRF/authority CAS below still prevents a stale URL from becoming authoritative.
        let authorization = self
            .provider
            .as_ref()
            .authorization_url(ProviderAuthorizationRequest {
                kind: current.provider_kind,
                issuer: current.issuer.clone(),
                client_id: current.client_id.clone(),
                callback_url: current.callback_url.clone(),
                state: state.to_string(),
                nonce: nonce.to_string(),
                pkce_challenge: challenge,
                profile: ProviderRequestProfile::ManagedProfile,
            })
            .await
            .map_err(|_| ApplicationError::ExternalStore)?;
        self.repository
            .start_provider(
                id,
                &interaction,
                &browser,
                &csrf,
                command.expected_revision,
                state_digest,
                nonce_digest,
                protected_verifier,
                authorization
                    .managed_supports_revocation
                    .ok_or(ApplicationError::Integrity)?,
                self.clock.now(),
            )
            .await?;
        drop(verifier);
        Ok(authorization.url)
    }

    pub(crate) async fn deny_callback(
        &self,
        denial: ManagedReauthorizationDenial,
    ) -> Result<ManagedReauthorizationView, ApplicationError> {
        let id = managed_callback_owner_id(&denial.state)?;
        let versions = self
            .repository
            .digest_versions(id, self.clock.now())
            .await?;
        let state = self.digest_id_at(
            OpaquePurpose::ManagedReauthorizationState,
            id,
            denial.state.as_bytes(),
            versions.upstream_state.ok_or(ApplicationError::Integrity)?,
        )?;
        let browser = self.digest_id_at(
            OpaquePurpose::ManagedReauthorizationBrowser,
            id,
            denial.browser_binding.as_bytes(),
            versions
                .browser_binding
                .ok_or(ApplicationError::Integrity)?,
        )?;
        let record = self
            .repository
            .deny_callback(
                &denial.project_public_id,
                &denial.provider_key,
                &state,
                &browser,
                denial.safe_outcome,
                self.clock.now(),
            )
            .await?;
        Ok((&record).into())
    }

    pub(crate) async fn complete_callback(
        &self,
        callback: ManagedReauthorizationCallback,
    ) -> Result<ManagedReauthorizationCallbackOutcome, ApplicationError> {
        if callback.code.is_empty() || callback.code.len() > 4096 {
            return Err(ApplicationError::InvalidInput);
        }
        // Provider callback state is shared by ordinary sign-in and managed reauthorization.
        // Managed state has exactly one separator (`uuid.secret`); ordinary sign-in freezes a
        // digest-key version as `uuid.version.secret`. Classify ownership before any repository
        // mutation or provider exchange. A syntactically valid state owned by another flow is a
        // non-error miss so the HTTP callback dispatcher can fall through to that owner.
        let id = managed_callback_owner_id(&callback.state)?;
        let versions = self
            .repository
            .digest_versions(id, self.clock.now())
            .await?;
        // Probe every remaining protected/digest field before the callback claim CAS. Generic
        // Runtime nonce/PKCE versions and the purpose-limited target version are checked against
        // their independent retained rings before any state mutation.
        for version in [versions.oidc_nonce, versions.provider_pkce]
            .into_iter()
            .flatten()
        {
            self.digest_id_at(
                OpaquePurpose::ManagedReauthorizationNonce,
                id,
                b"readability-probe",
                version,
            )?;
        }
        if let Some(version) = versions.create_result {
            self.target_verifier
                .digest_handle_at(id, b"readability-probe", version)?;
        }
        let state = self.digest_id_at(
            OpaquePurpose::ManagedReauthorizationState,
            id,
            callback.state.as_bytes(),
            versions.upstream_state.ok_or(ApplicationError::Integrity)?,
        )?;
        let browser = self.digest_id_at(
            OpaquePurpose::ManagedReauthorizationBrowser,
            id,
            callback.browser_binding.as_bytes(),
            versions
                .browser_binding
                .ok_or(ApplicationError::Integrity)?,
        )?;
        let claimed = self
            .repository
            .claim_callback(
                id,
                &callback.project_public_id,
                &callback.provider_key,
                &state,
                &browser,
                self.clock.now(),
            )
            .await?;
        let claimed = match claimed {
            ClaimManagedReauthorization::Claimed(claimed) => claimed,
            ClaimManagedReauthorization::Duplicate(record) => {
                return Ok(ManagedReauthorizationCallbackOutcome::Duplicate(
                    (&record).into(),
                ));
            }
            ClaimManagedReauthorization::TerminalizedStaleAuthority => {
                return Ok(ManagedReauthorizationCallbackOutcome::TerminalizedStaleAuthority);
            }
        };
        match self.exchange_and_complete(&callback, &claimed).await {
            Ok(outcome) => Ok(outcome),
            Err(_provider_error) => resolve_failed_callback(
                self.repository
                    .fail_callback(&claimed, "provider_exchange_failed", self.clock.now())
                    .await,
            ),
        }
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the callback keeps capability fencing, exchange, and successor commit visibly ordered"
    )]
    async fn exchange_and_complete(
        &self,
        callback: &ManagedReauthorizationCallback,
        claimed: &ManagedReauthorizationRecord,
    ) -> Result<ManagedReauthorizationCallbackOutcome, ApplicationError> {
        let capability = self
            .capabilities
            .for_kind(claimed.provider_kind)
            .ok_or(ApplicationError::RevisionConflict)?;
        let capability = ManagedAdapterCapabilitySnapshot::from_capability(capability)?;
        if !capability.matches_record(claimed) {
            return Err(ApplicationError::RevisionConflict);
        }
        let secret = self
            .provider_secrets
            .as_ref()
            .resolve(&claimed.secret_ref)
            .await?;
        let verifier = match &claimed.provider_pkce {
            Some(value) => self.protector.as_ref().unprotect(
                ProtectedPurpose::ManagedReauthorizationPkce,
                claimed.id.as_bytes(),
                value,
            )?,
            None if !claimed.provider_pkce_required => Zeroizing::new(Vec::new()),
            None => return Err(ApplicationError::Integrity),
        };
        let nonce = self.protector.as_ref().derive_opaque(
            OpaquePurpose::ManagedReauthorizationNonce,
            claimed.id.as_bytes(),
            Some(
                claimed
                    .oidc_nonce
                    .as_ref()
                    .ok_or(ApplicationError::Integrity)?
                    .key_version,
            ),
        )?;
        let identity = self
            .provider
            .as_ref()
            .exchange_code(ProviderCallbackRequest {
                kind: claimed.provider_kind,
                issuer: claimed.issuer.clone(),
                client_id: claimed.client_id.clone(),
                client_secret: secret,
                callback_url: claimed.callback_url.clone(),
                code: Zeroizing::new(callback.code.clone()),
                pkce_verifier: Zeroizing::new(
                    String::from_utf8(verifier.to_vec())
                        .map_err(|_| ApplicationError::Integrity)?,
                ),
                expected_nonce: nonce,
                now: self.clock.now(),
                allowed_clock_skew_seconds: CALLBACK_CLOCK_SKEW_SECONDS,
                profile: ProviderRequestProfile::ManagedProfile,
            })
            .await
            .map_err(|_| ApplicationError::ExternalStore)?;
        Self::validate_identity(claimed, &identity)?;
        let renewable = identity
            .renewable_credential
            .as_ref()
            .ok_or(ApplicationError::InvalidTransition)?;
        let context = ManagedCredentialContext {
            project_id: claimed.project_id,
            provider_configuration_id: claimed.provider_configuration_id,
            linked_identity_id: claimed.linked_identity_id,
            connection_id: claimed.connection_id,
            connection_generation: claimed.expected_connection_generation + 1,
            credential_generation: claimed.expected_credential_generation + 1,
        };
        let protected = self
            .credential_protector
            .as_ref()
            .protect_credential(&context, renewable.value.as_ref())?;
        // Re-check immediately before the successor commit. The callback freezes every adapter
        // property; a deployment capability change invalidates the exchanged observation.
        let capability = self
            .capabilities
            .for_kind(claimed.provider_kind)
            .ok_or(ApplicationError::RevisionConflict)?;
        let capability = ManagedAdapterCapabilitySnapshot::from_capability(capability)?;
        if !capability.matches_record(claimed) {
            return Err(ApplicationError::RevisionConflict);
        }
        let completed = self
            .repository
            .complete_callback(claimed, protected, Uuid::new_v4(), self.clock.now())
            .await?;
        // Callback claims are already adapter-validated. Their bounded profile commits only
        // after the successor transaction and under the successor generation guard.
        if let Ok(Some(profile)) = callback_profile(identity, self.clock.now()) {
            // Profile enrichment is optional and runs after the authoritative successor commit.
            // Neither invalid optional claims nor a projection transaction failure may roll the
            // callback's credential success back into a provider-exchange failure.
            let _ = self
                .connections
                .as_ref()
                .commit_reauthorization_profile(
                    &completed.successor,
                    profile,
                    self.clock.now() + Duration::hours(6),
                    self.clock.now(),
                )
                .await;
        }
        // The terminal interaction snapshot is read in the same transaction as the successor.
        // There is deliberately no fallible post-commit read that could report failure and try to
        // terminalize an already-successful callback.
        Ok(ManagedReauthorizationCallbackOutcome::Completed(
            (&completed.interaction).into(),
        ))
    }

    fn validate_identity(
        claimed: &ManagedReauthorizationRecord,
        identity: &ProviderIdentity,
    ) -> Result<(), ApplicationError> {
        if identity.issuer != claimed.issuer || identity.subject != claimed.subject {
            return Err(ApplicationError::InvalidTransition);
        }
        let renewable = identity
            .renewable_credential
            .as_ref()
            .ok_or(ApplicationError::InvalidTransition)?;
        let mut expected = claimed.required_scopes.clone();
        expected.sort_unstable();
        let mut actual = renewable.granted_scopes.clone();
        actual.sort_unstable();
        let actual_count = actual.len();
        actual.dedup();
        if actual.len() != actual_count
            || expected != actual
            || renewable.supports_revocation != claimed.supports_revocation
        {
            return Err(ApplicationError::InvalidTransition);
        }
        Ok(())
    }

    fn credential_with_id(&self, id: Uuid) -> Result<Zeroizing<String>, ApplicationError> {
        let random = self.protector.random_opaque(32)?;
        Ok(Zeroizing::new(format!("{id}.{}", random.as_str())))
    }

    fn digest_id(
        &self,
        purpose: OpaquePurpose,
        id: Uuid,
        value: &[u8],
    ) -> Result<VersionedDigest, ApplicationError> {
        self.protector.digest(purpose, id.as_bytes(), value)
    }

    fn digest_id_at(
        &self,
        purpose: OpaquePurpose,
        id: Uuid,
        value: &[u8],
        version: i32,
    ) -> Result<VersionedDigest, ApplicationError> {
        if purpose == OpaquePurpose::ManagedReauthorization {
            self.target_verifier.digest_handle_at(id, value, version)
        } else {
            self.protector
                .digest_at(purpose, id.as_bytes(), value, version)
        }
    }
}

fn resolve_failed_callback(
    terminalization: Result<FailManagedReauthorization, ApplicationError>,
) -> Result<ManagedReauthorizationCallbackOutcome, ApplicationError> {
    match terminalization {
        Ok(FailManagedReauthorization::Terminalized(terminal)) => Ok(
            ManagedReauthorizationCallbackOutcome::TerminalizedFailure((&terminal).into()),
        ),
        // A concurrent terminal owner won after this claim. The exact row was read under lock;
        // expose its terminal view without mutating or misrepresenting the winner.
        Ok(FailManagedReauthorization::TerminalWinner(terminal)) => Ok(
            ManagedReauthorizationCallbackOutcome::Duplicate((&terminal).into()),
        ),
        // Terminal cleanup is mandatory. Infrastructure/integrity failure while doing it
        // supersedes the provider-facing error instead of being silently discarded.
        Err(terminalization_error) => Err(terminalization_error),
    }
}

fn callback_profile(
    identity: ProviderIdentity,
    observed_at: OffsetDateTime,
) -> Result<Option<BoundedManagedProfile>, ApplicationError> {
    if identity.display_name.is_none() && identity.picture_url.is_none() {
        return Ok(None);
    }
    Ok(Some(BoundedManagedProfile {
        profile: BoundedProviderProfile {
            display_name: identity
                .display_name
                .map(ProfileDisplayName::parse)
                .transpose()?,
            picture_url: identity
                .picture_url
                .map(ProfilePictureUrl::parse)
                .transpose()?,
            locale: None,
        },
        observed_at,
    }))
}

fn managed_callback_owner_id(value: &str) -> Result<Uuid, ApplicationError> {
    let mut segments = value.split('.');
    let Some(id) = segments.next() else {
        return Err(ApplicationError::NotFound);
    };
    let Ok(id) = Uuid::parse_str(id) else {
        return Err(ApplicationError::NotFound);
    };
    let Some(second) = segments.next() else {
        return Err(ApplicationError::NotFound);
    };
    match (segments.next(), segments.next()) {
        // Managed reauthorization owns `uuid.secret`. Once that class is recognized,
        // malformed material is its error rather than another callback owner's input.
        (None, None) => credential_id(value),
        // Ordinary sign-in owns `uuid.digest-version.secret`. Its exact canonical shape is a
        // non-mutating miss here; Runtime Auth remains responsible for authenticating the MAC.
        (Some(secret), None)
            if !second.is_empty()
                && second.bytes().all(|byte| byte.is_ascii_digit())
                && second.parse::<i32>().is_ok_and(|version| version > 0)
                && !secret.is_empty() =>
        {
            Err(ApplicationError::NotFound)
        }
        // A UUID-prefixed but unknown credential class is not managed-owned. Do not derive a
        // managed digest, touch its repository, or perform provider I/O.
        _ => Err(ApplicationError::NotFound),
    }
    .map(|_| id)
}

fn credential_id(value: &str) -> Result<Uuid, ApplicationError> {
    if value.len() > 256 {
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

fn validate_create(command: &CreateManagedReauthorization) -> Result<(), ApplicationError> {
    if command.expected_connection_revision <= 0
        || command.expected_connection_generation <= 0
        || command.expected_credential_generation <= 0
        || !(8..=128).contains(&command.idempotency_key.len())
        || !command
            .idempotency_key
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(ApplicationError::InvalidInput);
    }
    Ok(())
}

fn create_request_digest(command: &CreateManagedReauthorization) -> Vec<u8> {
    let mut digest = Sha256::new();
    digest.update(b"owlauth.managed_reauthorization.create.v1\0");
    for value in [
        command.project_id,
        command.user_id,
        command.connection_id,
        command.application_id,
    ] {
        digest.update(value.as_bytes());
    }
    digest.update(command.expected_connection_revision.to_be_bytes());
    digest.update(command.expected_connection_generation.to_be_bytes());
    digest.update(command.expected_credential_generation.to_be_bytes());
    digest.finalize().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::application::RenewableProviderCredential;

    fn frozen_record() -> ManagedReauthorizationRecord {
        ManagedReauthorizationRecord {
            id: Uuid::new_v4(),
            project_id: Uuid::new_v4(),
            project_public_id: "prj_managed_test".to_owned(),
            connection_id: Uuid::new_v4(),
            linked_identity_id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            provider_configuration_id: Uuid::new_v4(),
            provider_key: "oidc-main".to_owned(),
            application_id: Uuid::new_v4(),
            expected_connection_generation: 1,
            expected_credential_generation: 1,
            expected_connection_revision: 1,
            provider_kind: crate::domain::ProviderKind::Oidc,
            project_security_revision: 1,
            user_security_revision: 1,
            identity_revision: 1,
            provider_revision: 1,
            managed_profile_revision: 1,
            application_revision: 1,
            assignment_security_revision: 1,
            issuer: "https://issuer.example".to_owned(),
            subject: "subject-1".to_owned(),
            client_id: "client".to_owned(),
            secret_ref: "secret/ref/oidc-main".to_owned(),
            callback_url: "https://runtime.example/callback".to_owned(),
            adapter_key: "controlled_oidc_profile_v1".to_owned(),
            adapter_capability_revision: 1,
            supports_revocation: true,
            required_scopes: ["offline_access", "openid", "profile"]
                .map(str::to_owned)
                .to_vec(),
            provider_pkce_required: true,
            oidc_nonce_required: true,
            revision: 4,
            status: ManagedReauthorizationStatus::ProviderExchangeInProgress,
            csrf_key_version: Some(1),
            oidc_nonce: Some(VersionedDigest {
                value: [7; 32],
                key_version: 1,
            }),
            provider_pkce: Some(ProtectedValue {
                ciphertext: vec![8; 48],
                key_version: 1,
            }),
            expires_at: OffsetDateTime::UNIX_EPOCH + Duration::minutes(10),
        }
    }

    fn identity() -> ProviderIdentity {
        ProviderIdentity {
            issuer: "https://issuer.example".to_owned(),
            subject: "subject-1".to_owned(),
            display_name: Some("Ada".to_owned()),
            picture_url: Some("https://cdn.example/ada.png".to_owned()),
            renewable_credential: Some(RenewableProviderCredential {
                value: Zeroizing::new(b"renewable-only".to_vec()),
                granted_scopes: ["profile", "offline_access", "openid"]
                    .map(str::to_owned)
                    .to_vec(),
                supports_revocation: true,
            }),
        }
    }

    #[test]
    fn reauthorization_freezes_and_rechecks_the_exact_adapter_capability() {
        let capability = ManagedProfileCapability {
            adapter_key: "controlled_oidc_profile_v1",
            adapter_revision: 1,
            exact_scopes: &["offline_access", "openid", "profile"],
            provider_pkce_required: true,
            oidc_nonce_required: true,
            credential_rotates: true,
            read_retry_safe: true,
            renewal_replay: crate::domain::RenewalReplay::Never,
            supports_revocation: true,
            profile_schema: "owlauth.provider-profile.v1",
            maximum_body_bytes: 16 * 1024,
            maximum_latency_seconds: 10,
        };
        let snapshot = ManagedAdapterCapabilitySnapshot::from_capability(&capability)
            .expect("reviewed adapter capability");
        let mut record = frozen_record();
        assert!(snapshot.matches_record(&record));
        record.adapter_capability_revision += 1;
        assert!(!snapshot.matches_record(&record));
        record.adapter_capability_revision -= 1;
        record.required_scopes.push("email".to_owned());
        assert!(!snapshot.matches_record(&record));
    }

    #[test]
    fn callback_state_classifier_has_one_exact_owner() {
        let id = Uuid::new_v4();
        assert_eq!(
            managed_callback_owner_id(&format!("{id}.managed-secret")),
            Ok(id)
        );
        assert_eq!(
            managed_callback_owner_id(&format!("{id}.1.ordinary-login-mac")),
            Err(ApplicationError::NotFound)
        );
        assert_eq!(
            managed_callback_owner_id(&format!("{id}.1.extra.unknown")),
            Err(ApplicationError::NotFound)
        );
        assert_eq!(
            managed_callback_owner_id("unknown-callback-state"),
            Err(ApplicationError::NotFound)
        );
        assert_eq!(
            managed_callback_owner_id(&format!("{id}.")),
            Err(ApplicationError::InvalidInput)
        );
    }

    #[test]
    fn callback_failure_requires_terminal_cleanup_and_preserves_a_concurrent_winner() {
        let mut terminal = frozen_record();
        terminal.status = ManagedReauthorizationStatus::ProviderExchangeFailed;
        assert!(matches!(
            resolve_failed_callback(Ok(FailManagedReauthorization::Terminalized(
                terminal.clone()
            ))),
            Ok(ManagedReauthorizationCallbackOutcome::TerminalizedFailure(
                _
            ))
        ));
        terminal.status = ManagedReauthorizationStatus::Completed;
        assert!(matches!(
            resolve_failed_callback(Ok(FailManagedReauthorization::TerminalWinner(terminal))),
            Ok(ManagedReauthorizationCallbackOutcome::Duplicate(view))
                if view.status == ManagedReauthorizationStatus::Completed
        ));
        assert_eq!(
            resolve_failed_callback(Err(ApplicationError::Persistence)).err(),
            Some(ApplicationError::Persistence),
            "mandatory terminal cleanup failure must be surfaced"
        );
        assert_eq!(
            resolve_failed_callback(Err(ApplicationError::Integrity)).err(),
            Some(ApplicationError::Integrity)
        );
    }

    #[test]
    fn callback_identity_requires_exact_frozen_owner_scopes_and_renewable_material() {
        let record = frozen_record();
        assert!(
            ManagedReauthorizationRuntimeService::validate_identity(&record, &identity()).is_ok()
        );

        let mut wrong_subject = identity();
        wrong_subject.subject = "other-subject".to_owned();
        assert_eq!(
            ManagedReauthorizationRuntimeService::validate_identity(&record, &wrong_subject),
            Err(ApplicationError::InvalidTransition)
        );
        let mut wrong_issuer = identity();
        wrong_issuer.issuer = "https://other-issuer.example".to_owned();
        assert_eq!(
            ManagedReauthorizationRuntimeService::validate_identity(&record, &wrong_issuer),
            Err(ApplicationError::InvalidTransition)
        );

        let mut scope_loss = identity();
        scope_loss
            .renewable_credential
            .as_mut()
            .expect("renewable fixture")
            .granted_scopes = ["openid", "profile"].map(str::to_owned).to_vec();
        assert_eq!(
            ManagedReauthorizationRuntimeService::validate_identity(&record, &scope_loss),
            Err(ApplicationError::InvalidTransition)
        );
        let mut scope_extra = identity();
        scope_extra
            .renewable_credential
            .as_mut()
            .expect("renewable fixture")
            .granted_scopes
            .push("email".to_owned());
        assert_eq!(
            ManagedReauthorizationRuntimeService::validate_identity(&record, &scope_extra),
            Err(ApplicationError::InvalidTransition)
        );
        let mut scope_duplicate = identity();
        scope_duplicate
            .renewable_credential
            .as_mut()
            .expect("renewable fixture")
            .granted_scopes
            .push("profile".to_owned());
        assert_eq!(
            ManagedReauthorizationRuntimeService::validate_identity(&record, &scope_duplicate),
            Err(ApplicationError::InvalidTransition)
        );

        let mut no_renewable = identity();
        no_renewable.renewable_credential = None;
        assert_eq!(
            ManagedReauthorizationRuntimeService::validate_identity(&record, &no_renewable),
            Err(ApplicationError::InvalidTransition)
        );
    }

    #[test]
    fn optional_callback_profile_is_bounded_independently_of_credential_success() {
        let observed = OffsetDateTime::UNIX_EPOCH;
        assert!(callback_profile(identity(), observed).is_ok_and(|profile| profile.is_some()));
        let mut invalid = identity();
        invalid.picture_url = Some("http://not-allowed.example/picture".to_owned());
        assert_eq!(
            callback_profile(invalid, observed),
            Err(ApplicationError::InvalidInput)
        );
    }

    #[test]
    fn create_digest_and_validation_bind_every_frozen_generation() {
        let mut command = CreateManagedReauthorization {
            project_id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            connection_id: Uuid::new_v4(),
            application_id: Uuid::new_v4(),
            expected_connection_revision: 1,
            expected_connection_generation: 1,
            expected_credential_generation: 1,
            idempotency_key: "managed-create-123".to_owned(),
            correlation_id: Uuid::new_v4(),
        };
        validate_create(&command).expect("valid create command");
        let first = create_request_digest(&command);
        command.expected_credential_generation += 1;
        assert_ne!(first, create_request_digest(&command));
        command.expected_credential_generation = 0;
        assert_eq!(
            validate_create(&command),
            Err(ApplicationError::InvalidInput)
        );
    }
}
