use std::{collections::BTreeMap, sync::Arc};

use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use owlauth_key_provider::{
    ConfigurationSecretSealer, DestroyOutcome, DestroySigningKeyRequest, InspectSigningKeyRequest,
    OpaqueEnvelope, OpaqueHandle, OperationId, ProtectionContext, ProviderError,
    ProviderErrorClass, ProviderFormatVersion, ProviderId, ProvisionSigningKeyRequest,
    ProvisionedSigningKey, RequestFingerprint, RetryClassification, SealSecretRequest,
    SecretPlaintext, SigningAlgorithm, SigningKeyProvisioner, SigningPublicKey,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;
use zeroize::Zeroizing;

use super::{ApplicationError, Clock, RequestDigester};
use crate::domain::{
    ApplicationType, DisplayName, MAX_ACCESS_TOKEN_LIFETIME_SECONDS,
    MIN_ACCESS_TOKEN_LIFETIME_SECONDS, OpaqueOwner, ProviderKey, ProviderKind, PublicId,
};

const SIGNING_ALGORITHM: &str = "EdDSA";
const SIGNING_PURPOSE: &str = "application_tokens";
const SIGNING_PROVIDER_LEASE_SECONDS: i64 = 30;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct ProjectRecord {
    pub id: Uuid,
    pub public_id: String,
    pub display_name: String,
    pub belongs_to: Option<String>,
    pub status: String,
    pub metadata_revision: i64,
    pub security_revision: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct ProjectPolicyRecord {
    pub project_id: Uuid,
    pub access_token_lifetime_seconds: i32,
    pub browser_session_reuse: bool,
    pub claims_revision: i64,
    pub session_revision: i64,
}

#[derive(Clone, Debug)]
pub(crate) struct UpdateProjectPolicy {
    pub access_token_lifetime_seconds: i32,
    pub browser_session_reuse: bool,
    pub expected_claims_revision: i64,
    pub expected_session_revision: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct ApplicationConfiguration {
    pub redirect_uris: Vec<String>,
    pub allowed_origins: Vec<String>,
    pub publishable_keys: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct ApplicationRecord {
    pub id: Uuid,
    pub project_id: Uuid,
    pub public_id: String,
    pub display_name: String,
    pub application_type: String,
    pub status: String,
    pub metadata_revision: i64,
    pub security_revision: i64,
    pub configuration: ApplicationConfiguration,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub(crate) struct SigningKeyRecord {
    pub id: Uuid,
    pub project_id: Uuid,
    pub kid: String,
    pub algorithm: String,
    pub state: String,
    pub ring_revision: i64,
    pub signing_epoch: i64,
    pub sign_not_before: Option<OffsetDateTime>,
    pub verify_not_after: Option<OffsetDateTime>,
    pub public_jwk: Value,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct ProviderRecord {
    pub id: Uuid,
    pub project_id: Uuid,
    pub provider_key: String,
    pub kind: String,
    pub display_name: String,
    pub issuer: String,
    pub client_id: String,
    pub callback_url: String,
    pub status: String,
    pub revision: i64,
    pub managed_profile_enabled: bool,
    pub managed_profile_revision: i64,
    pub secret_replacement_pending: bool,
    pub assigned_application_ids: Vec<Uuid>,
}

#[derive(Clone, Debug)]
pub(crate) struct CreateProject {
    pub display_name: String,
    pub belongs_to: Option<String>,
    pub idempotency_key: String,
}

#[derive(Clone, Debug)]
pub(crate) struct UpdateProject {
    pub display_name: String,
    pub belongs_to: Option<String>,
    pub expected_metadata_revision: i64,
}

#[derive(Clone, Debug)]
pub(crate) struct CreateApplication {
    pub display_name: String,
    pub application_type: ApplicationType,
    pub idempotency_key: String,
}

#[derive(Clone, Debug)]
pub(crate) struct UpdateApplication {
    pub display_name: String,
    pub expected_metadata_revision: i64,
}

#[derive(Clone, Debug)]
pub(crate) struct ReplaceApplicationConfiguration {
    pub redirect_uris: Vec<String>,
    pub allowed_origins: Vec<String>,
    pub expected_security_revision: i64,
}

#[derive(Clone, Debug)]
pub(crate) struct CreateProvider {
    pub kind: ProviderKind,
    pub provider_key: String,
    pub display_name: String,
    pub issuer: String,
    pub client_id: String,
    pub client_secret: Zeroizing<String>,
    pub managed_profile_enabled: bool,
    pub idempotency_key: String,
    pub expected_project_revision: i64,
    pub egress_policy_revision: Option<i64>,
}

#[derive(Clone, Debug)]
pub(crate) struct UpdateProvider {
    pub display_name: String,
    pub client_id: String,
    pub expected_provider_revision: i64,
}

#[derive(Clone, Debug)]
pub(crate) struct ReplaceProviderSecret {
    pub display_name: String,
    pub client_id: String,
    pub client_secret: Zeroizing<String>,
    pub idempotency_key: String,
    pub expected_provider_revision: i64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProvisioningOperationState {
    Prepared,
    Submitted,
    Stored,
    Completed,
    CleanupPending,
    CleanupLeased,
    CleanupBlocked,
    Failed,
    Abandoned,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SigningProviderLease {
    pub token: Uuid,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SigningProviderAction {
    Provision(SigningProviderLease),
    Inspect(SigningProviderLease),
    Cleanup(SigningProviderLease),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SigningProviderCall {
    Provision,
    Inspect,
    Cleanup,
}

#[derive(Clone, Debug)]
pub(crate) struct PreparedSigningKey {
    pub operation_id: Uuid,
    pub ring_id: Uuid,
    pub key_id: Uuid,
    pub kid: String,
    pub signer_material_id: Uuid,
    pub request_digest: Vec<u8>,
    pub state: ProvisioningOperationState,
}

#[derive(Debug)]
pub(crate) struct PreparedSigningMaterial {
    pub material_id: Uuid,
    pub provider_id: ProviderId,
    pub provider_format_version: ProviderFormatVersion,
    pub context: ProtectionContext,
    pub committed_handle: Option<OpaqueHandle>,
    pub committed_public_key: Option<SigningPublicKey>,
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct ProvisionedProtectedSigningMaterial {
    pub material_id: Uuid,
    pub handle: OpaqueHandle,
    pub public_key: SigningPublicKey,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum SigningKeyMaintenanceItem {
    Provision {
        project_id: Uuid,
        key_id: Uuid,
        operation_alias: String,
        expected_project_revision: i64,
    },
    Activate {
        project_id: Uuid,
        key_id: Uuid,
        expected_ring_revision: i64,
    },
    Retire {
        project_id: Uuid,
        key_id: Uuid,
        expected_ring_revision: i64,
    },
}

#[derive(Clone, Debug)]
pub(crate) struct PrepareProvider {
    pub kind: ProviderKind,
    pub provider_key: String,
    pub display_name: String,
    pub issuer: String,
    pub client_id: String,
    pub managed_profile_enabled: bool,
    pub operation_alias: String,
    pub expected_project_revision: i64,
    pub egress_policy_revision: Option<i64>,
    pub request_digest: Vec<u8>,
}

#[derive(Clone, Debug)]
pub(crate) struct PrepareProviderSecretReplacement {
    pub display_name: String,
    pub client_id: String,
    pub operation_alias: String,
    pub expected_provider_revision: i64,
    pub request_digest: Vec<u8>,
}

#[derive(Clone, Debug)]
pub(crate) struct PreparedProvider {
    pub operation_id: Uuid,
    pub provider_id: Uuid,
    pub request_digest: Vec<u8>,
    pub state: ProvisioningOperationState,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PreparedSecretMaterial {
    pub material_id: Uuid,
    pub provider_id: ProviderId,
    pub provider_format_version: ProviderFormatVersion,
    pub context: ProtectionContext,
}

#[derive(Clone, Default)]
pub(crate) struct ConfigurationSecretSealers {
    capabilities: Arc<BTreeMap<ProviderId, Arc<dyn ConfigurationSecretSealer>>>,
}

impl ConfigurationSecretSealers {
    pub(crate) fn new(
        capabilities: BTreeMap<ProviderId, Arc<dyn ConfigurationSecretSealer>>,
    ) -> Self {
        Self {
            capabilities: Arc::new(capabilities),
        }
    }

    #[cfg(test)]
    pub(crate) fn single<S>(capability: S) -> Self
    where
        S: ConfigurationSecretSealer + 'static,
    {
        let provider_id = capability.provider_id();
        Self::new(BTreeMap::from([(
            provider_id,
            Arc::new(capability) as Arc<dyn ConfigurationSecretSealer>,
        )]))
    }

    pub(crate) fn resolve(
        &self,
        material: &PreparedSecretMaterial,
    ) -> Result<Arc<dyn ConfigurationSecretSealer>, ApplicationError> {
        let capability = self
            .capabilities
            .get(&material.provider_id)
            .cloned()
            .ok_or(ApplicationError::Integrity)?;
        if !capability
            .supported_format_versions()
            .contains(material.provider_format_version)
        {
            return Err(ApplicationError::Integrity);
        }
        Ok(capability)
    }
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct SealedProtectedMaterial {
    pub material_id: Uuid,
    pub provider_id: ProviderId,
    pub provider_format_version: ProviderFormatVersion,
    pub envelope: OpaqueEnvelope,
    pub request_fingerprint: RequestFingerprint,
}

#[derive(Clone, Debug)]
pub(crate) struct ProviderSecretReplacementRecovery {
    pub operation_alias: String,
    pub display_name: String,
    pub client_id: String,
    pub expected_provider_revision: i64,
}

#[derive(Clone, Debug)]
pub(crate) struct ProviderRecovery {
    pub operation_alias: String,
    pub kind: ProviderKind,
    pub provider_key: String,
    pub display_name: String,
    pub issuer: String,
    pub client_id: String,
    pub managed_profile_enabled: bool,
    pub egress_policy_revision: Option<i64>,
}

impl CreateProject {
    fn normalize(mut self) -> Result<Self, ApplicationError> {
        validate_idempotency_key(&self.idempotency_key)?;
        self.display_name = DisplayName::parse(self.display_name)?.into_inner();
        self.belongs_to = normalize_owner(self.belongs_to)?;
        Ok(self)
    }
}

impl UpdateProject {
    fn normalize(mut self) -> Result<Self, ApplicationError> {
        self.display_name = DisplayName::parse(self.display_name)?.into_inner();
        self.belongs_to = normalize_owner(self.belongs_to)?;
        Ok(self)
    }
}

impl CreateApplication {
    fn normalize(mut self) -> Result<Self, ApplicationError> {
        validate_idempotency_key(&self.idempotency_key)?;
        self.display_name = DisplayName::parse(self.display_name)?.into_inner();
        Ok(self)
    }
}

impl UpdateApplication {
    fn normalize(mut self) -> Result<Self, ApplicationError> {
        self.display_name = DisplayName::parse(self.display_name)?.into_inner();
        Ok(self)
    }
}

impl UpdateProvider {
    fn normalize(mut self) -> Result<Self, ApplicationError> {
        self.display_name = DisplayName::parse(self.display_name)?.into_inner();
        validate_provider_client_id(&self.client_id)?;
        if self.expected_provider_revision <= 0 {
            return Err(ApplicationError::InvalidInput);
        }
        Ok(self)
    }
}

impl ReplaceProviderSecret {
    fn normalize(mut self) -> Result<Self, ApplicationError> {
        validate_idempotency_key(&self.idempotency_key)?;
        self.display_name = DisplayName::parse(self.display_name)?.into_inner();
        validate_provider_client_id(&self.client_id)?;
        if self.client_secret.is_empty()
            || self.client_secret.len() > 4096
            || self.expected_provider_revision <= 0
        {
            return Err(ApplicationError::InvalidInput);
        }
        Ok(self)
    }
}

impl CreateProvider {
    fn normalize(mut self, allow_http_loopback: bool) -> Result<Self, ApplicationError> {
        validate_idempotency_key(&self.idempotency_key)?;
        self.provider_key = ProviderKey::parse(self.provider_key)?.into_inner();
        self.display_name = DisplayName::parse(self.display_name)?.into_inner();
        validate_provider_issuer(&self.issuer, allow_http_loopback)?;
        if !self.kind.issuer_matches(&self.issuer)
            || (self.kind == ProviderKind::Oidc) != self.egress_policy_revision.is_some()
            || self
                .egress_policy_revision
                .is_some_and(|revision| revision <= 0)
            || (self.managed_profile_enabled && !self.kind.capabilities().managed_profile)
        {
            return Err(ApplicationError::InvalidInput);
        }
        if validate_provider_client_id(&self.client_id).is_err()
            || self.client_secret.is_empty()
            || self.client_secret.len() > 4096
        {
            return Err(ApplicationError::InvalidInput);
        }
        Ok(self)
    }
}

fn validate_provider_client_id(value: &str) -> Result<(), ApplicationError> {
    if value.is_empty() || value.len() > 512 {
        return Err(ApplicationError::InvalidInput);
    }
    Ok(())
}

fn normalize_owner(value: Option<String>) -> Result<Option<String>, ApplicationError> {
    value
        .map(OpaqueOwner::parse)
        .transpose()
        .map(|owner| owner.map(OpaqueOwner::into_inner))
        .map_err(Into::into)
}

fn validate_idempotency_key(value: &str) -> Result<(), ApplicationError> {
    PublicId::parse(value.to_owned())?;
    if value.len() > 128 {
        return Err(ApplicationError::InvalidInput);
    }
    Ok(())
}

fn validate_provider_issuer(
    value: &str,
    allow_http_loopback: bool,
) -> Result<(), ApplicationError> {
    let url = url::Url::parse(value).map_err(|_| ApplicationError::InvalidInput)?;
    let accepted_scheme = url.scheme() == "https"
        || (allow_http_loopback
            && url.scheme() == "http"
            && matches!(url.host_str(), Some("127.0.0.1" | "::1" | "[::1]")));
    let canonical_serialization = url.as_str() == value
        || (url.path() == "/" && url.as_str().strip_suffix('/') == Some(value));
    if !accepted_scheme
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || !canonical_serialization
    {
        return Err(ApplicationError::InvalidInput);
    }
    Ok(())
}

#[async_trait]
pub(crate) trait ProjectProvisioningPort: Send + Sync {
    async fn create_project(
        &self,
        command: CreateProject,
        correlation_id: Uuid,
    ) -> Result<ProjectRecord, ApplicationError>;
    async fn list_projects(
        &self,
        belongs_to: Option<String>,
    ) -> Result<Vec<ProjectRecord>, ApplicationError>;
    async fn get_project(&self, project_id: Uuid) -> Result<ProjectRecord, ApplicationError>;
    async fn get_project_policy(
        &self,
        project_id: Uuid,
    ) -> Result<ProjectPolicyRecord, ApplicationError>;
    async fn update_project_policy(
        &self,
        project_id: Uuid,
        command: UpdateProjectPolicy,
        correlation_id: Uuid,
    ) -> Result<ProjectPolicyRecord, ApplicationError>;
    async fn update_project(
        &self,
        project_id: Uuid,
        command: UpdateProject,
        correlation_id: Uuid,
    ) -> Result<ProjectRecord, ApplicationError>;
    async fn disable_project(
        &self,
        project_id: Uuid,
        expected_security_revision: i64,
        correlation_id: Uuid,
    ) -> Result<ProjectRecord, ApplicationError>;
    async fn enable_project(
        &self,
        project_id: Uuid,
        expected_security_revision: i64,
        correlation_id: Uuid,
    ) -> Result<ProjectRecord, ApplicationError>;
    async fn delete_project(
        &self,
        project_id: Uuid,
        expected_security_revision: i64,
        correlation_id: Uuid,
    ) -> Result<ProjectRecord, ApplicationError>;
    async fn finalize_project_deletions(&self, limit: usize) -> Result<usize, ApplicationError>;
}

#[async_trait]
pub(crate) trait ApplicationProvisioningPort: Send + Sync {
    async fn create_application(
        &self,
        project_id: Uuid,
        command: CreateApplication,
        correlation_id: Uuid,
    ) -> Result<ApplicationRecord, ApplicationError>;
    async fn list_applications(
        &self,
        project_id: Uuid,
    ) -> Result<Vec<ApplicationRecord>, ApplicationError>;
    async fn get_application(
        &self,
        project_id: Uuid,
        application_id: Uuid,
    ) -> Result<ApplicationRecord, ApplicationError>;
    async fn update_application(
        &self,
        project_id: Uuid,
        application_id: Uuid,
        command: UpdateApplication,
        correlation_id: Uuid,
    ) -> Result<ApplicationRecord, ApplicationError>;
    async fn replace_application_configuration(
        &self,
        project_id: Uuid,
        application_id: Uuid,
        command: ReplaceApplicationConfiguration,
        correlation_id: Uuid,
    ) -> Result<ApplicationRecord, ApplicationError>;
    async fn disable_application(
        &self,
        project_id: Uuid,
        application_id: Uuid,
        expected_security_revision: i64,
        correlation_id: Uuid,
    ) -> Result<ApplicationRecord, ApplicationError>;
}

#[allow(
    clippy::too_many_arguments,
    reason = "durable provider lifecycle transitions carry exact operation, lease, and outcome fences"
)]
#[async_trait]
pub(crate) trait SigningKeyProvisioningPort: Send + Sync {
    async fn prepare_signing_key(
        &self,
        project_id: Uuid,
        operation_alias: String,
        expected_project_revision: i64,
        request_digest: Vec<u8>,
    ) -> Result<PreparedSigningKey, ApplicationError>;
    async fn prepared_signing_material(
        &self,
        project_id: Uuid,
        prepared: &PreparedSigningKey,
    ) -> Result<Option<PreparedSigningMaterial>, ApplicationError>;
    async fn claim_signing_provider_action(
        &self,
        project_id: Uuid,
        prepared: &PreparedSigningKey,
        now: OffsetDateTime,
        lease_until: OffsetDateTime,
    ) -> Result<SigningProviderAction, ApplicationError>;
    async fn record_signing_provider_failure(
        &self,
        project_id: Uuid,
        prepared: &PreparedSigningKey,
        lease: SigningProviderLease,
        provider_call: SigningProviderCall,
        error_class: ProviderErrorClass,
        retry: RetryClassification,
        error_code: Option<String>,
        recorded_at: OffsetDateTime,
    ) -> Result<(), ApplicationError>;
    async fn record_signing_provider_absence(
        &self,
        project_id: Uuid,
        prepared: &PreparedSigningKey,
        lease: SigningProviderLease,
        recorded_at: OffsetDateTime,
    ) -> Result<(), ApplicationError>;
    async fn queue_signing_provider_cleanup(
        &self,
        project_id: Uuid,
        prepared: &PreparedSigningKey,
        lease: SigningProviderLease,
        recorded_at: OffsetDateTime,
    ) -> Result<(), ApplicationError>;
    async fn complete_signing_provider_cleanup(
        &self,
        project_id: Uuid,
        prepared: &PreparedSigningKey,
        lease: SigningProviderLease,
        destroyed: bool,
        correlation_id: Uuid,
        completed_at: OffsetDateTime,
    ) -> Result<(), ApplicationError>;
    async fn record_protected_signing_key_material(
        &self,
        project_id: Uuid,
        prepared: &PreparedSigningKey,
        lease: SigningProviderLease,
        material: ProvisionedProtectedSigningMaterial,
        public_jwk: Value,
        recorded_at: OffsetDateTime,
    ) -> Result<(), ApplicationError>;
    async fn publish_signing_key(
        &self,
        project_id: Uuid,
        prepared: &PreparedSigningKey,
        correlation_id: Uuid,
        published_at: OffsetDateTime,
    ) -> Result<SigningKeyRecord, ApplicationError>;
    async fn get_signing_key(
        &self,
        project_id: Uuid,
        key_id: Uuid,
    ) -> Result<SigningKeyRecord, ApplicationError>;
    async fn list_signing_keys(
        &self,
        project_id: Uuid,
    ) -> Result<Vec<SigningKeyRecord>, ApplicationError>;
    async fn signing_key_maintenance_items(
        &self,
        limit: usize,
    ) -> Result<Vec<SigningKeyMaintenanceItem>, ApplicationError>;
    async fn ensure_signing_key_activatable(
        &self,
        project_id: Uuid,
        key_id: Uuid,
    ) -> Result<(), ApplicationError>;
    async fn activate_signing_key_if_ready(
        &self,
        project_id: Uuid,
        key_id: Uuid,
        expected_ring_revision: i64,
        correlation_id: Uuid,
    ) -> Result<SigningKeyRecord, ApplicationError>;
    async fn retire_signing_key(
        &self,
        project_id: Uuid,
        key_id: Uuid,
        expected_ring_revision: i64,
        correlation_id: Uuid,
    ) -> Result<SigningKeyRecord, ApplicationError>;
    async fn revoke_signing_key(
        &self,
        project_id: Uuid,
        key_id: Uuid,
        expected_ring_revision: i64,
        correlation_id: Uuid,
    ) -> Result<SigningKeyRecord, ApplicationError>;
}

#[async_trait]
pub(crate) trait ProviderProvisioningPort: Send + Sync {
    async fn prepare_provider(
        &self,
        project_id: Uuid,
        command: PrepareProvider,
    ) -> Result<PreparedProvider, ApplicationError>;
    async fn provider_recovery(
        &self,
        project_id: Uuid,
        provider_id: Uuid,
    ) -> Result<ProviderRecovery, ApplicationError>;
    async fn prepare_provider_secret_replacement(
        &self,
        project_id: Uuid,
        provider_id: Uuid,
        command: PrepareProviderSecretReplacement,
    ) -> Result<PreparedProvider, ApplicationError>;
    async fn provider_secret_replacement_recovery(
        &self,
        project_id: Uuid,
        provider_id: Uuid,
        expected_provider_revision: i64,
    ) -> Result<ProviderSecretReplacementRecovery, ApplicationError>;
    async fn abandon_provider_secret_replacement(
        &self,
        project_id: Uuid,
        provider_id: Uuid,
        expected_provider_revision: i64,
        correlation_id: Uuid,
        abandoned_at: OffsetDateTime,
    ) -> Result<ProviderRecord, ApplicationError>;
    async fn prepared_provider_material(
        &self,
        project_id: Uuid,
        prepared: &PreparedProvider,
    ) -> Result<Option<PreparedSecretMaterial>, ApplicationError>;
    async fn finalize_protected_provider(
        &self,
        project_id: Uuid,
        prepared: &PreparedProvider,
        expected_project_revision: i64,
        material: SealedProtectedMaterial,
        correlation_id: Uuid,
        finalized_at: OffsetDateTime,
    ) -> Result<ProviderRecord, ApplicationError>;
    async fn finalize_provider_secret_replacement(
        &self,
        project_id: Uuid,
        prepared: &PreparedProvider,
        expected_provider_revision: i64,
        material: SealedProtectedMaterial,
        correlation_id: Uuid,
        finalized_at: OffsetDateTime,
    ) -> Result<ProviderRecord, ApplicationError>;
    async fn get_provider(
        &self,
        project_id: Uuid,
        provider_id: Uuid,
    ) -> Result<ProviderRecord, ApplicationError>;
    async fn list_providers(
        &self,
        project_id: Uuid,
    ) -> Result<Vec<ProviderRecord>, ApplicationError>;
    async fn update_provider(
        &self,
        project_id: Uuid,
        provider_id: Uuid,
        command: UpdateProvider,
        correlation_id: Uuid,
    ) -> Result<ProviderRecord, ApplicationError>;
    async fn assign_provider(
        &self,
        project_id: Uuid,
        provider_id: Uuid,
        application_id: Uuid,
        expected_application_revision: i64,
        correlation_id: Uuid,
    ) -> Result<ProviderRecord, ApplicationError>;
    async fn unassign_provider(
        &self,
        project_id: Uuid,
        provider_id: Uuid,
        application_id: Uuid,
        expected_application_revision: i64,
        correlation_id: Uuid,
    ) -> Result<ProviderRecord, ApplicationError>;
    async fn disable_provider(
        &self,
        project_id: Uuid,
        provider_id: Uuid,
        expected_provider_revision: i64,
        correlation_id: Uuid,
    ) -> Result<ProviderRecord, ApplicationError>;
}

#[derive(Clone)]
pub(crate) struct ProvisioningInfrastructure {
    signing_provisioners: Arc<BTreeMap<ProviderId, Arc<dyn SigningKeyProvisioner>>>,
    secret_sealers: ConfigurationSecretSealers,
    clock: Arc<dyn Clock>,
    digester: Arc<dyn RequestDigester>,
    allow_http_loopback_provider: bool,
}

impl ProvisioningInfrastructure {
    pub(crate) fn new_protected<K, D>(
        clock: K,
        digester: D,
        allow_http_loopback_provider: bool,
        signing_provisioners: BTreeMap<ProviderId, Arc<dyn SigningKeyProvisioner>>,
        secret_sealers: BTreeMap<ProviderId, Arc<dyn ConfigurationSecretSealer>>,
    ) -> Self
    where
        K: Clock + 'static,
        D: RequestDigester + 'static,
    {
        Self {
            signing_provisioners: Arc::new(signing_provisioners),
            secret_sealers: ConfigurationSecretSealers::new(secret_sealers),
            clock: Arc::new(clock),
            digester: Arc::new(digester),
            allow_http_loopback_provider,
        }
    }

    #[cfg(test)]
    pub(crate) fn with_signing_provisioner<S>(mut self, signing_provisioner: S) -> Self
    where
        S: SigningKeyProvisioner + 'static,
    {
        let provider_id = signing_provisioner.provider_id();
        self.signing_provisioners = Arc::new(BTreeMap::from([(
            provider_id,
            Arc::new(signing_provisioner) as Arc<dyn SigningKeyProvisioner>,
        )]));
        self
    }

    #[cfg(test)]
    pub(crate) fn with_provider_capabilities(
        mut self,
        signing_provisioners: BTreeMap<ProviderId, Arc<dyn SigningKeyProvisioner>>,
        secret_sealers: BTreeMap<ProviderId, Arc<dyn ConfigurationSecretSealer>>,
    ) -> Self {
        self.signing_provisioners = Arc::new(signing_provisioners);
        self.secret_sealers = ConfigurationSecretSealers::new(secret_sealers);
        self
    }

    fn signing_provisioner(
        &self,
        provider_id: &ProviderId,
        format_version: ProviderFormatVersion,
    ) -> Result<Arc<dyn SigningKeyProvisioner>, ApplicationError> {
        let provisioner = self
            .signing_provisioners
            .get(provider_id)
            .cloned()
            .ok_or(ApplicationError::Integrity)?;
        let capabilities = provisioner.capabilities();
        if !capabilities.supports_algorithm(SigningAlgorithm::Ed25519)
            || !capabilities.format_versions().contains(format_version)
        {
            return Err(ApplicationError::Integrity);
        }
        Ok(provisioner)
    }
}

mod project_application;
mod provider_secret;
mod signing;

#[derive(Clone)]
pub(crate) struct ProvisioningService {
    projects: Arc<dyn ProjectProvisioningPort>,
    applications: Arc<dyn ApplicationProvisioningPort>,
    signing_keys: Arc<dyn SigningKeyProvisioningPort>,
    providers: Arc<dyn ProviderProvisioningPort>,
    infrastructure: ProvisioningInfrastructure,
}

impl ProvisioningService {
    pub(crate) fn new<T>(adapter: Arc<T>, infrastructure: ProvisioningInfrastructure) -> Self
    where
        T: ProjectProvisioningPort
            + ApplicationProvisioningPort
            + SigningKeyProvisioningPort
            + ProviderProvisioningPort
            + 'static,
    {
        Self {
            projects: adapter.clone(),
            applications: adapter.clone(),
            signing_keys: adapter.clone(),
            providers: adapter,
            infrastructure,
        }
    }
}

fn normalized_ed25519_jwk(
    kid: &str,
    public_key: &SigningPublicKey,
) -> Result<Value, ApplicationError> {
    if public_key.algorithm() != SigningAlgorithm::Ed25519 || public_key.as_bytes().len() != 32 {
        return Err(ApplicationError::Integrity);
    }
    Ok(json!({
        "kty": "OKP",
        "crv": "Ed25519",
        "alg": SIGNING_ALGORITHM,
        "use": "sig",
        "kid": kid,
        "x": URL_SAFE_NO_PAD.encode(public_key.as_bytes()),
    }))
}

#[allow(
    clippy::needless_pass_by_value,
    reason = "Result::map_err supplies the owned provider error directly"
)]
pub(super) fn map_provider_error(error: ProviderError) -> ApplicationError {
    match error.class() {
        ProviderErrorClass::InvalidRequest
        | ProviderErrorClass::UnsupportedAlgorithm
        | ProviderErrorClass::Integrity => ApplicationError::Integrity,
        ProviderErrorClass::Conflict => ApplicationError::IdempotencyConflict,
        ProviderErrorClass::NotFound => ApplicationError::NotFound,
        ProviderErrorClass::PermissionDenied | ProviderErrorClass::Unavailable => {
            ApplicationError::ExternalStore
        }
        _ => ApplicationError::ExternalStore,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn provider_command() -> CreateProvider {
        CreateProvider {
            kind: ProviderKind::Oidc,
            provider_key: "workforce".to_owned(),
            display_name: "Workforce".to_owned(),
            issuer: "https://accounts.example/".to_owned(),
            client_id: "client".to_owned(),
            client_secret: Zeroizing::new("secret".to_owned()),
            managed_profile_enabled: false,
            idempotency_key: "provider-operation-12345678".to_owned(),
            expected_project_revision: 1,
            egress_policy_revision: Some(1),
        }
    }

    #[test]
    fn provider_kind_registry_enforces_named_issuer_and_capability() {
        let mut google = provider_command();
        google.kind = ProviderKind::Google;
        google.issuer = crate::domain::GOOGLE_ISSUER.to_owned();
        google.egress_policy_revision = None;
        google.managed_profile_enabled = true;
        assert!(google.normalize(false).is_ok());

        let mut github = provider_command();
        github.kind = ProviderKind::Github;
        github.egress_policy_revision = None;
        github.issuer = crate::domain::GITHUB_ISSUER.to_owned();
        assert!(github.normalize(false).is_ok());

        let mut managed_github = provider_command();
        managed_github.kind = ProviderKind::Github;
        managed_github.issuer = crate::domain::GITHUB_ISSUER.to_owned();
        managed_github.managed_profile_enabled = true;
        assert!(matches!(
            managed_github.normalize(false),
            Err(ApplicationError::InvalidInput)
        ));

        let mut generic_named = provider_command();
        generic_named.issuer = crate::domain::GOOGLE_ISSUER.to_owned();
        assert!(matches!(
            generic_named.normalize(false),
            Err(ApplicationError::InvalidInput)
        ));
    }

    #[test]
    fn provider_issuer_requires_https_unless_exact_loopback_is_enabled() {
        assert!(validate_provider_issuer("https://accounts.example/", false).is_ok());
        assert!(validate_provider_issuer("https://accounts.example", false).is_ok());
        assert_eq!(
            validate_provider_issuer("http://127.0.0.1:8080/", false),
            Err(ApplicationError::InvalidInput)
        );
        assert!(validate_provider_issuer("http://127.0.0.1:8080/", true).is_ok());
        assert!(validate_provider_issuer("http://[::1]:8080/", true).is_ok());
        assert_eq!(
            validate_provider_issuer("http://localhost:8080/", true),
            Err(ApplicationError::InvalidInput)
        );
        assert_eq!(
            validate_provider_issuer("http://192.0.2.1:8080/", true),
            Err(ApplicationError::InvalidInput)
        );
    }

    #[test]
    fn provider_edit_commands_validate_mutable_fields_and_fences() {
        assert!(
            UpdateProvider {
                display_name: "Workforce Login".to_owned(),
                client_id: "client-v2".to_owned(),
                expected_provider_revision: 4,
            }
            .normalize()
            .is_ok()
        );
        assert!(matches!(
            UpdateProvider {
                display_name: "Workforce Login".to_owned(),
                client_id: String::new(),
                expected_provider_revision: 4,
            }
            .normalize(),
            Err(ApplicationError::InvalidInput)
        ));
        assert!(
            ReplaceProviderSecret {
                display_name: "Workforce Login".to_owned(),
                client_id: "client-v2".to_owned(),
                client_secret: Zeroizing::new("replacement-secret".to_owned()),
                idempotency_key: "provider-replacement-12345678".to_owned(),
                expected_provider_revision: 4,
            }
            .normalize()
            .is_ok()
        );
        assert!(matches!(
            ReplaceProviderSecret {
                display_name: "Workforce Login".to_owned(),
                client_id: "client-v2".to_owned(),
                client_secret: Zeroizing::new(String::new()),
                idempotency_key: "provider-replacement-12345678".to_owned(),
                expected_provider_revision: 4,
            }
            .normalize(),
            Err(ApplicationError::InvalidInput)
        ));
    }
}
