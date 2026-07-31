use std::sync::Arc;

use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use time::OffsetDateTime;
use uuid::Uuid;
use zeroize::Zeroizing;

use super::{
    ApplicationError, Clock, ConfigurationSecretStore, EntropySource, RequestDigester, SignerStore,
};
use crate::domain::{
    ApplicationType, DisplayName, MAX_ACCESS_TOKEN_LIFETIME_SECONDS,
    MIN_ACCESS_TOKEN_LIFETIME_SECONDS, OpaqueOwner, ProviderKey, PublicId,
};

const SIGNING_ALGORITHM: &str = "EdDSA";
const SIGNING_PURPOSE: &str = "application_tokens";

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
    pub provider_key: String,
    pub display_name: String,
    pub issuer: String,
    pub client_id: String,
    pub client_secret: Zeroizing<String>,
    pub idempotency_key: String,
    pub expected_project_revision: i64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProvisioningOperationState {
    Prepared,
    Stored,
    Completed,
}

#[derive(Clone, Debug)]
pub(crate) struct PreparedSigningKey {
    pub operation_id: Uuid,
    pub ring_id: Uuid,
    pub key_id: Uuid,
    pub kid: String,
    pub signer_ref: String,
    pub request_digest: Vec<u8>,
    pub state: ProvisioningOperationState,
}

#[derive(Clone, Debug)]
pub(crate) struct SigningKeyRecovery {
    pub operation_alias: String,
}

#[derive(Clone, Debug)]
pub(crate) struct SigningKeyActivationCandidate {
    pub kid: String,
    pub signer_ref: String,
    pub public_jwk: Value,
}

#[derive(Clone, Debug)]
pub(crate) struct PrepareProvider {
    pub provider_key: String,
    pub display_name: String,
    pub issuer: String,
    pub client_id: String,
    pub operation_alias: String,
    pub expected_project_revision: i64,
    pub request_digest: Vec<u8>,
}

#[derive(Clone, Debug)]
pub(crate) struct PreparedProvider {
    pub operation_id: Uuid,
    pub provider_id: Uuid,
    pub request_digest: Vec<u8>,
    pub state: ProvisioningOperationState,
}

#[derive(Clone, Debug)]
pub(crate) struct ProviderRecovery {
    pub operation_alias: String,
    pub provider_key: String,
    pub display_name: String,
    pub issuer: String,
    pub client_id: String,
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

impl CreateProvider {
    fn normalize(mut self, allow_http_loopback: bool) -> Result<Self, ApplicationError> {
        validate_idempotency_key(&self.idempotency_key)?;
        self.provider_key = ProviderKey::parse(self.provider_key)?.into_inner();
        self.display_name = DisplayName::parse(self.display_name)?.into_inner();
        validate_provider_issuer(&self.issuer, allow_http_loopback)?;
        if self.client_id.is_empty()
            || self.client_id.len() > 512
            || self.client_secret.is_empty()
            || self.client_secret.len() > 4096
        {
            return Err(ApplicationError::InvalidInput);
        }
        Ok(self)
    }
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

fn external_store_alias(
    digester: &dyn RequestDigester,
    purpose: &str,
    project_id: Uuid,
    operation_alias: &str,
) -> String {
    let digest = digester.digest_bytes(operation_alias.as_bytes());
    format!(
        "{purpose}_{}_{}",
        project_id.simple(),
        URL_SAFE_NO_PAD.encode(&digest[..16])
    )
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
    if !accepted_scheme
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.as_str() != value
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

#[async_trait]
pub(crate) trait SigningKeyProvisioningPort: Send + Sync {
    async fn prepare_signing_key(
        &self,
        project_id: Uuid,
        operation_alias: String,
        signer_ref: String,
        expected_project_revision: i64,
        request_digest: Vec<u8>,
    ) -> Result<PreparedSigningKey, ApplicationError>;
    async fn signing_key_recovery(
        &self,
        project_id: Uuid,
        key_id: Uuid,
    ) -> Result<SigningKeyRecovery, ApplicationError>;
    async fn record_signing_key_material(
        &self,
        project_id: Uuid,
        prepared: &PreparedSigningKey,
        expected_project_revision: i64,
        public_jwk: Value,
        recorded_at: OffsetDateTime,
    ) -> Result<(), ApplicationError>;
    async fn publish_signing_key(
        &self,
        project_id: Uuid,
        prepared: &PreparedSigningKey,
        expected_project_revision: i64,
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
    async fn signing_key_activation_candidate(
        &self,
        project_id: Uuid,
        key_id: Uuid,
    ) -> Result<SigningKeyActivationCandidate, ApplicationError>;
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
    async fn mark_provider_secret_stored(
        &self,
        project_id: Uuid,
        prepared: &PreparedProvider,
        expected_project_revision: i64,
        stored_at: OffsetDateTime,
    ) -> Result<(), ApplicationError>;
    async fn finalize_provider(
        &self,
        project_id: Uuid,
        prepared: &PreparedProvider,
        expected_project_revision: i64,
        secret_ref: String,
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
    signer_store: Arc<dyn SignerStore>,
    secret_store: Arc<dyn ConfigurationSecretStore>,
    clock: Arc<dyn Clock>,
    entropy: Arc<dyn EntropySource>,
    digester: Arc<dyn RequestDigester>,
    allow_http_loopback_provider: bool,
}

impl ProvisioningInfrastructure {
    pub(crate) fn new<S, C, K, E, D>(
        signer_store: S,
        secret_store: C,
        clock: K,
        entropy: E,
        digester: D,
        allow_http_loopback_provider: bool,
    ) -> Self
    where
        S: SignerStore + 'static,
        C: ConfigurationSecretStore + 'static,
        K: Clock + 'static,
        E: EntropySource + 'static,
        D: RequestDigester + 'static,
    {
        Self {
            signer_store: Arc::new(signer_store),
            secret_store: Arc::new(secret_store),
            clock: Arc::new(clock),
            entropy: Arc::new(entropy),
            digester: Arc::new(digester),
            allow_http_loopback_provider,
        }
    }
}

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

    pub(crate) async fn create_project(
        &self,
        command: CreateProject,
        correlation_id: Uuid,
    ) -> Result<ProjectRecord, ApplicationError> {
        self.projects
            .create_project(command.normalize()?, correlation_id)
            .await
    }
    pub(crate) async fn list_projects(
        &self,
        belongs_to: Option<String>,
    ) -> Result<Vec<ProjectRecord>, ApplicationError> {
        self.projects
            .list_projects(normalize_owner(belongs_to)?)
            .await
    }
    pub(crate) async fn get_project(
        &self,
        project_id: Uuid,
    ) -> Result<ProjectRecord, ApplicationError> {
        self.projects.get_project(project_id).await
    }
    pub(crate) async fn get_project_policy(
        &self,
        project_id: Uuid,
    ) -> Result<ProjectPolicyRecord, ApplicationError> {
        self.projects.get_project_policy(project_id).await
    }
    pub(crate) async fn update_project_policy(
        &self,
        project_id: Uuid,
        command: UpdateProjectPolicy,
        correlation_id: Uuid,
    ) -> Result<ProjectPolicyRecord, ApplicationError> {
        if !(MIN_ACCESS_TOKEN_LIFETIME_SECONDS..=MAX_ACCESS_TOKEN_LIFETIME_SECONDS)
            .contains(&command.access_token_lifetime_seconds)
        {
            return Err(ApplicationError::InvalidInput);
        }
        self.projects
            .update_project_policy(project_id, command, correlation_id)
            .await
    }
    pub(crate) async fn update_project(
        &self,
        project_id: Uuid,
        command: UpdateProject,
        correlation_id: Uuid,
    ) -> Result<ProjectRecord, ApplicationError> {
        self.projects
            .update_project(project_id, command.normalize()?, correlation_id)
            .await
    }
    pub(crate) async fn disable_project(
        &self,
        project_id: Uuid,
        expected_security_revision: i64,
        correlation_id: Uuid,
    ) -> Result<ProjectRecord, ApplicationError> {
        self.projects
            .disable_project(project_id, expected_security_revision, correlation_id)
            .await
    }
    pub(crate) async fn create_application(
        &self,
        project_id: Uuid,
        command: CreateApplication,
        correlation_id: Uuid,
    ) -> Result<ApplicationRecord, ApplicationError> {
        self.applications
            .create_application(project_id, command.normalize()?, correlation_id)
            .await
    }
    pub(crate) async fn list_applications(
        &self,
        project_id: Uuid,
    ) -> Result<Vec<ApplicationRecord>, ApplicationError> {
        self.applications.list_applications(project_id).await
    }
    pub(crate) async fn get_application(
        &self,
        project_id: Uuid,
        application_id: Uuid,
    ) -> Result<ApplicationRecord, ApplicationError> {
        self.applications
            .get_application(project_id, application_id)
            .await
    }
    pub(crate) async fn update_application(
        &self,
        project_id: Uuid,
        application_id: Uuid,
        command: UpdateApplication,
        correlation_id: Uuid,
    ) -> Result<ApplicationRecord, ApplicationError> {
        self.applications
            .update_application(
                project_id,
                application_id,
                command.normalize()?,
                correlation_id,
            )
            .await
    }
    pub(crate) async fn replace_application_configuration(
        &self,
        project_id: Uuid,
        application_id: Uuid,
        command: ReplaceApplicationConfiguration,
        correlation_id: Uuid,
    ) -> Result<ApplicationRecord, ApplicationError> {
        self.applications
            .replace_application_configuration(project_id, application_id, command, correlation_id)
            .await
    }
    pub(crate) async fn disable_application(
        &self,
        project_id: Uuid,
        application_id: Uuid,
        expected_security_revision: i64,
        correlation_id: Uuid,
    ) -> Result<ApplicationRecord, ApplicationError> {
        self.applications
            .disable_application(
                project_id,
                application_id,
                expected_security_revision,
                correlation_id,
            )
            .await
    }
    pub(crate) async fn provision_signing_key(
        &self,
        project_id: Uuid,
        operation_alias: String,
        expected_project_revision: i64,
        correlation_id: Uuid,
    ) -> Result<SigningKeyRecord, ApplicationError> {
        provision_signing_key_workflow(
            self.signing_keys.as_ref(),
            &self.infrastructure,
            project_id,
            operation_alias,
            expected_project_revision,
            correlation_id,
        )
        .await
    }
    pub(crate) async fn list_signing_keys(
        &self,
        project_id: Uuid,
    ) -> Result<Vec<SigningKeyRecord>, ApplicationError> {
        self.signing_keys.list_signing_keys(project_id).await
    }
    pub(crate) async fn reconcile_signing_key(
        &self,
        project_id: Uuid,
        key_id: Uuid,
        expected_project_revision: i64,
        correlation_id: Uuid,
    ) -> Result<SigningKeyRecord, ApplicationError> {
        let recovery = self
            .signing_keys
            .signing_key_recovery(project_id, key_id)
            .await?;
        provision_signing_key_workflow(
            self.signing_keys.as_ref(),
            &self.infrastructure,
            project_id,
            recovery.operation_alias,
            expected_project_revision,
            correlation_id,
        )
        .await
    }
    pub(crate) async fn activate_signing_key(
        &self,
        project_id: Uuid,
        key_id: Uuid,
        expected_ring_revision: i64,
        correlation_id: Uuid,
    ) -> Result<SigningKeyRecord, ApplicationError> {
        let candidate = self
            .signing_keys
            .signing_key_activation_candidate(project_id, key_id)
            .await?;
        self.infrastructure
            .signer_store
            .verify(candidate.signer_ref, &candidate.kid, &candidate.public_jwk)
            .await?;
        self.signing_keys
            .activate_signing_key_if_ready(
                project_id,
                key_id,
                expected_ring_revision,
                correlation_id,
            )
            .await
    }
    pub(crate) async fn retire_signing_key(
        &self,
        project_id: Uuid,
        key_id: Uuid,
        expected_ring_revision: i64,
        correlation_id: Uuid,
    ) -> Result<SigningKeyRecord, ApplicationError> {
        self.signing_keys
            .retire_signing_key(project_id, key_id, expected_ring_revision, correlation_id)
            .await
    }
    pub(crate) async fn revoke_signing_key(
        &self,
        project_id: Uuid,
        key_id: Uuid,
        expected_ring_revision: i64,
        correlation_id: Uuid,
    ) -> Result<SigningKeyRecord, ApplicationError> {
        self.signing_keys
            .revoke_signing_key(project_id, key_id, expected_ring_revision, correlation_id)
            .await
    }
    pub(crate) async fn create_provider(
        &self,
        project_id: Uuid,
        command: CreateProvider,
        correlation_id: Uuid,
    ) -> Result<ProviderRecord, ApplicationError> {
        create_provider_workflow(
            self.providers.as_ref(),
            &self.infrastructure,
            project_id,
            command,
            correlation_id,
        )
        .await
    }
    pub(crate) async fn list_providers(
        &self,
        project_id: Uuid,
    ) -> Result<Vec<ProviderRecord>, ApplicationError> {
        self.providers.list_providers(project_id).await
    }
    pub(crate) async fn reconcile_provider(
        &self,
        project_id: Uuid,
        provider_id: Uuid,
        client_secret: Zeroizing<String>,
        expected_project_revision: i64,
        correlation_id: Uuid,
    ) -> Result<ProviderRecord, ApplicationError> {
        let recovery = self
            .providers
            .provider_recovery(project_id, provider_id)
            .await?;
        create_provider_workflow(
            self.providers.as_ref(),
            &self.infrastructure,
            project_id,
            CreateProvider {
                provider_key: recovery.provider_key,
                display_name: recovery.display_name,
                issuer: recovery.issuer,
                client_id: recovery.client_id,
                client_secret,
                idempotency_key: recovery.operation_alias,
                expected_project_revision,
            },
            correlation_id,
        )
        .await
    }
    pub(crate) async fn assign_provider(
        &self,
        project_id: Uuid,
        provider_id: Uuid,
        application_id: Uuid,
        expected_application_revision: i64,
        correlation_id: Uuid,
    ) -> Result<ProviderRecord, ApplicationError> {
        self.providers
            .assign_provider(
                project_id,
                provider_id,
                application_id,
                expected_application_revision,
                correlation_id,
            )
            .await
    }
    pub(crate) async fn unassign_provider(
        &self,
        project_id: Uuid,
        provider_id: Uuid,
        application_id: Uuid,
        expected_application_revision: i64,
        correlation_id: Uuid,
    ) -> Result<ProviderRecord, ApplicationError> {
        self.providers
            .unassign_provider(
                project_id,
                provider_id,
                application_id,
                expected_application_revision,
                correlation_id,
            )
            .await
    }
    pub(crate) async fn disable_provider(
        &self,
        project_id: Uuid,
        provider_id: Uuid,
        expected_provider_revision: i64,
        correlation_id: Uuid,
    ) -> Result<ProviderRecord, ApplicationError> {
        self.providers
            .disable_provider(
                project_id,
                provider_id,
                expected_provider_revision,
                correlation_id,
            )
            .await
    }
}

async fn provision_signing_key_workflow(
    signing_keys: &dyn SigningKeyProvisioningPort,
    infrastructure: &ProvisioningInfrastructure,
    project_id: Uuid,
    operation_alias: String,
    expected_project_revision: i64,
    correlation_id: Uuid,
) -> Result<SigningKeyRecord, ApplicationError> {
    validate_idempotency_key(&operation_alias)?;
    let digest = infrastructure.digester.digest_json(&json!({
        "project_id": project_id,
        "algorithm": SIGNING_ALGORITHM,
        "purpose": SIGNING_PURPOSE,
    }))?;
    let signer_ref = external_store_alias(
        infrastructure.digester.as_ref(),
        "signer",
        project_id,
        &operation_alias,
    );
    let prepared = signing_keys
        .prepare_signing_key(
            project_id,
            operation_alias,
            signer_ref,
            expected_project_revision,
            digest.clone(),
        )
        .await?;
    if prepared.request_digest != digest {
        return Err(ApplicationError::IdempotencyConflict);
    }
    if prepared.state == ProvisioningOperationState::Completed {
        return signing_keys
            .get_signing_key(project_id, prepared.key_id)
            .await;
    }

    infrastructure
        .signer_store
        .put_if_absent(
            prepared.signer_ref.clone(),
            infrastructure.entropy.signing_seed()?,
        )
        .await?;
    let public_jwk = infrastructure
        .signer_store
        .public_jwk(prepared.signer_ref.clone(), &prepared.kid)
        .await?;
    let now = infrastructure.clock.now();
    signing_keys
        .record_signing_key_material(
            project_id,
            &prepared,
            expected_project_revision,
            public_jwk,
            now,
        )
        .await?;
    signing_keys
        .publish_signing_key(
            project_id,
            &prepared,
            expected_project_revision,
            correlation_id,
            now,
        )
        .await
}

async fn create_provider_workflow(
    providers: &dyn ProviderProvisioningPort,
    infrastructure: &ProvisioningInfrastructure,
    project_id: Uuid,
    command: CreateProvider,
    correlation_id: Uuid,
) -> Result<ProviderRecord, ApplicationError> {
    let command = command.normalize(infrastructure.allow_http_loopback_provider)?;
    let secret_digest = infrastructure
        .secret_store
        .request_fingerprint(command.client_secret.as_bytes());
    let digest = infrastructure.digester.digest_json(&json!({
        "project_id": project_id,
        "provider_key": &command.provider_key,
        "display_name": &command.display_name,
        "issuer": &command.issuer,
        "client_id": &command.client_id,
        "secret_digest": URL_SAFE_NO_PAD.encode(secret_digest),
    }))?;
    let prepared = providers
        .prepare_provider(
            project_id,
            PrepareProvider {
                provider_key: command.provider_key,
                display_name: command.display_name,
                issuer: command.issuer,
                client_id: command.client_id,
                operation_alias: command.idempotency_key.clone(),
                expected_project_revision: command.expected_project_revision,
                request_digest: digest.clone(),
            },
        )
        .await?;
    if prepared.request_digest != digest {
        return Err(ApplicationError::IdempotencyConflict);
    }
    if prepared.state == ProvisioningOperationState::Completed {
        return providers
            .get_provider(project_id, prepared.provider_id)
            .await;
    }

    let secret_ref = external_store_alias(
        infrastructure.digester.as_ref(),
        "secret",
        project_id,
        &command.idempotency_key,
    );
    infrastructure
        .secret_store
        .put_if_absent(
            secret_ref.clone(),
            Zeroizing::new(command.client_secret.as_bytes().to_vec()),
        )
        .await?;
    infrastructure
        .secret_store
        .ensure_readable(secret_ref.clone())
        .await?;
    let now = infrastructure.clock.now();
    providers
        .mark_provider_secret_stored(
            project_id,
            &prepared,
            command.expected_project_revision,
            now,
        )
        .await?;
    providers
        .finalize_provider(
            project_id,
            &prepared,
            command.expected_project_revision,
            secret_ref,
            correlation_id,
            now,
        )
        .await
}

#[cfg(test)]
mod tests {
    use std::{
        collections::{BTreeMap, VecDeque},
        sync::{Arc, Mutex},
    };

    use sha2::{Digest, Sha256};
    use subtle::ConstantTimeEq;

    use super::*;
    use crate::adapters::system::Sha256RequestDigester;

    #[derive(Clone, Copy)]
    enum WriteFault {
        BeforeWrite,
        AfterWrite,
    }

    #[derive(Clone)]
    struct FixedClock;

    impl Clock for FixedClock {
        fn now(&self) -> OffsetDateTime {
            OffsetDateTime::UNIX_EPOCH + time::Duration::hours(1)
        }
    }

    #[derive(Clone)]
    struct RecordingEntropy {
        calls: Arc<Mutex<usize>>,
    }

    impl EntropySource for RecordingEntropy {
        fn signing_seed(&self) -> Result<Zeroizing<[u8; 32]>, ApplicationError> {
            *self.calls.lock().unwrap() += 1;
            Ok(Zeroizing::new([7; 32]))
        }
    }

    #[derive(Clone)]
    struct RecordingSignerStore {
        log: Arc<Mutex<Vec<&'static str>>>,
        values: Arc<Mutex<BTreeMap<String, [u8; 32]>>>,
        faults: Arc<Mutex<VecDeque<WriteFault>>>,
    }

    #[async_trait]
    impl SignerStore for RecordingSignerStore {
        async fn put_if_absent(
            &self,
            alias: String,
            seed: Zeroizing<[u8; 32]>,
        ) -> Result<(), ApplicationError> {
            self.log.lock().unwrap().push("signer.put");
            let fault = self.faults.lock().unwrap().pop_front();
            if matches!(fault, Some(WriteFault::BeforeWrite)) {
                return Err(ApplicationError::ExternalStore);
            }
            self.values.lock().unwrap().entry(alias).or_insert(*seed);
            if matches!(fault, Some(WriteFault::AfterWrite)) {
                return Err(ApplicationError::ExternalStore);
            }
            Ok(())
        }

        async fn public_jwk(&self, _alias: String, kid: &str) -> Result<Value, ApplicationError> {
            self.log.lock().unwrap().push("signer.public_jwk");
            Ok(json!({ "kid": kid }))
        }

        async fn verify(
            &self,
            _alias: String,
            _kid: &str,
            _public_jwk: &Value,
        ) -> Result<(), ApplicationError> {
            unimplemented!("not used by provisioning workflow tests")
        }
    }

    #[derive(Clone)]
    struct RecordingSecretStore {
        log: Arc<Mutex<Vec<&'static str>>>,
        values: Arc<Mutex<BTreeMap<String, Vec<u8>>>>,
        faults: Arc<Mutex<VecDeque<WriteFault>>>,
    }

    #[async_trait]
    impl ConfigurationSecretStore for RecordingSecretStore {
        fn request_fingerprint(&self, value: &[u8]) -> [u8; 32] {
            Sha256::digest(value).into()
        }

        async fn put_if_absent(
            &self,
            alias: String,
            value: Zeroizing<Vec<u8>>,
        ) -> Result<(), ApplicationError> {
            self.log.lock().unwrap().push("secret.put");
            let fault = self.faults.lock().unwrap().pop_front();
            if matches!(fault, Some(WriteFault::BeforeWrite)) {
                return Err(ApplicationError::ExternalStore);
            }
            let mut values = self.values.lock().unwrap();
            if let Some(existing) = values.get(&alias) {
                if !bool::from(existing.as_slice().ct_eq(value.as_slice())) {
                    return Err(ApplicationError::Integrity);
                }
            } else {
                values.insert(alias, value.to_vec());
            }
            drop(values);
            if matches!(fault, Some(WriteFault::AfterWrite)) {
                return Err(ApplicationError::ExternalStore);
            }
            Ok(())
        }

        async fn ensure_readable(&self, alias: String) -> Result<(), ApplicationError> {
            self.log.lock().unwrap().push("secret.ensure_readable");
            if self.values.lock().unwrap().contains_key(&alias) {
                Ok(())
            } else {
                Err(ApplicationError::Integrity)
            }
        }
    }

    struct RecordingSigningPort {
        log: Arc<Mutex<Vec<&'static str>>>,
        operation: Mutex<Option<PreparedSigningKey>>,
        initial_state: ProvisioningOperationState,
        conflicting_digest: bool,
    }

    impl RecordingSigningPort {
        fn new(
            log: Arc<Mutex<Vec<&'static str>>>,
            initial_state: ProvisioningOperationState,
            conflicting_digest: bool,
        ) -> Self {
            Self {
                log,
                operation: Mutex::new(None),
                initial_state,
                conflicting_digest,
            }
        }

        fn record(&self) -> SigningKeyRecord {
            let operation = self.operation.lock().unwrap();
            let prepared = operation.as_ref().unwrap();
            SigningKeyRecord {
                id: prepared.key_id,
                project_id: Uuid::from_u128(1),
                kid: prepared.kid.clone(),
                algorithm: SIGNING_ALGORITHM.to_owned(),
                state: "published".to_owned(),
                ring_revision: 2,
                signing_epoch: 1,
                sign_not_before: None,
                verify_not_after: None,
                public_jwk: json!({ "kid": prepared.kid }),
            }
        }
    }

    #[async_trait]
    impl SigningKeyProvisioningPort for RecordingSigningPort {
        async fn prepare_signing_key(
            &self,
            _project_id: Uuid,
            _operation_alias: String,
            signer_ref: String,
            _expected_project_revision: i64,
            request_digest: Vec<u8>,
        ) -> Result<PreparedSigningKey, ApplicationError> {
            self.log.lock().unwrap().push("key.prepare");
            let mut operation = self.operation.lock().unwrap();
            let prepared = operation.get_or_insert_with(|| PreparedSigningKey {
                operation_id: Uuid::from_u128(2),
                ring_id: Uuid::from_u128(3),
                key_id: Uuid::from_u128(4),
                kid: "kid_test".to_owned(),
                signer_ref,
                request_digest: if self.conflicting_digest {
                    vec![0; 32]
                } else {
                    request_digest
                },
                state: self.initial_state,
            });
            Ok(prepared.clone())
        }

        async fn signing_key_recovery(
            &self,
            _project_id: Uuid,
            _key_id: Uuid,
        ) -> Result<SigningKeyRecovery, ApplicationError> {
            unimplemented!("not used by provisioning workflow tests")
        }

        async fn record_signing_key_material(
            &self,
            _project_id: Uuid,
            prepared: &PreparedSigningKey,
            _expected_project_revision: i64,
            _public_jwk: Value,
            _recorded_at: OffsetDateTime,
        ) -> Result<(), ApplicationError> {
            self.log.lock().unwrap().push("key.record_material");
            let mut operation = self.operation.lock().unwrap();
            assert_eq!(operation.as_ref().unwrap().key_id, prepared.key_id);
            operation.as_mut().unwrap().state = ProvisioningOperationState::Stored;
            Ok(())
        }

        async fn publish_signing_key(
            &self,
            _project_id: Uuid,
            prepared: &PreparedSigningKey,
            _expected_project_revision: i64,
            _correlation_id: Uuid,
            _published_at: OffsetDateTime,
        ) -> Result<SigningKeyRecord, ApplicationError> {
            self.log.lock().unwrap().push("key.publish");
            let mut operation = self.operation.lock().unwrap();
            assert_eq!(operation.as_ref().unwrap().key_id, prepared.key_id);
            operation.as_mut().unwrap().state = ProvisioningOperationState::Completed;
            drop(operation);
            Ok(self.record())
        }

        async fn get_signing_key(
            &self,
            _project_id: Uuid,
            _key_id: Uuid,
        ) -> Result<SigningKeyRecord, ApplicationError> {
            self.log.lock().unwrap().push("key.get");
            Ok(self.record())
        }

        async fn list_signing_keys(
            &self,
            _project_id: Uuid,
        ) -> Result<Vec<SigningKeyRecord>, ApplicationError> {
            unimplemented!("not used by provisioning workflow tests")
        }

        async fn signing_key_activation_candidate(
            &self,
            _project_id: Uuid,
            _key_id: Uuid,
        ) -> Result<SigningKeyActivationCandidate, ApplicationError> {
            unimplemented!("not used by provisioning workflow tests")
        }

        async fn activate_signing_key_if_ready(
            &self,
            _project_id: Uuid,
            _key_id: Uuid,
            _expected_ring_revision: i64,
            _correlation_id: Uuid,
        ) -> Result<SigningKeyRecord, ApplicationError> {
            unimplemented!("not used by provisioning workflow tests")
        }

        async fn retire_signing_key(
            &self,
            _project_id: Uuid,
            _key_id: Uuid,
            _expected_ring_revision: i64,
            _correlation_id: Uuid,
        ) -> Result<SigningKeyRecord, ApplicationError> {
            unimplemented!("not used by provisioning workflow tests")
        }

        async fn revoke_signing_key(
            &self,
            _project_id: Uuid,
            _key_id: Uuid,
            _expected_ring_revision: i64,
            _correlation_id: Uuid,
        ) -> Result<SigningKeyRecord, ApplicationError> {
            unimplemented!("not used by provisioning workflow tests")
        }
    }

    struct RecordingProviderPort {
        log: Arc<Mutex<Vec<&'static str>>>,
        operation: Mutex<Option<PreparedProvider>>,
        initial_state: ProvisioningOperationState,
        conflicting_digest: bool,
    }

    impl RecordingProviderPort {
        fn new(
            log: Arc<Mutex<Vec<&'static str>>>,
            initial_state: ProvisioningOperationState,
            conflicting_digest: bool,
        ) -> Self {
            Self {
                log,
                operation: Mutex::new(None),
                initial_state,
                conflicting_digest,
            }
        }

        fn record(&self) -> ProviderRecord {
            let operation = self.operation.lock().unwrap();
            ProviderRecord {
                id: operation.as_ref().unwrap().provider_id,
                project_id: Uuid::from_u128(1),
                provider_key: "workforce".to_owned(),
                kind: "oidc".to_owned(),
                display_name: "Workforce".to_owned(),
                issuer: "https://accounts.example/".to_owned(),
                client_id: "client".to_owned(),
                callback_url: "https://identity.example/callback".to_owned(),
                status: "active".to_owned(),
                revision: 2,
                assigned_application_ids: Vec::new(),
            }
        }
    }

    #[async_trait]
    impl ProviderProvisioningPort for RecordingProviderPort {
        async fn prepare_provider(
            &self,
            _project_id: Uuid,
            command: PrepareProvider,
        ) -> Result<PreparedProvider, ApplicationError> {
            self.log.lock().unwrap().push("provider.prepare");
            let mut operation = self.operation.lock().unwrap();
            let prepared = operation.get_or_insert_with(|| PreparedProvider {
                operation_id: Uuid::from_u128(5),
                provider_id: Uuid::from_u128(6),
                request_digest: if self.conflicting_digest {
                    vec![0; 32]
                } else {
                    command.request_digest
                },
                state: self.initial_state,
            });
            Ok(prepared.clone())
        }

        async fn provider_recovery(
            &self,
            _project_id: Uuid,
            _provider_id: Uuid,
        ) -> Result<ProviderRecovery, ApplicationError> {
            unimplemented!("not used by provisioning workflow tests")
        }

        async fn mark_provider_secret_stored(
            &self,
            _project_id: Uuid,
            prepared: &PreparedProvider,
            _expected_project_revision: i64,
            _stored_at: OffsetDateTime,
        ) -> Result<(), ApplicationError> {
            self.log.lock().unwrap().push("provider.mark_stored");
            let mut operation = self.operation.lock().unwrap();
            assert_eq!(
                operation.as_ref().unwrap().provider_id,
                prepared.provider_id
            );
            operation.as_mut().unwrap().state = ProvisioningOperationState::Stored;
            Ok(())
        }

        async fn finalize_provider(
            &self,
            _project_id: Uuid,
            prepared: &PreparedProvider,
            _expected_project_revision: i64,
            _secret_ref: String,
            _correlation_id: Uuid,
            _finalized_at: OffsetDateTime,
        ) -> Result<ProviderRecord, ApplicationError> {
            self.log.lock().unwrap().push("provider.finalize");
            let mut operation = self.operation.lock().unwrap();
            assert_eq!(
                operation.as_ref().unwrap().provider_id,
                prepared.provider_id
            );
            operation.as_mut().unwrap().state = ProvisioningOperationState::Completed;
            drop(operation);
            Ok(self.record())
        }

        async fn get_provider(
            &self,
            _project_id: Uuid,
            _provider_id: Uuid,
        ) -> Result<ProviderRecord, ApplicationError> {
            self.log.lock().unwrap().push("provider.get");
            Ok(self.record())
        }

        async fn list_providers(
            &self,
            _project_id: Uuid,
        ) -> Result<Vec<ProviderRecord>, ApplicationError> {
            unimplemented!("not used by provisioning workflow tests")
        }

        async fn assign_provider(
            &self,
            _project_id: Uuid,
            _provider_id: Uuid,
            _application_id: Uuid,
            _expected_application_revision: i64,
            _correlation_id: Uuid,
        ) -> Result<ProviderRecord, ApplicationError> {
            unimplemented!("not used by provisioning workflow tests")
        }

        async fn unassign_provider(
            &self,
            _project_id: Uuid,
            _provider_id: Uuid,
            _application_id: Uuid,
            _expected_application_revision: i64,
            _correlation_id: Uuid,
        ) -> Result<ProviderRecord, ApplicationError> {
            unimplemented!("not used by provisioning workflow tests")
        }

        async fn disable_provider(
            &self,
            _project_id: Uuid,
            _provider_id: Uuid,
            _expected_provider_revision: i64,
            _correlation_id: Uuid,
        ) -> Result<ProviderRecord, ApplicationError> {
            unimplemented!("not used by provisioning workflow tests")
        }
    }

    fn infrastructure(
        signer_store: RecordingSignerStore,
        secret_store: RecordingSecretStore,
        entropy_calls: Arc<Mutex<usize>>,
    ) -> ProvisioningInfrastructure {
        ProvisioningInfrastructure::new(
            signer_store,
            secret_store,
            FixedClock,
            RecordingEntropy {
                calls: entropy_calls,
            },
            Sha256RequestDigester,
            false,
        )
    }

    fn stores(
        log: Arc<Mutex<Vec<&'static str>>>,
        signer_fault: Option<WriteFault>,
        secret_fault: Option<WriteFault>,
    ) -> (RecordingSignerStore, RecordingSecretStore) {
        (
            RecordingSignerStore {
                log: log.clone(),
                values: Arc::new(Mutex::new(BTreeMap::new())),
                faults: Arc::new(Mutex::new(signer_fault.into_iter().collect())),
            },
            RecordingSecretStore {
                log,
                values: Arc::new(Mutex::new(BTreeMap::new())),
                faults: Arc::new(Mutex::new(secret_fault.into_iter().collect())),
            },
        )
    }

    fn provider_command() -> CreateProvider {
        CreateProvider {
            provider_key: "workforce".to_owned(),
            display_name: "Workforce".to_owned(),
            issuer: "https://accounts.example/".to_owned(),
            client_id: "client".to_owned(),
            client_secret: Zeroizing::new("secret".to_owned()),
            idempotency_key: "provider-operation-12345678".to_owned(),
            expected_project_revision: 1,
        }
    }

    #[test]
    fn provider_issuer_requires_https_unless_exact_loopback_is_enabled() {
        assert!(validate_provider_issuer("https://accounts.example/", false).is_ok());
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

    #[tokio::test]
    async fn signing_retry_converges_after_errors_before_and_after_external_write() {
        for fault in [WriteFault::BeforeWrite, WriteFault::AfterWrite] {
            let log = Arc::new(Mutex::new(Vec::new()));
            let (signer_store, secret_store) = stores(log.clone(), Some(fault), None);
            let signer_values = signer_store.values.clone();
            let entropy_calls = Arc::new(Mutex::new(0));
            let infrastructure = infrastructure(signer_store, secret_store, entropy_calls.clone());
            let port =
                RecordingSigningPort::new(log.clone(), ProvisioningOperationState::Prepared, false);

            let first = provision_signing_key_workflow(
                &port,
                &infrastructure,
                Uuid::from_u128(1),
                "signing-operation-12345678".to_owned(),
                1,
                Uuid::new_v4(),
            )
            .await;
            assert_eq!(first, Err(ApplicationError::ExternalStore));
            assert_eq!(
                signer_values.lock().unwrap().len(),
                usize::from(matches!(fault, WriteFault::AfterWrite))
            );

            let completed = provision_signing_key_workflow(
                &port,
                &infrastructure,
                Uuid::from_u128(1),
                "signing-operation-12345678".to_owned(),
                1,
                Uuid::new_v4(),
            )
            .await
            .expect("retry should reconcile the stable signer alias");
            assert_eq!(completed.id, Uuid::from_u128(4));
            assert_eq!(signer_values.lock().unwrap().len(), 1);
            assert_eq!(*entropy_calls.lock().unwrap(), 2);
            assert_eq!(
                *log.lock().unwrap(),
                [
                    "key.prepare",
                    "signer.put",
                    "key.prepare",
                    "signer.put",
                    "signer.public_jwk",
                    "key.record_material",
                    "key.publish",
                ]
            );
        }
    }

    #[tokio::test]
    async fn signing_replay_and_digest_conflict_skip_external_effects() {
        for (state, conflicting_digest, expected_log) in [
            (
                ProvisioningOperationState::Completed,
                false,
                vec!["key.prepare", "key.get"],
            ),
            (
                ProvisioningOperationState::Prepared,
                true,
                vec!["key.prepare"],
            ),
        ] {
            let log = Arc::new(Mutex::new(Vec::new()));
            let (signer_store, secret_store) = stores(log.clone(), None, None);
            let signer_values = signer_store.values.clone();
            let entropy_calls = Arc::new(Mutex::new(0));
            let infrastructure = infrastructure(signer_store, secret_store, entropy_calls.clone());
            let port = RecordingSigningPort::new(log.clone(), state, conflicting_digest);

            let result = provision_signing_key_workflow(
                &port,
                &infrastructure,
                Uuid::from_u128(1),
                "signing-operation-12345678".to_owned(),
                1,
                Uuid::new_v4(),
            )
            .await;
            if conflicting_digest {
                assert_eq!(result, Err(ApplicationError::IdempotencyConflict));
            } else {
                assert!(result.is_ok());
            }
            assert!(signer_values.lock().unwrap().is_empty());
            assert_eq!(*entropy_calls.lock().unwrap(), 0);
            assert_eq!(*log.lock().unwrap(), expected_log);
        }
    }

    #[tokio::test]
    async fn provider_retry_converges_after_errors_before_and_after_external_write() {
        for fault in [WriteFault::BeforeWrite, WriteFault::AfterWrite] {
            let log = Arc::new(Mutex::new(Vec::new()));
            let (signer_store, secret_store) = stores(log.clone(), None, Some(fault));
            let secret_values = secret_store.values.clone();
            let infrastructure =
                infrastructure(signer_store, secret_store, Arc::new(Mutex::new(0)));
            let port = RecordingProviderPort::new(
                log.clone(),
                ProvisioningOperationState::Prepared,
                false,
            );

            let first = create_provider_workflow(
                &port,
                &infrastructure,
                Uuid::from_u128(1),
                provider_command(),
                Uuid::new_v4(),
            )
            .await;
            assert_eq!(first, Err(ApplicationError::ExternalStore));
            assert_eq!(
                secret_values.lock().unwrap().len(),
                usize::from(matches!(fault, WriteFault::AfterWrite))
            );

            let completed = create_provider_workflow(
                &port,
                &infrastructure,
                Uuid::from_u128(1),
                provider_command(),
                Uuid::new_v4(),
            )
            .await
            .expect("retry should reconcile the stable secret alias");
            assert_eq!(completed.id, Uuid::from_u128(6));
            assert_eq!(secret_values.lock().unwrap().len(), 1);
            assert_eq!(
                *log.lock().unwrap(),
                [
                    "provider.prepare",
                    "secret.put",
                    "provider.prepare",
                    "secret.put",
                    "secret.ensure_readable",
                    "provider.mark_stored",
                    "provider.finalize",
                ]
            );
        }
    }

    #[tokio::test]
    async fn provider_secret_alias_mismatch_fails_before_database_finalization() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let (signer_store, secret_store) = stores(log.clone(), None, None);
        let command = provider_command();
        let alias = external_store_alias(
            &Sha256RequestDigester,
            "secret",
            Uuid::from_u128(1),
            &command.idempotency_key,
        );
        secret_store
            .values
            .lock()
            .unwrap()
            .insert(alias, b"other-secret".to_vec());
        let infrastructure = infrastructure(signer_store, secret_store, Arc::new(Mutex::new(0)));
        let port =
            RecordingProviderPort::new(log.clone(), ProvisioningOperationState::Prepared, false);

        assert_eq!(
            create_provider_workflow(
                &port,
                &infrastructure,
                Uuid::from_u128(1),
                command,
                Uuid::new_v4(),
            )
            .await,
            Err(ApplicationError::Integrity)
        );
        assert_eq!(*log.lock().unwrap(), ["provider.prepare", "secret.put"]);
    }

    #[tokio::test]
    async fn provider_replay_and_digest_conflict_skip_external_effects() {
        for (state, conflicting_digest, expected_log) in [
            (
                ProvisioningOperationState::Completed,
                false,
                vec!["provider.prepare", "provider.get"],
            ),
            (
                ProvisioningOperationState::Prepared,
                true,
                vec!["provider.prepare"],
            ),
        ] {
            let log = Arc::new(Mutex::new(Vec::new()));
            let (signer_store, secret_store) = stores(log.clone(), None, None);
            let secret_values = secret_store.values.clone();
            let infrastructure =
                infrastructure(signer_store, secret_store, Arc::new(Mutex::new(0)));
            let port = RecordingProviderPort::new(log.clone(), state, conflicting_digest);

            let result = create_provider_workflow(
                &port,
                &infrastructure,
                Uuid::from_u128(1),
                provider_command(),
                Uuid::new_v4(),
            )
            .await;
            if conflicting_digest {
                assert_eq!(result, Err(ApplicationError::IdempotencyConflict));
            } else {
                assert!(result.is_ok());
            }
            assert!(secret_values.lock().unwrap().is_empty());
            assert_eq!(*log.lock().unwrap(), expected_log);
        }
    }
}
