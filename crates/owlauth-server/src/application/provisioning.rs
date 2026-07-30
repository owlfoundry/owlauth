use std::sync::Arc;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::OffsetDateTime;
use uuid::Uuid;
use zeroize::Zeroizing;

use super::ApplicationError;
use crate::domain::ApplicationType;

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

#[async_trait]
pub(crate) trait ProvisioningPort: Send + Sync {
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
    async fn provision_signing_key(
        &self,
        project_id: Uuid,
        operation_alias: String,
        expected_project_revision: i64,
        correlation_id: Uuid,
    ) -> Result<SigningKeyRecord, ApplicationError>;
    async fn list_signing_keys(
        &self,
        project_id: Uuid,
    ) -> Result<Vec<SigningKeyRecord>, ApplicationError>;
    async fn activate_signing_key(
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
    async fn create_provider(
        &self,
        project_id: Uuid,
        command: CreateProvider,
        correlation_id: Uuid,
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
pub(crate) struct ProvisioningService {
    port: Arc<dyn ProvisioningPort>,
}

impl ProvisioningService {
    pub(crate) fn new(port: Arc<dyn ProvisioningPort>) -> Self {
        Self { port }
    }

    pub(crate) async fn create_project(
        &self,
        command: CreateProject,
        correlation_id: Uuid,
    ) -> Result<ProjectRecord, ApplicationError> {
        self.port.create_project(command, correlation_id).await
    }
    pub(crate) async fn list_projects(
        &self,
        belongs_to: Option<String>,
    ) -> Result<Vec<ProjectRecord>, ApplicationError> {
        self.port.list_projects(belongs_to).await
    }
    pub(crate) async fn get_project(
        &self,
        project_id: Uuid,
    ) -> Result<ProjectRecord, ApplicationError> {
        self.port.get_project(project_id).await
    }
    pub(crate) async fn get_project_policy(
        &self,
        project_id: Uuid,
    ) -> Result<ProjectPolicyRecord, ApplicationError> {
        self.port.get_project_policy(project_id).await
    }
    pub(crate) async fn update_project_policy(
        &self,
        project_id: Uuid,
        command: UpdateProjectPolicy,
        correlation_id: Uuid,
    ) -> Result<ProjectPolicyRecord, ApplicationError> {
        self.port
            .update_project_policy(project_id, command, correlation_id)
            .await
    }
    pub(crate) async fn update_project(
        &self,
        project_id: Uuid,
        command: UpdateProject,
        correlation_id: Uuid,
    ) -> Result<ProjectRecord, ApplicationError> {
        self.port
            .update_project(project_id, command, correlation_id)
            .await
    }
    pub(crate) async fn disable_project(
        &self,
        project_id: Uuid,
        expected_security_revision: i64,
        correlation_id: Uuid,
    ) -> Result<ProjectRecord, ApplicationError> {
        self.port
            .disable_project(project_id, expected_security_revision, correlation_id)
            .await
    }
    pub(crate) async fn create_application(
        &self,
        project_id: Uuid,
        command: CreateApplication,
        correlation_id: Uuid,
    ) -> Result<ApplicationRecord, ApplicationError> {
        self.port
            .create_application(project_id, command, correlation_id)
            .await
    }
    pub(crate) async fn list_applications(
        &self,
        project_id: Uuid,
    ) -> Result<Vec<ApplicationRecord>, ApplicationError> {
        self.port.list_applications(project_id).await
    }
    pub(crate) async fn get_application(
        &self,
        project_id: Uuid,
        application_id: Uuid,
    ) -> Result<ApplicationRecord, ApplicationError> {
        self.port.get_application(project_id, application_id).await
    }
    pub(crate) async fn update_application(
        &self,
        project_id: Uuid,
        application_id: Uuid,
        command: UpdateApplication,
        correlation_id: Uuid,
    ) -> Result<ApplicationRecord, ApplicationError> {
        self.port
            .update_application(project_id, application_id, command, correlation_id)
            .await
    }
    pub(crate) async fn replace_application_configuration(
        &self,
        project_id: Uuid,
        application_id: Uuid,
        command: ReplaceApplicationConfiguration,
        correlation_id: Uuid,
    ) -> Result<ApplicationRecord, ApplicationError> {
        self.port
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
        self.port
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
        self.port
            .provision_signing_key(
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
        self.port.list_signing_keys(project_id).await
    }
    pub(crate) async fn activate_signing_key(
        &self,
        project_id: Uuid,
        key_id: Uuid,
        expected_ring_revision: i64,
        correlation_id: Uuid,
    ) -> Result<SigningKeyRecord, ApplicationError> {
        self.port
            .activate_signing_key(project_id, key_id, expected_ring_revision, correlation_id)
            .await
    }
    pub(crate) async fn retire_signing_key(
        &self,
        project_id: Uuid,
        key_id: Uuid,
        expected_ring_revision: i64,
        correlation_id: Uuid,
    ) -> Result<SigningKeyRecord, ApplicationError> {
        self.port
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
        self.port
            .revoke_signing_key(project_id, key_id, expected_ring_revision, correlation_id)
            .await
    }
    pub(crate) async fn create_provider(
        &self,
        project_id: Uuid,
        command: CreateProvider,
        correlation_id: Uuid,
    ) -> Result<ProviderRecord, ApplicationError> {
        self.port
            .create_provider(project_id, command, correlation_id)
            .await
    }
    pub(crate) async fn list_providers(
        &self,
        project_id: Uuid,
    ) -> Result<Vec<ProviderRecord>, ApplicationError> {
        self.port.list_providers(project_id).await
    }
    pub(crate) async fn assign_provider(
        &self,
        project_id: Uuid,
        provider_id: Uuid,
        application_id: Uuid,
        expected_application_revision: i64,
        correlation_id: Uuid,
    ) -> Result<ProviderRecord, ApplicationError> {
        self.port
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
        self.port
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
        self.port
            .disable_provider(
                project_id,
                provider_id,
                expected_provider_revision,
                correlation_id,
            )
            .await
    }
}
