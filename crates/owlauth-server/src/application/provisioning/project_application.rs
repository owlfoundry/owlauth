use super::{
    ApplicationError, ApplicationRecord, CreateApplication, CreateProject,
    MAX_ACCESS_TOKEN_LIFETIME_SECONDS, MIN_ACCESS_TOKEN_LIFETIME_SECONDS, ProjectPolicyRecord,
    ProjectRecord, ProvisioningService, ReplaceApplicationConfiguration, UpdateApplication,
    UpdateProject, UpdateProjectPolicy, Uuid, normalize_owner,
};

impl ProvisioningService {
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
}
