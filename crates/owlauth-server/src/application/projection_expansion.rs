use std::{sync::Arc, time::Duration};

use async_trait::async_trait;
use time::OffsetDateTime;
use uuid::Uuid;

use super::{ApplicationError, Clock};

pub(crate) const DEFAULT_PROJECTION_EXPANSION_BATCH_SIZE: usize = 64;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ProjectionPolicyRecord {
    pub project_id: Uuid,
    pub application_id: Option<Uuid>,
    pub verified_email_enabled: bool,
    pub revision: i64,
    pub expansion_operation_id: Option<Uuid>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct UpdateProjectionPolicy {
    pub verified_email_enabled: bool,
    pub expected_revision: i64,
}

#[async_trait]
pub(crate) trait ProjectionPolicyPort: Send + Sync {
    async fn get_project_projection_policy(
        &self,
        project_id: Uuid,
    ) -> Result<ProjectionPolicyRecord, ApplicationError>;

    async fn update_project_projection_policy(
        &self,
        project_id: Uuid,
        command: UpdateProjectionPolicy,
        now: OffsetDateTime,
        correlation_id: Uuid,
    ) -> Result<ProjectionPolicyRecord, ApplicationError>;

    async fn get_application_projection_policy(
        &self,
        project_id: Uuid,
        application_id: Uuid,
    ) -> Result<ProjectionPolicyRecord, ApplicationError>;

    async fn update_application_projection_policy(
        &self,
        project_id: Uuid,
        application_id: Uuid,
        command: UpdateProjectionPolicy,
        now: OffsetDateTime,
        correlation_id: Uuid,
    ) -> Result<ProjectionPolicyRecord, ApplicationError>;
}

#[async_trait]
pub(crate) trait ProjectionExpansionRepository: Send + Sync {
    async fn process_one_batch(
        &self,
        worker_id: &str,
        worker_incarnation: Uuid,
        now: OffsetDateTime,
        lease_duration: Duration,
        batch_size: usize,
    ) -> Result<bool, ApplicationError>;
}

#[derive(Clone)]
pub(crate) struct ProjectionPolicyService {
    port: Arc<dyn ProjectionPolicyPort>,
    clock: Arc<dyn Clock>,
}

impl ProjectionPolicyService {
    pub(crate) fn new(port: Arc<dyn ProjectionPolicyPort>, clock: Arc<dyn Clock>) -> Self {
        Self { port, clock }
    }

    pub(crate) async fn get_project(
        &self,
        project_id: Uuid,
    ) -> Result<ProjectionPolicyRecord, ApplicationError> {
        self.port.get_project_projection_policy(project_id).await
    }

    pub(crate) async fn update_project(
        &self,
        project_id: Uuid,
        command: UpdateProjectionPolicy,
        correlation_id: Uuid,
    ) -> Result<ProjectionPolicyRecord, ApplicationError> {
        validate_command(command)?;
        self.port
            .update_project_projection_policy(project_id, command, self.clock.now(), correlation_id)
            .await
    }

    pub(crate) async fn get_application(
        &self,
        project_id: Uuid,
        application_id: Uuid,
    ) -> Result<ProjectionPolicyRecord, ApplicationError> {
        self.port
            .get_application_projection_policy(project_id, application_id)
            .await
    }

    pub(crate) async fn update_application(
        &self,
        project_id: Uuid,
        application_id: Uuid,
        command: UpdateProjectionPolicy,
        correlation_id: Uuid,
    ) -> Result<ProjectionPolicyRecord, ApplicationError> {
        validate_command(command)?;
        self.port
            .update_application_projection_policy(
                project_id,
                application_id,
                command,
                self.clock.now(),
                correlation_id,
            )
            .await
    }
}

#[derive(Clone)]
pub(crate) struct ProjectionExpansionWorker {
    repository: Arc<dyn ProjectionExpansionRepository>,
    clock: Arc<dyn Clock>,
    worker_id: String,
    worker_incarnation: Uuid,
    lease_duration: Duration,
    batch_size: usize,
}

impl ProjectionExpansionWorker {
    pub(crate) fn new(
        repository: Arc<dyn ProjectionExpansionRepository>,
        clock: Arc<dyn Clock>,
        worker_id: String,
        worker_incarnation: Uuid,
        lease_duration: Duration,
        batch_size: usize,
    ) -> Result<Self, ApplicationError> {
        if worker_id.is_empty()
            || worker_id.len() > 128
            || lease_duration.is_zero()
            || !(1..=DEFAULT_PROJECTION_EXPANSION_BATCH_SIZE).contains(&batch_size)
        {
            return Err(ApplicationError::InvalidInput);
        }
        Ok(Self {
            repository,
            clock,
            worker_id,
            worker_incarnation,
            lease_duration,
            batch_size,
        })
    }

    pub(crate) async fn run_once(&self) -> Result<bool, ApplicationError> {
        self.repository
            .process_one_batch(
                &self.worker_id,
                self.worker_incarnation,
                self.clock.now(),
                self.lease_duration,
                self.batch_size,
            )
            .await
    }
}

fn validate_command(command: UpdateProjectionPolicy) -> Result<(), ApplicationError> {
    if command.expected_revision <= 0 {
        return Err(ApplicationError::InvalidInput);
    }
    Ok(())
}
