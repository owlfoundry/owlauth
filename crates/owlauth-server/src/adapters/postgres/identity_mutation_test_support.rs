use std::{ops::Deref, sync::Arc};

use sea_orm::DatabaseConnection;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::application::{
    ApplicationError, ControlIdentityMutationRepository, CreateIdentityMutationResult,
    IdentityMutationControlConfirmationPreparation, IdentityMutationRecord,
    PreparedIdentityMutationConfirmation, PreparedIdentityMutationCreate,
};
use crate::domain::IdentityMutationKind;

use super::{
    identity_mutation::{
        PostgresControlIdentityMutationRepository, PostgresRuntimeIdentityMutationRepository,
    },
    projection::IdentityProjectionMaterializer,
};

#[derive(Clone)]
pub(crate) struct PostgresIdentityMutationRepository {
    runtime: PostgresRuntimeIdentityMutationRepository,
    control: PostgresControlIdentityMutationRepository,
}

impl PostgresIdentityMutationRepository {
    pub(crate) fn new(
        database: DatabaseConnection,
        process_id: String,
        incarnation: Uuid,
        projection_materializer: Arc<dyn IdentityProjectionMaterializer>,
        required_runtime_process_ids: Vec<String>,
    ) -> Self {
        Self {
            runtime: PostgresRuntimeIdentityMutationRepository::new(
                database.clone(),
                process_id,
                incarnation,
                required_runtime_process_ids.clone(),
            ),
            control: PostgresControlIdentityMutationRepository::new(
                database,
                projection_materializer,
                required_runtime_process_ids,
            ),
        }
    }

    pub(crate) async fn create(
        &self,
        prepared: PreparedIdentityMutationCreate,
    ) -> Result<CreateIdentityMutationResult, ApplicationError> {
        self.control.create(prepared).await
    }

    pub(crate) async fn control_read(
        &self,
        project_id: Uuid,
        intent_id: Uuid,
        now: OffsetDateTime,
    ) -> Result<IdentityMutationRecord, ApplicationError> {
        self.control.control_read(project_id, intent_id, now).await
    }

    pub(crate) async fn cancel(
        &self,
        project_id: Uuid,
        intent_id: Uuid,
        expected_revision: i64,
        correlation_id: Uuid,
        now: OffsetDateTime,
    ) -> Result<IdentityMutationRecord, ApplicationError> {
        self.control
            .cancel(
                project_id,
                intent_id,
                expected_revision,
                correlation_id,
                now,
            )
            .await
    }

    pub(crate) async fn prepare_control_confirmation(
        &self,
        project_id: Uuid,
        intent_id: Uuid,
        expected_revision: i64,
        expected_kind: IdentityMutationKind,
        now: OffsetDateTime,
    ) -> Result<IdentityMutationControlConfirmationPreparation, ApplicationError> {
        self.control
            .prepare_control_confirmation(
                project_id,
                intent_id,
                expected_revision,
                expected_kind,
                now,
            )
            .await
    }

    pub(crate) async fn confirm_control(
        &self,
        confirmation: PreparedIdentityMutationConfirmation,
    ) -> Result<IdentityMutationRecord, ApplicationError> {
        self.control.confirm_control(confirmation).await
    }
}

impl Deref for PostgresIdentityMutationRepository {
    type Target = PostgresRuntimeIdentityMutationRepository;

    fn deref(&self) -> &Self::Target {
        &self.runtime
    }
}
