use std::{collections::BTreeSet, sync::Arc, time::Duration};

use async_trait::async_trait;
use sea_orm::{
    ActiveModelTrait, ActiveValue::Set, ColumnTrait, ConnectionTrait, DatabaseConnection,
    DatabaseTransaction, DbErr, EntityTrait, FromQueryResult, IntoActiveModel, QueryFilter,
    QueryOrder, QuerySelect, RuntimeErr, Statement, TransactionTrait,
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use time::OffsetDateTime;
use url::Url;
use uuid::Uuid;

use crate::{
    adapters::{
        postgres::entity::{
            application, application_origin, application_provider_assignment,
            application_publishable_key, application_redirect, audit_event,
            control_idempotency_record, key_provisioning_operation, key_state_event, project,
            project_key_ring, project_policy, project_signing_key, provider_configuration,
            provider_secret_operation, runtime_publication_lease,
        },
        system::{Sha256RequestDigester, SystemClock},
    },
    application::{
        ApplicationConfiguration, ApplicationError, ApplicationProvisioningPort, ApplicationRecord,
        Clock, CreateApplication, CreateProject, PrepareProvider, PreparedProvider,
        PreparedSigningKey, ProjectPolicyRecord, ProjectProvisioningPort, ProjectRecord,
        ProviderProvisioningPort, ProviderRecord, ProviderRecovery, ProvisioningOperationState,
        ReplaceApplicationConfiguration, RequestDigester, SigningKeyActivationCandidate,
        SigningKeyProvisioningPort, SigningKeyRecord, SigningKeyRecovery, UpdateApplication,
        UpdateProject, UpdateProjectPolicy,
    },
    domain::{
        ApplicationStatus, ApplicationType, BrowserOrigin, MAX_ACCESS_TOKEN_LIFETIME_SECONDS,
        ProjectStatus, ProviderStatus, RedirectUri, SigningKeyState,
    },
};

const LIST_LIMIT: u64 = 100;
const CONFIGURATION_VALUE_LIMIT: usize = 50;
const PROJECT_CAPACITY_LOCK: &str = "owlauth:deployment-project-capacity:v1";
const SIGNING_PURPOSE: &str = "application_tokens";
const SIGNING_ALGORITHM: &str = "EdDSA";

#[derive(Clone)]
pub(crate) struct PostgresProvisioningAdapter {
    database: DatabaseConnection,
    clock: Arc<dyn Clock>,
    digester: Arc<dyn RequestDigester>,
    runtime_base: Arc<Url>,
    required_runtime_process_ids: Arc<BTreeSet<String>>,
    propagation_delay: Duration,
    verification_retention: Duration,
}

impl PostgresProvisioningAdapter {
    pub(crate) fn new(
        database: DatabaseConnection,
        runtime_base: Url,
        required_runtime_process_ids: Vec<String>,
        propagation_delay: Duration,
        verification_retention: Duration,
    ) -> Self {
        Self {
            database,
            clock: Arc::new(SystemClock),
            digester: Arc::new(Sha256RequestDigester),
            runtime_base: Arc::new(runtime_base),
            required_runtime_process_ids: Arc::new(
                required_runtime_process_ids.into_iter().collect(),
            ),
            propagation_delay,
            verification_retention,
        }
    }

    pub(crate) async fn create_project(
        &self,
        command: CreateProject,
        correlation_id: Uuid,
    ) -> Result<ProjectRecord, ApplicationError> {
        let display_name = command.display_name;
        let belongs_to = command.belongs_to;
        let digest = self.digester.digest_json(&json!({
            "display_name": display_name,
            "belongs_to": belongs_to,
        }))?;
        let transaction = self.database.begin().await.map_err(persistence)?;
        lock_idempotency_key(&transaction, &command.idempotency_key).await?;
        if let Some(replayed) = replay::<ProjectRecord>(
            &transaction,
            &command.idempotency_key,
            "project.create",
            "deployment",
            &digest,
        )
        .await?
        {
            transaction.commit().await.map_err(persistence)?;
            return Ok(replayed);
        }
        lock_project_capacity(&transaction).await?;
        let projects = project::Entity::find()
            .limit(LIST_LIMIT + 1)
            .all(&transaction)
            .await
            .map_err(persistence)?;
        ensure_capacity(projects.len(), LIST_LIMIT, ApplicationError::InvalidInput)?;
        let id = Uuid::new_v4();
        let public_id = generated_id("prj");
        project::ActiveModel {
            id: Set(id),
            public_id: Set(public_id.clone()),
            belongs_to: Set(belongs_to.clone()),
            display_name: Set(display_name.clone()),
            status: Set("active".to_owned()),
            metadata_revision: Set(1),
            security_revision: Set(1),
            ..Default::default()
        }
        .insert(&transaction)
        .await
        .map_err(persistence)?;
        project_policy::ActiveModel {
            project_id: Set(id),
            claims_revision: Set(1),
            session_revision: Set(1),
            projection_revision: Set(1),
            claims_policy: Set(json!({ "access_token_lifetime_seconds": 900 })),
            session_policy: Set(json!({
                "browser_session_reuse": false,
                "browser_session_reuse_max_age_seconds": 28_800,
            })),
        }
        .insert(&transaction)
        .await
        .map_err(persistence)?;
        let record = ProjectRecord {
            id,
            public_id,
            display_name,
            belongs_to,
            status: "active".to_owned(),
            metadata_revision: 1,
            security_revision: 1,
        };
        insert_audit(
            &transaction,
            Some(id),
            "project.created",
            "project",
            Some(id),
            correlation_id,
        )
        .await?;
        complete_idempotency(
            &transaction,
            command.idempotency_key,
            Some(id),
            Some(id),
            "project.create",
            "deployment",
            digest,
            &record,
        )
        .await?;
        transaction.commit().await.map_err(persistence)?;
        Ok(record)
    }

    pub(crate) async fn list_projects(
        &self,
        belongs_to: Option<String>,
    ) -> Result<Vec<ProjectRecord>, ApplicationError> {
        let mut query = project::Entity::find();
        if let Some(owner) = belongs_to {
            query = query.filter(project::Column::BelongsTo.eq(owner));
        }
        query
            .order_by_asc(project::Column::CreatedAt)
            .order_by_asc(project::Column::Id)
            .limit(LIST_LIMIT + 1)
            .all(&self.database)
            .await
            .map_err(persistence)
            .and_then(bounded_list)
            .map(|models| models.into_iter().map(project_record).collect())
    }

    pub(crate) async fn get_project(
        &self,
        project_id: Uuid,
    ) -> Result<ProjectRecord, ApplicationError> {
        let model = project::Entity::find_by_id(project_id)
            .one(&self.database)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        Ok(project_record(model))
    }

    pub(crate) async fn get_project_policy(
        &self,
        project_id: Uuid,
    ) -> Result<ProjectPolicyRecord, ApplicationError> {
        ensure_project(&self.database, project_id).await?;
        let policy = project_policy::Entity::find_by_id(project_id)
            .one(&self.database)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        project_policy_record(&policy)
    }

    pub(crate) async fn update_project_policy(
        &self,
        project_id: Uuid,
        command: UpdateProjectPolicy,
        correlation_id: Uuid,
    ) -> Result<ProjectPolicyRecord, ApplicationError> {
        let transaction = self.database.begin().await.map_err(persistence)?;
        active_project(&transaction, project_id).await?;
        let policy = project_policy::Entity::find_by_id(project_id)
            .lock_exclusive()
            .one(&transaction)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        if policy.claims_revision != command.expected_claims_revision
            || policy.session_revision != command.expected_session_revision
        {
            return Err(ApplicationError::RevisionConflict);
        }
        let browser_session_reuse_max_age_seconds = policy
            .session_policy
            .get("browser_session_reuse_max_age_seconds")
            .and_then(Value::as_i64)
            .filter(|value| (0..=86_400).contains(value))
            .ok_or(ApplicationError::Integrity)?;
        let mut active = policy.into_active_model();
        active.claims_policy = Set(json!({
            "access_token_lifetime_seconds": command.access_token_lifetime_seconds,
        }));
        active.session_policy = Set(json!({
            "browser_session_reuse": command.browser_session_reuse,
            "browser_session_reuse_max_age_seconds": browser_session_reuse_max_age_seconds,
        }));
        active.claims_revision = Set(command.expected_claims_revision + 1);
        active.session_revision = Set(command.expected_session_revision + 1);
        let updated = active.update(&transaction).await.map_err(persistence)?;
        insert_audit(
            &transaction,
            Some(project_id),
            "project.policy_updated",
            "project_policy",
            Some(project_id),
            correlation_id,
        )
        .await?;
        transaction.commit().await.map_err(persistence)?;
        project_policy_record(&updated)
    }

    pub(crate) async fn update_project(
        &self,
        project_id: Uuid,
        command: UpdateProject,
        correlation_id: Uuid,
    ) -> Result<ProjectRecord, ApplicationError> {
        let display_name = command.display_name;
        let belongs_to = command.belongs_to;
        let transaction = self.database.begin().await.map_err(persistence)?;
        let model = active_project(&transaction, project_id).await?;
        if model.metadata_revision != command.expected_metadata_revision {
            return Err(ApplicationError::RevisionConflict);
        }
        let mut active = model.into_active_model();
        active.display_name = Set(display_name);
        active.belongs_to = Set(belongs_to);
        active.metadata_revision = Set(command.expected_metadata_revision + 1);
        active.updated_at = Set(self.clock.now());
        let updated = active.update(&transaction).await.map_err(persistence)?;
        insert_audit(
            &transaction,
            Some(project_id),
            "project.metadata_updated",
            "project",
            Some(project_id),
            correlation_id,
        )
        .await?;
        transaction.commit().await.map_err(persistence)?;
        Ok(project_record(updated))
    }

    pub(crate) async fn disable_project(
        &self,
        project_id: Uuid,
        expected_security_revision: i64,
        correlation_id: Uuid,
    ) -> Result<ProjectRecord, ApplicationError> {
        let transaction = self.database.begin().await.map_err(persistence)?;
        let model = active_project(&transaction, project_id).await?;
        if model.security_revision != expected_security_revision {
            return Err(ApplicationError::RevisionConflict);
        }
        let mut status = ProjectStatus::Active;
        status
            .disable()
            .map_err(|_| ApplicationError::InvalidTransition)?;
        let mut active = model.into_active_model();
        active.status = Set(status.as_str().to_owned());
        active.security_revision = Set(expected_security_revision + 1);
        active.updated_at = Set(self.clock.now());
        let updated = active.update(&transaction).await.map_err(persistence)?;
        insert_audit(
            &transaction,
            Some(project_id),
            "project.disabled",
            "project",
            Some(project_id),
            correlation_id,
        )
        .await?;
        transaction.commit().await.map_err(persistence)?;
        Ok(project_record(updated))
    }

    pub(crate) async fn create_application(
        &self,
        project_id: Uuid,
        command: CreateApplication,
        correlation_id: Uuid,
    ) -> Result<ApplicationRecord, ApplicationError> {
        let display_name = command.display_name;
        let digest = self.digester.digest_json(&json!({
            "project_id": project_id,
            "display_name": display_name,
            "application_type": command.application_type.as_str(),
        }))?;
        let scope = project_id.to_string();
        let transaction = self.database.begin().await.map_err(persistence)?;
        lock_idempotency_key(&transaction, &command.idempotency_key).await?;
        active_project(&transaction, project_id).await?;
        if let Some(replayed) = replay::<ApplicationRecord>(
            &transaction,
            &command.idempotency_key,
            "application.create",
            &scope,
            &digest,
        )
        .await?
        {
            transaction.commit().await.map_err(persistence)?;
            return Ok(replayed);
        }
        ensure_application_capacity(&transaction, project_id, ApplicationError::InvalidInput)
            .await?;
        let id = Uuid::new_v4();
        let public_id = generated_id("app");
        application::ActiveModel {
            id: Set(id),
            project_id: Set(project_id),
            public_id: Set(public_id.clone()),
            display_name: Set(display_name.clone()),
            application_type: Set(command.application_type.as_str().to_owned()),
            status: Set("active".to_owned()),
            revision: Set(1),
            metadata_revision: Set(1),
            security_revision: Set(1),
            projection_revision: Set(1),
            ..Default::default()
        }
        .insert(&transaction)
        .await
        .map_err(persistence)?;
        let publishable_id = generated_id("owl_app");
        application_publishable_key::ActiveModel {
            id: Set(Uuid::new_v4()),
            project_id: Set(project_id),
            application_id: Set(id),
            public_id: Set(publishable_id.clone()),
            status: Set("active".to_owned()),
            revision: Set(1),
        }
        .insert(&transaction)
        .await
        .map_err(persistence)?;
        let record = ApplicationRecord {
            id,
            project_id,
            public_id,
            display_name,
            application_type: command.application_type.as_str().to_owned(),
            status: "active".to_owned(),
            metadata_revision: 1,
            security_revision: 1,
            configuration: ApplicationConfiguration {
                redirect_uris: Vec::new(),
                allowed_origins: Vec::new(),
                publishable_keys: vec![publishable_id],
            },
        };
        insert_audit(
            &transaction,
            Some(project_id),
            "application.created",
            "application",
            Some(id),
            correlation_id,
        )
        .await?;
        complete_idempotency(
            &transaction,
            command.idempotency_key,
            Some(project_id),
            Some(id),
            "application.create",
            &scope,
            digest,
            &record,
        )
        .await?;
        transaction.commit().await.map_err(persistence)?;
        Ok(record)
    }

    pub(crate) async fn list_applications(
        &self,
        project_id: Uuid,
    ) -> Result<Vec<ApplicationRecord>, ApplicationError> {
        ensure_project(&self.database, project_id).await?;
        let models = application::Entity::find()
            .filter(application::Column::ProjectId.eq(project_id))
            .order_by_asc(application::Column::CreatedAt)
            .order_by_asc(application::Column::Id)
            .limit(LIST_LIMIT + 1)
            .all(&self.database)
            .await
            .map_err(persistence)?;
        let models = bounded_list(models)?;
        let mut records = Vec::with_capacity(models.len());
        for model in models {
            records.push(self.application_record(model).await?);
        }
        Ok(records)
    }

    pub(crate) async fn get_application(
        &self,
        project_id: Uuid,
        application_id: Uuid,
    ) -> Result<ApplicationRecord, ApplicationError> {
        let model = find_application(&self.database, project_id, application_id).await?;
        self.application_record(model).await
    }

    pub(crate) async fn update_application(
        &self,
        project_id: Uuid,
        application_id: Uuid,
        command: UpdateApplication,
        correlation_id: Uuid,
    ) -> Result<ApplicationRecord, ApplicationError> {
        let display_name = command.display_name;
        let transaction = self.database.begin().await.map_err(persistence)?;
        active_project(&transaction, project_id).await?;
        let model = active_application(&transaction, project_id, application_id).await?;
        if model.metadata_revision != command.expected_metadata_revision {
            return Err(ApplicationError::RevisionConflict);
        }
        let aggregate_revision = model.revision + 1;
        let mut active = model.into_active_model();
        active.display_name = Set(display_name);
        active.metadata_revision = Set(command.expected_metadata_revision + 1);
        active.revision = Set(aggregate_revision);
        active.updated_at = Set(self.clock.now());
        let updated = active.update(&transaction).await.map_err(persistence)?;
        insert_audit(
            &transaction,
            Some(project_id),
            "application.metadata_updated",
            "application",
            Some(application_id),
            correlation_id,
        )
        .await?;
        transaction.commit().await.map_err(persistence)?;
        self.application_record(updated).await
    }

    pub(crate) async fn replace_application_configuration(
        &self,
        project_id: Uuid,
        application_id: Uuid,
        command: ReplaceApplicationConfiguration,
        correlation_id: Uuid,
    ) -> Result<ApplicationRecord, ApplicationError> {
        if command.redirect_uris.len() > CONFIGURATION_VALUE_LIMIT
            || command.allowed_origins.len() > CONFIGURATION_VALUE_LIMIT
        {
            return Err(ApplicationError::InvalidInput);
        }
        let model = find_application(&self.database, project_id, application_id).await?;
        if model.status != "active" {
            return Err(ApplicationError::Disabled);
        }
        let application_type = parse_application_type(&model.application_type)?;
        let redirects = command
            .redirect_uris
            .into_iter()
            .map(|value| RedirectUri::parse(value, application_type))
            .collect::<Result<Vec<_>, _>>()?;
        let origins = command
            .allowed_origins
            .into_iter()
            .map(BrowserOrigin::parse)
            .collect::<Result<Vec<_>, _>>()?;
        reject_duplicates(redirects.iter().map(|value| value.clone().into_parts().0))?;
        reject_duplicates(origins.iter().map(|value| value.clone().into_inner()))?;

        let transaction = self.database.begin().await.map_err(persistence)?;
        active_project(&transaction, project_id).await?;
        let current = active_application(&transaction, project_id, application_id).await?;
        if current.security_revision != command.expected_security_revision {
            return Err(ApplicationError::RevisionConflict);
        }
        application_redirect::Entity::delete_many()
            .filter(application_redirect::Column::ProjectId.eq(project_id))
            .filter(application_redirect::Column::ApplicationId.eq(application_id))
            .exec(&transaction)
            .await
            .map_err(persistence)?;
        application_origin::Entity::delete_many()
            .filter(application_origin::Column::ProjectId.eq(project_id))
            .filter(application_origin::Column::ApplicationId.eq(application_id))
            .exec(&transaction)
            .await
            .map_err(persistence)?;
        for redirect in redirects {
            let (uri, kind) = redirect.into_parts();
            application_redirect::ActiveModel {
                project_id: Set(project_id),
                application_id: Set(application_id),
                redirect_uri: Set(uri),
                redirect_type: Set(kind.as_str().to_owned()),
            }
            .insert(&transaction)
            .await
            .map_err(persistence)?;
        }
        for origin in origins {
            application_origin::ActiveModel {
                project_id: Set(project_id),
                application_id: Set(application_id),
                origin: Set(origin.into_inner()),
            }
            .insert(&transaction)
            .await
            .map_err(persistence)?;
        }
        let aggregate_revision = current.revision + 1;
        let mut active = current.into_active_model();
        active.security_revision = Set(command.expected_security_revision + 1);
        active.revision = Set(aggregate_revision);
        active.updated_at = Set(self.clock.now());
        active.update(&transaction).await.map_err(persistence)?;
        insert_audit(
            &transaction,
            Some(project_id),
            "application.configuration_replaced",
            "application",
            Some(application_id),
            correlation_id,
        )
        .await?;
        transaction.commit().await.map_err(persistence)?;
        self.get_application(project_id, application_id).await
    }

    pub(crate) async fn disable_application(
        &self,
        project_id: Uuid,
        application_id: Uuid,
        expected_security_revision: i64,
        correlation_id: Uuid,
    ) -> Result<ApplicationRecord, ApplicationError> {
        let transaction = self.database.begin().await.map_err(persistence)?;
        active_project(&transaction, project_id).await?;
        let model = active_application(&transaction, project_id, application_id).await?;
        if model.security_revision != expected_security_revision {
            return Err(ApplicationError::RevisionConflict);
        }
        let mut status = ApplicationStatus::Active;
        status
            .disable()
            .map_err(|_| ApplicationError::InvalidTransition)?;
        let aggregate_revision = model.revision + 1;
        let next_security_revision = expected_security_revision + 1;
        let assignments = application_provider_assignment::Entity::find()
            .filter(application_provider_assignment::Column::ProjectId.eq(project_id))
            .filter(application_provider_assignment::Column::ApplicationId.eq(application_id))
            .filter(application_provider_assignment::Column::Status.eq("active"))
            .order_by_asc(application_provider_assignment::Column::ProviderId)
            .lock_exclusive()
            .all(&transaction)
            .await
            .map_err(persistence)?;
        for assignment in assignments {
            let provider =
                active_provider(&transaction, project_id, assignment.provider_id).await?;
            bump_provider_revision(&transaction, provider).await?;
            let mut active = assignment.into_active_model();
            active.status = Set("disabled".to_owned());
            active.security_revision = Set(next_security_revision);
            active.update(&transaction).await.map_err(persistence)?;
        }
        let publishable_keys = application_publishable_key::Entity::find()
            .filter(application_publishable_key::Column::ProjectId.eq(project_id))
            .filter(application_publishable_key::Column::ApplicationId.eq(application_id))
            .filter(application_publishable_key::Column::Status.eq("active"))
            .order_by_asc(application_publishable_key::Column::Id)
            .lock_exclusive()
            .all(&transaction)
            .await
            .map_err(persistence)?;
        for publishable_key in publishable_keys {
            let next_key_revision = publishable_key.revision + 1;
            let mut active = publishable_key.into_active_model();
            active.status = Set("disabled".to_owned());
            active.revision = Set(next_key_revision);
            active.update(&transaction).await.map_err(persistence)?;
        }
        let mut active = model.into_active_model();
        active.status = Set(status.as_str().to_owned());
        active.security_revision = Set(next_security_revision);
        active.revision = Set(aggregate_revision);
        active.updated_at = Set(self.clock.now());
        active.update(&transaction).await.map_err(persistence)?;
        insert_audit(
            &transaction,
            Some(project_id),
            "application.disabled",
            "application",
            Some(application_id),
            correlation_id,
        )
        .await?;
        transaction.commit().await.map_err(persistence)?;
        self.get_application(project_id, application_id).await
    }

    async fn application_record(
        &self,
        model: application::Model,
    ) -> Result<ApplicationRecord, ApplicationError> {
        let redirects = application_redirect::Entity::find()
            .filter(application_redirect::Column::ProjectId.eq(model.project_id))
            .filter(application_redirect::Column::ApplicationId.eq(model.id))
            .order_by_asc(application_redirect::Column::RedirectUri)
            .limit((CONFIGURATION_VALUE_LIMIT + 1) as u64)
            .all(&self.database)
            .await
            .map_err(persistence)?;
        let redirects = bounded_items(redirects, CONFIGURATION_VALUE_LIMIT)?
            .into_iter()
            .map(|value| value.redirect_uri)
            .collect();
        let origins = application_origin::Entity::find()
            .filter(application_origin::Column::ProjectId.eq(model.project_id))
            .filter(application_origin::Column::ApplicationId.eq(model.id))
            .order_by_asc(application_origin::Column::Origin)
            .limit((CONFIGURATION_VALUE_LIMIT + 1) as u64)
            .all(&self.database)
            .await
            .map_err(persistence)?;
        let origins = bounded_items(origins, CONFIGURATION_VALUE_LIMIT)?
            .into_iter()
            .map(|value| value.origin)
            .collect();
        let publishable_keys = application_publishable_key::Entity::find()
            .filter(application_publishable_key::Column::ProjectId.eq(model.project_id))
            .filter(application_publishable_key::Column::ApplicationId.eq(model.id))
            .filter(application_publishable_key::Column::Status.eq("active"))
            .order_by_asc(application_publishable_key::Column::PublicId)
            .limit((CONFIGURATION_VALUE_LIMIT + 1) as u64)
            .all(&self.database)
            .await
            .map_err(persistence)?;
        let publishable_keys = bounded_items(publishable_keys, CONFIGURATION_VALUE_LIMIT)?
            .into_iter()
            .map(|value| value.public_id)
            .collect();
        Ok(ApplicationRecord {
            id: model.id,
            project_id: model.project_id,
            public_id: model.public_id,
            display_name: model.display_name,
            application_type: model.application_type,
            status: model.status,
            metadata_revision: model.metadata_revision,
            security_revision: model.security_revision,
            configuration: ApplicationConfiguration {
                redirect_uris: redirects,
                allowed_origins: origins,
                publishable_keys,
            },
        })
    }

    async fn find_or_create_signing_ring(
        &self,
        transaction: &DatabaseTransaction,
        project: &project::Model,
    ) -> Result<project_key_ring::Model, ApplicationError> {
        let issuer = self
            .runtime_base
            .join(&format!("projects/{}/", project.public_id))
            .map_err(|_| ApplicationError::InvalidInput)?
            .to_string();
        if let Some(ring) = project_key_ring::Entity::find()
            .filter(project_key_ring::Column::ProjectId.eq(project.id))
            .filter(project_key_ring::Column::Issuer.eq(&issuer))
            .filter(project_key_ring::Column::Purpose.eq(SIGNING_PURPOSE))
            .filter(project_key_ring::Column::Algorithm.eq(SIGNING_ALGORITHM))
            .one(transaction)
            .await
            .map_err(persistence)?
        {
            return Ok(ring);
        }
        project_key_ring::ActiveModel {
            id: Set(Uuid::new_v4()),
            project_id: Set(project.id),
            issuer: Set(issuer),
            purpose: Set(SIGNING_PURPOSE.to_owned()),
            algorithm: Set(SIGNING_ALGORITHM.to_owned()),
            revision: Set(1),
            signing_epoch: Set(1),
        }
        .insert(transaction)
        .await
        .map_err(persistence)
    }

    async fn prepare_signing_key_models(
        &self,
        project_id: Uuid,
        operation_alias: String,
        signer_ref: String,
        expected_project_revision: i64,
        digest: Vec<u8>,
    ) -> Result<
        (
            project_key_ring::Model,
            project_signing_key::Model,
            key_provisioning_operation::Model,
        ),
        ApplicationError,
    > {
        let transaction = self.database.begin().await.map_err(persistence)?;
        let project = locked_project(&transaction, project_id).await?;
        if let Some(operation) = key_provisioning_operation::Entity::find()
            .filter(key_provisioning_operation::Column::ProjectId.eq(project_id))
            .filter(key_provisioning_operation::Column::OperationAlias.eq(&operation_alias))
            .lock_exclusive()
            .one(&transaction)
            .await
            .map_err(persistence)?
        {
            if operation.request_digest.as_slice() != digest.as_slice() {
                return Err(ApplicationError::IdempotencyConflict);
            }
            let operation = if requires_project_reauthorization(
                &project,
                &operation.state,
                operation.expected_project_revision,
                expected_project_revision,
            )? {
                let mut active = operation.into_active_model();
                active.expected_project_revision = Set(expected_project_revision);
                active.update(&transaction).await.map_err(persistence)?
            } else {
                operation
            };
            let ring = project_key_ring::Entity::find_by_id(operation.ring_id)
                .filter(project_key_ring::Column::ProjectId.eq(project_id))
                .one(&transaction)
                .await
                .map_err(persistence)?
                .ok_or(ApplicationError::NotFound)?;
            let key = project_signing_key::Entity::find_by_id(operation.key_id)
                .filter(project_signing_key::Column::ProjectId.eq(project_id))
                .one(&transaction)
                .await
                .map_err(persistence)?
                .ok_or(ApplicationError::NotFound)?;
            transaction.commit().await.map_err(persistence)?;
            return Ok((ring, key, operation));
        }
        if project.status != "active" {
            return Err(ApplicationError::Disabled);
        }
        if project.metadata_revision != expected_project_revision {
            return Err(ApplicationError::RevisionConflict);
        }
        let keys = project_signing_key::Entity::find()
            .filter(project_signing_key::Column::ProjectId.eq(project_id))
            .limit(LIST_LIMIT + 1)
            .all(&transaction)
            .await
            .map_err(persistence)?;
        ensure_capacity(keys.len(), LIST_LIMIT, ApplicationError::InvalidInput)?;
        let ring = self
            .find_or_create_signing_ring(&transaction, &project)
            .await?;
        let key = project_signing_key::ActiveModel {
            id: Set(Uuid::new_v4()),
            project_id: Set(project_id),
            ring_id: Set(ring.id),
            kid: Set(generated_id("kid")),
            public_jwk: Set(json!({})),
            signer_ref: Set(signer_ref),
            state: Set(SigningKeyState::Provisioning.as_str().to_owned()),
            ring_revision: Set(ring.revision),
            ..Default::default()
        }
        .insert(&transaction)
        .await
        .map_err(persistence)?;
        let operation = key_provisioning_operation::ActiveModel {
            id: Set(Uuid::new_v4()),
            project_id: Set(project_id),
            ring_id: Set(ring.id),
            key_id: Set(key.id),
            operation_alias: Set(operation_alias),
            request_digest: Set(digest),
            state: Set("prepared".to_owned()),
            attempt_count: Set(0),
            expected_project_revision: Set(expected_project_revision),
            expected_ring_revision: Set(ring.revision),
            last_attempt_at: Set(None),
            completed_at: Set(None),
        }
        .insert(&transaction)
        .await
        .map_err(persistence)?;
        transaction.commit().await.map_err(persistence)?;
        Ok((ring, key, operation))
    }

    async fn prepare_signing_key_stage(
        &self,
        project_id: Uuid,
        operation_alias: String,
        signer_ref: String,
        expected_project_revision: i64,
        request_digest: Vec<u8>,
    ) -> Result<PreparedSigningKey, ApplicationError> {
        let (_, key, operation) = self
            .prepare_signing_key_models(
                project_id,
                operation_alias,
                signer_ref,
                expected_project_revision,
                request_digest,
            )
            .await?;
        prepared_signing_key(key, operation)
    }

    async fn record_signing_key_material_stage(
        &self,
        project_id: Uuid,
        prepared: &PreparedSigningKey,
        expected_project_revision: i64,
        public_jwk: Value,
        recorded_at: OffsetDateTime,
    ) -> Result<(), ApplicationError> {
        let transaction = self.database.begin().await.map_err(persistence)?;
        let project = locked_project(&transaction, project_id).await?;
        let operation = key_provisioning_operation::Entity::find_by_id(prepared.operation_id)
            .filter(key_provisioning_operation::Column::ProjectId.eq(project_id))
            .lock_exclusive()
            .one(&transaction)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        if operation.key_id != prepared.key_id
            || operation.ring_id != prepared.ring_id
            || operation.request_digest != prepared.request_digest
        {
            return Err(ApplicationError::Integrity);
        }
        if operation.state == "completed" {
            transaction.commit().await.map_err(persistence)?;
            return Ok(());
        }
        enforce_project_fence(&project, expected_project_revision)?;
        if operation.expected_project_revision != expected_project_revision {
            return Err(ApplicationError::Integrity);
        }
        if !matches!(operation.state.as_str(), "prepared" | "stored") {
            return Err(ApplicationError::InvalidTransition);
        }
        let key = project_signing_key::Entity::find_by_id(prepared.key_id)
            .filter(project_signing_key::Column::ProjectId.eq(project_id))
            .filter(project_signing_key::Column::RingId.eq(prepared.ring_id))
            .lock_exclusive()
            .one(&transaction)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        if key.state != SigningKeyState::Provisioning.as_str()
            || key.signer_ref != prepared.signer_ref
            || key.kid != prepared.kid
        {
            return Err(ApplicationError::InvalidTransition);
        }
        let mut key_active = key.into_active_model();
        key_active.public_jwk = Set(public_jwk);
        key_active.provisioned_at = Set(Some(recorded_at));
        key_active.updated_at = Set(recorded_at);
        key_active.update(&transaction).await.map_err(persistence)?;
        let mut operation_active = operation.into_active_model();
        operation_active.state = Set("stored".to_owned());
        operation_active.attempt_count =
            Set(operation_active.attempt_count.take().unwrap_or(0) + 1);
        operation_active.last_attempt_at = Set(Some(recorded_at));
        operation_active
            .update(&transaction)
            .await
            .map_err(persistence)?;
        transaction.commit().await.map_err(persistence)
    }

    async fn publish_signing_key_stage(
        &self,
        project_id: Uuid,
        prepared: &PreparedSigningKey,
        expected_project_revision: i64,
        correlation_id: Uuid,
        published_at: OffsetDateTime,
    ) -> Result<SigningKeyRecord, ApplicationError> {
        let transaction = self.database.begin().await.map_err(persistence)?;
        let project = locked_project(&transaction, project_id).await?;
        let operation = key_provisioning_operation::Entity::find_by_id(prepared.operation_id)
            .filter(key_provisioning_operation::Column::ProjectId.eq(project_id))
            .lock_exclusive()
            .one(&transaction)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        if operation.key_id != prepared.key_id
            || operation.ring_id != prepared.ring_id
            || operation.request_digest != prepared.request_digest
        {
            return Err(ApplicationError::Integrity);
        }
        if operation.state == "completed" {
            transaction.commit().await.map_err(persistence)?;
            return self.get_signing_key(project_id, prepared.key_id).await;
        }
        enforce_project_fence(&project, expected_project_revision)?;
        if operation.expected_project_revision != expected_project_revision {
            return Err(ApplicationError::Integrity);
        }
        let ring = project_key_ring::Entity::find_by_id(prepared.ring_id)
            .filter(project_key_ring::Column::ProjectId.eq(project_id))
            .lock_exclusive()
            .one(&transaction)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        let key = project_signing_key::Entity::find_by_id(prepared.key_id)
            .filter(project_signing_key::Column::ProjectId.eq(project_id))
            .filter(project_signing_key::Column::RingId.eq(prepared.ring_id))
            .lock_exclusive()
            .one(&transaction)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        if operation.state != "stored"
            || key.state != SigningKeyState::Provisioning.as_str()
            || key.signer_ref != prepared.signer_ref
            || key.kid != prepared.kid
        {
            return Err(ApplicationError::InvalidTransition);
        }
        ensure_publishable_signing_key_capacity(&transaction, project_id).await?;
        let next_revision = ring.revision + 1;
        let mut key_active = key.into_active_model();
        key_active.state = Set(SigningKeyState::Published.as_str().to_owned());
        key_active.ring_revision = Set(next_revision);
        key_active.published_at = Set(Some(published_at));
        key_active.updated_at = Set(published_at);
        let published = key_active.update(&transaction).await.map_err(persistence)?;
        let mut ring_active = ring.into_active_model();
        ring_active.revision = Set(next_revision);
        ring_active
            .update(&transaction)
            .await
            .map_err(persistence)?;
        let mut operation_active = operation.into_active_model();
        operation_active.state = Set("completed".to_owned());
        operation_active.completed_at = Set(Some(published_at));
        operation_active
            .update(&transaction)
            .await
            .map_err(persistence)?;
        insert_key_state_event(
            &transaction,
            project_id,
            prepared.ring_id,
            prepared.key_id,
            next_revision,
            SigningKeyState::Provisioning,
            SigningKeyState::Published,
            published_at,
        )
        .await?;
        insert_audit(
            &transaction,
            Some(project_id),
            "signing_key.published",
            "signing_key",
            Some(prepared.key_id),
            correlation_id,
        )
        .await?;
        transaction.commit().await.map_err(persistence)?;
        signing_key_record(&self.database, published).await
    }

    pub(crate) async fn list_signing_keys(
        &self,
        project_id: Uuid,
    ) -> Result<Vec<SigningKeyRecord>, ApplicationError> {
        ensure_project(&self.database, project_id).await?;
        let keys = project_signing_key::Entity::find()
            .filter(project_signing_key::Column::ProjectId.eq(project_id))
            .order_by_asc(project_signing_key::Column::CreatedAt)
            .limit(LIST_LIMIT + 1)
            .all(&self.database)
            .await
            .map_err(persistence)?;
        let keys = bounded_list(keys)?;
        let mut records = Vec::with_capacity(keys.len());
        for key in keys {
            records.push(signing_key_record(&self.database, key).await?);
        }
        Ok(records)
    }

    async fn signing_key_recovery_stage(
        &self,
        project_id: Uuid,
        key_id: Uuid,
    ) -> Result<SigningKeyRecovery, ApplicationError> {
        let transaction = self.database.begin().await.map_err(persistence)?;
        active_project(&transaction, project_id).await?;
        let key = find_signing_key(&transaction, project_id, key_id).await?;
        let operation = key_provisioning_operation::Entity::find()
            .filter(key_provisioning_operation::Column::ProjectId.eq(project_id))
            .filter(key_provisioning_operation::Column::KeyId.eq(key_id))
            .lock_exclusive()
            .one(&transaction)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::InvalidTransition)?;
        match operation.state.as_str() {
            "prepared" | "stored"
                if parse_signing_state(&key.state)? == SigningKeyState::Provisioning => {}
            "completed" => {}
            _ => return Err(ApplicationError::InvalidTransition),
        }
        transaction.commit().await.map_err(persistence)?;
        Ok(SigningKeyRecovery {
            operation_alias: operation.operation_alias,
        })
    }

    async fn signing_key_activation_candidate_stage(
        &self,
        project_id: Uuid,
        key_id: Uuid,
    ) -> Result<SigningKeyActivationCandidate, ApplicationError> {
        let candidate = find_signing_key(&self.database, project_id, key_id).await?;
        if candidate.state != SigningKeyState::Published.as_str()
            || candidate.published_at.is_none()
        {
            return Err(ApplicationError::InvalidTransition);
        }
        Ok(SigningKeyActivationCandidate {
            kid: candidate.kid,
            signer_ref: candidate.signer_ref,
            public_jwk: candidate.public_jwk,
        })
    }

    #[allow(
        clippy::too_many_lines,
        reason = "activation validates publication leases and rotates the key ring atomically"
    )]
    pub(crate) async fn activate_signing_key_if_ready(
        &self,
        project_id: Uuid,
        key_id: Uuid,
        expected_ring_revision: i64,
        correlation_id: Uuid,
    ) -> Result<SigningKeyRecord, ApplicationError> {
        let candidate = find_signing_key(&self.database, project_id, key_id).await?;
        let transaction = self.database.begin().await.map_err(persistence)?;
        active_project(&transaction, project_id).await?;
        let ring = project_key_ring::Entity::find_by_id(candidate.ring_id)
            .filter(project_key_ring::Column::ProjectId.eq(project_id))
            .lock_exclusive()
            .one(&transaction)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        if ring.revision != expected_ring_revision {
            return Err(ApplicationError::RevisionConflict);
        }
        let candidate = project_signing_key::Entity::find_by_id(key_id)
            .filter(project_signing_key::Column::ProjectId.eq(project_id))
            .filter(project_signing_key::Column::RingId.eq(ring.id))
            .lock_exclusive()
            .one(&transaction)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        if candidate.state != SigningKeyState::Published.as_str()
            || candidate.published_at.is_none()
        {
            return Err(ApplicationError::InvalidTransition);
        }
        let now = database_now(&transaction).await?;
        if self.required_runtime_process_ids.is_empty() {
            return Err(ApplicationError::PublicationPending);
        }
        let minimum_observation = now - self.propagation_delay;
        let current_leases = runtime_publication_lease::Entity::find()
            .filter(runtime_publication_lease::Column::ProjectId.eq(project_id))
            .filter(runtime_publication_lease::Column::RingId.eq(ring.id))
            .filter(runtime_publication_lease::Column::ExpiresAt.gt(now))
            .lock_shared()
            .all(&transaction)
            .await
            .map_err(persistence)?;
        let required_roster_present = self.required_runtime_process_ids.iter().all(|process_id| {
            current_leases
                .iter()
                .any(|lease| &lease.process_id == process_id)
        });
        let every_live_process_qualified = current_leases.iter().all(|lease| {
            lease.loaded_revision >= candidate.ring_revision
                && lease.first_observed_at <= minimum_observation
        });
        if current_leases.is_empty() || !required_roster_present || !every_live_process_qualified {
            return Err(ApplicationError::PublicationPending);
        }

        let next_revision = ring.revision + 1;
        if let Some(old) = project_signing_key::Entity::find()
            .filter(project_signing_key::Column::ProjectId.eq(project_id))
            .filter(project_signing_key::Column::RingId.eq(ring.id))
            .filter(project_signing_key::Column::State.eq(SigningKeyState::Active.as_str()))
            .lock_exclusive()
            .one(&transaction)
            .await
            .map_err(persistence)?
        {
            let maximum_token_lifetime = Duration::from_secs(
                u64::try_from(MAX_ACCESS_TOKEN_LIFETIME_SECONDS)
                    .expect("the access-token lifetime maximum is positive"),
            );
            let retention = maximum_token_lifetime
                .checked_add(self.verification_retention)
                .and_then(|retention| retention.checked_add(self.propagation_delay))
                .ok_or(ApplicationError::InvalidInput)?;
            let retention =
                time::Duration::try_from(retention).map_err(|_| ApplicationError::InvalidInput)?;
            let old_id = old.id;
            let mut old_active = old.into_active_model();
            old_active.state = Set(SigningKeyState::Retiring.as_str().to_owned());
            old_active.ring_revision = Set(next_revision);
            old_active.retiring_at = Set(Some(now));
            old_active.verify_not_after = Set(Some(now + retention));
            old_active.updated_at = Set(now);
            old_active.update(&transaction).await.map_err(persistence)?;
            insert_key_state_event(
                &transaction,
                project_id,
                ring.id,
                old_id,
                next_revision,
                SigningKeyState::Active,
                SigningKeyState::Retiring,
                now,
            )
            .await?;
        }

        let mut candidate_active = candidate.into_active_model();
        candidate_active.state = Set(SigningKeyState::Active.as_str().to_owned());
        candidate_active.ring_revision = Set(next_revision);
        candidate_active.activated_at = Set(Some(now));
        candidate_active.sign_not_before = Set(Some(now));
        candidate_active.updated_at = Set(now);
        let updated = candidate_active
            .update(&transaction)
            .await
            .map_err(persistence)?;
        insert_key_state_event(
            &transaction,
            project_id,
            ring.id,
            key_id,
            next_revision,
            SigningKeyState::Published,
            SigningKeyState::Active,
            now,
        )
        .await?;
        let mut ring_active = ring.into_active_model();
        ring_active.revision = Set(next_revision);
        ring_active.signing_epoch = Set(ring_active.signing_epoch.take().unwrap_or(1) + 1);
        ring_active
            .update(&transaction)
            .await
            .map_err(persistence)?;
        insert_audit(
            &transaction,
            Some(project_id),
            "signing_key.activated",
            "signing_key",
            Some(key_id),
            correlation_id,
        )
        .await?;
        transaction.commit().await.map_err(persistence)?;
        signing_key_record(&self.database, updated).await
    }

    pub(crate) async fn retire_signing_key(
        &self,
        project_id: Uuid,
        key_id: Uuid,
        expected_ring_revision: i64,
        correlation_id: Uuid,
    ) -> Result<SigningKeyRecord, ApplicationError> {
        let current = find_signing_key(&self.database, project_id, key_id).await?;
        if parse_signing_state(&current.state)? != SigningKeyState::Retiring {
            return Err(ApplicationError::InvalidTransition);
        }
        self.transition_signing_key(
            project_id,
            key_id,
            expected_ring_revision,
            SigningKeyState::Retired,
            "signing_key.retired",
            correlation_id,
        )
        .await
    }

    pub(crate) async fn revoke_signing_key(
        &self,
        project_id: Uuid,
        key_id: Uuid,
        expected_ring_revision: i64,
        correlation_id: Uuid,
    ) -> Result<SigningKeyRecord, ApplicationError> {
        self.transition_signing_key(
            project_id,
            key_id,
            expected_ring_revision,
            SigningKeyState::Revoked,
            "signing_key.revoked",
            correlation_id,
        )
        .await
    }

    async fn transition_signing_key(
        &self,
        project_id: Uuid,
        key_id: Uuid,
        expected_ring_revision: i64,
        target: SigningKeyState,
        audit_action: &str,
        correlation_id: Uuid,
    ) -> Result<SigningKeyRecord, ApplicationError> {
        let transaction = self.database.begin().await.map_err(persistence)?;
        active_project(&transaction, project_id).await?;
        let key = find_signing_key(&transaction, project_id, key_id).await?;
        let ring = project_key_ring::Entity::find_by_id(key.ring_id)
            .filter(project_key_ring::Column::ProjectId.eq(project_id))
            .lock_exclusive()
            .one(&transaction)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        if ring.revision != expected_ring_revision {
            return Err(ApplicationError::RevisionConflict);
        }
        let key = project_signing_key::Entity::find_by_id(key_id)
            .filter(project_signing_key::Column::ProjectId.eq(project_id))
            .filter(project_signing_key::Column::RingId.eq(ring.id))
            .lock_exclusive()
            .one(&transaction)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        let current = parse_signing_state(&key.state)?;
        let target = if target == SigningKeyState::Revoked
            && current == SigningKeyState::Provisioning
            && key.public_jwk == json!({})
        {
            SigningKeyState::Abandoned
        } else {
            target
        };
        let audit_action = if target == SigningKeyState::Abandoned {
            "signing_key.abandoned"
        } else {
            audit_action
        };
        let now = database_now(&transaction).await?;
        if target == SigningKeyState::Retired {
            if current != SigningKeyState::Retiring
                || key.verify_not_after.is_none_or(|cutoff| cutoff > now)
            {
                return Err(ApplicationError::InvalidTransition);
            }
        } else {
            let mut state = current;
            state
                .transition(target)
                .map_err(|_| ApplicationError::InvalidTransition)?;
        }
        if target == SigningKeyState::Abandoned {
            abandon_signing_key_operation(&transaction, project_id, key_id).await?;
        }
        let next_revision = ring.revision + 1;
        let mut key_active = key.into_active_model();
        key_active.state = Set(target.as_str().to_owned());
        key_active.ring_revision = Set(next_revision);
        key_active.updated_at = Set(now);
        match target {
            SigningKeyState::Active => key_active.activated_at = Set(Some(now)),
            SigningKeyState::Retiring => key_active.retiring_at = Set(Some(now)),
            SigningKeyState::Retired => key_active.retired_at = Set(Some(now)),
            SigningKeyState::Revoked => key_active.revoked_at = Set(Some(now)),
            _ => {}
        }
        let updated = key_active.update(&transaction).await.map_err(persistence)?;
        insert_key_state_event(
            &transaction,
            project_id,
            ring.id,
            key_id,
            next_revision,
            current,
            target,
            now,
        )
        .await?;
        let mut ring_active = ring.into_active_model();
        ring_active.revision = Set(next_revision);
        ring_active.signing_epoch = Set(ring_active.signing_epoch.take().unwrap_or(1) + 1);
        ring_active
            .update(&transaction)
            .await
            .map_err(persistence)?;
        insert_audit(
            &transaction,
            Some(project_id),
            audit_action,
            "signing_key",
            Some(key_id),
            correlation_id,
        )
        .await?;
        transaction.commit().await.map_err(persistence)?;
        signing_key_record(&self.database, updated).await
    }

    async fn prepare_provider_stage(
        &self,
        project_id: Uuid,
        command: PrepareProvider,
    ) -> Result<PreparedProvider, ApplicationError> {
        let transaction = self.database.begin().await.map_err(persistence)?;
        let project = locked_project(&transaction, project_id).await?;
        if let Some(operation) = provider_secret_operation::Entity::find()
            .filter(provider_secret_operation::Column::ProjectId.eq(project_id))
            .filter(provider_secret_operation::Column::OperationAlias.eq(&command.operation_alias))
            .lock_exclusive()
            .one(&transaction)
            .await
            .map_err(persistence)?
        {
            if operation.request_digest.as_slice() != command.request_digest.as_slice() {
                return Err(ApplicationError::IdempotencyConflict);
            }
            let operation = if requires_project_reauthorization(
                &project,
                &operation.state,
                operation.expected_project_revision,
                command.expected_project_revision,
            )? {
                let mut active = operation.into_active_model();
                active.expected_project_revision = Set(command.expected_project_revision);
                active.update(&transaction).await.map_err(persistence)?
            } else {
                operation
            };
            provider_configuration::Entity::find_by_id(operation.provider_id)
                .filter(provider_configuration::Column::ProjectId.eq(project_id))
                .one(&transaction)
                .await
                .map_err(persistence)?
                .ok_or(ApplicationError::NotFound)?;
            transaction.commit().await.map_err(persistence)?;
            return prepared_provider(operation);
        }
        if project.status != "active" {
            return Err(ApplicationError::Disabled);
        }
        if project.metadata_revision != command.expected_project_revision {
            return Err(ApplicationError::RevisionConflict);
        }
        let providers = provider_configuration::Entity::find()
            .filter(provider_configuration::Column::ProjectId.eq(project_id))
            .limit(LIST_LIMIT + 1)
            .all(&transaction)
            .await
            .map_err(persistence)?;
        ensure_capacity(providers.len(), LIST_LIMIT, ApplicationError::InvalidInput)?;
        let callback_url = self
            .runtime_base
            .join(&format!(
                "projects/{}/auth/callback/{}",
                project.public_id, command.provider_key
            ))
            .map_err(|_| ApplicationError::InvalidInput)?
            .to_string();
        let provider = provider_configuration::ActiveModel {
            id: Set(Uuid::new_v4()),
            project_id: Set(project_id),
            provider_key: Set(command.provider_key),
            kind: Set("oidc".to_owned()),
            display_name: Set(command.display_name),
            issuer: Set(command.issuer),
            client_id: Set(command.client_id),
            callback_url: Set(callback_url),
            secret_ref: Set(None),
            status: Set("provisioning".to_owned()),
            revision: Set(1),
        }
        .insert(&transaction)
        .await
        .map_err(persistence)?;
        let operation = provider_secret_operation::ActiveModel {
            id: Set(Uuid::new_v4()),
            project_id: Set(project_id),
            provider_id: Set(provider.id),
            operation_alias: Set(command.operation_alias),
            request_digest: Set(command.request_digest),
            state: Set("prepared".to_owned()),
            attempt_count: Set(0),
            expected_project_revision: Set(command.expected_project_revision),
            expected_provider_revision: Set(1),
            last_attempt_at: Set(None),
            completed_at: Set(None),
        }
        .insert(&transaction)
        .await
        .map_err(persistence)?;
        transaction.commit().await.map_err(persistence)?;
        prepared_provider(operation)
    }

    async fn mark_provider_secret_stored_stage(
        &self,
        project_id: Uuid,
        prepared: &PreparedProvider,
        expected_project_revision: i64,
        stored_at: OffsetDateTime,
    ) -> Result<(), ApplicationError> {
        let transaction = self.database.begin().await.map_err(persistence)?;
        let project = locked_project(&transaction, project_id).await?;
        let operation = provider_secret_operation::Entity::find_by_id(prepared.operation_id)
            .filter(provider_secret_operation::Column::ProjectId.eq(project_id))
            .lock_exclusive()
            .one(&transaction)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        if operation.provider_id != prepared.provider_id
            || operation.request_digest != prepared.request_digest
        {
            return Err(ApplicationError::Integrity);
        }
        if operation.state == "completed" {
            transaction.commit().await.map_err(persistence)?;
            return Ok(());
        }
        enforce_project_fence(&project, expected_project_revision)?;
        if operation.expected_project_revision != expected_project_revision {
            return Err(ApplicationError::Integrity);
        }
        if !matches!(operation.state.as_str(), "prepared" | "stored") {
            return Err(ApplicationError::InvalidTransition);
        }
        let provider = provider_configuration::Entity::find_by_id(prepared.provider_id)
            .filter(provider_configuration::Column::ProjectId.eq(project_id))
            .lock_exclusive()
            .one(&transaction)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        if provider.status != ProviderStatus::Provisioning.as_str()
            || provider.revision != operation.expected_provider_revision
        {
            return Err(ApplicationError::InvalidTransition);
        }
        let mut operation_active = operation.into_active_model();
        operation_active.state = Set("stored".to_owned());
        operation_active.attempt_count =
            Set(operation_active.attempt_count.take().unwrap_or(0) + 1);
        operation_active.last_attempt_at = Set(Some(stored_at));
        operation_active
            .update(&transaction)
            .await
            .map_err(persistence)?;
        transaction.commit().await.map_err(persistence)
    }

    async fn finalize_provider_stage(
        &self,
        project_id: Uuid,
        prepared: &PreparedProvider,
        expected_project_revision: i64,
        secret_ref: String,
        correlation_id: Uuid,
        finalized_at: OffsetDateTime,
    ) -> Result<ProviderRecord, ApplicationError> {
        let transaction = self.database.begin().await.map_err(persistence)?;
        let project = locked_project(&transaction, project_id).await?;
        let operation = provider_secret_operation::Entity::find_by_id(prepared.operation_id)
            .filter(provider_secret_operation::Column::ProjectId.eq(project_id))
            .lock_exclusive()
            .one(&transaction)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        if operation.provider_id != prepared.provider_id
            || operation.request_digest != prepared.request_digest
        {
            return Err(ApplicationError::Integrity);
        }
        if operation.state == "completed" {
            transaction.commit().await.map_err(persistence)?;
            return self.get_provider(project_id, prepared.provider_id).await;
        }
        enforce_project_fence(&project, expected_project_revision)?;
        if operation.expected_project_revision != expected_project_revision {
            return Err(ApplicationError::Integrity);
        }
        let provider = provider_configuration::Entity::find_by_id(prepared.provider_id)
            .filter(provider_configuration::Column::ProjectId.eq(project_id))
            .lock_exclusive()
            .one(&transaction)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        if operation.state != "stored"
            || provider.status != ProviderStatus::Provisioning.as_str()
            || provider.revision != operation.expected_provider_revision
        {
            return Err(ApplicationError::InvalidTransition);
        }
        let mut status = ProviderStatus::Provisioning;
        status
            .provision()
            .map_err(|_| ApplicationError::InvalidTransition)?;
        let mut provider_active = provider.into_active_model();
        provider_active.secret_ref = Set(Some(secret_ref));
        provider_active.status = Set(status.as_str().to_owned());
        provider_active.revision = Set(operation.expected_provider_revision + 1);
        let updated = provider_active
            .update(&transaction)
            .await
            .map_err(persistence)?;
        let mut operation_active = operation.into_active_model();
        operation_active.state = Set("completed".to_owned());
        operation_active.completed_at = Set(Some(finalized_at));
        operation_active
            .update(&transaction)
            .await
            .map_err(persistence)?;
        insert_audit(
            &transaction,
            Some(project_id),
            "provider.configured",
            "provider",
            Some(updated.id),
            correlation_id,
        )
        .await?;
        transaction.commit().await.map_err(persistence)?;
        self.provider_record(updated).await
    }

    pub(crate) async fn list_providers(
        &self,
        project_id: Uuid,
    ) -> Result<Vec<ProviderRecord>, ApplicationError> {
        ensure_project(&self.database, project_id).await?;
        let providers = provider_configuration::Entity::find()
            .filter(provider_configuration::Column::ProjectId.eq(project_id))
            .order_by_asc(provider_configuration::Column::ProviderKey)
            .limit(LIST_LIMIT + 1)
            .all(&self.database)
            .await
            .map_err(persistence)?;
        let providers = bounded_list(providers)?;
        let mut records = Vec::with_capacity(providers.len());
        for provider in providers {
            records.push(self.provider_record(provider).await?);
        }
        Ok(records)
    }

    async fn provider_recovery_stage(
        &self,
        project_id: Uuid,
        provider_id: Uuid,
    ) -> Result<ProviderRecovery, ApplicationError> {
        let transaction = self.database.begin().await.map_err(persistence)?;
        active_project(&transaction, project_id).await?;
        let provider = find_provider(&transaction, project_id, provider_id).await?;
        let operation = provider_secret_operation::Entity::find()
            .filter(provider_secret_operation::Column::ProjectId.eq(project_id))
            .filter(provider_secret_operation::Column::ProviderId.eq(provider_id))
            .lock_exclusive()
            .one(&transaction)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::InvalidTransition)?;
        match operation.state.as_str() {
            "prepared" | "stored" if provider.status == ProviderStatus::Provisioning.as_str() => {}
            "completed" => {}
            _ => return Err(ApplicationError::InvalidTransition),
        }
        transaction.commit().await.map_err(persistence)?;
        Ok(ProviderRecovery {
            operation_alias: operation.operation_alias,
            provider_key: provider.provider_key,
            display_name: provider.display_name,
            issuer: provider.issuer,
            client_id: provider.client_id,
        })
    }

    pub(crate) async fn assign_provider(
        &self,
        project_id: Uuid,
        provider_id: Uuid,
        application_id: Uuid,
        expected_application_revision: i64,
        correlation_id: Uuid,
    ) -> Result<ProviderRecord, ApplicationError> {
        let transaction = self.database.begin().await.map_err(persistence)?;
        active_project(&transaction, project_id).await?;
        let application = active_application(&transaction, project_id, application_id).await?;
        let provider = active_provider(&transaction, project_id, provider_id).await?;
        if application.security_revision != expected_application_revision {
            return Err(ApplicationError::RevisionConflict);
        }
        let next_revision = expected_application_revision + 1;
        let existing = application_provider_assignment::Entity::find_by_id((
            project_id,
            application_id,
            provider_id,
        ))
        .lock_exclusive()
        .one(&transaction)
        .await
        .map_err(persistence)?;
        if existing
            .as_ref()
            .is_some_and(|assignment| assignment.status == "active")
        {
            return Err(ApplicationError::InvalidTransition);
        }
        let application_assignments = application_provider_assignment::Entity::find()
            .filter(application_provider_assignment::Column::ProjectId.eq(project_id))
            .filter(application_provider_assignment::Column::ApplicationId.eq(application_id))
            .filter(application_provider_assignment::Column::Status.eq("active"))
            .limit((CONFIGURATION_VALUE_LIMIT + 1) as u64)
            .all(&transaction)
            .await
            .map_err(persistence)?;
        ensure_capacity(
            application_assignments.len(),
            CONFIGURATION_VALUE_LIMIT as u64,
            ApplicationError::InvalidTransition,
        )?;
        let provider_assignments = application_provider_assignment::Entity::find()
            .filter(application_provider_assignment::Column::ProjectId.eq(project_id))
            .filter(application_provider_assignment::Column::ProviderId.eq(provider_id))
            .filter(application_provider_assignment::Column::Status.eq("active"))
            .limit(LIST_LIMIT + 1)
            .all(&transaction)
            .await
            .map_err(persistence)?;
        ensure_capacity(
            provider_assignments.len(),
            LIST_LIMIT,
            ApplicationError::InvalidTransition,
        )?;
        match existing {
            Some(existing) => {
                let mut active = existing.into_active_model();
                active.status = Set("active".to_owned());
                active.security_revision = Set(next_revision);
                active.update(&transaction).await.map_err(persistence)?;
            }
            None => {
                application_provider_assignment::ActiveModel {
                    project_id: Set(project_id),
                    application_id: Set(application_id),
                    provider_id: Set(provider_id),
                    status: Set("active".to_owned()),
                    security_revision: Set(next_revision),
                }
                .insert(&transaction)
                .await
                .map_err(persistence)?;
            }
        }
        bump_application_security(&transaction, application, next_revision).await?;
        let provider = bump_provider_revision(&transaction, provider).await?;
        insert_audit(
            &transaction,
            Some(project_id),
            "provider.assigned",
            "provider",
            Some(provider_id),
            correlation_id,
        )
        .await?;
        transaction.commit().await.map_err(persistence)?;
        self.provider_record(provider).await
    }

    pub(crate) async fn unassign_provider(
        &self,
        project_id: Uuid,
        provider_id: Uuid,
        application_id: Uuid,
        expected_application_revision: i64,
        correlation_id: Uuid,
    ) -> Result<ProviderRecord, ApplicationError> {
        let transaction = self.database.begin().await.map_err(persistence)?;
        active_project(&transaction, project_id).await?;
        let application = active_application(&transaction, project_id, application_id).await?;
        let provider = active_provider(&transaction, project_id, provider_id).await?;
        if application.security_revision != expected_application_revision {
            return Err(ApplicationError::RevisionConflict);
        }
        let assignment = application_provider_assignment::Entity::find_by_id((
            project_id,
            application_id,
            provider_id,
        ))
        .lock_exclusive()
        .one(&transaction)
        .await
        .map_err(persistence)?
        .ok_or(ApplicationError::NotFound)?;
        if assignment.status != "active" {
            return Err(ApplicationError::InvalidTransition);
        }
        let next_revision = expected_application_revision + 1;
        let mut active = assignment.into_active_model();
        active.status = Set("disabled".to_owned());
        active.security_revision = Set(next_revision);
        active.update(&transaction).await.map_err(persistence)?;
        bump_application_security(&transaction, application, next_revision).await?;
        let provider = bump_provider_revision(&transaction, provider).await?;
        insert_audit(
            &transaction,
            Some(project_id),
            "provider.unassigned",
            "provider",
            Some(provider_id),
            correlation_id,
        )
        .await?;
        transaction.commit().await.map_err(persistence)?;
        self.provider_record(provider).await
    }

    pub(crate) async fn disable_provider(
        &self,
        project_id: Uuid,
        provider_id: Uuid,
        expected_provider_revision: i64,
        correlation_id: Uuid,
    ) -> Result<ProviderRecord, ApplicationError> {
        let transaction = self.database.begin().await.map_err(persistence)?;
        active_project(&transaction, project_id).await?;
        let provider = active_provider(&transaction, project_id, provider_id).await?;
        if provider.revision != expected_provider_revision {
            return Err(ApplicationError::RevisionConflict);
        }
        let assignments = application_provider_assignment::Entity::find()
            .filter(application_provider_assignment::Column::ProjectId.eq(project_id))
            .filter(application_provider_assignment::Column::ProviderId.eq(provider_id))
            .filter(application_provider_assignment::Column::Status.eq("active"))
            .order_by_asc(application_provider_assignment::Column::ApplicationId)
            .lock_exclusive()
            .all(&transaction)
            .await
            .map_err(persistence)?;
        for assignment in assignments {
            let application =
                active_application(&transaction, project_id, assignment.application_id).await?;
            let next_revision = application.security_revision + 1;
            let mut assignment_active = assignment.into_active_model();
            assignment_active.status = Set("disabled".to_owned());
            assignment_active.security_revision = Set(next_revision);
            assignment_active
                .update(&transaction)
                .await
                .map_err(persistence)?;
            bump_application_security(&transaction, application, next_revision).await?;
        }
        let mut status = ProviderStatus::Active;
        status
            .disable()
            .map_err(|_| ApplicationError::InvalidTransition)?;
        let mut active = provider.into_active_model();
        active.status = Set(status.as_str().to_owned());
        active.revision = Set(expected_provider_revision + 1);
        let updated = active.update(&transaction).await.map_err(persistence)?;
        insert_audit(
            &transaction,
            Some(project_id),
            "provider.disabled",
            "provider",
            Some(provider_id),
            correlation_id,
        )
        .await?;
        transaction.commit().await.map_err(persistence)?;
        self.provider_record(updated).await
    }

    async fn provider_record(
        &self,
        provider: provider_configuration::Model,
    ) -> Result<ProviderRecord, ApplicationError> {
        let assignments = application_provider_assignment::Entity::find()
            .filter(application_provider_assignment::Column::ProjectId.eq(provider.project_id))
            .filter(application_provider_assignment::Column::ProviderId.eq(provider.id))
            .filter(application_provider_assignment::Column::Status.eq("active"))
            .order_by_asc(application_provider_assignment::Column::ApplicationId)
            .limit(LIST_LIMIT + 1)
            .all(&self.database)
            .await
            .map_err(persistence)?;
        let assignments = bounded_list(assignments)?
            .into_iter()
            .map(|assignment| assignment.application_id)
            .collect();
        Ok(ProviderRecord {
            id: provider.id,
            project_id: provider.project_id,
            provider_key: provider.provider_key,
            kind: provider.kind,
            display_name: provider.display_name,
            issuer: provider.issuer,
            client_id: provider.client_id,
            callback_url: provider.callback_url,
            status: provider.status,
            revision: provider.revision,
            assigned_application_ids: assignments,
        })
    }
}

fn provisioning_operation_state(
    value: &str,
) -> Result<ProvisioningOperationState, ApplicationError> {
    match value {
        "prepared" => Ok(ProvisioningOperationState::Prepared),
        "stored" => Ok(ProvisioningOperationState::Stored),
        "completed" => Ok(ProvisioningOperationState::Completed),
        _ => Err(ApplicationError::Integrity),
    }
}

fn prepared_signing_key(
    key: project_signing_key::Model,
    operation: key_provisioning_operation::Model,
) -> Result<PreparedSigningKey, ApplicationError> {
    if operation.key_id != key.id || operation.ring_id != key.ring_id {
        return Err(ApplicationError::Integrity);
    }
    Ok(PreparedSigningKey {
        operation_id: operation.id,
        ring_id: operation.ring_id,
        key_id: operation.key_id,
        kid: key.kid,
        signer_ref: key.signer_ref,
        request_digest: operation.request_digest,
        state: provisioning_operation_state(&operation.state)?,
    })
}

fn prepared_provider(
    operation: provider_secret_operation::Model,
) -> Result<PreparedProvider, ApplicationError> {
    Ok(PreparedProvider {
        operation_id: operation.id,
        provider_id: operation.provider_id,
        request_digest: operation.request_digest,
        state: provisioning_operation_state(&operation.state)?,
    })
}

fn project_policy_record(
    model: &project_policy::Model,
) -> Result<ProjectPolicyRecord, ApplicationError> {
    let access_token_lifetime_seconds = model
        .claims_policy
        .get("access_token_lifetime_seconds")
        .and_then(Value::as_i64)
        .and_then(|value| i32::try_from(value).ok())
        .filter(|value| (60..=3600).contains(value))
        .ok_or(ApplicationError::InvalidTransition)?;
    let browser_session_reuse = model
        .session_policy
        .get("browser_session_reuse")
        .and_then(Value::as_bool)
        .ok_or(ApplicationError::InvalidTransition)?;
    Ok(ProjectPolicyRecord {
        project_id: model.project_id,
        access_token_lifetime_seconds,
        browser_session_reuse,
        claims_revision: model.claims_revision,
        session_revision: model.session_revision,
    })
}

fn project_record(model: project::Model) -> ProjectRecord {
    ProjectRecord {
        id: model.id,
        public_id: model.public_id,
        display_name: model.display_name,
        belongs_to: model.belongs_to,
        status: model.status,
        metadata_revision: model.metadata_revision,
        security_revision: model.security_revision,
    }
}

async fn locked_project<C>(
    connection: &C,
    project_id: Uuid,
) -> Result<project::Model, ApplicationError>
where
    C: ConnectionTrait,
{
    project::Entity::find_by_id(project_id)
        .lock_exclusive()
        .one(connection)
        .await
        .map_err(persistence)?
        .ok_or(ApplicationError::NotFound)
}

async fn active_project<C>(
    connection: &C,
    project_id: Uuid,
) -> Result<project::Model, ApplicationError>
where
    C: ConnectionTrait,
{
    let project = locked_project(connection, project_id).await?;
    if project.status != "active" {
        return Err(ApplicationError::Disabled);
    }
    Ok(project)
}

fn enforce_project_fence(
    project: &project::Model,
    expected_revision: i64,
) -> Result<(), ApplicationError> {
    if project.status != "active" {
        return Err(ApplicationError::Disabled);
    }
    if project.metadata_revision != expected_revision {
        return Err(ApplicationError::RevisionConflict);
    }
    Ok(())
}

fn requires_project_reauthorization(
    project: &project::Model,
    operation_state: &str,
    captured_revision: i64,
    expected_revision: i64,
) -> Result<bool, ApplicationError> {
    if operation_state == "completed" {
        return Ok(false);
    }
    enforce_project_fence(project, expected_revision)?;
    Ok(captured_revision != expected_revision)
}

async fn ensure_project<C>(connection: &C, project_id: Uuid) -> Result<(), ApplicationError>
where
    C: ConnectionTrait,
{
    project::Entity::find_by_id(project_id)
        .one(connection)
        .await
        .map_err(persistence)?
        .ok_or(ApplicationError::NotFound)?;
    Ok(())
}

async fn find_application<C>(
    connection: &C,
    project_id: Uuid,
    application_id: Uuid,
) -> Result<application::Model, ApplicationError>
where
    C: ConnectionTrait,
{
    application::Entity::find_by_id(application_id)
        .filter(application::Column::ProjectId.eq(project_id))
        .one(connection)
        .await
        .map_err(persistence)?
        .ok_or(ApplicationError::NotFound)
}

async fn active_application<C>(
    connection: &C,
    project_id: Uuid,
    application_id: Uuid,
) -> Result<application::Model, ApplicationError>
where
    C: ConnectionTrait,
{
    let application = find_application(connection, project_id, application_id).await?;
    if application.status != "active" {
        return Err(ApplicationError::Disabled);
    }
    Ok(application)
}

async fn find_signing_key<C>(
    connection: &C,
    project_id: Uuid,
    key_id: Uuid,
) -> Result<project_signing_key::Model, ApplicationError>
where
    C: ConnectionTrait,
{
    project_signing_key::Entity::find_by_id(key_id)
        .filter(project_signing_key::Column::ProjectId.eq(project_id))
        .one(connection)
        .await
        .map_err(persistence)?
        .ok_or(ApplicationError::NotFound)
}

async fn signing_key_record<C>(
    connection: &C,
    key: project_signing_key::Model,
) -> Result<SigningKeyRecord, ApplicationError>
where
    C: ConnectionTrait,
{
    let ring = project_key_ring::Entity::find_by_id(key.ring_id)
        .filter(project_key_ring::Column::ProjectId.eq(key.project_id))
        .one(connection)
        .await
        .map_err(persistence)?
        .ok_or(ApplicationError::NotFound)?;
    Ok(SigningKeyRecord {
        id: key.id,
        project_id: key.project_id,
        kid: key.kid,
        algorithm: ring.algorithm,
        state: key.state,
        ring_revision: ring.revision,
        signing_epoch: ring.signing_epoch,
        sign_not_before: key.sign_not_before,
        verify_not_after: key.verify_not_after,
        public_jwk: key.public_jwk,
    })
}

async fn find_provider<C>(
    connection: &C,
    project_id: Uuid,
    provider_id: Uuid,
) -> Result<provider_configuration::Model, ApplicationError>
where
    C: ConnectionTrait,
{
    provider_configuration::Entity::find_by_id(provider_id)
        .filter(provider_configuration::Column::ProjectId.eq(project_id))
        .one(connection)
        .await
        .map_err(persistence)?
        .ok_or(ApplicationError::NotFound)
}

async fn active_provider<C>(
    connection: &C,
    project_id: Uuid,
    provider_id: Uuid,
) -> Result<provider_configuration::Model, ApplicationError>
where
    C: ConnectionTrait,
{
    let provider = find_provider(connection, project_id, provider_id).await?;
    if provider.status != "active" {
        return Err(ApplicationError::Disabled);
    }
    Ok(provider)
}

async fn bump_application_security(
    transaction: &DatabaseTransaction,
    application: application::Model,
    next_revision: i64,
) -> Result<(), ApplicationError> {
    let aggregate_revision = application.revision + 1;
    let mut active = application.into_active_model();
    active.security_revision = Set(next_revision);
    active.revision = Set(aggregate_revision);
    active.updated_at = Set(OffsetDateTime::now_utc());
    active.update(transaction).await.map_err(persistence)?;
    Ok(())
}

async fn bump_provider_revision(
    transaction: &DatabaseTransaction,
    provider: provider_configuration::Model,
) -> Result<provider_configuration::Model, ApplicationError> {
    let next_revision = provider.revision + 1;
    let mut active = provider.into_active_model();
    active.revision = Set(next_revision);
    active.update(transaction).await.map_err(persistence)
}

#[allow(
    clippy::too_many_arguments,
    reason = "the arguments are the complete immutable key transition event"
)]
async fn insert_key_state_event(
    transaction: &DatabaseTransaction,
    project_id: Uuid,
    ring_id: Uuid,
    signing_key_id: Uuid,
    ring_revision: i64,
    from_state: SigningKeyState,
    to_state: SigningKeyState,
    occurred_at: OffsetDateTime,
) -> Result<(), ApplicationError> {
    key_state_event::ActiveModel {
        id: Set(Uuid::new_v4()),
        project_id: Set(project_id),
        ring_id: Set(ring_id),
        signing_key_id: Set(signing_key_id),
        ring_revision: Set(ring_revision),
        from_state: Set(from_state.as_str().to_owned()),
        to_state: Set(to_state.as_str().to_owned()),
        actor_kind: Set("deployment_operator".to_owned()),
        occurred_at: Set(occurred_at),
    }
    .insert(transaction)
    .await
    .map_err(persistence)?;
    Ok(())
}

async fn insert_audit(
    transaction: &DatabaseTransaction,
    project_id: Option<Uuid>,
    action: &str,
    target_kind: &str,
    target_id: Option<Uuid>,
    correlation_id: Uuid,
) -> Result<(), ApplicationError> {
    audit_event::ActiveModel {
        id: Set(Uuid::new_v4()),
        project_id: Set(project_id),
        actor_kind: Set("deployment_operator".to_owned()),
        action: Set(action.to_owned()),
        target_kind: Set(target_kind.to_owned()),
        target_id: Set(target_id),
        outcome: Set("succeeded".to_owned()),
        correlation_id: Set(correlation_id),
        safe_context: Set(Value::Object(Map::new())),
    }
    .insert(transaction)
    .await
    .map_err(persistence)?;
    Ok(())
}

async fn lock_idempotency_key(
    transaction: &DatabaseTransaction,
    idempotency_key: &str,
) -> Result<(), ApplicationError> {
    lock_advisory(transaction, idempotency_key).await
}

async fn lock_project_capacity(transaction: &DatabaseTransaction) -> Result<(), ApplicationError> {
    lock_advisory(transaction, PROJECT_CAPACITY_LOCK).await
}

async fn ensure_application_capacity(
    transaction: &DatabaseTransaction,
    project_id: Uuid,
    capacity_error: ApplicationError,
) -> Result<(), ApplicationError> {
    let applications = application::Entity::find()
        .filter(application::Column::ProjectId.eq(project_id))
        .limit(LIST_LIMIT + 1)
        .all(transaction)
        .await
        .map_err(persistence)?;
    ensure_capacity(applications.len(), LIST_LIMIT, capacity_error)
}

async fn ensure_publishable_signing_key_capacity(
    transaction: &DatabaseTransaction,
    project_id: Uuid,
) -> Result<(), ApplicationError> {
    let keys = project_signing_key::Entity::find()
        .filter(project_signing_key::Column::ProjectId.eq(project_id))
        .filter(project_signing_key::Column::State.is_in([
            SigningKeyState::Published.as_str(),
            SigningKeyState::Active.as_str(),
            SigningKeyState::Retiring.as_str(),
        ]))
        .limit(LIST_LIMIT + 1)
        .all(transaction)
        .await
        .map_err(persistence)?;
    ensure_capacity(keys.len(), LIST_LIMIT, ApplicationError::InvalidTransition)
}

async fn abandon_signing_key_operation(
    transaction: &DatabaseTransaction,
    project_id: Uuid,
    key_id: Uuid,
) -> Result<(), ApplicationError> {
    let operation = key_provisioning_operation::Entity::find()
        .filter(key_provisioning_operation::Column::ProjectId.eq(project_id))
        .filter(key_provisioning_operation::Column::KeyId.eq(key_id))
        .lock_exclusive()
        .one(transaction)
        .await
        .map_err(persistence)?
        .ok_or(ApplicationError::Integrity)?;
    if !matches!(operation.state.as_str(), "prepared" | "stored") {
        return Err(ApplicationError::InvalidTransition);
    }
    let mut operation = operation.into_active_model();
    operation.state = Set("abandoned".to_owned());
    operation.update(transaction).await.map_err(persistence)?;
    Ok(())
}

async fn lock_advisory(
    transaction: &DatabaseTransaction,
    namespace: &str,
) -> Result<(), ApplicationError> {
    transaction
        .execute_raw(Statement::from_sql_and_values(
            transaction.get_database_backend(),
            "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))",
            [namespace.to_owned().into()],
        ))
        .await
        .map_err(persistence)?;
    Ok(())
}

async fn replay<T>(
    transaction: &DatabaseTransaction,
    idempotency_key: &str,
    operation_kind: &str,
    scope: &str,
    digest: &[u8],
) -> Result<Option<T>, ApplicationError>
where
    T: for<'de> Deserialize<'de>,
{
    let Some(existing) = control_idempotency_record::Entity::find_by_id(idempotency_key)
        .one(transaction)
        .await
        .map_err(persistence)?
    else {
        return Ok(None);
    };
    if existing.operation_kind != operation_kind
        || existing.request_scope != scope
        || existing.request_digest != digest
    {
        return Err(ApplicationError::IdempotencyConflict);
    }
    if existing.state != "completed" {
        return Err(ApplicationError::OperationInProgress);
    }
    let response = existing.response.ok_or(ApplicationError::Persistence)?;
    serde_json::from_value(response)
        .map(Some)
        .map_err(|_| ApplicationError::Persistence)
}

#[allow(
    clippy::too_many_arguments,
    reason = "the arguments are the durable idempotency record and its response"
)]
async fn complete_idempotency<T>(
    transaction: &DatabaseTransaction,
    idempotency_key: String,
    owner_project_id: Option<Uuid>,
    result_resource_id: Option<Uuid>,
    operation_kind: &str,
    scope: &str,
    digest: Vec<u8>,
    result: &T,
) -> Result<(), ApplicationError>
where
    T: Serialize,
{
    control_idempotency_record::ActiveModel {
        idempotency_key: Set(idempotency_key),
        project_id: Set(owner_project_id),
        request_digest: Set(digest),
        state: Set("completed".to_owned()),
        result_resource_id: Set(result_resource_id),
        response: Set(Some(
            serde_json::to_value(result).map_err(|_| ApplicationError::Persistence)?,
        )),
        operation_kind: Set(operation_kind.to_owned()),
        request_scope: Set(scope.to_owned()),
        expires_at: Set(None),
        completed_at: Set(Some(OffsetDateTime::now_utc())),
    }
    .insert(transaction)
    .await
    .map_err(persistence)?;
    Ok(())
}

fn generated_id(prefix: &str) -> String {
    format!("{prefix}_{}", Uuid::new_v4().simple())
}

fn ensure_capacity(
    item_count: usize,
    limit: u64,
    capacity_error: ApplicationError,
) -> Result<(), ApplicationError> {
    let item_count = u64::try_from(item_count).map_err(|_| ApplicationError::Integrity)?;
    if item_count > limit {
        return Err(ApplicationError::Integrity);
    }
    if item_count == limit {
        return Err(capacity_error);
    }
    Ok(())
}

fn bounded_items<T>(items: Vec<T>, limit: usize) -> Result<Vec<T>, ApplicationError> {
    if items.len() > limit {
        return Err(ApplicationError::Integrity);
    }
    Ok(items)
}

fn bounded_list<T>(items: Vec<T>) -> Result<Vec<T>, ApplicationError> {
    bounded_items(
        items,
        usize::try_from(LIST_LIMIT).expect("the list limit fits usize"),
    )
}

fn reject_duplicates(values: impl Iterator<Item = String>) -> Result<(), ApplicationError> {
    let mut unique = BTreeSet::new();
    for value in values {
        if !unique.insert(value) {
            return Err(ApplicationError::InvalidInput);
        }
    }
    Ok(())
}

fn parse_application_type(value: &str) -> Result<ApplicationType, ApplicationError> {
    match value {
        "web" => Ok(ApplicationType::Web),
        "native" => Ok(ApplicationType::Native),
        _ => Err(ApplicationError::Persistence),
    }
}

fn parse_signing_state(value: &str) -> Result<SigningKeyState, ApplicationError> {
    match value {
        "provisioning" => Ok(SigningKeyState::Provisioning),
        "published" => Ok(SigningKeyState::Published),
        "active" => Ok(SigningKeyState::Active),
        "retiring" => Ok(SigningKeyState::Retiring),
        "retired" => Ok(SigningKeyState::Retired),
        "revoked" => Ok(SigningKeyState::Revoked),
        "abandoned" => Ok(SigningKeyState::Abandoned),
        _ => Err(ApplicationError::Persistence),
    }
}

#[derive(FromQueryResult)]
struct DatabaseTime {
    database_now: OffsetDateTime,
}

async fn database_now<C>(connection: &C) -> Result<OffsetDateTime, ApplicationError>
where
    C: ConnectionTrait,
{
    DatabaseTime::find_by_statement(Statement::from_string(
        connection.get_database_backend(),
        "SELECT transaction_timestamp() AS database_now",
    ))
    .one(connection)
    .await
    .map_err(persistence)?
    .map(|row| row.database_now)
    .ok_or(ApplicationError::Persistence)
}

fn persistence(error: DbErr) -> ApplicationError {
    match error {
        DbErr::Exec(RuntimeErr::SqlxError(error)) | DbErr::Query(RuntimeErr::SqlxError(error)) => {
            match error.as_ref() {
                sqlx::Error::Database(error) => match error.code().as_deref() {
                    Some("23505" | "40001" | "40P01") => ApplicationError::RevisionConflict,
                    Some("23503" | "23514" | "23P01") => ApplicationError::InvalidInput,
                    _ => ApplicationError::Integrity,
                },
                _ => ApplicationError::Integrity,
            }
        }
        DbErr::Conn(_) | DbErr::ConnectionAcquire(_) => ApplicationError::Persistence,
        _ => ApplicationError::Integrity,
    }
}

#[async_trait]
impl ProjectProvisioningPort for PostgresProvisioningAdapter {
    async fn create_project(
        &self,
        command: CreateProject,
        correlation_id: Uuid,
    ) -> Result<ProjectRecord, ApplicationError> {
        PostgresProvisioningAdapter::create_project(self, command, correlation_id).await
    }

    async fn list_projects(
        &self,
        belongs_to: Option<String>,
    ) -> Result<Vec<ProjectRecord>, ApplicationError> {
        PostgresProvisioningAdapter::list_projects(self, belongs_to).await
    }

    async fn get_project(&self, project_id: Uuid) -> Result<ProjectRecord, ApplicationError> {
        PostgresProvisioningAdapter::get_project(self, project_id).await
    }

    async fn get_project_policy(
        &self,
        project_id: Uuid,
    ) -> Result<ProjectPolicyRecord, ApplicationError> {
        PostgresProvisioningAdapter::get_project_policy(self, project_id).await
    }

    async fn update_project_policy(
        &self,
        project_id: Uuid,
        command: UpdateProjectPolicy,
        correlation_id: Uuid,
    ) -> Result<ProjectPolicyRecord, ApplicationError> {
        PostgresProvisioningAdapter::update_project_policy(
            self,
            project_id,
            command,
            correlation_id,
        )
        .await
    }

    async fn update_project(
        &self,
        project_id: Uuid,
        command: UpdateProject,
        correlation_id: Uuid,
    ) -> Result<ProjectRecord, ApplicationError> {
        PostgresProvisioningAdapter::update_project(self, project_id, command, correlation_id).await
    }

    async fn disable_project(
        &self,
        project_id: Uuid,
        expected_security_revision: i64,
        correlation_id: Uuid,
    ) -> Result<ProjectRecord, ApplicationError> {
        PostgresProvisioningAdapter::disable_project(
            self,
            project_id,
            expected_security_revision,
            correlation_id,
        )
        .await
    }
}

#[async_trait]
impl ApplicationProvisioningPort for PostgresProvisioningAdapter {
    async fn create_application(
        &self,
        project_id: Uuid,
        command: CreateApplication,
        correlation_id: Uuid,
    ) -> Result<ApplicationRecord, ApplicationError> {
        PostgresProvisioningAdapter::create_application(self, project_id, command, correlation_id)
            .await
    }

    async fn list_applications(
        &self,
        project_id: Uuid,
    ) -> Result<Vec<ApplicationRecord>, ApplicationError> {
        PostgresProvisioningAdapter::list_applications(self, project_id).await
    }

    async fn get_application(
        &self,
        project_id: Uuid,
        application_id: Uuid,
    ) -> Result<ApplicationRecord, ApplicationError> {
        PostgresProvisioningAdapter::get_application(self, project_id, application_id).await
    }

    async fn update_application(
        &self,
        project_id: Uuid,
        application_id: Uuid,
        command: UpdateApplication,
        correlation_id: Uuid,
    ) -> Result<ApplicationRecord, ApplicationError> {
        PostgresProvisioningAdapter::update_application(
            self,
            project_id,
            application_id,
            command,
            correlation_id,
        )
        .await
    }

    async fn replace_application_configuration(
        &self,
        project_id: Uuid,
        application_id: Uuid,
        command: ReplaceApplicationConfiguration,
        correlation_id: Uuid,
    ) -> Result<ApplicationRecord, ApplicationError> {
        PostgresProvisioningAdapter::replace_application_configuration(
            self,
            project_id,
            application_id,
            command,
            correlation_id,
        )
        .await
    }

    async fn disable_application(
        &self,
        project_id: Uuid,
        application_id: Uuid,
        expected_security_revision: i64,
        correlation_id: Uuid,
    ) -> Result<ApplicationRecord, ApplicationError> {
        PostgresProvisioningAdapter::disable_application(
            self,
            project_id,
            application_id,
            expected_security_revision,
            correlation_id,
        )
        .await
    }
}

#[async_trait]
impl SigningKeyProvisioningPort for PostgresProvisioningAdapter {
    async fn prepare_signing_key(
        &self,
        project_id: Uuid,
        operation_alias: String,
        signer_ref: String,
        expected_project_revision: i64,
        request_digest: Vec<u8>,
    ) -> Result<PreparedSigningKey, ApplicationError> {
        self.prepare_signing_key_stage(
            project_id,
            operation_alias,
            signer_ref,
            expected_project_revision,
            request_digest,
        )
        .await
    }

    async fn signing_key_recovery(
        &self,
        project_id: Uuid,
        key_id: Uuid,
    ) -> Result<SigningKeyRecovery, ApplicationError> {
        self.signing_key_recovery_stage(project_id, key_id).await
    }

    async fn record_signing_key_material(
        &self,
        project_id: Uuid,
        prepared: &PreparedSigningKey,
        expected_project_revision: i64,
        public_jwk: Value,
        recorded_at: OffsetDateTime,
    ) -> Result<(), ApplicationError> {
        self.record_signing_key_material_stage(
            project_id,
            prepared,
            expected_project_revision,
            public_jwk,
            recorded_at,
        )
        .await
    }

    async fn publish_signing_key(
        &self,
        project_id: Uuid,
        prepared: &PreparedSigningKey,
        expected_project_revision: i64,
        correlation_id: Uuid,
        published_at: OffsetDateTime,
    ) -> Result<SigningKeyRecord, ApplicationError> {
        self.publish_signing_key_stage(
            project_id,
            prepared,
            expected_project_revision,
            correlation_id,
            published_at,
        )
        .await
    }

    async fn get_signing_key(
        &self,
        project_id: Uuid,
        key_id: Uuid,
    ) -> Result<SigningKeyRecord, ApplicationError> {
        let key = find_signing_key(&self.database, project_id, key_id).await?;
        signing_key_record(&self.database, key).await
    }

    async fn list_signing_keys(
        &self,
        project_id: Uuid,
    ) -> Result<Vec<SigningKeyRecord>, ApplicationError> {
        PostgresProvisioningAdapter::list_signing_keys(self, project_id).await
    }

    async fn signing_key_activation_candidate(
        &self,
        project_id: Uuid,
        key_id: Uuid,
    ) -> Result<SigningKeyActivationCandidate, ApplicationError> {
        self.signing_key_activation_candidate_stage(project_id, key_id)
            .await
    }

    async fn activate_signing_key_if_ready(
        &self,
        project_id: Uuid,
        key_id: Uuid,
        expected_ring_revision: i64,
        correlation_id: Uuid,
    ) -> Result<SigningKeyRecord, ApplicationError> {
        PostgresProvisioningAdapter::activate_signing_key_if_ready(
            self,
            project_id,
            key_id,
            expected_ring_revision,
            correlation_id,
        )
        .await
    }

    async fn retire_signing_key(
        &self,
        project_id: Uuid,
        key_id: Uuid,
        expected_ring_revision: i64,
        correlation_id: Uuid,
    ) -> Result<SigningKeyRecord, ApplicationError> {
        PostgresProvisioningAdapter::retire_signing_key(
            self,
            project_id,
            key_id,
            expected_ring_revision,
            correlation_id,
        )
        .await
    }

    async fn revoke_signing_key(
        &self,
        project_id: Uuid,
        key_id: Uuid,
        expected_ring_revision: i64,
        correlation_id: Uuid,
    ) -> Result<SigningKeyRecord, ApplicationError> {
        PostgresProvisioningAdapter::revoke_signing_key(
            self,
            project_id,
            key_id,
            expected_ring_revision,
            correlation_id,
        )
        .await
    }
}

#[async_trait]
impl ProviderProvisioningPort for PostgresProvisioningAdapter {
    async fn prepare_provider(
        &self,
        project_id: Uuid,
        command: PrepareProvider,
    ) -> Result<PreparedProvider, ApplicationError> {
        self.prepare_provider_stage(project_id, command).await
    }

    async fn provider_recovery(
        &self,
        project_id: Uuid,
        provider_id: Uuid,
    ) -> Result<ProviderRecovery, ApplicationError> {
        self.provider_recovery_stage(project_id, provider_id).await
    }

    async fn mark_provider_secret_stored(
        &self,
        project_id: Uuid,
        prepared: &PreparedProvider,
        expected_project_revision: i64,
        stored_at: OffsetDateTime,
    ) -> Result<(), ApplicationError> {
        self.mark_provider_secret_stored_stage(
            project_id,
            prepared,
            expected_project_revision,
            stored_at,
        )
        .await
    }

    async fn finalize_provider(
        &self,
        project_id: Uuid,
        prepared: &PreparedProvider,
        expected_project_revision: i64,
        secret_ref: String,
        correlation_id: Uuid,
        finalized_at: OffsetDateTime,
    ) -> Result<ProviderRecord, ApplicationError> {
        self.finalize_provider_stage(
            project_id,
            prepared,
            expected_project_revision,
            secret_ref,
            correlation_id,
            finalized_at,
        )
        .await
    }

    async fn get_provider(
        &self,
        project_id: Uuid,
        provider_id: Uuid,
    ) -> Result<ProviderRecord, ApplicationError> {
        let provider = find_provider(&self.database, project_id, provider_id).await?;
        self.provider_record(provider).await
    }

    async fn list_providers(
        &self,
        project_id: Uuid,
    ) -> Result<Vec<ProviderRecord>, ApplicationError> {
        PostgresProvisioningAdapter::list_providers(self, project_id).await
    }

    async fn assign_provider(
        &self,
        project_id: Uuid,
        provider_id: Uuid,
        application_id: Uuid,
        expected_application_revision: i64,
        correlation_id: Uuid,
    ) -> Result<ProviderRecord, ApplicationError> {
        PostgresProvisioningAdapter::assign_provider(
            self,
            project_id,
            provider_id,
            application_id,
            expected_application_revision,
            correlation_id,
        )
        .await
    }

    async fn unassign_provider(
        &self,
        project_id: Uuid,
        provider_id: Uuid,
        application_id: Uuid,
        expected_application_revision: i64,
        correlation_id: Uuid,
    ) -> Result<ProviderRecord, ApplicationError> {
        PostgresProvisioningAdapter::unassign_provider(
            self,
            project_id,
            provider_id,
            application_id,
            expected_application_revision,
            correlation_id,
        )
        .await
    }

    async fn disable_provider(
        &self,
        project_id: Uuid,
        provider_id: Uuid,
        expected_provider_revision: i64,
        correlation_id: Uuid,
    ) -> Result<ProviderRecord, ApplicationError> {
        PostgresProvisioningAdapter::disable_provider(
            self,
            project_id,
            provider_id,
            expected_provider_revision,
            correlation_id,
        )
        .await
    }
}
