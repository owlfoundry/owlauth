use super::{
    ActiveModelTrait, ApplicationConfiguration, ApplicationError, ApplicationProvisioningPort,
    ApplicationRecord, ApplicationStatus, BrowserOrigin, CONFIGURATION_VALUE_LIMIT, ColumnTrait,
    CreateApplication, CreateProject, EntityTrait, IntoActiveModel, LIST_LIMIT,
    MAX_WEBHOOK_ENDPOINTS_PER_APPLICATION, MaterialKind, MaterialOwnerKind, MaterialPurpose,
    PostgresProvisioningAdapter, ProjectPolicyRecord, ProjectProvisioningPort, ProjectRecord,
    ProjectStatus, QueryFilter, QueryOrder, QuerySelect, RedirectUri,
    ReplaceApplicationConfiguration, SIGNING_ALGORITHM, SIGNING_PURPOSE, Set, SigningKeyState,
    TransactionTrait, UpdateApplication, UpdateProject, UpdateProjectPolicy, Uuid, Value,
    active_application, active_project, active_provider, application, application_origin,
    application_provider_assignment, application_publishable_key, application_redirect,
    async_trait, bounded_items, bounded_list, bump_provider_revision, complete_idempotency,
    ensure_application_capacity, ensure_capacity, ensure_project, find_application, generated_id,
    insert_audit, json, key_provisioning_operation, lock_idempotency_key, lock_project_capacity,
    parse_application_type, persistence, project, project_key_ring, project_policy,
    project_policy_record, project_record, project_signing_key, reject_duplicates, replay,
    webhook_endpoint,
};

impl PostgresProvisioningAdapter {
    #[allow(
        clippy::too_many_lines,
        reason = "the atomic Project, policy, key-ring, initial-key, idempotency, and audit transaction stays visible"
    )]
    async fn create_project(
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
        ensure_capacity(
            projects.len(),
            LIST_LIMIT,
            ApplicationError::CapacityExceeded,
        )?;
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
            claims_policy: Set(json!({ "access_token_lifetime_seconds": 900 })),
            session_policy: Set(json!({
                "browser_session_reuse": true,
                "browser_session_reuse_max_age_seconds": 28_800,
            })),
        }
        .insert(&transaction)
        .await
        .map_err(persistence)?;

        // Project creation owns the durable initial signing intent. Provider effects happen only
        // after commit, under the ordinary provider lease state machine.
        let ring = project_key_ring::ActiveModel {
            id: Set(Uuid::new_v4()),
            project_id: Set(id),
            issuer: Set(self
                .runtime_base
                .join(&format!("projects/{public_id}/"))
                .map_err(|_| ApplicationError::InvalidInput)?
                .to_string()),
            purpose: Set(SIGNING_PURPOSE.to_owned()),
            algorithm: Set(SIGNING_ALGORITHM.to_owned()),
            revision: Set(1),
            signing_epoch: Set(1),
        }
        .insert(&transaction)
        .await
        .map_err(persistence)?;
        let operation_alias = format!("signing_initial_{}", id.simple());
        let request_digest = self.digester.digest_json(&json!({
            "project_id": id,
            "algorithm": SIGNING_ALGORITHM,
            "purpose": SIGNING_PURPOSE,
        }))?;
        let key_id = Uuid::new_v4();
        let material_id = Uuid::new_v4();
        let key = project_signing_key::ActiveModel {
            id: Set(key_id),
            project_id: Set(id),
            ring_id: Set(ring.id),
            kid: Set(generated_id("kid")),
            public_jwk: Set(json!({})),
            signer_material_id: Set(material_id),
            state: Set(SigningKeyState::Provisioning.as_str().to_owned()),
            ring_revision: Set(ring.revision),
            ..Default::default()
        }
        .insert(&transaction)
        .await
        .map_err(persistence)?;
        let custody = self.custody();
        custody
            .materials
            .reserve_project_in_transaction(
                &transaction,
                id,
                material_id,
                MaterialOwnerKind::SigningKey,
                key.id,
                1,
                MaterialKind::SigningKey,
                MaterialPurpose::SigningSeed,
                custody.signing.provider_id.clone(),
                custody.signing.provider_format_version,
            )
            .await?;
        key_provisioning_operation::ActiveModel {
            id: Set(Uuid::new_v4()),
            project_id: Set(id),
            ring_id: Set(ring.id),
            key_id: Set(key.id),
            operation_alias: Set(operation_alias),
            request_digest: Set(request_digest),
            state: Set("prepared".to_owned()),
            attempt_count: Set(0),
            expected_project_revision: Set(1),
            expected_ring_revision: Set(ring.revision),
            maintenance_claimed_at: Set(None),
            material_id: Set(material_id),
            provider_lease_token: Set(None),
            provider_lease_expires_at: Set(None),
            provider_lease_generation: Set(0),
            destroy_attempt_count: Set(0),
            next_attempt_at: Set(None),
            last_provider_error_class: Set(None),
            last_retry_classification: Set(None),
            last_provider_error_code: Set(None),
            abandoned_at: Set(None),
            destroyed_at: Set(None),
            last_attempt_at: Set(None),
            completed_at: Set(None),
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

    async fn list_projects(
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

    async fn get_project(&self, project_id: Uuid) -> Result<ProjectRecord, ApplicationError> {
        let model = project::Entity::find_by_id(project_id)
            .one(&self.database)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        Ok(project_record(model))
    }

    async fn get_project_policy(
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

    async fn update_project_policy(
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

    async fn update_project(
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

    async fn disable_project(
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

    async fn create_application(
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
        ensure_application_capacity(&transaction, project_id, ApplicationError::CapacityExceeded)
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

    async fn list_applications(
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

    async fn get_application(
        &self,
        project_id: Uuid,
        application_id: Uuid,
    ) -> Result<ApplicationRecord, ApplicationError> {
        let model = find_application(&self.database, project_id, application_id).await?;
        self.application_record(model).await
    }

    async fn update_application(
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

    async fn replace_application_configuration(
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

    async fn disable_application(
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
        let now = self.clock.now();
        let endpoints = webhook_endpoint::Entity::find()
            .filter(webhook_endpoint::Column::ProjectId.eq(project_id))
            .filter(webhook_endpoint::Column::ApplicationId.eq(application_id))
            .filter(webhook_endpoint::Column::Status.is_in(["pending", "active"]))
            .order_by_asc(webhook_endpoint::Column::Id)
            .limit((MAX_WEBHOOK_ENDPOINTS_PER_APPLICATION + 1) as u64)
            .lock_exclusive()
            .all(&transaction)
            .await
            .map_err(persistence)?;
        if endpoints.len() > MAX_WEBHOOK_ENDPOINTS_PER_APPLICATION {
            return Err(ApplicationError::Integrity);
        }
        for endpoint in endpoints {
            let next_endpoint_revision = endpoint
                .revision
                .checked_add(1)
                .ok_or(ApplicationError::Integrity)?;
            let mut active = endpoint.into_active_model();
            active.status = Set("disabled".to_owned());
            active.revision = Set(next_endpoint_revision);
            active.disabled_at = Set(Some(now));
            active.updated_at = Set(now);
            active.update(&transaction).await.map_err(persistence)?;
        }
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
        active.updated_at = Set(now);
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
