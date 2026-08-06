use super::{
    ActiveModelTrait, ApplicationError, ColumnTrait, ConnectionTrait, DatabaseTransaction,
    DbBackend, Duration, EntityTrait, IntoActiveModel, LIST_LIMIT,
    MAX_ACCESS_TOKEN_LIFETIME_SECONDS, MaterialKind, MaterialOwnerKind, MaterialPurpose,
    OffsetDateTime, OpaqueHandle, PostgresProvisioningAdapter, PreparedSigningKey,
    PreparedSigningMaterial, ProviderErrorClass, ProvisionedProtectedSigningMaterial, QueryFilter,
    QueryOrder, QuerySelect, RetryClassification, SIGNING_ALGORITHM, SIGNING_PURPOSE, Set,
    SigningKeyMaintenanceItem, SigningKeyProvisioningPort, SigningKeyRecord, SigningKeyState,
    SigningProviderAction, SigningProviderCall, SigningProviderLease, Statement, TransactionTrait,
    Uuid, Value, abandon_signing_key_operation, active_project, async_trait,
    authenticate_committed_signing_provider_replay, bounded_list, database_now, ensure_capacity,
    ensure_project, ensure_publishable_signing_key_capacity, ensure_signing_provider_lease,
    finalize_pending_material, find_signing_key, generated_id, insert_audit,
    insert_key_state_event, json, key_provisioning_operation, locked_project, parse_signing_state,
    persistence, prepared_signing_key, project, project_key_ring, project_signing_key,
    protected_material, provider_error_class_name, retry_classification_name,
    runtime_publication_lease, signing_key_record, signing_public_key_from_jwk,
    validate_protected_signing_jwk, validate_signing_operation,
};

async fn claim_maintenance_ids(
    transaction: &DatabaseTransaction,
    sql: &'static str,
    values: Vec<sea_orm::Value>,
) -> Result<Vec<Uuid>, ApplicationError> {
    transaction
        .query_all_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            sql,
            values,
        ))
        .await
        .map_err(persistence)?
        .into_iter()
        .map(|row| row.try_get::<Uuid>("", "id").map_err(persistence))
        .collect()
}

fn maintenance_category_limits(limit: u64) -> [u64; 3] {
    let base = limit / 3;
    let remainder = limit % 3;
    [
        base + u64::from(remainder >= 1),
        base + u64::from(remainder >= 2),
        base,
    ]
}

impl PostgresProvisioningAdapter {
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

    #[allow(
        clippy::too_many_lines,
        reason = "one transaction owns the full signing reservation and replay fence"
    )]
    async fn prepare_signing_key_models(
        &self,
        project_id: Uuid,
        operation_alias: String,
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
        let pending_candidate = project_signing_key::Entity::find()
            .filter(project_signing_key::Column::ProjectId.eq(project_id))
            .filter(project_signing_key::Column::State.is_in([
                SigningKeyState::Provisioning.as_str(),
                SigningKeyState::Published.as_str(),
            ]))
            .lock_exclusive()
            .one(&transaction)
            .await
            .map_err(persistence)?;
        if pending_candidate.is_some() {
            return Err(ApplicationError::InvalidTransition);
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
        let key_id = Uuid::new_v4();
        let material_id = Uuid::new_v4();
        let key = project_signing_key::ActiveModel {
            id: Set(key_id),
            project_id: Set(project_id),
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
                project_id,
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
        transaction.commit().await.map_err(persistence)?;
        Ok((ring, key, operation))
    }

    async fn prepare_signing_key_stage(
        &self,
        project_id: Uuid,
        operation_alias: String,
        expected_project_revision: i64,
        request_digest: Vec<u8>,
    ) -> Result<PreparedSigningKey, ApplicationError> {
        let (_, key, operation) = self
            .prepare_signing_key_models(
                project_id,
                operation_alias,
                expected_project_revision,
                request_digest,
            )
            .await?;
        prepared_signing_key(key, operation)
    }

    async fn claim_signing_provider_action_stage(
        &self,
        project_id: Uuid,
        prepared: &PreparedSigningKey,
        now: OffsetDateTime,
        lease_until: OffsetDateTime,
    ) -> Result<SigningProviderAction, ApplicationError> {
        let lease_duration = lease_until - now;
        if lease_duration <= time::Duration::ZERO || lease_duration > time::Duration::minutes(5) {
            return Err(ApplicationError::InvalidInput);
        }
        let transaction = self.database.begin().await.map_err(persistence)?;
        let project = locked_project(&transaction, project_id).await?;
        let now = database_now(&transaction).await?;
        let lease_until = now + lease_duration;
        let operation = key_provisioning_operation::Entity::find_by_id(prepared.operation_id)
            .filter(key_provisioning_operation::Column::ProjectId.eq(project_id))
            .lock_exclusive()
            .one(&transaction)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        validate_signing_operation(prepared, &operation)?;
        if operation.state == "prepared" && project.status != "active" {
            let ring_revision = project_key_ring::Entity::find_by_id(operation.ring_id)
                .filter(project_key_ring::Column::ProjectId.eq(project_id))
                .one(&transaction)
                .await
                .map_err(persistence)?
                .ok_or(ApplicationError::NotFound)?
                .revision;
            let key_id = operation.key_id;
            transaction.commit().await.map_err(persistence)?;
            match self
                .transition_signing_key(
                    project_id,
                    key_id,
                    ring_revision,
                    SigningKeyState::Revoked,
                    "signing_key.revoked",
                    Uuid::new_v4(),
                )
                .await
            {
                Ok(_)
                | Err(ApplicationError::InvalidTransition | ApplicationError::RevisionConflict) => {
                    return Err(ApplicationError::Disabled);
                }
                Err(error) => return Err(error),
            }
        }
        if operation
            .provider_lease_expires_at
            .is_some_and(|expires_at| expires_at > now)
        {
            return Err(ApplicationError::OperationInProgress);
        }
        if operation.next_attempt_at.is_some_and(|due| due > now) {
            return Err(ApplicationError::OperationInProgress);
        }
        let (next_state, action) = match operation.state.as_str() {
            "prepared" => ("submitted", 0_u8),
            "submitted" => ("submitted", 1_u8),
            "cleanup_pending" | "cleanup_leased" => ("cleanup_leased", 2_u8),
            "cleanup_blocked" | "failed" | "abandoned" => {
                return Err(ApplicationError::InvalidTransition);
            }
            _ => return Err(ApplicationError::Integrity),
        };
        let token = Uuid::new_v4();
        let lease = SigningProviderLease { token };
        let mut active = operation.into_active_model();
        active.state = Set(next_state.to_owned());
        active.provider_lease_token = Set(Some(token));
        active.provider_lease_expires_at = Set(Some(lease_until));
        active.provider_lease_generation =
            Set(active.provider_lease_generation.take().unwrap_or(0) + 1);
        active.attempt_count = Set(active.attempt_count.take().unwrap_or(0) + 1);
        if action == 2 {
            active.destroy_attempt_count =
                Set(active.destroy_attempt_count.take().unwrap_or(0) + 1);
        }
        active.last_attempt_at = Set(Some(now));
        active.next_attempt_at = Set(None);
        active.update(&transaction).await.map_err(persistence)?;
        transaction.commit().await.map_err(persistence)?;
        Ok(match action {
            0 => SigningProviderAction::Provision(lease),
            1 => SigningProviderAction::Inspect(lease),
            2 => SigningProviderAction::Cleanup(lease),
            _ => return Err(ApplicationError::Integrity),
        })
    }

    #[allow(clippy::too_many_arguments)]
    async fn record_signing_provider_failure_stage(
        &self,
        project_id: Uuid,
        prepared: &PreparedSigningKey,
        lease: SigningProviderLease,
        provider_call: SigningProviderCall,
        error_class: ProviderErrorClass,
        retry: RetryClassification,
        error_code: Option<String>,
        recorded_at: OffsetDateTime,
    ) -> Result<(), ApplicationError> {
        let transaction = self.database.begin().await.map_err(persistence)?;
        let operation = key_provisioning_operation::Entity::find_by_id(prepared.operation_id)
            .filter(key_provisioning_operation::Column::ProjectId.eq(project_id))
            .lock_exclusive()
            .one(&transaction)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        validate_signing_operation(prepared, &operation)?;
        ensure_signing_provider_lease(&transaction, &operation, lease).await?;
        let next_state = match provider_call {
            SigningProviderCall::Provision => match retry {
                RetryClassification::ExactInputSafe => "prepared",
                _ => "submitted",
            },
            SigningProviderCall::Inspect => match retry {
                RetryClassification::Never => "cleanup_blocked",
                _ => "submitted",
            },
            SigningProviderCall::Cleanup => match retry {
                RetryClassification::Never => "cleanup_blocked",
                _ => "cleanup_pending",
            },
        };
        let retry_at = (retry != RetryClassification::Never).then(|| {
            let exponent = u32::try_from(operation.attempt_count.clamp(1, 6)).unwrap_or(6);
            let seconds = 1_i64 << exponent;
            recorded_at + time::Duration::seconds(seconds)
        });
        let mut active = operation.into_active_model();
        active.state = Set(next_state.to_owned());
        active.provider_lease_token = Set(None);
        active.provider_lease_expires_at = Set(None);
        active.next_attempt_at = Set(retry_at);
        active.last_provider_error_class =
            Set(Some(provider_error_class_name(error_class).to_owned()));
        active.last_retry_classification = Set(Some(retry_classification_name(retry).to_owned()));
        active.last_provider_error_code = Set(error_code);
        active.last_attempt_at = Set(Some(recorded_at));
        active.update(&transaction).await.map_err(persistence)?;
        transaction.commit().await.map_err(persistence)
    }

    async fn record_signing_provider_absence_stage(
        &self,
        project_id: Uuid,
        prepared: &PreparedSigningKey,
        lease: SigningProviderLease,
        recorded_at: OffsetDateTime,
    ) -> Result<(), ApplicationError> {
        let transaction = self.database.begin().await.map_err(persistence)?;
        let operation = key_provisioning_operation::Entity::find_by_id(prepared.operation_id)
            .filter(key_provisioning_operation::Column::ProjectId.eq(project_id))
            .lock_exclusive()
            .one(&transaction)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        validate_signing_operation(prepared, &operation)?;
        if operation.state != "submitted" {
            return Err(ApplicationError::OperationInProgress);
        }
        ensure_signing_provider_lease(&transaction, &operation, lease).await?;
        let project = project::Entity::find_by_id(project_id)
            .one(&transaction)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        let terminal = project.status != "active"
            || operation.last_retry_classification.as_deref() == Some("never");
        let mut active = operation.into_active_model();
        active.state = Set(if terminal {
            "failed".to_owned()
        } else {
            "prepared".to_owned()
        });
        active.provider_lease_token = Set(None);
        active.provider_lease_expires_at = Set(None);
        active.last_attempt_at = Set(Some(recorded_at));
        if !terminal {
            active.last_provider_error_class = Set(None);
            active.last_retry_classification = Set(None);
            active.last_provider_error_code = Set(None);
        }
        active.update(&transaction).await.map_err(persistence)?;
        transaction.commit().await.map_err(persistence)
    }

    async fn queue_signing_provider_cleanup_stage(
        &self,
        project_id: Uuid,
        prepared: &PreparedSigningKey,
        lease: SigningProviderLease,
        _recorded_at: OffsetDateTime,
    ) -> Result<(), ApplicationError> {
        let transaction = self.database.begin().await.map_err(persistence)?;
        let operation = key_provisioning_operation::Entity::find_by_id(prepared.operation_id)
            .filter(key_provisioning_operation::Column::ProjectId.eq(project_id))
            .lock_exclusive()
            .one(&transaction)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        validate_signing_operation(prepared, &operation)?;
        if operation.state == "cleanup_pending" && operation.provider_lease_token.is_none() {
            transaction.commit().await.map_err(persistence)?;
            return Ok(());
        }
        if operation.state != "submitted" {
            return Err(ApplicationError::OperationInProgress);
        }
        ensure_signing_provider_lease(&transaction, &operation, lease).await?;
        let mut active = operation.into_active_model();
        active.state = Set("cleanup_pending".to_owned());
        active.provider_lease_token = Set(None);
        active.provider_lease_expires_at = Set(None);
        active.next_attempt_at = Set(None);
        active.update(&transaction).await.map_err(persistence)?;
        transaction.commit().await.map_err(persistence)
    }

    #[allow(
        clippy::too_many_lines,
        reason = "cleanup atomically terminalizes the provider operation, protected material, key, ring, and audit"
    )]
    async fn complete_signing_provider_cleanup_stage(
        &self,
        project_id: Uuid,
        prepared: &PreparedSigningKey,
        lease: SigningProviderLease,
        destroyed: bool,
        correlation_id: Uuid,
        completed_at: OffsetDateTime,
    ) -> Result<(), ApplicationError> {
        let transaction = self.database.begin().await.map_err(persistence)?;
        let operation = key_provisioning_operation::Entity::find_by_id(prepared.operation_id)
            .filter(key_provisioning_operation::Column::ProjectId.eq(project_id))
            .one(&transaction)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        validate_signing_operation(prepared, &operation)?;
        if operation.state != "cleanup_leased"
            || operation.provider_lease_token != Some(lease.token)
        {
            return Err(ApplicationError::OperationInProgress);
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
        let operation = key_provisioning_operation::Entity::find_by_id(prepared.operation_id)
            .filter(key_provisioning_operation::Column::ProjectId.eq(project_id))
            .lock_exclusive()
            .one(&transaction)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        validate_signing_operation(prepared, &operation)?;
        if operation.state != "cleanup_leased" {
            return Err(ApplicationError::OperationInProgress);
        }
        ensure_signing_provider_lease(&transaction, &operation, lease).await?;
        if !destroyed {
            let mut active = operation.into_active_model();
            active.state = Set("cleanup_blocked".to_owned());
            active.provider_lease_token = Set(None);
            active.provider_lease_expires_at = Set(None);
            active.last_attempt_at = Set(Some(completed_at));
            active.update(&transaction).await.map_err(persistence)?;
            transaction.commit().await.map_err(persistence)?;
            return Ok(());
        }
        let material_id = operation.material_id;
        if key.state != SigningKeyState::Provisioning.as_str()
            && key.state != SigningKeyState::Abandoned.as_str()
        {
            return Err(ApplicationError::InvalidTransition);
        }
        let was_provisioning = key.state == SigningKeyState::Provisioning.as_str();
        let next_revision = if was_provisioning {
            ring.revision + 1
        } else {
            ring.revision
        };
        let mut key_active = key.into_active_model();
        key_active.state = Set(SigningKeyState::Abandoned.as_str().to_owned());
        key_active.signer_material_id = Set(material_id);
        key_active.ring_revision = Set(next_revision);
        key_active.updated_at = Set(completed_at);
        key_active.update(&transaction).await.map_err(persistence)?;
        let custody = self.custody();
        custody
            .materials
            .erase_by_id_in_transaction(&transaction, material_id, completed_at)
            .await?;
        if was_provisioning {
            let mut ring_active = ring.into_active_model();
            ring_active.revision = Set(next_revision);
            ring_active.signing_epoch = Set(ring_active.signing_epoch.take().unwrap_or(1) + 1);
            ring_active
                .update(&transaction)
                .await
                .map_err(persistence)?;
        }
        let mut operation_active = operation.into_active_model();
        operation_active.state = Set("abandoned".to_owned());
        operation_active.provider_lease_token = Set(None);
        operation_active.provider_lease_expires_at = Set(None);
        operation_active.abandoned_at = Set(Some(completed_at));
        operation_active.destroyed_at = Set(Some(completed_at));
        operation_active.last_attempt_at = Set(Some(completed_at));
        operation_active
            .update(&transaction)
            .await
            .map_err(persistence)?;
        if was_provisioning {
            insert_key_state_event(
                &transaction,
                project_id,
                prepared.ring_id,
                prepared.key_id,
                next_revision,
                SigningKeyState::Provisioning,
                SigningKeyState::Abandoned,
                completed_at,
            )
            .await?;
            insert_audit(
                &transaction,
                Some(project_id),
                "signing_key.abandoned",
                "signing_key",
                Some(prepared.key_id),
                correlation_id,
            )
            .await?;
        }
        transaction.commit().await.map_err(persistence)
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "containment carries exact operation, active-Project, lease, provider result, and timestamp fences"
    )]
    async fn record_protected_signing_key_material_stage(
        &self,
        project_id: Uuid,
        prepared: &PreparedSigningKey,
        lease: SigningProviderLease,
        material: ProvisionedProtectedSigningMaterial,
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
        validate_signing_operation(prepared, &operation)?;
        if operation.material_id != material.material_id {
            return Err(ApplicationError::Integrity);
        }
        if matches!(operation.state.as_str(), "stored" | "completed") {
            authenticate_committed_signing_provider_replay(
                &transaction,
                project_id,
                prepared,
                &material,
                &public_jwk,
            )
            .await?;
            transaction.commit().await.map_err(persistence)?;
            return Ok(());
        }
        if operation.state != "submitted" {
            return Err(ApplicationError::OperationInProgress);
        }
        ensure_signing_provider_lease(&transaction, &operation, lease).await?;
        let containment_error = (project.status != "active").then_some(ApplicationError::Disabled);
        let key = project_signing_key::Entity::find_by_id(prepared.key_id)
            .filter(project_signing_key::Column::ProjectId.eq(project_id))
            .filter(project_signing_key::Column::RingId.eq(prepared.ring_id))
            .lock_exclusive()
            .one(&transaction)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        if key.state != SigningKeyState::Provisioning.as_str()
            || key.signer_material_id != material.material_id
            || key.signer_material_id != prepared.signer_material_id
            || key.kid != prepared.kid
            || key.signer_material_generation != 1
        {
            return Err(ApplicationError::InvalidTransition);
        }
        validate_protected_signing_jwk(&prepared.kid, &material.public_key, &public_jwk)?;
        let mut key_active = key.into_active_model();
        key_active.public_jwk = Set(public_jwk);
        key_active.signer_material_id = Set(material.material_id);
        key_active.provisioned_at = Set(Some(recorded_at));
        key_active.updated_at = Set(recorded_at);
        key_active.update(&transaction).await.map_err(persistence)?;
        finalize_pending_material(
            &transaction,
            material.material_id,
            Some(project_id),
            material.handle.into_zeroizing().to_vec(),
            None,
            recorded_at,
        )
        .await?;
        let mut operation_active = operation.into_active_model();
        operation_active.state = Set(if containment_error.is_some() {
            "cleanup_pending".to_owned()
        } else {
            "stored".to_owned()
        });
        operation_active.provider_lease_token = Set(None);
        operation_active.provider_lease_expires_at = Set(None);
        operation_active.next_attempt_at = Set(None);
        operation_active.last_attempt_at = Set(Some(recorded_at));
        operation_active
            .update(&transaction)
            .await
            .map_err(persistence)?;
        transaction.commit().await.map_err(persistence)?;
        containment_error.map_or(Ok(()), Err)
    }

    #[allow(
        clippy::too_many_lines,
        reason = "publish atomically validates the accepted operation and contains stale or disabled material"
    )]
    async fn publish_signing_key_stage(
        &self,
        project_id: Uuid,
        prepared: &PreparedSigningKey,
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
        if project.status != "active" {
            if operation.state == "stored" {
                let mut operation_active = operation.into_active_model();
                operation_active.state = Set("cleanup_pending".to_owned());
                operation_active.next_attempt_at = Set(None);
                operation_active
                    .update(&transaction)
                    .await
                    .map_err(persistence)?;
                transaction.commit().await.map_err(persistence)?;
            }
            return Err(ApplicationError::Disabled);
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
            || key.signer_material_id != prepared.signer_material_id
            || key.kid != prepared.kid
        {
            return Err(ApplicationError::InvalidTransition);
        }
        if ring.revision != operation.expected_ring_revision {
            let mut operation_active = operation.into_active_model();
            operation_active.state = Set("cleanup_pending".to_owned());
            operation_active.next_attempt_at = Set(None);
            operation_active
                .update(&transaction)
                .await
                .map_err(persistence)?;
            transaction.commit().await.map_err(persistence)?;
            return Err(ApplicationError::RevisionConflict);
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

    async fn list_signing_keys(
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

    #[allow(
        clippy::too_many_lines,
        reason = "one bounded claim transaction keeps all three signing maintenance categories and their persistent fairness ordering visible"
    )]
    async fn signing_key_maintenance_items_stage(
        &self,
        limit: usize,
    ) -> Result<Vec<SigningKeyMaintenanceItem>, ApplicationError> {
        let item_limit = limit;
        let query_limit = u64::try_from(limit).map_err(|_| ApplicationError::InvalidInput)?;
        if !(1..=LIST_LIMIT).contains(&query_limit) {
            return Err(ApplicationError::InvalidInput);
        }
        let mut items = Vec::with_capacity(item_limit);
        let [operation_limit, published_limit, retiring_limit] =
            maintenance_category_limits(query_limit).map(|category_limit| {
                i64::try_from(category_limit).expect("maintenance limit is bounded to 100")
            });
        let now = database_now(&self.database).await?;

        // Claim each category in persistent oldest-claim order. The short transaction and
        // SKIP LOCKED make concurrent sweepers disjoint; committing the claim before inspecting
        // owner rows ensures one corrupt or externally pending item cannot pin the first page.
        let claim = self.database.begin().await.map_err(persistence)?;
        let operation_ids = claim_maintenance_ids(
            &claim,
            "WITH candidates AS (
                 SELECT id FROM key_provisioning_operations
                 WHERE state IN ('prepared','submitted','stored','cleanup_pending','cleanup_leased')
                   AND (next_attempt_at IS NULL OR next_attempt_at <= $1)
                   AND (provider_lease_expires_at IS NULL OR provider_lease_expires_at <= $1)
                 ORDER BY maintenance_claimed_at NULLS FIRST, id
                 FOR UPDATE SKIP LOCKED
                 LIMIT $2
             )
             UPDATE key_provisioning_operations AS operation
                SET maintenance_claimed_at = $1
               FROM candidates
              WHERE operation.id = candidates.id
             RETURNING operation.id",
            vec![now.into(), operation_limit.into()],
        )
        .await?;
        let published_ids = claim_maintenance_ids(
            &claim,
            "WITH candidates AS (
                 SELECT id FROM project_signing_keys
                 WHERE state = 'published'
                 ORDER BY maintenance_claimed_at NULLS FIRST, id
                 FOR UPDATE SKIP LOCKED
                 LIMIT $1
             )
             UPDATE project_signing_keys AS signing_key
                SET maintenance_claimed_at = transaction_timestamp()
               FROM candidates
              WHERE signing_key.id = candidates.id
             RETURNING signing_key.id",
            vec![published_limit.into()],
        )
        .await?;
        let retiring_ids = claim_maintenance_ids(
            &claim,
            "WITH candidates AS (
                 SELECT id FROM project_signing_keys
                 WHERE state = 'retiring' AND verify_not_after <= $1
                 ORDER BY maintenance_claimed_at NULLS FIRST, verify_not_after, id
                 FOR UPDATE SKIP LOCKED
                 LIMIT $2
             )
             UPDATE project_signing_keys AS signing_key
                SET maintenance_claimed_at = $1
               FROM candidates
              WHERE signing_key.id = candidates.id
             RETURNING signing_key.id",
            vec![now.into(), retiring_limit.into()],
        )
        .await?;
        claim.commit().await.map_err(persistence)?;

        let operations = key_provisioning_operation::Entity::find()
            .filter(key_provisioning_operation::Column::Id.is_in(operation_ids))
            .all(&self.database)
            .await
            .map_err(persistence)?;
        for operation in operations {
            let project = project::Entity::find_by_id(operation.project_id)
                .one(&self.database)
                .await
                .map_err(persistence)?
                .ok_or(ApplicationError::Integrity)?;
            items.push(SigningKeyMaintenanceItem::Provision {
                project_id: operation.project_id,
                key_id: operation.key_id,
                operation_alias: operation.operation_alias,
                expected_project_revision: project.metadata_revision,
            });
        }

        let published = project_signing_key::Entity::find()
            .filter(project_signing_key::Column::Id.is_in(published_ids))
            .all(&self.database)
            .await
            .map_err(persistence)?;
        for key in published {
            let ring = project_key_ring::Entity::find_by_id(key.ring_id)
                .filter(project_key_ring::Column::ProjectId.eq(key.project_id))
                .one(&self.database)
                .await
                .map_err(persistence)?
                .ok_or(ApplicationError::Integrity)?;
            items.push(SigningKeyMaintenanceItem::Activate {
                project_id: key.project_id,
                key_id: key.id,
                expected_ring_revision: ring.revision,
            });
        }

        let retiring = project_signing_key::Entity::find()
            .filter(project_signing_key::Column::Id.is_in(retiring_ids))
            .all(&self.database)
            .await
            .map_err(persistence)?;
        for key in retiring {
            let ring = project_key_ring::Entity::find_by_id(key.ring_id)
                .filter(project_key_ring::Column::ProjectId.eq(key.project_id))
                .one(&self.database)
                .await
                .map_err(persistence)?
                .ok_or(ApplicationError::Integrity)?;
            items.push(SigningKeyMaintenanceItem::Retire {
                project_id: key.project_id,
                key_id: key.id,
                expected_ring_revision: ring.revision,
            });
        }

        debug_assert!(items.len() <= item_limit);
        Ok(items)
    }

    async fn ensure_signing_key_activatable_stage(
        &self,
        project_id: Uuid,
        key_id: Uuid,
    ) -> Result<(), ApplicationError> {
        let candidate = find_signing_key(&self.database, project_id, key_id).await?;
        if candidate.state != SigningKeyState::Published.as_str()
            || candidate.published_at.is_none()
        {
            return Err(ApplicationError::InvalidTransition);
        }
        Ok(())
    }

    #[allow(
        clippy::too_many_lines,
        reason = "activation validates publication leases and rotates the key ring atomically"
    )]
    async fn activate_signing_key_if_ready(
        &self,
        project_id: Uuid,
        key_id: Uuid,
        expected_ring_revision: i64,
        correlation_id: Uuid,
    ) -> Result<SigningKeyRecord, ApplicationError> {
        let candidate = find_signing_key(&self.database, project_id, key_id).await?;
        let transaction = self.database.begin().await.map_err(persistence)?;
        // Match Runtime's global lock order: exact incarnation rows are always acquired before
        // Project/ring/publication rows. Holding these shared locks through activation also makes
        // predecessor leases atomically unusable when a replacement startup claims the ID.
        let current_incarnations = transaction
            .query_all_raw(Statement::from_sql_and_values(
                DbBackend::Postgres,
                "SELECT current.process_id,current.process_incarnation
                 FROM runtime_process_incarnations current
                 WHERE current.process_id IN (
                   SELECT required.process_id
                   FROM jsonb_array_elements_text($1::jsonb) required(process_id)
                   UNION
                   SELECT lease.process_id FROM runtime_publication_leases lease
                   WHERE lease.project_id=$2 AND lease.ring_id=$3
                     AND lease.expires_at>transaction_timestamp())
                 ORDER BY current.process_id LIMIT 65 FOR SHARE OF current",
                vec![
                    serde_json::json!(self.required_runtime_process_ids).into(),
                    project_id.into(),
                    candidate.ring_id.into(),
                ],
            ))
            .await
            .map_err(persistence)?
            .into_iter()
            .map(|row| {
                Ok((
                    row.try_get::<String>("", "process_id")
                        .map_err(persistence)?,
                    row.try_get::<Uuid>("", "process_incarnation")
                        .map_err(persistence)?,
                ))
            })
            .collect::<Result<Vec<_>, ApplicationError>>()?;
        if current_incarnations.len() > 64 {
            return Err(ApplicationError::Integrity);
        }
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
            current_incarnations
                .iter()
                .find(|(current_id, _)| current_id == process_id)
                .is_some_and(|(_, incarnation)| {
                    current_leases.iter().any(|lease| {
                        &lease.process_id == process_id && lease.process_incarnation == *incarnation
                    })
                })
        });
        let every_live_process_qualified = current_leases.iter().all(|lease| {
            current_incarnations
                .iter()
                .any(|(process_id, incarnation)| {
                    process_id == &lease.process_id && *incarnation == lease.process_incarnation
                })
                && lease.loaded_revision >= candidate.ring_revision
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

    async fn retire_signing_key(
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

    async fn revoke_signing_key(
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

    #[allow(
        clippy::too_many_lines,
        reason = "one transaction owns key transition, remote cleanup intent, ring revision, events, and audit"
    )]
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
        let project = locked_project(&transaction, project_id).await?;
        if project.status != "active" && target != SigningKeyState::Revoked {
            return Err(ApplicationError::Disabled);
        }
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
        let protected_operation_state =
            if target == SigningKeyState::Revoked && current == SigningKeyState::Provisioning {
                key_provisioning_operation::Entity::find()
                    .filter(key_provisioning_operation::Column::ProjectId.eq(project_id))
                    .filter(key_provisioning_operation::Column::KeyId.eq(key_id))
                    .lock_exclusive()
                    .one(&transaction)
                    .await
                    .map_err(persistence)?
                    .map(|operation| operation.state)
            } else {
                None
            };
        if protected_operation_state.as_deref() == Some("cleanup_leased") {
            return Err(ApplicationError::OperationInProgress);
        }
        let target = if target == SigningKeyState::Revoked
            && current == SigningKeyState::Provisioning
            && (key.public_jwk == json!({}) || protected_operation_state.is_some())
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
        let abandoned_material_id = if target == SigningKeyState::Abandoned {
            abandon_signing_key_operation(&transaction, project_id, key_id, now).await?
        } else {
            None
        };
        let next_revision = ring.revision + 1;
        let mut key_active = key.into_active_model();
        if let Some(material_id) = abandoned_material_id {
            key_active.signer_material_id = Set(material_id);
        }
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
        if let Some(material_id) = abandoned_material_id {
            let custody = self.custody();
            custody
                .materials
                .erase_by_id_in_transaction(&transaction, material_id, now)
                .await?;
        }
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
}

#[async_trait]
impl SigningKeyProvisioningPort for PostgresProvisioningAdapter {
    async fn prepare_signing_key(
        &self,
        project_id: Uuid,
        operation_alias: String,
        expected_project_revision: i64,
        request_digest: Vec<u8>,
    ) -> Result<PreparedSigningKey, ApplicationError> {
        self.prepare_signing_key_stage(
            project_id,
            operation_alias,
            expected_project_revision,
            request_digest,
        )
        .await
    }

    async fn prepared_signing_material(
        &self,
        project_id: Uuid,
        prepared: &PreparedSigningKey,
    ) -> Result<Option<PreparedSigningMaterial>, ApplicationError> {
        let operation = key_provisioning_operation::Entity::find_by_id(prepared.operation_id)
            .filter(key_provisioning_operation::Column::ProjectId.eq(project_id))
            .one(&self.database)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        if operation.key_id != prepared.key_id
            || operation.ring_id != prepared.ring_id
            || operation.request_digest != prepared.request_digest
        {
            return Err(ApplicationError::Integrity);
        }
        let material_id = operation.material_id;
        let custody = self.custody();
        let reservation = custody
            .materials
            .load_project_reservation(project_id, material_id, MaterialPurpose::SigningSeed)
            .await?;
        if reservation.owner_kind != MaterialOwnerKind::SigningKey
            || reservation.owner_id != prepared.key_id
            || reservation.generation != 1
            || reservation.material_kind != MaterialKind::SigningKey
        {
            return Err(ApplicationError::Integrity);
        }
        let stored_material = protected_material::Entity::find_by_id(material_id)
            .filter(protected_material::Column::ProjectId.eq(project_id))
            .one(&self.database)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::Integrity)?;
        let (committed_handle, committed_public_key) =
            if let Some(opaque_value) = stored_material.opaque_value {
                if stored_material.state != "live" {
                    return Err(ApplicationError::Integrity);
                }
                let owner = project_signing_key::Entity::find_by_id(prepared.key_id)
                    .filter(project_signing_key::Column::ProjectId.eq(project_id))
                    .one(&self.database)
                    .await
                    .map_err(persistence)?
                    .ok_or(ApplicationError::Integrity)?;
                let public_key = signing_public_key_from_jwk(&owner.public_jwk)?;
                validate_protected_signing_jwk(&prepared.kid, &public_key, &owner.public_jwk)?;
                (
                    Some(OpaqueHandle::new(opaque_value).map_err(|_| ApplicationError::Integrity)?),
                    Some(public_key),
                )
            } else {
                (None, None)
            };
        Ok(Some(PreparedSigningMaterial {
            material_id,
            provider_id: reservation.provider_id,
            provider_format_version: reservation.provider_format_version,
            context: reservation.context,
            committed_handle,
            committed_public_key,
        }))
    }

    async fn claim_signing_provider_action(
        &self,
        project_id: Uuid,
        prepared: &PreparedSigningKey,
        now: OffsetDateTime,
        lease_until: OffsetDateTime,
    ) -> Result<SigningProviderAction, ApplicationError> {
        self.claim_signing_provider_action_stage(project_id, prepared, now, lease_until)
            .await
    }

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
    ) -> Result<(), ApplicationError> {
        self.record_signing_provider_failure_stage(
            project_id,
            prepared,
            lease,
            provider_call,
            error_class,
            retry,
            error_code,
            recorded_at,
        )
        .await
    }

    async fn record_signing_provider_absence(
        &self,
        project_id: Uuid,
        prepared: &PreparedSigningKey,
        lease: SigningProviderLease,
        recorded_at: OffsetDateTime,
    ) -> Result<(), ApplicationError> {
        self.record_signing_provider_absence_stage(project_id, prepared, lease, recorded_at)
            .await
    }

    async fn queue_signing_provider_cleanup(
        &self,
        project_id: Uuid,
        prepared: &PreparedSigningKey,
        lease: SigningProviderLease,
        recorded_at: OffsetDateTime,
    ) -> Result<(), ApplicationError> {
        self.queue_signing_provider_cleanup_stage(project_id, prepared, lease, recorded_at)
            .await
    }

    async fn complete_signing_provider_cleanup(
        &self,
        project_id: Uuid,
        prepared: &PreparedSigningKey,
        lease: SigningProviderLease,
        destroyed: bool,
        correlation_id: Uuid,
        completed_at: OffsetDateTime,
    ) -> Result<(), ApplicationError> {
        self.complete_signing_provider_cleanup_stage(
            project_id,
            prepared,
            lease,
            destroyed,
            correlation_id,
            completed_at,
        )
        .await
    }

    async fn record_protected_signing_key_material(
        &self,
        project_id: Uuid,
        prepared: &PreparedSigningKey,
        lease: SigningProviderLease,
        material: ProvisionedProtectedSigningMaterial,
        public_jwk: Value,
        recorded_at: OffsetDateTime,
    ) -> Result<(), ApplicationError> {
        self.record_protected_signing_key_material_stage(
            project_id,
            prepared,
            lease,
            material,
            public_jwk,
            recorded_at,
        )
        .await
    }

    async fn publish_signing_key(
        &self,
        project_id: Uuid,
        prepared: &PreparedSigningKey,
        correlation_id: Uuid,
        published_at: OffsetDateTime,
    ) -> Result<SigningKeyRecord, ApplicationError> {
        self.publish_signing_key_stage(project_id, prepared, correlation_id, published_at)
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

    async fn signing_key_maintenance_items(
        &self,
        limit: usize,
    ) -> Result<Vec<SigningKeyMaintenanceItem>, ApplicationError> {
        self.signing_key_maintenance_items_stage(limit).await
    }

    async fn ensure_signing_key_activatable(
        &self,
        project_id: Uuid,
        key_id: Uuid,
    ) -> Result<(), ApplicationError> {
        self.ensure_signing_key_activatable_stage(project_id, key_id)
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

#[cfg(test)]
mod maintenance_limit_tests {
    use super::maintenance_category_limits;

    #[test]
    fn category_claim_quotas_never_exceed_or_drop_the_worker_limit() {
        for limit in 1..=100 {
            let quotas = maintenance_category_limits(limit);
            assert_eq!(quotas.into_iter().sum::<u64>(), limit);
            assert!(quotas.into_iter().max().unwrap() - quotas.into_iter().min().unwrap() <= 1);
        }
        assert_eq!(maintenance_category_limits(100), [34, 33, 33]);
    }
}
