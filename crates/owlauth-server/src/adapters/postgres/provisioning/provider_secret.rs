use super::{
    ActiveModelTrait, ApplicationError, CONFIGURATION_VALUE_LIMIT, ColumnTrait,
    DatabaseTransaction, EntityTrait, IntoActiveModel, LIST_LIMIT, MaterialKind, MaterialOwnerKind,
    MaterialPurpose, OffsetDateTime, PostgresProvisioningAdapter, PrepareProvider,
    PrepareProviderSecretReplacement, PreparedProvider, PreparedSecretMaterial,
    ProviderProvisioningPort, ProviderRecord, ProviderRecovery, ProviderSecretReplacementRecovery,
    ProviderStatus, QueryFilter, QueryOrder, QuerySelect, SealedProtectedMaterial, Set,
    TransactionTrait, UpdateProvider, Uuid, active_application, active_project,
    application_provider_assignment, async_trait, bounded_list, bump_application_security,
    bump_provider_revision, enforce_project_fence, enforce_provider_egress_fence, ensure_capacity,
    ensure_no_pending_secret_replacement, ensure_project, finalize_pending_material, find_provider,
    insert_audit, locked_active_provider, locked_project, persistence, prepared_provider,
    project_provider_egress_policy, provider_configuration, provider_secret_generation,
    provider_secret_operation, requires_project_reauthorization,
};

async fn locked_pending_secret_replacement(
    transaction: &DatabaseTransaction,
    project_id: Uuid,
    provider_id: Uuid,
) -> Result<provider_secret_operation::Model, ApplicationError> {
    provider_secret_operation::Entity::find()
        .filter(provider_secret_operation::Column::ProjectId.eq(project_id))
        .filter(provider_secret_operation::Column::ProviderId.eq(provider_id))
        .filter(provider_secret_operation::Column::OperationKind.eq("replace"))
        .filter(provider_secret_operation::Column::State.is_in(["prepared", "stored"]))
        .lock_exclusive()
        .one(transaction)
        .await
        .map_err(persistence)?
        .ok_or(ApplicationError::NotFound)
}

impl PostgresProvisioningAdapter {
    #[allow(
        clippy::too_many_lines,
        reason = "one transaction owns the full provider reservation and replay fence"
    )]
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
            if operation.request_digest.as_slice() != command.request_digest.as_slice()
                || operation.egress_policy_revision != command.egress_policy_revision
            {
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
        ensure_capacity(
            providers.len(),
            LIST_LIMIT,
            ApplicationError::CapacityExceeded,
        )?;
        let egress_policy_revision = if command.kind == crate::domain::ProviderKind::Oidc {
            let expected = command
                .egress_policy_revision
                .ok_or(ApplicationError::InvalidInput)?;
            let current = project_provider_egress_policy::Entity::find_by_id(project_id)
                .lock_shared()
                .one(&transaction)
                .await
                .map_err(persistence)?
                .ok_or(ApplicationError::Integrity)?;
            if current.revision != expected {
                return Err(ApplicationError::RevisionConflict);
            }
            Some(expected)
        } else if command.egress_policy_revision.is_none() {
            None
        } else {
            return Err(ApplicationError::InvalidInput);
        };
        let provider_key = crate::domain::ProviderKey::parse(command.provider_key.clone())?;
        let callback_url = crate::domain::provider_callback_url(
            &self.runtime_base,
            &project.public_id,
            &provider_key,
        )?;
        let provider_id = Uuid::new_v4();
        let material_id = Uuid::new_v4();
        let provider = provider_configuration::ActiveModel {
            id: Set(provider_id),
            project_id: Set(project_id),
            provider_key: Set(command.provider_key),
            kind: Set(command.kind.as_str().to_owned()),
            display_name: Set(command.display_name),
            issuer: Set(command.issuer),
            client_id: Set(command.client_id),
            callback_url: Set(callback_url),
            secret_material_id: Set(material_id),
            secret_generation: Set(1),
            status: Set("provisioning".to_owned()),
            revision: Set(1),
            managed_profile_enabled: Set(command.managed_profile_enabled),
            managed_profile_revision: Set(1),
            onboarding_policy_revision: Set(egress_policy_revision),
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
                MaterialOwnerKind::ProviderSecret,
                provider.id,
                1,
                MaterialKind::ConfigurationSecret,
                MaterialPurpose::ProviderClientSecret,
                custody.secrets.provider_id.clone(),
                custody.secrets.provider_format_version,
            )
            .await?;
        let operation = provider_secret_operation::ActiveModel {
            id: Set(Uuid::new_v4()),
            project_id: Set(project_id),
            provider_id: Set(provider.id),
            operation_alias: Set(command.operation_alias),
            operation_kind: Set("create".to_owned()),
            target_secret_generation: Set(1),
            target_display_name: Set(provider.display_name.clone()),
            target_client_id: Set(provider.client_id.clone()),
            request_digest: Set(command.request_digest),
            state: Set("prepared".to_owned()),
            attempt_count: Set(0),
            expected_project_revision: Set(command.expected_project_revision),
            expected_provider_revision: Set(1),
            egress_policy_revision: Set(egress_policy_revision),
            material_id: Set(material_id),
            last_attempt_at: Set(None),
            completed_at: Set(None),
        }
        .insert(&transaction)
        .await
        .map_err(persistence)?;
        transaction.commit().await.map_err(persistence)?;
        prepared_provider(operation)
    }

    #[allow(clippy::too_many_arguments)]
    #[allow(
        clippy::too_many_lines,
        reason = "one transaction verifies and publishes the protected provider owner"
    )]
    async fn finalize_protected_provider_stage(
        &self,
        project_id: Uuid,
        prepared: &PreparedProvider,
        expected_project_revision: i64,
        material: SealedProtectedMaterial,
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
            || operation.operation_kind != "create"
            || operation.target_secret_generation != 1
            || operation.request_digest != prepared.request_digest
            || operation.material_id != material.material_id
        {
            return Err(ApplicationError::Integrity);
        }
        let custody = self.custody();
        let reservation = custody
            .materials
            .load_project_reservation_in_transaction(
                &transaction,
                project_id,
                material.material_id,
                MaterialPurpose::ProviderClientSecret,
            )
            .await?;
        if reservation.owner_kind != MaterialOwnerKind::ProviderSecret
            || reservation.owner_id != prepared.provider_id
            || reservation.generation != 1
            || reservation.material_kind != MaterialKind::ConfigurationSecret
            || reservation.provider_id != material.provider_id
            || reservation.provider_format_version != material.provider_format_version
        {
            return Err(ApplicationError::Integrity);
        }
        if operation.state == "completed" {
            finalize_pending_material(
                &transaction,
                material.material_id,
                Some(project_id),
                material.envelope.into_zeroizing().to_vec(),
                Some(material.request_fingerprint.into_bytes()),
                finalized_at,
            )
            .await?;
            let generation = provider_secret_generation::Entity::find_by_id((
                project_id,
                prepared.provider_id,
                operation.target_secret_generation,
            ))
            .one(&transaction)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::Integrity)?;
            if generation.material_id != material.material_id {
                return Err(ApplicationError::Integrity);
            }
            transaction.commit().await.map_err(persistence)?;
            return self.get_provider(project_id, prepared.provider_id).await;
        }
        enforce_project_fence(&project, expected_project_revision)?;
        enforce_provider_egress_fence(&transaction, project_id, operation.egress_policy_revision)
            .await?;
        if operation.expected_project_revision != expected_project_revision
            || !matches!(operation.state.as_str(), "prepared" | "stored")
        {
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
            || provider.secret_generation != 1
        {
            return Err(ApplicationError::InvalidTransition);
        }
        let mut status = ProviderStatus::Provisioning;
        status
            .provision()
            .map_err(|_| ApplicationError::InvalidTransition)?;
        let mut provider_active = provider.into_active_model();
        provider_active.secret_material_id = Set(material.material_id);
        provider_active.status = Set(status.as_str().to_owned());
        provider_active.revision = Set(operation.expected_provider_revision + 1);
        let updated = provider_active
            .update(&transaction)
            .await
            .map_err(persistence)?;
        finalize_pending_material(
            &transaction,
            material.material_id,
            Some(project_id),
            material.envelope.into_zeroizing().to_vec(),
            Some(material.request_fingerprint.into_bytes()),
            finalized_at,
        )
        .await?;
        let generation =
            provider_secret_generation::Entity::find_by_id((project_id, prepared.provider_id, 1))
                .lock_exclusive()
                .one(&transaction)
                .await
                .map_err(persistence)?
                .ok_or(ApplicationError::Integrity)?;
        if generation.material_id != material.material_id || generation.status != "pending" {
            return Err(ApplicationError::Integrity);
        }
        let mut generation_active = generation.into_active_model();
        generation_active.status = Set("active".to_owned());
        generation_active.activated_at = Set(Some(finalized_at));
        generation_active
            .update(&transaction)
            .await
            .map_err(persistence)?;
        let mut operation_active = operation.into_active_model();
        operation_active.state = Set("completed".to_owned());
        operation_active.attempt_count =
            Set(operation_active.attempt_count.take().unwrap_or(0) + 1);
        operation_active.last_attempt_at = Set(Some(finalized_at));
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

    async fn prepare_provider_secret_replacement_stage(
        &self,
        project_id: Uuid,
        provider_id: Uuid,
        command: PrepareProviderSecretReplacement,
    ) -> Result<PreparedProvider, ApplicationError> {
        let transaction = self.database.begin().await.map_err(persistence)?;
        let project = active_project(&transaction, project_id).await?;
        if let Some(operation) = provider_secret_operation::Entity::find()
            .filter(provider_secret_operation::Column::ProjectId.eq(project_id))
            .filter(provider_secret_operation::Column::OperationAlias.eq(&command.operation_alias))
            .lock_exclusive()
            .one(&transaction)
            .await
            .map_err(persistence)?
        {
            if operation.provider_id != provider_id
                || operation.operation_kind != "replace"
                || operation.request_digest != command.request_digest
                || operation.expected_provider_revision != command.expected_provider_revision
            {
                return Err(ApplicationError::IdempotencyConflict);
            }
            transaction.commit().await.map_err(persistence)?;
            return prepared_provider(operation);
        }
        let provider = locked_active_provider(&transaction, project_id, provider_id).await?;
        if provider.revision != command.expected_provider_revision {
            return Err(ApplicationError::RevisionConflict);
        }
        ensure_no_pending_secret_replacement(&transaction, project_id, provider_id).await?;
        let latest_generation = provider_secret_generation::Entity::find()
            .filter(provider_secret_generation::Column::ProjectId.eq(project_id))
            .filter(provider_secret_generation::Column::ProviderId.eq(provider_id))
            .order_by_desc(provider_secret_generation::Column::Generation)
            .one(&transaction)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::Integrity)?;
        let target_generation = latest_generation
            .generation
            .checked_add(1)
            .ok_or(ApplicationError::CapacityExceeded)?;
        let material_id = Uuid::new_v4();
        let custody = self.custody();
        custody
            .materials
            .reserve_project_in_transaction(
                &transaction,
                project_id,
                material_id,
                MaterialOwnerKind::ProviderSecret,
                provider.id,
                target_generation,
                MaterialKind::ConfigurationSecret,
                MaterialPurpose::ProviderClientSecret,
                custody.secrets.provider_id.clone(),
                custody.secrets.provider_format_version,
            )
            .await?;
        provider_secret_generation::ActiveModel {
            project_id: Set(project_id),
            provider_id: Set(provider.id),
            generation: Set(target_generation),
            material_id: Set(material_id),
            status: Set("pending".to_owned()),
            created_at: Set(self.clock.now()),
            activated_at: Set(None),
            retired_at: Set(None),
            abandoned_at: Set(None),
        }
        .insert(&transaction)
        .await
        .map_err(persistence)?;
        let operation = provider_secret_operation::ActiveModel {
            id: Set(Uuid::new_v4()),
            project_id: Set(project_id),
            provider_id: Set(provider.id),
            operation_alias: Set(command.operation_alias),
            operation_kind: Set("replace".to_owned()),
            target_secret_generation: Set(target_generation),
            target_display_name: Set(command.display_name),
            target_client_id: Set(command.client_id),
            request_digest: Set(command.request_digest),
            state: Set("prepared".to_owned()),
            attempt_count: Set(0),
            expected_project_revision: Set(project.metadata_revision),
            expected_provider_revision: Set(command.expected_provider_revision),
            egress_policy_revision: Set(None),
            material_id: Set(material_id),
            last_attempt_at: Set(None),
            completed_at: Set(None),
        }
        .insert(&transaction)
        .await
        .map_err(persistence)?;
        transaction.commit().await.map_err(persistence)?;
        prepared_provider(operation)
    }

    #[allow(
        clippy::too_many_arguments,
        clippy::too_many_lines,
        reason = "replacement finalization keeps the protected generation transition in one auditable transaction"
    )]
    async fn finalize_provider_secret_replacement_stage(
        &self,
        project_id: Uuid,
        prepared: &PreparedProvider,
        expected_provider_revision: i64,
        material: SealedProtectedMaterial,
        correlation_id: Uuid,
        finalized_at: OffsetDateTime,
    ) -> Result<ProviderRecord, ApplicationError> {
        let transaction = self.database.begin().await.map_err(persistence)?;
        active_project(&transaction, project_id).await?;
        let provider =
            locked_active_provider(&transaction, project_id, prepared.provider_id).await?;
        let operation = provider_secret_operation::Entity::find_by_id(prepared.operation_id)
            .filter(provider_secret_operation::Column::ProjectId.eq(project_id))
            .lock_exclusive()
            .one(&transaction)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        if operation.provider_id != prepared.provider_id
            || operation.operation_kind != "replace"
            || operation.request_digest != prepared.request_digest
            || operation.material_id != material.material_id
        {
            return Err(ApplicationError::Integrity);
        }
        let custody = self.custody();
        let reservation = custody
            .materials
            .load_project_reservation_in_transaction(
                &transaction,
                project_id,
                material.material_id,
                MaterialPurpose::ProviderClientSecret,
            )
            .await?;
        if reservation.owner_kind != MaterialOwnerKind::ProviderSecret
            || reservation.owner_id != prepared.provider_id
            || reservation.generation != operation.target_secret_generation
            || reservation.material_kind != MaterialKind::ConfigurationSecret
            || reservation.provider_id != material.provider_id
            || reservation.provider_format_version != material.provider_format_version
        {
            return Err(ApplicationError::Integrity);
        }
        if operation.state == "completed" {
            finalize_pending_material(
                &transaction,
                material.material_id,
                Some(project_id),
                material.envelope.into_zeroizing().to_vec(),
                Some(material.request_fingerprint.into_bytes()),
                finalized_at,
            )
            .await?;
            transaction.commit().await.map_err(persistence)?;
            return self.get_provider(project_id, prepared.provider_id).await;
        }
        if operation.expected_provider_revision != expected_provider_revision
            || !matches!(operation.state.as_str(), "prepared" | "stored")
        {
            return Err(ApplicationError::InvalidTransition);
        }
        if provider.revision != expected_provider_revision
            || provider.secret_generation >= operation.target_secret_generation
        {
            return Err(ApplicationError::RevisionConflict);
        }
        let current_generation = provider_secret_generation::Entity::find_by_id((
            project_id,
            provider.id,
            provider.secret_generation,
        ))
        .lock_exclusive()
        .one(&transaction)
        .await
        .map_err(persistence)?
        .ok_or(ApplicationError::Integrity)?;
        let target_generation = provider_secret_generation::Entity::find_by_id((
            project_id,
            provider.id,
            operation.target_secret_generation,
        ))
        .lock_exclusive()
        .one(&transaction)
        .await
        .map_err(persistence)?
        .ok_or(ApplicationError::Integrity)?;
        if current_generation.status != "active"
            || current_generation.material_id != provider.secret_material_id
            || target_generation.status != "pending"
            || target_generation.material_id != material.material_id
        {
            return Err(ApplicationError::Integrity);
        }
        finalize_pending_material(
            &transaction,
            material.material_id,
            Some(project_id),
            material.envelope.into_zeroizing().to_vec(),
            Some(material.request_fingerprint.into_bytes()),
            finalized_at,
        )
        .await?;
        let old_material_id = provider.secret_material_id;
        let mut provider_active = provider.into_active_model();
        provider_active.display_name = Set(operation.target_display_name.clone());
        provider_active.client_id = Set(operation.target_client_id.clone());
        provider_active.secret_material_id = Set(material.material_id);
        provider_active.secret_generation = Set(operation.target_secret_generation);
        provider_active.revision = Set(expected_provider_revision + 1);
        let updated = provider_active
            .update(&transaction)
            .await
            .map_err(persistence)?;
        let mut current_active = current_generation.into_active_model();
        current_active.status = Set("retired".to_owned());
        current_active.retired_at = Set(Some(finalized_at));
        current_active
            .update(&transaction)
            .await
            .map_err(persistence)?;
        let mut target_active = target_generation.into_active_model();
        target_active.status = Set("active".to_owned());
        target_active.activated_at = Set(Some(finalized_at));
        target_active
            .update(&transaction)
            .await
            .map_err(persistence)?;
        custody
            .materials
            .erase_by_id_in_transaction(&transaction, old_material_id, finalized_at)
            .await?;
        let mut operation_active = operation.into_active_model();
        operation_active.state = Set("completed".to_owned());
        operation_active.attempt_count =
            Set(operation_active.attempt_count.take().unwrap_or(0) + 1);
        operation_active.last_attempt_at = Set(Some(finalized_at));
        operation_active.completed_at = Set(Some(finalized_at));
        operation_active
            .update(&transaction)
            .await
            .map_err(persistence)?;
        insert_audit(
            &transaction,
            Some(project_id),
            "provider.secret_replaced",
            "provider",
            Some(updated.id),
            correlation_id,
        )
        .await?;
        transaction.commit().await.map_err(persistence)?;
        self.provider_record(updated).await
    }

    async fn provider_secret_replacement_recovery_stage(
        &self,
        project_id: Uuid,
        provider_id: Uuid,
        expected_provider_revision: i64,
    ) -> Result<ProviderSecretReplacementRecovery, ApplicationError> {
        let transaction = self.database.begin().await.map_err(persistence)?;
        active_project(&transaction, project_id).await?;
        let provider = locked_active_provider(&transaction, project_id, provider_id).await?;
        if provider.revision != expected_provider_revision {
            return Err(ApplicationError::RevisionConflict);
        }
        let operation =
            locked_pending_secret_replacement(&transaction, project_id, provider_id).await?;
        if operation.expected_provider_revision != expected_provider_revision
            || operation.target_secret_generation <= provider.secret_generation
        {
            return Err(ApplicationError::RevisionConflict);
        }
        transaction.commit().await.map_err(persistence)?;
        Ok(ProviderSecretReplacementRecovery {
            operation_alias: operation.operation_alias,
            display_name: operation.target_display_name,
            client_id: operation.target_client_id,
            expected_provider_revision: operation.expected_provider_revision,
        })
    }

    async fn abandon_provider_secret_replacement_stage(
        &self,
        project_id: Uuid,
        provider_id: Uuid,
        expected_provider_revision: i64,
        correlation_id: Uuid,
        abandoned_at: OffsetDateTime,
    ) -> Result<ProviderRecord, ApplicationError> {
        let transaction = self.database.begin().await.map_err(persistence)?;
        active_project(&transaction, project_id).await?;
        let provider = locked_active_provider(&transaction, project_id, provider_id).await?;
        if provider.revision != expected_provider_revision {
            return Err(ApplicationError::RevisionConflict);
        }
        let operation =
            locked_pending_secret_replacement(&transaction, project_id, provider_id).await?;
        if operation.expected_provider_revision != expected_provider_revision
            || operation.target_secret_generation <= provider.secret_generation
        {
            return Err(ApplicationError::RevisionConflict);
        }
        let generation = provider_secret_generation::Entity::find_by_id((
            project_id,
            provider_id,
            operation.target_secret_generation,
        ))
        .lock_exclusive()
        .one(&transaction)
        .await
        .map_err(persistence)?
        .ok_or(ApplicationError::Integrity)?;
        if generation.status != "pending"
            || generation.material_id != operation.material_id
            || generation.abandoned_at.is_some()
        {
            return Err(ApplicationError::Integrity);
        }
        self.custody()
            .materials
            .erase_by_id_in_transaction(&transaction, operation.material_id, abandoned_at)
            .await?;
        let mut generation_active = generation.into_active_model();
        generation_active.status = Set("abandoned".to_owned());
        generation_active.abandoned_at = Set(Some(abandoned_at));
        generation_active
            .update(&transaction)
            .await
            .map_err(persistence)?;
        let mut operation_active = operation.into_active_model();
        operation_active.state = Set("abandoned".to_owned());
        operation_active.attempt_count =
            Set(operation_active.attempt_count.take().unwrap_or(0) + 1);
        operation_active.last_attempt_at = Set(Some(abandoned_at));
        operation_active.completed_at = Set(Some(abandoned_at));
        operation_active
            .update(&transaction)
            .await
            .map_err(persistence)?;
        insert_audit(
            &transaction,
            Some(project_id),
            "provider.secret_replacement_abandoned",
            "provider",
            Some(provider_id),
            correlation_id,
        )
        .await?;
        transaction.commit().await.map_err(persistence)?;
        self.provider_record(provider).await
    }

    async fn update_provider(
        &self,
        project_id: Uuid,
        provider_id: Uuid,
        command: UpdateProvider,
        correlation_id: Uuid,
    ) -> Result<ProviderRecord, ApplicationError> {
        let transaction = self.database.begin().await.map_err(persistence)?;
        active_project(&transaction, project_id).await?;
        let provider = locked_active_provider(&transaction, project_id, provider_id).await?;
        if provider.revision != command.expected_provider_revision {
            return Err(ApplicationError::RevisionConflict);
        }
        ensure_no_pending_secret_replacement(&transaction, project_id, provider_id).await?;
        let mut active = provider.into_active_model();
        active.display_name = Set(command.display_name);
        active.client_id = Set(command.client_id);
        active.revision = Set(command.expected_provider_revision + 1);
        let updated = active.update(&transaction).await.map_err(persistence)?;
        insert_audit(
            &transaction,
            Some(project_id),
            "provider.updated",
            "provider",
            Some(provider_id),
            correlation_id,
        )
        .await?;
        transaction.commit().await.map_err(persistence)?;
        self.provider_record(updated).await
    }

    async fn list_providers(
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
            .filter(provider_secret_operation::Column::OperationKind.eq("create"))
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
        let provider_kind =
            super::super::provider_row::effective_provider_kind(&provider.kind, &provider.issuer)?;
        Ok(ProviderRecovery {
            operation_alias: operation.operation_alias,
            kind: provider_kind,
            provider_key: provider.provider_key,
            display_name: provider.display_name,
            issuer: provider.issuer,
            client_id: provider.client_id,
            managed_profile_enabled: provider.managed_profile_enabled,
            egress_policy_revision: operation.egress_policy_revision,
        })
    }

    async fn assign_provider(
        &self,
        project_id: Uuid,
        provider_id: Uuid,
        application_id: Uuid,
        expected_application_revision: i64,
        correlation_id: Uuid,
    ) -> Result<ProviderRecord, ApplicationError> {
        let transaction = self.database.begin().await.map_err(persistence)?;
        active_project(&transaction, project_id).await?;
        let provider = locked_active_provider(&transaction, project_id, provider_id).await?;
        ensure_no_pending_secret_replacement(&transaction, project_id, provider_id).await?;
        let application = active_application(&transaction, project_id, application_id).await?;
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
            ApplicationError::CapacityExceeded,
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
            ApplicationError::CapacityExceeded,
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

    async fn unassign_provider(
        &self,
        project_id: Uuid,
        provider_id: Uuid,
        application_id: Uuid,
        expected_application_revision: i64,
        correlation_id: Uuid,
    ) -> Result<ProviderRecord, ApplicationError> {
        let transaction = self.database.begin().await.map_err(persistence)?;
        active_project(&transaction, project_id).await?;
        let provider = locked_active_provider(&transaction, project_id, provider_id).await?;
        ensure_no_pending_secret_replacement(&transaction, project_id, provider_id).await?;
        let application = active_application(&transaction, project_id, application_id).await?;
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

    async fn disable_provider(
        &self,
        project_id: Uuid,
        provider_id: Uuid,
        expected_provider_revision: i64,
        correlation_id: Uuid,
    ) -> Result<ProviderRecord, ApplicationError> {
        let transaction = self.database.begin().await.map_err(persistence)?;
        active_project(&transaction, project_id).await?;
        let provider = locked_active_provider(&transaction, project_id, provider_id).await?;
        if provider.revision != expected_provider_revision {
            return Err(ApplicationError::RevisionConflict);
        }
        ensure_no_pending_secret_replacement(&transaction, project_id, provider_id).await?;
        let assignments = application_provider_assignment::Entity::find()
            .filter(application_provider_assignment::Column::ProjectId.eq(project_id))
            .filter(application_provider_assignment::Column::ProviderId.eq(provider_id))
            .filter(application_provider_assignment::Column::Status.eq("active"))
            .order_by_asc(application_provider_assignment::Column::ApplicationId)
            .all(&transaction)
            .await
            .map_err(persistence)?;
        let mut applications = Vec::with_capacity(assignments.len());
        for assignment in &assignments {
            applications.push(
                active_application(&transaction, project_id, assignment.application_id).await?,
            );
        }
        for (assignment, application) in assignments.into_iter().zip(applications) {
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
        let secret_replacement_pending = provider_secret_operation::Entity::find()
            .filter(provider_secret_operation::Column::ProjectId.eq(provider.project_id))
            .filter(provider_secret_operation::Column::ProviderId.eq(provider.id))
            .filter(provider_secret_operation::Column::OperationKind.eq("replace"))
            .filter(provider_secret_operation::Column::State.is_in(["prepared", "stored"]))
            .one(&self.database)
            .await
            .map_err(persistence)?
            .is_some();
        let provider_kind =
            super::super::provider_row::effective_provider_kind(&provider.kind, &provider.issuer)?;
        Ok(ProviderRecord {
            id: provider.id,
            project_id: provider.project_id,
            provider_key: provider.provider_key,
            kind: provider_kind.as_str().to_owned(),
            display_name: provider.display_name,
            issuer: provider.issuer,
            client_id: provider.client_id,
            callback_url: provider.callback_url,
            status: provider.status,
            revision: provider.revision,
            managed_profile_enabled: provider.managed_profile_enabled,
            managed_profile_revision: provider.managed_profile_revision,
            secret_replacement_pending,
            assigned_application_ids: assignments,
        })
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

    async fn prepare_provider_secret_replacement(
        &self,
        project_id: Uuid,
        provider_id: Uuid,
        command: PrepareProviderSecretReplacement,
    ) -> Result<PreparedProvider, ApplicationError> {
        self.prepare_provider_secret_replacement_stage(project_id, provider_id, command)
            .await
    }

    async fn provider_secret_replacement_recovery(
        &self,
        project_id: Uuid,
        provider_id: Uuid,
        expected_provider_revision: i64,
    ) -> Result<ProviderSecretReplacementRecovery, ApplicationError> {
        self.provider_secret_replacement_recovery_stage(
            project_id,
            provider_id,
            expected_provider_revision,
        )
        .await
    }

    async fn abandon_provider_secret_replacement(
        &self,
        project_id: Uuid,
        provider_id: Uuid,
        expected_provider_revision: i64,
        correlation_id: Uuid,
        abandoned_at: OffsetDateTime,
    ) -> Result<ProviderRecord, ApplicationError> {
        self.abandon_provider_secret_replacement_stage(
            project_id,
            provider_id,
            expected_provider_revision,
            correlation_id,
            abandoned_at,
        )
        .await
    }

    async fn prepared_provider_material(
        &self,
        project_id: Uuid,
        prepared: &PreparedProvider,
    ) -> Result<Option<PreparedSecretMaterial>, ApplicationError> {
        let operation = provider_secret_operation::Entity::find_by_id(prepared.operation_id)
            .filter(provider_secret_operation::Column::ProjectId.eq(project_id))
            .one(&self.database)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        if operation.provider_id != prepared.provider_id
            || operation.request_digest != prepared.request_digest
        {
            return Err(ApplicationError::Integrity);
        }
        let material_id = operation.material_id;
        let custody = self.custody();
        let reservation = custody
            .materials
            .load_project_reservation(
                project_id,
                material_id,
                MaterialPurpose::ProviderClientSecret,
            )
            .await?;
        if reservation.owner_kind != MaterialOwnerKind::ProviderSecret
            || reservation.owner_id != prepared.provider_id
            || reservation.generation != operation.target_secret_generation
            || reservation.material_kind != MaterialKind::ConfigurationSecret
        {
            return Err(ApplicationError::Integrity);
        }
        Ok(Some(PreparedSecretMaterial {
            material_id,
            provider_id: reservation.provider_id,
            provider_format_version: reservation.provider_format_version,
            context: reservation.context,
        }))
    }

    async fn finalize_protected_provider(
        &self,
        project_id: Uuid,
        prepared: &PreparedProvider,
        expected_project_revision: i64,
        material: SealedProtectedMaterial,
        correlation_id: Uuid,
        finalized_at: OffsetDateTime,
    ) -> Result<ProviderRecord, ApplicationError> {
        self.finalize_protected_provider_stage(
            project_id,
            prepared,
            expected_project_revision,
            material,
            correlation_id,
            finalized_at,
        )
        .await
    }

    async fn finalize_provider_secret_replacement(
        &self,
        project_id: Uuid,
        prepared: &PreparedProvider,
        expected_provider_revision: i64,
        material: SealedProtectedMaterial,
        correlation_id: Uuid,
        finalized_at: OffsetDateTime,
    ) -> Result<ProviderRecord, ApplicationError> {
        self.finalize_provider_secret_replacement_stage(
            project_id,
            prepared,
            expected_provider_revision,
            material,
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

    async fn update_provider(
        &self,
        project_id: Uuid,
        provider_id: Uuid,
        command: UpdateProvider,
        correlation_id: Uuid,
    ) -> Result<ProviderRecord, ApplicationError> {
        PostgresProvisioningAdapter::update_provider(
            self,
            project_id,
            provider_id,
            command,
            correlation_id,
        )
        .await
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
