use super::{
    ActiveModelTrait, ApplicationError, CONFIGURATION_VALUE_LIMIT, ColumnTrait, EntityTrait,
    IntoActiveModel, LIST_LIMIT, MaterialKind, MaterialOwnerKind, MaterialPurpose, OffsetDateTime,
    PostgresProvisioningAdapter, PrepareProvider, PreparedProvider, PreparedSecretMaterial,
    ProviderProvisioningPort, ProviderRecord, ProviderRecovery, ProviderStatus, QueryFilter,
    QueryOrder, QuerySelect, SealedProtectedMaterial, Set, TransactionTrait, Uuid,
    active_application, active_project, active_provider, application_provider_assignment,
    async_trait, bounded_list, bump_application_security, bump_provider_revision,
    enforce_project_fence, enforce_provider_egress_fence, ensure_capacity, ensure_project,
    finalize_pending_material, find_provider, insert_audit, locked_project, persistence,
    prepared_provider, project_provider_egress_policy, provider_configuration,
    provider_secret_operation, requires_project_reauthorization,
};

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
        ensure_capacity(providers.len(), LIST_LIMIT, ApplicationError::InvalidInput)?;
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
        let callback_url = self
            .runtime_base
            .join(&format!(
                "projects/{}/auth/callback/{}",
                project.public_id, command.provider_key
            ))
            .map_err(|_| ApplicationError::InvalidInput)?
            .to_string();
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
            let provider = provider_configuration::Entity::find_by_id(prepared.provider_id)
                .filter(provider_configuration::Column::ProjectId.eq(project_id))
                .one(&transaction)
                .await
                .map_err(persistence)?
                .ok_or(ApplicationError::NotFound)?;
            if provider.secret_material_id != material.material_id {
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

    async fn disable_provider(
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
            || reservation.generation != 1
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
