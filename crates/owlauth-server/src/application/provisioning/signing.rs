use super::{
    ApplicationError, DestroyOutcome, DestroySigningKeyRequest, Duration, InspectSigningKeyRequest,
    OffsetDateTime, OperationId, PreparedSigningKey, PreparedSigningMaterial, ProviderError,
    ProviderErrorClass, ProvisionSigningKeyRequest, ProvisionedProtectedSigningMaterial,
    ProvisionedSigningKey, ProvisioningInfrastructure, ProvisioningOperationState,
    ProvisioningService, RetryClassification, SIGNING_ALGORITHM, SIGNING_PROVIDER_LEASE_SECONDS,
    SIGNING_PURPOSE, SigningAlgorithm, SigningKeyProvisioner, SigningKeyProvisioningPort,
    SigningKeyRecord, SigningProviderAction, SigningProviderCall, SigningProviderLease, Uuid,
    external_store_alias, json, map_provider_error, normalized_ed25519_jwk,
    validate_idempotency_key,
};

impl ProvisioningService {
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
        if Uuid::parse_str(&candidate.signer_ref).is_err() {
            #[cfg(not(test))]
            return Err(ApplicationError::Integrity);
            #[cfg(test)]
            self.infrastructure
                .signer_store
                .as_ref()
                .ok_or(ApplicationError::Integrity)?
                .verify(candidate.signer_ref, &candidate.kid, &candidate.public_jwk)
                .await?;
        }
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
}

#[allow(
    clippy::too_many_lines,
    reason = "the complete durable prepare, provider effect, finalize, and publish workflow stays visible"
)]
pub(super) async fn provision_signing_key_workflow(
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

    if let Some(material) = signing_keys
        .prepared_signing_material(project_id, &prepared)
        .await?
    {
        let now = infrastructure.clock.now();
        if prepared.state == ProvisioningOperationState::Stored {
            return signing_keys
                .publish_signing_key(
                    project_id,
                    &prepared,
                    expected_project_revision,
                    correlation_id,
                    now,
                )
                .await;
        }
        let provisioner = infrastructure
            .signing_provisioner(&material.provider_id, material.provider_format_version)?;
        return reconcile_protected_signing_key(
            signing_keys,
            provisioner.as_ref(),
            infrastructure,
            project_id,
            &prepared,
            material,
            expected_project_revision,
            correlation_id,
        )
        .await;
    }

    #[cfg(not(test))]
    return Err(ApplicationError::Integrity);

    #[cfg(test)]
    {
        let signer_store = infrastructure
            .signer_store
            .as_ref()
            .ok_or(ApplicationError::Integrity)?;
        let entropy = infrastructure
            .entropy
            .as_ref()
            .ok_or(ApplicationError::Integrity)?;
        signer_store
            .put_if_absent(prepared.signer_ref.clone(), entropy.signing_seed()?)
            .await?;
        let public_jwk = signer_store
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
}

#[allow(
    clippy::similar_names,
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "the complete leased provision, inspect, containment, and cleanup state machine stays visible"
)]
async fn reconcile_protected_signing_key(
    signing_keys: &dyn SigningKeyProvisioningPort,
    provisioner: &dyn SigningKeyProvisioner,
    infrastructure: &ProvisioningInfrastructure,
    project_id: Uuid,
    prepared: &PreparedSigningKey,
    material: PreparedSigningMaterial,
    expected_project_revision: i64,
    correlation_id: Uuid,
) -> Result<SigningKeyRecord, ApplicationError> {
    let operation_id = OperationId::new(prepared.operation_id.as_bytes().to_vec())
        .map_err(|_| ApplicationError::Integrity)?;
    for _ in 0..3 {
        let now = infrastructure.clock.now();
        let lease_until = now + Duration::seconds(SIGNING_PROVIDER_LEASE_SECONDS);
        let action = signing_keys
            .claim_signing_provider_action(project_id, prepared, now, lease_until)
            .await?;
        match action {
            SigningProviderAction::Provision(lease) => {
                let result = provisioner
                    .provision(ProvisionSigningKeyRequest {
                        operation_id: operation_id.clone(),
                        algorithm: SigningAlgorithm::Ed25519,
                        context: material.context.clone(),
                    })
                    .await;
                let provisioned = match result {
                    Ok(provisioned) => provisioned,
                    Err(error) => {
                        persist_signing_provider_failure(
                            signing_keys,
                            project_id,
                            prepared,
                            lease,
                            SigningProviderCall::Provision,
                            &error,
                            infrastructure.clock.now(),
                        )
                        .await?;
                        return Err(map_provider_error(error));
                    }
                };
                return contain_signing_provider_result(
                    signing_keys,
                    infrastructure,
                    project_id,
                    prepared,
                    &material,
                    expected_project_revision,
                    correlation_id,
                    lease,
                    provisioned,
                )
                .await;
            }
            SigningProviderAction::Inspect(lease) => {
                let result = provisioner
                    .inspect(InspectSigningKeyRequest {
                        operation_id: operation_id.clone(),
                        algorithm: SigningAlgorithm::Ed25519,
                        context: material.context.clone(),
                    })
                    .await;
                match result {
                    Ok(provisioned) => {
                        return contain_signing_provider_result(
                            signing_keys,
                            infrastructure,
                            project_id,
                            prepared,
                            &material,
                            expected_project_revision,
                            correlation_id,
                            lease,
                            provisioned,
                        )
                        .await;
                    }
                    Err(error)
                        if error.class() == ProviderErrorClass::NotFound
                            && error.retry_classification()
                                == RetryClassification::ExactInputSafe =>
                    {
                        signing_keys
                            .record_signing_provider_absence(
                                project_id,
                                prepared,
                                lease,
                                infrastructure.clock.now(),
                            )
                            .await?;
                    }
                    Err(error) => {
                        persist_signing_provider_failure(
                            signing_keys,
                            project_id,
                            prepared,
                            lease,
                            SigningProviderCall::Inspect,
                            &error,
                            infrastructure.clock.now(),
                        )
                        .await?;
                        return Err(map_provider_error(error));
                    }
                }
            }
            SigningProviderAction::Cleanup(lease) => {
                let inspected = provisioner
                    .inspect(InspectSigningKeyRequest {
                        operation_id: operation_id.clone(),
                        algorithm: SigningAlgorithm::Ed25519,
                        context: material.context.clone(),
                    })
                    .await;
                let provisioned = match inspected {
                    Ok(provisioned) => provisioned,
                    Err(error)
                        if error.class() == ProviderErrorClass::NotFound
                            && error.retry_classification()
                                == RetryClassification::ExactInputSafe =>
                    {
                        signing_keys
                            .complete_signing_provider_cleanup(
                                project_id,
                                prepared,
                                lease,
                                true,
                                correlation_id,
                                infrastructure.clock.now(),
                            )
                            .await?;
                        return signing_keys
                            .get_signing_key(project_id, prepared.key_id)
                            .await;
                    }
                    Err(error) => {
                        persist_signing_provider_failure(
                            signing_keys,
                            project_id,
                            prepared,
                            lease,
                            SigningProviderCall::Cleanup,
                            &error,
                            infrastructure.clock.now(),
                        )
                        .await?;
                        return Err(map_provider_error(error));
                    }
                };
                let handle_matches = material.committed_handle.as_ref().is_none_or(|expected| {
                    expected.expose(|expected_bytes| {
                        provisioned
                            .handle
                            .expose(|actual_bytes| actual_bytes == expected_bytes)
                    })
                });
                let public_key_matches = material
                    .committed_public_key
                    .as_ref()
                    .is_none_or(|expected| expected == &provisioned.public_key);
                if !handle_matches || !public_key_matches {
                    let error = ProviderError::new(
                        ProviderErrorClass::Integrity,
                        RetryClassification::Never,
                    );
                    persist_signing_provider_failure(
                        signing_keys,
                        project_id,
                        prepared,
                        lease,
                        SigningProviderCall::Cleanup,
                        &error,
                        infrastructure.clock.now(),
                    )
                    .await?;
                    return Err(ApplicationError::Integrity);
                }
                match provisioner
                    .destroy(DestroySigningKeyRequest {
                        algorithm: SigningAlgorithm::Ed25519,
                        context: material.context.clone(),
                        handle: provisioned.handle,
                    })
                    .await
                {
                    Ok(DestroyOutcome::Destroyed | DestroyOutcome::AlreadyAbsent) => {
                        signing_keys
                            .complete_signing_provider_cleanup(
                                project_id,
                                prepared,
                                lease,
                                true,
                                correlation_id,
                                infrastructure.clock.now(),
                            )
                            .await?;
                        return signing_keys
                            .get_signing_key(project_id, prepared.key_id)
                            .await;
                    }
                    Ok(DestroyOutcome::Unsupported) => {
                        signing_keys
                            .complete_signing_provider_cleanup(
                                project_id,
                                prepared,
                                lease,
                                false,
                                correlation_id,
                                infrastructure.clock.now(),
                            )
                            .await?;
                        return Err(ApplicationError::Integrity);
                    }
                    Ok(_) => return Err(ApplicationError::Integrity),
                    Err(error) => {
                        persist_signing_provider_failure(
                            signing_keys,
                            project_id,
                            prepared,
                            lease,
                            SigningProviderCall::Cleanup,
                            &error,
                            infrastructure.clock.now(),
                        )
                        .await?;
                        return Err(map_provider_error(error));
                    }
                }
            }
        }
    }
    Err(ApplicationError::OperationInProgress)
}

#[allow(clippy::too_many_arguments)]
async fn contain_signing_provider_result(
    signing_keys: &dyn SigningKeyProvisioningPort,
    infrastructure: &ProvisioningInfrastructure,
    project_id: Uuid,
    prepared: &PreparedSigningKey,
    material: &PreparedSigningMaterial,
    expected_project_revision: i64,
    correlation_id: Uuid,
    lease: SigningProviderLease,
    provisioned: ProvisionedSigningKey,
) -> Result<SigningKeyRecord, ApplicationError> {
    let now = infrastructure.clock.now();
    let public_jwk = match normalized_ed25519_jwk(&prepared.kid, &provisioned.public_key) {
        Ok(public_jwk) => public_jwk,
        Err(error) => {
            signing_keys
                .queue_signing_provider_cleanup(project_id, prepared, lease, now)
                .await?;
            return Err(error);
        }
    };
    let recorded = signing_keys
        .record_protected_signing_key_material(
            project_id,
            prepared,
            expected_project_revision,
            lease,
            ProvisionedProtectedSigningMaterial {
                material_id: material.material_id,
                handle: provisioned.handle,
                public_key: provisioned.public_key,
            },
            public_jwk,
            now,
        )
        .await;
    if let Err(error) = recorded {
        if matches!(
            error,
            ApplicationError::Disabled
                | ApplicationError::RevisionConflict
                | ApplicationError::InvalidTransition
        ) {
            signing_keys
                .queue_signing_provider_cleanup(project_id, prepared, lease, now)
                .await?;
        }
        return Err(error);
    }
    signing_keys
        .publish_signing_key(
            project_id,
            prepared,
            expected_project_revision,
            correlation_id,
            now,
        )
        .await
}

async fn persist_signing_provider_failure(
    signing_keys: &dyn SigningKeyProvisioningPort,
    project_id: Uuid,
    prepared: &PreparedSigningKey,
    lease: SigningProviderLease,
    provider_call: SigningProviderCall,
    error: &ProviderError,
    recorded_at: OffsetDateTime,
) -> Result<(), ApplicationError> {
    signing_keys
        .record_signing_provider_failure(
            project_id,
            prepared,
            lease,
            provider_call,
            error.class(),
            error.retry_classification(),
            error.code().map(|code| code.as_str().to_owned()),
            recorded_at,
        )
        .await
}
