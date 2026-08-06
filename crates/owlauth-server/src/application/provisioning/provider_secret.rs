use super::{
    ApplicationError, CreateProvider, PrepareProvider, ProviderProvisioningPort, ProviderRecord,
    ProvisioningInfrastructure, ProvisioningOperationState, ProvisioningService, SealSecretRequest,
    SealedProtectedMaterial, SecretPlaintext, Uuid, Zeroizing, json, map_provider_error,
};
impl ProvisioningService {
    pub(crate) async fn create_provider(
        &self,
        project_id: Uuid,
        command: CreateProvider,
        correlation_id: Uuid,
    ) -> Result<ProviderRecord, ApplicationError> {
        create_provider_workflow(
            self.providers.as_ref(),
            &self.infrastructure,
            project_id,
            command,
            correlation_id,
        )
        .await
    }
    pub(crate) async fn list_providers(
        &self,
        project_id: Uuid,
    ) -> Result<Vec<ProviderRecord>, ApplicationError> {
        self.providers.list_providers(project_id).await
    }
    pub(crate) async fn reconcile_provider(
        &self,
        project_id: Uuid,
        provider_id: Uuid,
        client_secret: Zeroizing<String>,
        expected_project_revision: i64,
        correlation_id: Uuid,
    ) -> Result<ProviderRecord, ApplicationError> {
        let recovery = self
            .providers
            .provider_recovery(project_id, provider_id)
            .await?;
        create_provider_workflow(
            self.providers.as_ref(),
            &self.infrastructure,
            project_id,
            CreateProvider {
                kind: recovery.kind,
                provider_key: recovery.provider_key,
                display_name: recovery.display_name,
                issuer: recovery.issuer,
                client_id: recovery.client_id,
                client_secret,
                managed_profile_enabled: recovery.managed_profile_enabled,
                idempotency_key: recovery.operation_alias,
                expected_project_revision,
                egress_policy_revision: recovery.egress_policy_revision,
            },
            correlation_id,
        )
        .await
    }
    pub(crate) async fn assign_provider(
        &self,
        project_id: Uuid,
        provider_id: Uuid,
        application_id: Uuid,
        expected_application_revision: i64,
        correlation_id: Uuid,
    ) -> Result<ProviderRecord, ApplicationError> {
        self.providers
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
        self.providers
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
        self.providers
            .disable_provider(
                project_id,
                provider_id,
                expected_provider_revision,
                correlation_id,
            )
            .await
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "the complete durable prepare, provider effect, and finalize workflow stays visible"
)]
pub(super) async fn create_provider_workflow(
    providers: &dyn ProviderProvisioningPort,
    infrastructure: &ProvisioningInfrastructure,
    project_id: Uuid,
    command: CreateProvider,
    correlation_id: Uuid,
) -> Result<ProviderRecord, ApplicationError> {
    let command = command.normalize(infrastructure.allow_http_loopback_provider)?;
    let digest = protected_provider_request_digest(infrastructure, project_id, &command)?;
    let prepared = providers
        .prepare_provider(
            project_id,
            PrepareProvider {
                kind: command.kind,
                provider_key: command.provider_key,
                display_name: command.display_name,
                issuer: command.issuer,
                client_id: command.client_id,
                managed_profile_enabled: command.managed_profile_enabled,
                operation_alias: command.idempotency_key.clone(),
                expected_project_revision: command.expected_project_revision,
                egress_policy_revision: command.egress_policy_revision,
                request_digest: digest.clone(),
            },
        )
        .await?;
    if prepared.request_digest != digest {
        return Err(ApplicationError::IdempotencyConflict);
    }
    let prepared_material = providers
        .prepared_provider_material(project_id, &prepared)
        .await?;
    if let Some(material) = prepared_material {
        let sealer = infrastructure.secret_sealers.resolve(&material)?;
        let protected_secret = sealer
            .seal(SealSecretRequest {
                context: material.context,
                plaintext: SecretPlaintext::new(command.client_secret.as_bytes().to_vec())
                    .map_err(|_| ApplicationError::InvalidInput)?,
            })
            .await
            .map_err(map_provider_error)?;
        return providers
            .finalize_protected_provider(
                project_id,
                &prepared,
                command.expected_project_revision,
                SealedProtectedMaterial {
                    material_id: material.material_id,
                    provider_id: material.provider_id,
                    provider_format_version: material.provider_format_version,
                    envelope: protected_secret.envelope,
                    request_fingerprint: protected_secret.request_fingerprint,
                },
                correlation_id,
                infrastructure.clock.now(),
            )
            .await;
    }
    if prepared.state == ProvisioningOperationState::Completed {
        return providers
            .get_provider(project_id, prepared.provider_id)
            .await;
    }

    Err(ApplicationError::Integrity)
}

fn protected_provider_request_digest(
    infrastructure: &ProvisioningInfrastructure,
    project_id: Uuid,
    command: &CreateProvider,
) -> Result<Vec<u8>, ApplicationError> {
    // Protected material uses the provider's keyed safe fingerprint at finalization. The prepare
    // digest deliberately covers only normalized non-secret request fields.
    infrastructure.digester.digest_json(&json!({
        "project_id": project_id,
        "kind": command.kind.as_str(),
        "provider_key": &command.provider_key,
        "display_name": &command.display_name,
        "issuer": &command.issuer,
        "client_id": &command.client_id,
        "managed_profile_enabled": command.managed_profile_enabled,
        "egress_policy_revision": command.egress_policy_revision,
    }))
}
