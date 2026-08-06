use std::sync::Arc;

use owlauth_key_provider::{
    ConfigurationSecretOpener, ConfigurationSecretSealer, ContextVersion, DeploymentId,
    DestroyOutcome, DestroySigningKeyRequest, FieldPurpose, InspectSigningKeyRequest, MaterialId,
    MaterialKind, OpaqueEnvelope, OpaqueHandle, OpenSecretRequest, OperationId, OwnerId, OwnerKind,
    ProjectId, ProtectionContext, ProtectionContextParts, ProviderError, ProviderFormatVersion,
    ProviderFormatVersions, ProviderId, ProvisionSigningKeyRequest, ProvisionedSigningKey,
    RequestFingerprint, RetryClassification, RuntimeSigner, Scope, SealSecretRequest, SealedSecret,
    SecretPlaintext, SignRequest, Signature, SigningAlgorithm, SigningInput, SigningKeyProvisioner,
    SigningProviderCapabilities, SigningProvisioningSemantics, SigningPublicKey, async_trait,
};

struct IndependentProvider;

fn formats() -> ProviderFormatVersions {
    ProviderFormatVersions::new(&[ProviderFormatVersion::new(1).unwrap()]).unwrap()
}

fn signing_capabilities() -> SigningProviderCapabilities {
    SigningProviderCapabilities::new(&[SigningAlgorithm::Ed25519], formats()).unwrap()
}

#[async_trait]
impl SigningKeyProvisioner for IndependentProvider {
    fn provider_id(&self) -> ProviderId {
        ProviderId::new("independent").unwrap()
    }

    fn capabilities(&self) -> SigningProviderCapabilities {
        signing_capabilities()
    }

    async fn provision(
        &self,
        _request: ProvisionSigningKeyRequest,
    ) -> Result<ProvisionedSigningKey, ProviderError> {
        Ok(ProvisionedSigningKey {
            handle: OpaqueHandle::new(b"independent-handle".to_vec()).unwrap(),
            public_key: SigningPublicKey::new(SigningAlgorithm::Ed25519, vec![7; 32]).unwrap(),
        })
    }

    async fn inspect(
        &self,
        _request: InspectSigningKeyRequest,
    ) -> Result<ProvisionedSigningKey, ProviderError> {
        Ok(ProvisionedSigningKey {
            handle: OpaqueHandle::new(b"independent-handle".to_vec()).unwrap(),
            public_key: SigningPublicKey::new(SigningAlgorithm::Ed25519, vec![7; 32]).unwrap(),
        })
    }

    async fn destroy(
        &self,
        _request: DestroySigningKeyRequest,
    ) -> Result<DestroyOutcome, ProviderError> {
        Ok(DestroyOutcome::Unsupported)
    }
}

#[async_trait]
impl RuntimeSigner for IndependentProvider {
    fn provider_id(&self) -> ProviderId {
        ProviderId::new("independent").unwrap()
    }

    fn capabilities(&self) -> SigningProviderCapabilities {
        signing_capabilities()
    }

    async fn sign(&self, request: SignRequest) -> Result<Signature, ProviderError> {
        assert_eq!(request.algorithm, SigningAlgorithm::Ed25519);
        Ok(Signature::new(SigningAlgorithm::Ed25519, vec![8; 64]).unwrap())
    }
}

#[async_trait]
impl ConfigurationSecretSealer for IndependentProvider {
    fn provider_id(&self) -> ProviderId {
        ProviderId::new("independent").unwrap()
    }

    fn supported_format_versions(&self) -> ProviderFormatVersions {
        formats()
    }

    async fn seal(&self, request: SealSecretRequest) -> Result<SealedSecret, ProviderError> {
        let length = request.plaintext.expose(<[u8]>::len);
        assert!(length > 0);
        Ok(SealedSecret {
            envelope: OpaqueEnvelope::new(vec![9; 48]).unwrap(),
            request_fingerprint: RequestFingerprint::new(vec![10; 32]).unwrap(),
        })
    }
}

#[async_trait]
impl ConfigurationSecretOpener for IndependentProvider {
    fn provider_id(&self) -> ProviderId {
        ProviderId::new("independent").unwrap()
    }

    fn supported_format_versions(&self) -> ProviderFormatVersions {
        formats()
    }

    async fn open(&self, request: OpenSecretRequest) -> Result<SecretPlaintext, ProviderError> {
        assert!(request.envelope.expose(|envelope| !envelope.is_empty()));
        SecretPlaintext::new(b"opened".to_vec()).map_err(|_| {
            ProviderError::new(
                owlauth_key_provider::ProviderErrorClass::Integrity,
                RetryClassification::Never,
            )
        })
    }
}

fn context() -> ProtectionContext {
    ProtectionContext::new(ProtectionContextParts {
        version: ContextVersion::V1,
        deployment_id: DeploymentId::new("deployment-1").unwrap(),
        scope: Scope::Project(ProjectId::new("project-1").unwrap()),
        material_id: MaterialId::new("material-1").unwrap(),
        material_kind: MaterialKind::SigningKey,
        owner_kind: OwnerKind::new("signing-key").unwrap(),
        owner_id: OwnerId::new("owner-1").unwrap(),
        generation: 1,
        field_purpose: FieldPurpose::new("application-token").unwrap(),
        provider_id: ProviderId::new("independent").unwrap(),
        provider_format_version: ProviderFormatVersion::new(1).unwrap(),
    })
    .unwrap()
}

#[test]
fn independent_crate_can_construct_every_role_object() {
    let provider = Arc::new(IndependentProvider);
    let provisioner: Arc<dyn SigningKeyProvisioner> = provider.clone();
    let signer: Arc<dyn RuntimeSigner> = provider.clone();
    let sealer: Arc<dyn ConfigurationSecretSealer> = provider.clone();
    let opener: Arc<dyn ConfigurationSecretOpener> = provider;

    assert_eq!(provisioner.provider_id().as_str(), "independent");
    assert_eq!(
        provisioner.provisioning_semantics(),
        SigningProvisioningSemantics::StableOperation
    );
    assert_eq!(signer.provider_id().as_str(), "independent");
    assert_eq!(sealer.provider_id().as_str(), "independent");
    assert_eq!(opener.provider_id().as_str(), "independent");
    assert!(
        provisioner
            .capabilities()
            .supports_algorithm(SigningAlgorithm::Ed25519)
    );
    assert!(
        signer
            .capabilities()
            .supports_algorithm(SigningAlgorithm::Ed25519)
    );
    assert!(
        sealer
            .supported_format_versions()
            .contains(ProviderFormatVersion::new(1).unwrap())
    );
    assert!(
        opener
            .supported_format_versions()
            .contains(ProviderFormatVersion::new(1).unwrap())
    );
    let _provision_request = ProvisionSigningKeyRequest {
        operation_id: OperationId::new(b"operation-1".to_vec()).unwrap(),
        algorithm: SigningAlgorithm::Ed25519,
        context: context(),
    };
    let _sign_request = SignRequest {
        algorithm: SigningAlgorithm::Ed25519,
        context: context(),
        handle: OpaqueHandle::new(b"handle-1".to_vec()).unwrap(),
        signing_input: SigningInput::new(b"header.payload".to_vec()).unwrap(),
    };
}
