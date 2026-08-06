use std::sync::Arc;

use async_trait::async_trait;
use owlauth_key_provider::{
    ConfigurationSecretOpener, ConfigurationSecretSealer, DestroyOutcome, DestroySigningKeyRequest,
    InspectSigningKeyRequest, OpenSecretRequest, ProviderError, ProviderFormatVersion,
    ProviderFormatVersions, ProviderId, ProvisionSigningKeyRequest, ProvisionedSigningKey,
    RuntimeSigner, SealSecretRequest, SealedSecret, SecretPlaintext, SignRequest, Signature,
    SigningAlgorithm, SigningKeyProvisioner, SigningProviderCapabilities,
};
use owlauth_server::{
    ActiveProvider, ProviderCompositionError, ProviderRegistrations, config::PlaneMode,
    run_with_providers,
};

#[derive(Clone)]
struct DownstreamProvider {
    id: ProviderId,
    formats: ProviderFormatVersions,
}

impl DownstreamProvider {
    fn new(id: &str, version: u16) -> Self {
        Self {
            id: ProviderId::new(id).expect("provider ID"),
            formats: ProviderFormatVersions::new(&[
                ProviderFormatVersion::new(version).expect("format version")
            ])
            .expect("format versions"),
        }
    }

    fn signing_capabilities(&self) -> SigningProviderCapabilities {
        SigningProviderCapabilities::new(&[SigningAlgorithm::Ed25519], self.formats.clone())
            .expect("signing capabilities")
    }
}

#[async_trait]
impl SigningKeyProvisioner for DownstreamProvider {
    fn provider_id(&self) -> ProviderId {
        self.id.clone()
    }

    fn capabilities(&self) -> SigningProviderCapabilities {
        self.signing_capabilities()
    }

    async fn provision(
        &self,
        _request: ProvisionSigningKeyRequest,
    ) -> Result<ProvisionedSigningKey, ProviderError> {
        panic!("compile fixture does not invoke provider effects")
    }

    async fn inspect(
        &self,
        _request: InspectSigningKeyRequest,
    ) -> Result<ProvisionedSigningKey, ProviderError> {
        panic!("compile fixture does not invoke provider effects")
    }

    async fn destroy(
        &self,
        _request: DestroySigningKeyRequest,
    ) -> Result<DestroyOutcome, ProviderError> {
        panic!("compile fixture does not invoke provider effects")
    }
}

#[async_trait]
impl RuntimeSigner for DownstreamProvider {
    fn provider_id(&self) -> ProviderId {
        self.id.clone()
    }

    fn capabilities(&self) -> SigningProviderCapabilities {
        self.signing_capabilities()
    }

    async fn sign(&self, _request: SignRequest) -> Result<Signature, ProviderError> {
        panic!("compile fixture does not invoke provider effects")
    }
}

#[async_trait]
impl ConfigurationSecretSealer for DownstreamProvider {
    fn provider_id(&self) -> ProviderId {
        self.id.clone()
    }

    fn supported_format_versions(&self) -> ProviderFormatVersions {
        self.formats.clone()
    }

    async fn seal(&self, _request: SealSecretRequest) -> Result<SealedSecret, ProviderError> {
        panic!("compile fixture does not invoke provider effects")
    }
}

#[async_trait]
impl ConfigurationSecretOpener for DownstreamProvider {
    fn provider_id(&self) -> ProviderId {
        self.id.clone()
    }

    fn supported_format_versions(&self) -> ProviderFormatVersions {
        self.formats.clone()
    }

    async fn open(&self, _request: OpenSecretRequest) -> Result<SecretPlaintext, ProviderError> {
        panic!("compile fixture does not invoke provider effects")
    }
}

fn full_registrations() -> ProviderRegistrations {
    let provider_id = ProviderId::new("downstream-kms").expect("provider ID");
    let format_version = ProviderFormatVersion::new(7).expect("format version");
    let provider = Arc::new(DownstreamProvider::new("downstream-kms", 7));
    let mut registrations = ProviderRegistrations::new();
    registrations
        .register_signing_provisioner(provider_id.clone(), provider.clone())
        .expect("signing provisioner")
        .register_runtime_signer(provider_id.clone(), provider.clone())
        .expect("Runtime signer")
        .register_secret_sealer(provider_id.clone(), provider.clone())
        .expect("secret sealer")
        .register_secret_opener(provider_id.clone(), provider)
        .expect("secret opener")
        .select_active_signing_provider(ActiveProvider::new(provider_id.clone(), format_version))
        .select_active_secret_provider(ActiveProvider::new(provider_id, format_version));
    registrations
}

#[test]
fn downstream_provider_composes_without_private_server_types() {
    let registrations = full_registrations();
    registrations
        .validate_for_mode(PlaneMode::All)
        .expect("complete all-plane composition");

    // Type-check the public custom entry point without starting a server or importing private
    // repositories, routers, rows, or application errors.
    std::hint::black_box(run_with_providers);
}

#[test]
fn role_requirements_and_duplicate_or_mismatched_ids_fail_closed() {
    let provider_id = ProviderId::new("downstream-kms").expect("provider ID");
    let provider = Arc::new(DownstreamProvider::new("downstream-kms", 7));
    let mut runtime_only = ProviderRegistrations::new();
    runtime_only
        .register_runtime_signer(provider_id.clone(), provider.clone())
        .expect("Runtime signer")
        .register_secret_opener(provider_id.clone(), provider.clone())
        .expect("secret opener");
    runtime_only
        .validate_for_mode(PlaneMode::Runtime)
        .expect("Runtime receives only Runtime capabilities");
    assert_eq!(
        runtime_only.validate_for_mode(PlaneMode::Control),
        Err(ProviderCompositionError::MissingActiveProvider)
    );
    assert_eq!(
        runtime_only
            .register_runtime_signer(provider_id.clone(), provider.clone())
            .expect_err("duplicate capability must fail"),
        ProviderCompositionError::DuplicateCapability
    );

    let mismatched = ProviderId::new("another-provider").expect("provider ID");
    let mut registrations = ProviderRegistrations::new();
    assert_eq!(
        registrations
            .register_secret_opener(mismatched, provider)
            .expect_err("mismatched provider ID must fail"),
        ProviderCompositionError::ProviderIdMismatch
    );
}

#[test]
fn independent_active_selections_validate_exact_formats() {
    let signing_id = ProviderId::new("signing-hsm").expect("provider ID");
    let secret_id = ProviderId::new("secret-kms").expect("provider ID");
    let signing = Arc::new(DownstreamProvider::new("signing-hsm", 3));
    let secrets = Arc::new(DownstreamProvider::new("secret-kms", 9));
    let mut registrations = ProviderRegistrations::new();
    registrations
        .register_signing_provisioner(signing_id.clone(), signing.clone())
        .expect("signing provisioner")
        .register_runtime_signer(signing_id.clone(), signing)
        .expect("Runtime signer")
        .register_secret_sealer(secret_id.clone(), secrets.clone())
        .expect("secret sealer")
        .register_secret_opener(secret_id.clone(), secrets)
        .expect("secret opener")
        .select_active_signing_provider(ActiveProvider::new(
            signing_id,
            ProviderFormatVersion::new(3).expect("format version"),
        ))
        .select_active_secret_provider(ActiveProvider::new(
            secret_id,
            ProviderFormatVersion::new(9).expect("format version"),
        ));
    registrations
        .validate_for_mode(PlaneMode::All)
        .expect("independent active providers");

    registrations.select_active_secret_provider(ActiveProvider::new(
        ProviderId::new("secret-kms").expect("provider ID"),
        ProviderFormatVersion::new(10).expect("format version"),
    ));
    assert_eq!(
        registrations.validate_for_mode(PlaneMode::All),
        Err(ProviderCompositionError::UnsupportedSelection)
    );
}
