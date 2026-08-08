use std::sync::Arc;

use async_trait::async_trait;
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use ed25519_dalek::{Signer as _, SigningKey};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use owlauth_key_provider::{
    ConfigurationSecretOpener, ConfigurationSecretSealer, DestroyOutcome, DestroySigningKeyRequest,
    InspectSigningKeyRequest, MaterialKind, OpaqueEnvelope, OpaqueHandle, OpenSecretRequest,
    ProviderError, ProviderErrorClass, ProviderErrorCode, ProviderFormatVersion,
    ProviderFormatVersions, ProviderId, ProvisionSigningKeyRequest, ProvisionedSigningKey,
    RequestFingerprint, RetryClassification, RuntimeSigner, SealSecretRequest, SealedSecret,
    SecretPlaintext, SignRequest, Signature, SigningAlgorithm, SigningKeyProvisioner,
    SigningProviderCapabilities, SigningProvisioningSemantics, SigningPublicKey,
};
use sha2::Sha256;
use zeroize::Zeroizing;

const EXTRACT_SALT: &[u8] = b"owlauth-software-custody-extract-v1";
const DERIVE_DOMAIN: &[u8] = b"owlauth-software-custody-derive-v1\0";
const SIGNING_KEY_LABEL: &[u8] = b"signing-material-envelope";
const SECRET_KEY_LABEL: &[u8] = b"configuration-secret-envelope";
const FINGERPRINT_KEY_LABEL: &[u8] = b"configuration-secret-fingerprint";
const FINGERPRINT_DOMAIN: &[u8] = b"owlauth-software-custody-fingerprint-v1\0";
const ENVELOPE_VERSION: u8 = 1;
const NONCE_LEN: usize = 24;
const ED25519_SEED_LEN: usize = 32;

type HmacSha256 = Hmac<Sha256>;

struct SoftwareKeys {
    signing: Zeroizing<[u8; 32]>,
    secrets: Zeroizing<[u8; 32]>,
    fingerprints: Zeroizing<[u8; 32]>,
}

impl std::fmt::Debug for SoftwareKeys {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SoftwareKeys([REDACTED])")
    }
}

/// Bundled stateless software implementation. `PostgreSQL` owns envelope identity and lifecycle;
/// this object owns only derived cryptographic capabilities.
#[derive(Clone)]
pub(crate) struct SoftwareCustodyProvider {
    provider_id: ProviderId,
    keys: Arc<SoftwareKeys>,
}

impl std::fmt::Debug for SoftwareCustodyProvider {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SoftwareCustodyProvider")
            .field("provider_id", &self.provider_id)
            .field("keys", &self.keys)
            .finish()
    }
}

impl SoftwareCustodyProvider {
    pub(crate) fn new(provider_id: ProviderId, root: [u8; 32]) -> Result<Self, ProviderError> {
        let root = Zeroizing::new(root);
        let hkdf = Hkdf::<Sha256>::new(Some(EXTRACT_SALT), root.as_ref());
        Ok(Self {
            provider_id,
            keys: Arc::new(SoftwareKeys {
                signing: Zeroizing::new(derive(&hkdf, SIGNING_KEY_LABEL)?),
                secrets: Zeroizing::new(derive(&hkdf, SECRET_KEY_LABEL)?),
                fingerprints: Zeroizing::new(derive(&hkdf, FINGERPRINT_KEY_LABEL)?),
            }),
        })
    }

    fn format_versions() -> ProviderFormatVersions {
        ProviderFormatVersions::new(&[ProviderFormatVersion::new(u16::from(ENVELOPE_VERSION))
            .expect("software envelope version is non-zero")])
        .expect("software format set is valid")
    }

    fn signing_capabilities() -> SigningProviderCapabilities {
        SigningProviderCapabilities::new(&[SigningAlgorithm::Ed25519], Self::format_versions())
            .expect("software signing capabilities are valid")
    }

    fn validate_context(
        &self,
        context: &owlauth_key_provider::ProtectionContext,
        expected_kind: MaterialKind,
    ) -> Result<(), ProviderError> {
        let parts = context.parts();
        if parts.provider_id != self.provider_id
            || parts.provider_format_version.get() != u16::from(ENVELOPE_VERSION)
            || parts.material_kind != expected_kind
        {
            return Err(provider_error(
                ProviderErrorClass::InvalidRequest,
                RetryClassification::Never,
                "context.mismatch",
            ));
        }
        Ok(())
    }

    fn seal_envelope(
        key: &[u8; 32],
        context: &owlauth_key_provider::ProtectionContext,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, ProviderError> {
        let mut nonce = [0_u8; NONCE_LEN];
        getrandom::fill(&mut nonce).map_err(|_| unavailable())?;
        let cipher = XChaCha20Poly1305::new_from_slice(key).map_err(|_| integrity())?;
        let ciphertext = cipher
            .encrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: plaintext,
                    aad: context.canonical_bytes(),
                },
            )
            .map_err(|_| unavailable())?;
        let mut envelope = Vec::with_capacity(1 + NONCE_LEN + ciphertext.len());
        envelope.push(ENVELOPE_VERSION);
        envelope.extend_from_slice(&nonce);
        envelope.extend_from_slice(&ciphertext);
        Ok(envelope)
    }

    fn open_envelope(
        key: &[u8; 32],
        context: &owlauth_key_provider::ProtectionContext,
        envelope: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, ProviderError> {
        if envelope.len() <= 1 + NONCE_LEN || envelope[0] != ENVELOPE_VERSION {
            return Err(integrity());
        }
        let (nonce, ciphertext) = envelope[1..].split_at(NONCE_LEN);
        let nonce: [u8; NONCE_LEN] = nonce.try_into().map_err(|_| integrity())?;
        let cipher = XChaCha20Poly1305::new_from_slice(key).map_err(|_| integrity())?;
        cipher
            .decrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: ciphertext,
                    aad: context.canonical_bytes(),
                },
            )
            .map(Zeroizing::new)
            .map_err(|_| integrity())
    }

    fn fingerprint(
        &self,
        context: &owlauth_key_provider::ProtectionContext,
        plaintext: &[u8],
    ) -> Result<[u8; 32], ProviderError> {
        let mut mac =
            <HmacSha256 as hmac::KeyInit>::new_from_slice(self.keys.fingerprints.as_ref())
                .map_err(|_| integrity())?;
        mac.update(FINGERPRINT_DOMAIN);
        update_framed(&mut mac, context.canonical_bytes())?;
        update_framed(&mut mac, plaintext)?;
        Ok(mac.finalize().into_bytes().into())
    }
}

#[async_trait]
impl SigningKeyProvisioner for SoftwareCustodyProvider {
    fn provider_id(&self) -> ProviderId {
        self.provider_id.clone()
    }

    fn capabilities(&self) -> SigningProviderCapabilities {
        Self::signing_capabilities()
    }

    fn provisioning_semantics(&self) -> SigningProvisioningSemantics {
        SigningProvisioningSemantics::StatelessHandle
    }

    async fn provision(
        &self,
        request: ProvisionSigningKeyRequest,
    ) -> Result<ProvisionedSigningKey, ProviderError> {
        self.validate_context(&request.context, MaterialKind::SigningKey)?;
        if request.algorithm != SigningAlgorithm::Ed25519 {
            return Err(unsupported_algorithm());
        }
        let mut seed = Zeroizing::new([0_u8; ED25519_SEED_LEN]);
        getrandom::fill(seed.as_mut()).map_err(|_| unavailable())?;
        let signing_key = SigningKey::from_bytes(&seed);
        let public_key = SigningPublicKey::new(
            SigningAlgorithm::Ed25519,
            signing_key.verifying_key().to_bytes().to_vec(),
        )
        .map_err(|_| integrity())?;
        let envelope = Self::seal_envelope(&self.keys.signing, &request.context, seed.as_ref())?;
        Ok(ProvisionedSigningKey {
            handle: OpaqueHandle::new(envelope).map_err(|_| integrity())?,
            public_key,
        })
    }

    async fn inspect(
        &self,
        _request: InspectSigningKeyRequest,
    ) -> Result<ProvisionedSigningKey, ProviderError> {
        // No provider-side result exists: PostgreSQL owns the sole self-contained live handle.
        Err(provider_error(
            ProviderErrorClass::NotFound,
            RetryClassification::ExactInputSafe,
            "stateless.no-result",
        ))
    }

    async fn destroy(
        &self,
        _request: DestroySigningKeyRequest,
    ) -> Result<DestroyOutcome, ProviderError> {
        // PostgreSQL crypto-erasure removes the self-contained handle from live authority.
        Ok(DestroyOutcome::Unsupported)
    }
}

#[async_trait]
impl RuntimeSigner for SoftwareCustodyProvider {
    fn provider_id(&self) -> ProviderId {
        self.provider_id.clone()
    }

    fn capabilities(&self) -> SigningProviderCapabilities {
        Self::signing_capabilities()
    }

    async fn sign(&self, request: SignRequest) -> Result<Signature, ProviderError> {
        self.validate_context(&request.context, MaterialKind::SigningKey)?;
        if request.algorithm != SigningAlgorithm::Ed25519 {
            return Err(unsupported_algorithm());
        }
        let stored = request
            .handle
            .expose(|handle| Self::open_envelope(&self.keys.signing, &request.context, handle))?;
        let seed: [u8; ED25519_SEED_LEN] = stored.as_slice().try_into().map_err(|_| integrity())?;
        let seed = Zeroizing::new(seed);
        let signing_key = SigningKey::from_bytes(&seed);
        Signature::new(
            SigningAlgorithm::Ed25519,
            signing_key
                .sign(request.signing_input.as_bytes())
                .to_bytes()
                .to_vec(),
        )
        .map_err(|_| integrity())
    }
}

#[async_trait]
impl ConfigurationSecretSealer for SoftwareCustodyProvider {
    fn provider_id(&self) -> ProviderId {
        self.provider_id.clone()
    }

    fn supported_format_versions(&self) -> ProviderFormatVersions {
        Self::format_versions()
    }

    async fn seal(&self, request: SealSecretRequest) -> Result<SealedSecret, ProviderError> {
        self.validate_context(&request.context, MaterialKind::ConfigurationSecret)?;
        let fingerprint = request
            .plaintext
            .expose(|plaintext| self.fingerprint(&request.context, plaintext))?;
        let envelope = request.plaintext.expose(|plaintext| {
            Self::seal_envelope(&self.keys.secrets, &request.context, plaintext)
        })?;
        Ok(SealedSecret {
            envelope: OpaqueEnvelope::new(envelope).map_err(|_| integrity())?,
            request_fingerprint: RequestFingerprint::new(fingerprint.to_vec())
                .map_err(|_| integrity())?,
        })
    }
}

#[async_trait]
impl ConfigurationSecretOpener for SoftwareCustodyProvider {
    fn provider_id(&self) -> ProviderId {
        self.provider_id.clone()
    }

    fn supported_format_versions(&self) -> ProviderFormatVersions {
        Self::format_versions()
    }

    async fn open(&self, request: OpenSecretRequest) -> Result<SecretPlaintext, ProviderError> {
        self.validate_context(&request.context, MaterialKind::ConfigurationSecret)?;
        let plaintext = request.envelope.expose(|envelope| {
            Self::open_envelope(&self.keys.secrets, &request.context, envelope)
        })?;
        SecretPlaintext::from_zeroizing(plaintext).map_err(|_| integrity())
    }
}

fn derive(hkdf: &Hkdf<Sha256>, label: &[u8]) -> Result<[u8; 32], ProviderError> {
    let label_len = u32::try_from(label.len()).map_err(|_| integrity())?;
    let mut info = Vec::with_capacity(DERIVE_DOMAIN.len() + 4 + label.len());
    info.extend_from_slice(DERIVE_DOMAIN);
    info.extend_from_slice(&label_len.to_be_bytes());
    info.extend_from_slice(label);
    let mut output = [0_u8; 32];
    hkdf.expand(&info, &mut output).map_err(|_| integrity())?;
    Ok(output)
}

fn update_framed(mac: &mut HmacSha256, value: &[u8]) -> Result<(), ProviderError> {
    let length = u64::try_from(value.len()).map_err(|_| integrity())?;
    mac.update(&length.to_be_bytes());
    mac.update(value);
    Ok(())
}

fn provider_error(
    class: ProviderErrorClass,
    retry: RetryClassification,
    code: &str,
) -> ProviderError {
    let error = ProviderError::new(class, retry);
    ProviderErrorCode::new(code).map_or(error.clone(), |code| error.with_code(code))
}

fn unsupported_algorithm() -> ProviderError {
    provider_error(
        ProviderErrorClass::UnsupportedAlgorithm,
        RetryClassification::Never,
        "algorithm.unsupported",
    )
}

fn unavailable() -> ProviderError {
    provider_error(
        ProviderErrorClass::Unavailable,
        RetryClassification::ExactInputSafe,
        "software.unavailable",
    )
}

fn integrity() -> ProviderError {
    provider_error(
        ProviderErrorClass::Integrity,
        RetryClassification::Never,
        "software.integrity",
    )
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signature as Ed25519Signature, Verifier as _, VerifyingKey};
    use owlauth_key_provider::{
        ContextVersion, DeploymentId, FieldPurpose, MaterialId, OwnerId, OwnerKind, ProjectId,
        ProtectionContext, ProtectionContextParts, ProviderFormatVersion, Scope, SigningInput,
    };

    use super::*;

    fn context(material_kind: MaterialKind, generation: u64) -> ProtectionContext {
        ProtectionContext::new(ProtectionContextParts {
            version: ContextVersion::V1,
            deployment_id: DeploymentId::new("deployment-1").unwrap(),
            scope: Scope::Project(ProjectId::new("project-1").unwrap()),
            material_id: MaterialId::new("material-1").unwrap(),
            material_kind,
            owner_kind: OwnerKind::new("provider").unwrap(),
            owner_id: OwnerId::new("owner-1").unwrap(),
            generation,
            field_purpose: FieldPurpose::new("client-secret").unwrap(),
            provider_id: ProviderId::new("software").unwrap(),
            provider_format_version: ProviderFormatVersion::new(1).unwrap(),
        })
        .unwrap()
    }

    fn software_provider(root: u8) -> SoftwareCustodyProvider {
        SoftwareCustodyProvider::new(ProviderId::new("software").unwrap(), [root; 32]).unwrap()
    }

    #[tokio::test]
    async fn secret_envelopes_are_randomized_with_stable_fingerprints() {
        let provider = software_provider(7);
        let context = context(MaterialKind::ConfigurationSecret, 1);
        let first = ConfigurationSecretSealer::seal(
            &provider,
            SealSecretRequest {
                context: context.clone(),
                plaintext: SecretPlaintext::new(b"secret".to_vec()).unwrap(),
            },
        )
        .await
        .unwrap();
        let second = ConfigurationSecretSealer::seal(
            &provider,
            SealSecretRequest {
                context: context.clone(),
                plaintext: SecretPlaintext::new(b"secret".to_vec()).unwrap(),
            },
        )
        .await
        .unwrap();
        assert_ne!(first.envelope, second.envelope);
        assert_eq!(first.request_fingerprint, second.request_fingerprint);

        let opened = ConfigurationSecretOpener::open(
            &provider,
            OpenSecretRequest {
                context,
                envelope: first.envelope,
            },
        )
        .await
        .unwrap();
        opened.expose(|value| assert_eq!(value, b"secret"));
    }

    #[tokio::test]
    async fn context_generation_and_root_substitution_fail_closed() {
        let provider = software_provider(7);
        let original = context(MaterialKind::ConfigurationSecret, 1);
        let sealed = ConfigurationSecretSealer::seal(
            &provider,
            SealSecretRequest {
                context: original,
                plaintext: SecretPlaintext::new(b"secret".to_vec()).unwrap(),
            },
        )
        .await
        .unwrap();

        let wrong_generation = ConfigurationSecretOpener::open(
            &provider,
            OpenSecretRequest {
                context: context(MaterialKind::ConfigurationSecret, 2),
                envelope: OpaqueEnvelope::new(sealed.envelope.expose(<[u8]>::to_vec)).unwrap(),
            },
        )
        .await
        .unwrap_err();
        assert_eq!(wrong_generation.class(), ProviderErrorClass::Integrity);

        let wrong_root = ConfigurationSecretOpener::open(
            &software_provider(8),
            OpenSecretRequest {
                context: context(MaterialKind::ConfigurationSecret, 1),
                envelope: sealed.envelope,
            },
        )
        .await
        .unwrap_err();
        assert_eq!(wrong_root.class(), ProviderErrorClass::Integrity);
    }

    #[tokio::test]
    async fn signing_handle_produces_a_verifiable_ed25519_signature() {
        let provider = software_provider(9);
        let context = context(MaterialKind::SigningKey, 1);
        let operation_id = owlauth_key_provider::OperationId::new(b"operation-1".to_vec()).unwrap();
        assert_eq!(
            provider.provisioning_semantics(),
            SigningProvisioningSemantics::StatelessHandle
        );
        let provisioned = provider
            .provision(ProvisionSigningKeyRequest {
                operation_id: operation_id.clone(),
                algorithm: SigningAlgorithm::Ed25519,
                context: context.clone(),
            })
            .await
            .unwrap();
        let retried = provider
            .provision(ProvisionSigningKeyRequest {
                operation_id: operation_id.clone(),
                algorithm: SigningAlgorithm::Ed25519,
                context: context.clone(),
            })
            .await
            .unwrap();
        assert_ne!(provisioned.public_key, retried.public_key);
        assert!(
            !provisioned
                .handle
                .expose(|first| retried.handle.expose(|second| first == second))
        );
        let inspection = provider
            .inspect(InspectSigningKeyRequest {
                operation_id,
                algorithm: SigningAlgorithm::Ed25519,
                context: context.clone(),
            })
            .await
            .unwrap_err();
        assert_eq!(inspection.class(), ProviderErrorClass::NotFound);
        assert_eq!(
            inspection.retry_classification(),
            RetryClassification::ExactInputSafe
        );
        let input = SigningInput::new(b"header.payload".to_vec()).unwrap();
        let signature = RuntimeSigner::sign(
            &provider,
            SignRequest {
                algorithm: SigningAlgorithm::Ed25519,
                context,
                handle: provisioned.handle,
                signing_input: input.clone(),
            },
        )
        .await
        .unwrap();
        let verifying_key = VerifyingKey::from_bytes(
            provisioned
                .public_key
                .as_bytes()
                .try_into()
                .expect("Ed25519 public key length"),
        )
        .unwrap();
        let signature = Ed25519Signature::from_slice(signature.as_bytes()).unwrap();
        verifying_key.verify(input.as_bytes(), &signature).unwrap();
    }

    #[test]
    fn derived_subkeys_are_distinct_and_stable() {
        let provider = software_provider(11);
        assert_ne!(
            provider.keys.signing.as_ref(),
            provider.keys.secrets.as_ref()
        );
        assert_ne!(
            provider.keys.signing.as_ref(),
            provider.keys.fingerprints.as_ref()
        );
        assert_eq!(
            provider.keys.signing.as_ref(),
            software_provider(11).keys.signing.as_ref()
        );
    }

    #[test]
    fn software_derivation_and_fingerprint_vector() {
        let provider = software_provider(0);
        let context = context(MaterialKind::ConfigurationSecret, 1);
        assert_eq!(
            hex(provider.keys.signing.as_ref()),
            "d4856ae8f56a0ec4495ec58a29b12f10a990daba3405facbbe9fc4a860320798"
        );
        assert_eq!(
            hex(provider.keys.secrets.as_ref()),
            "6c5589d9ae5301b714fb5db14fa1b2f023bf0f0c92edfdaa820ce9fbfd8df59a"
        );
        assert_eq!(
            hex(provider.keys.fingerprints.as_ref()),
            "70befd39bb89269088c27e0abe64c982e0b9b10f684b53c8a07a83e04c18ba12"
        );
        assert_eq!(
            hex(&provider.fingerprint(&context, b"fixture-secret").unwrap()),
            "bb98ed273eb04a9edf5a96100ae2d67d996ea05fcfbfb01c0579f0979ae66970"
        );
    }

    fn hex(value: &[u8]) -> String {
        use std::fmt::Write as _;

        let mut encoded = String::with_capacity(value.len() * 2);
        for byte in value {
            write!(&mut encoded, "{byte:02x}").expect("writing to a String cannot fail");
        }
        encoded
    }
}
