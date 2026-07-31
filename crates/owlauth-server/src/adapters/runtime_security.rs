use std::{collections::BTreeMap, sync::Arc};

use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use ed25519_dalek::{Signature, VerifyingKey};
use hmac::{Hmac, Mac};
use serde_json::{Map, Value};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::application::{
    ApplicationError, OpaquePurpose, ProtectedPurpose, ProtectedValue, ProviderSecretResolver,
    RuntimeProtector, RuntimeSigner, VersionedDigest,
};

use super::software_store::EncryptedFileStore;

const DIGEST_DOMAIN: &[u8] = b"owlauth-runtime-digest-v1\0";
const DERIVATION_DOMAIN: &[u8] = b"owlauth-runtime-derived-opaque-v1\0";
const PROTECTION_DOMAIN: &[u8] = b"owlauth-runtime-protection-v1\0";
const NONCE_BYTES: usize = 24;
const TAG_BYTES: usize = 16;
const SIGNING_ALGORITHM: &str = "EdDSA";

type HmacSha256 = Hmac<Sha256>;

/// Independent roots for keyed digests and authenticated encryption at one key version.
///
/// This type intentionally has no `Debug` implementation: both fields are secret key material.
pub(crate) struct RuntimeKeyMaterial {
    digest_key: Zeroizing<[u8; 32]>,
    protection_key: Zeroizing<[u8; 32]>,
}

impl RuntimeKeyMaterial {
    pub(crate) fn new(digest_key: [u8; 32], protection_key: [u8; 32]) -> Self {
        Self {
            digest_key: Zeroizing::new(digest_key),
            protection_key: Zeroizing::new(protection_key),
        }
    }
}

/// In-process Runtime cryptography backed by explicitly supplied active and retained keys.
///
/// The active version is used for new values. Retained versions are accepted only for
/// deterministic derivation and decryption of already-persisted values.
#[derive(Clone)]
pub(crate) struct SoftwareRuntimeProtector {
    deployment_context: Arc<str>,
    active_version: i32,
    keys: Arc<BTreeMap<i32, RuntimeKeyMaterial>>,
}

impl SoftwareRuntimeProtector {
    pub(crate) fn new(
        deployment_context: String,
        active_version: i32,
        active: RuntimeKeyMaterial,
        retained: BTreeMap<i32, RuntimeKeyMaterial>,
    ) -> Result<Self, ApplicationError> {
        if deployment_context.is_empty()
            || deployment_context.len() > 128
            || active_version <= 0
            || retained.keys().any(|version| *version <= 0)
            || retained.contains_key(&active_version)
        {
            return Err(ApplicationError::InvalidInput);
        }

        let mut keys = retained;
        keys.insert(active_version, active);
        Ok(Self {
            deployment_context: Arc::from(deployment_context),
            active_version,
            keys: Arc::new(keys),
        })
    }

    fn key(&self, version: i32) -> Result<&RuntimeKeyMaterial, ApplicationError> {
        self.keys.get(&version).ok_or(ApplicationError::Integrity)
    }

    fn keyed_output(
        &self,
        domain: &[u8],
        version: i32,
        purpose: &str,
        context: &[u8],
        value: &[u8],
    ) -> Result<[u8; 32], ApplicationError> {
        let key = self.key(version)?;
        let mut mac = <HmacSha256 as Mac>::new_from_slice(key.digest_key.as_ref())
            .map_err(|_| ApplicationError::Integrity)?;
        mac.update(domain);
        update_framed(&mut mac, self.deployment_context.as_bytes())?;
        update_framed(&mut mac, &version.to_be_bytes())?;
        update_framed(&mut mac, purpose.as_bytes())?;
        update_framed(&mut mac, context)?;
        update_framed(&mut mac, value)?;
        Ok(mac.finalize().into_bytes().into())
    }

    fn associated_data(
        &self,
        version: i32,
        purpose: ProtectedPurpose,
        context: &[u8],
    ) -> Result<Vec<u8>, ApplicationError> {
        let mut associated_data = Vec::with_capacity(
            PROTECTION_DOMAIN.len()
                + self.deployment_context.len()
                + purpose.as_str().len()
                + context.len()
                + 48,
        );
        associated_data.extend_from_slice(PROTECTION_DOMAIN);
        append_framed(&mut associated_data, self.deployment_context.as_bytes())?;
        append_framed(&mut associated_data, &version.to_be_bytes())?;
        append_framed(&mut associated_data, purpose.as_str().as_bytes())?;
        append_framed(&mut associated_data, context)?;
        Ok(associated_data)
    }
}

impl RuntimeProtector for SoftwareRuntimeProtector {
    fn active_version(&self) -> i32 {
        self.active_version
    }

    fn random_opaque(&self, bytes: usize) -> Result<Zeroizing<String>, ApplicationError> {
        if bytes == 0 {
            return Err(ApplicationError::InvalidInput);
        }
        let mut random = Zeroizing::new(vec![0_u8; bytes]);
        getrandom::fill(random.as_mut()).map_err(|_| ApplicationError::ExternalStore)?;
        Ok(Zeroizing::new(URL_SAFE_NO_PAD.encode(random.as_slice())))
    }

    fn digest(
        &self,
        purpose: OpaquePurpose,
        context: &[u8],
        value: &[u8],
    ) -> Result<VersionedDigest, ApplicationError> {
        self.digest_at(purpose, context, value, self.active_version)
    }

    fn digest_at(
        &self,
        purpose: OpaquePurpose,
        context: &[u8],
        value: &[u8],
        key_version: i32,
    ) -> Result<VersionedDigest, ApplicationError> {
        Ok(VersionedDigest {
            value: self.keyed_output(
                DIGEST_DOMAIN,
                key_version,
                purpose.as_str(),
                context,
                value,
            )?,
            key_version,
        })
    }

    fn derive_opaque(
        &self,
        purpose: OpaquePurpose,
        context: &[u8],
        key_version: Option<i32>,
    ) -> Result<Zeroizing<String>, ApplicationError> {
        let version = key_version.unwrap_or(self.active_version);
        let derived = Zeroizing::new(self.keyed_output(
            DERIVATION_DOMAIN,
            version,
            purpose.as_str(),
            context,
            &[],
        )?);
        Ok(Zeroizing::new(URL_SAFE_NO_PAD.encode(derived.as_slice())))
    }

    fn protect(
        &self,
        purpose: ProtectedPurpose,
        context: &[u8],
        value: &[u8],
    ) -> Result<ProtectedValue, ApplicationError> {
        let key = self.key(self.active_version)?;
        let cipher = XChaCha20Poly1305::new_from_slice(key.protection_key.as_ref())
            .map_err(|_| ApplicationError::Integrity)?;
        let mut nonce = [0_u8; NONCE_BYTES];
        getrandom::fill(&mut nonce).map_err(|_| ApplicationError::ExternalStore)?;
        let associated_data = self.associated_data(self.active_version, purpose, context)?;
        let nonce_value = XNonce::from(nonce);
        let encrypted = cipher
            .encrypt(
                &nonce_value,
                Payload {
                    msg: value,
                    aad: &associated_data,
                },
            )
            .map_err(|_| ApplicationError::Integrity)?;
        let mut ciphertext = Vec::with_capacity(NONCE_BYTES + encrypted.len());
        ciphertext.extend_from_slice(&nonce);
        ciphertext.extend_from_slice(&encrypted);
        nonce.fill(0);
        Ok(ProtectedValue {
            ciphertext,
            key_version: self.active_version,
        })
    }

    fn unprotect(
        &self,
        purpose: ProtectedPurpose,
        context: &[u8],
        value: &ProtectedValue,
    ) -> Result<Zeroizing<Vec<u8>>, ApplicationError> {
        if value.ciphertext.len() < NONCE_BYTES + TAG_BYTES {
            return Err(ApplicationError::Integrity);
        }
        let key = self.key(value.key_version)?;
        let cipher = XChaCha20Poly1305::new_from_slice(key.protection_key.as_ref())
            .map_err(|_| ApplicationError::Integrity)?;
        let (nonce, ciphertext) = value.ciphertext.split_at(NONCE_BYTES);
        let nonce: [u8; NONCE_BYTES] = nonce.try_into().map_err(|_| ApplicationError::Integrity)?;
        let nonce_value = XNonce::from(nonce);
        let associated_data = self.associated_data(value.key_version, purpose, context)?;
        let plaintext = cipher
            .decrypt(
                &nonce_value,
                Payload {
                    msg: ciphertext,
                    aad: &associated_data,
                },
            )
            .map_err(|_| ApplicationError::Integrity)?;
        Ok(Zeroizing::new(plaintext))
    }
}

/// A signer capability over an encrypted file store. It cannot read or return signing seeds.
#[derive(Clone)]
pub(crate) struct EncryptedFileRuntimeSigner {
    store: EncryptedFileStore,
}

impl EncryptedFileRuntimeSigner {
    pub(crate) fn new(store: EncryptedFileStore) -> Self {
        Self { store }
    }
}

#[async_trait]
impl RuntimeSigner for EncryptedFileRuntimeSigner {
    async fn sign(
        &self,
        signer_ref: &str,
        signing_input: &[u8],
    ) -> Result<Vec<u8>, ApplicationError> {
        self.store
            .sign_ed25519(signer_ref, signing_input)
            .await
            .map_err(authoritative_reference_error)
    }

    fn verify(
        &self,
        public_jwk: &Value,
        signing_input: &[u8],
        signature: &[u8],
    ) -> Result<(), ApplicationError> {
        verify_ed25519(public_jwk, signing_input, signature)
    }
}

/// A resolver capability over an encrypted file store. References are used exactly as supplied.
#[derive(Clone)]
pub(crate) struct EncryptedFileProviderSecretResolver {
    store: EncryptedFileStore,
}

impl EncryptedFileProviderSecretResolver {
    pub(crate) fn new(store: EncryptedFileStore) -> Self {
        Self { store }
    }
}

#[async_trait]
impl ProviderSecretResolver for EncryptedFileProviderSecretResolver {
    async fn resolve(&self, secret_ref: &str) -> Result<Zeroizing<String>, ApplicationError> {
        self.store
            .read_utf8_secret(secret_ref)
            .await
            .map_err(authoritative_reference_error)
    }
}

fn verify_ed25519(
    public_jwk: &Value,
    signing_input: &[u8],
    signature: &[u8],
) -> Result<(), ApplicationError> {
    let jwk = public_jwk.as_object().ok_or(ApplicationError::Integrity)?;
    validate_public_ed25519_jwk(jwk)?;
    let encoded_key = jwk
        .get("x")
        .and_then(Value::as_str)
        .ok_or(ApplicationError::Integrity)?;
    let decoded_key = URL_SAFE_NO_PAD
        .decode(encoded_key)
        .map_err(|_| ApplicationError::Integrity)?;
    if URL_SAFE_NO_PAD.encode(&decoded_key) != encoded_key {
        return Err(ApplicationError::Integrity);
    }
    let key_bytes: [u8; 32] = decoded_key
        .try_into()
        .map_err(|_| ApplicationError::Integrity)?;
    let verifying_key =
        VerifyingKey::from_bytes(&key_bytes).map_err(|_| ApplicationError::Integrity)?;
    let signature = Signature::from_slice(signature).map_err(|_| ApplicationError::InvalidInput)?;
    verifying_key
        .verify_strict(signing_input, &signature)
        .map_err(|_| ApplicationError::InvalidTransition)
}

fn validate_public_ed25519_jwk(jwk: &Map<String, Value>) -> Result<(), ApplicationError> {
    const ALLOWED_FIELDS: [&str; 6] = ["alg", "crv", "kid", "kty", "use", "x"];
    let fields_are_known = jwk
        .keys()
        .all(|field| ALLOWED_FIELDS.contains(&field.as_str()));
    if !fields_are_known
        || jwk.get("kty").and_then(Value::as_str) != Some("OKP")
        || jwk.get("crv").and_then(Value::as_str) != Some("Ed25519")
        || jwk.get("alg").and_then(Value::as_str) != Some(SIGNING_ALGORITHM)
        || jwk.get("use").and_then(Value::as_str) != Some("sig")
        || !jwk.get("x").is_some_and(Value::is_string)
        || jwk
            .get("kid")
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
    {
        return Err(ApplicationError::Integrity);
    }
    Ok(())
}

fn authoritative_reference_error(error: ApplicationError) -> ApplicationError {
    if error == ApplicationError::InvalidInput {
        ApplicationError::Integrity
    } else {
        error
    }
}

fn update_framed(mac: &mut HmacSha256, value: &[u8]) -> Result<(), ApplicationError> {
    let length = u64::try_from(value.len()).map_err(|_| ApplicationError::InvalidInput)?;
    mac.update(&length.to_be_bytes());
    mac.update(value);
    Ok(())
}

fn append_framed(output: &mut Vec<u8>, value: &[u8]) -> Result<(), ApplicationError> {
    let length = u64::try_from(value.len()).map_err(|_| ApplicationError::InvalidInput)?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value);
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, fs, path::PathBuf};

    use ed25519_dalek::SigningKey;
    use serde_json::json;
    use uuid::Uuid;

    use super::*;

    fn material(digest: u8, protection: u8) -> RuntimeKeyMaterial {
        RuntimeKeyMaterial::new([digest; 32], [protection; 32])
    }

    fn protector() -> SoftwareRuntimeProtector {
        SoftwareRuntimeProtector::new(
            "deployment".to_owned(),
            2,
            material(2, 12),
            BTreeMap::from([(1, material(1, 11))]),
        )
        .unwrap()
    }

    fn temporary_root(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!("owlauth-{label}-{}", Uuid::new_v4()))
    }

    #[test]
    fn digests_and_derivations_separate_purpose_context_and_version() {
        let protector = protector();
        assert_eq!(protector.active_version(), 2);
        let digest = protector
            .digest(OpaquePurpose::Interaction, b"project-a", b"opaque")
            .unwrap();
        assert_eq!(digest.key_version, 2);
        let old = SoftwareRuntimeProtector::new(
            "deployment".to_owned(),
            1,
            material(1, 11),
            BTreeMap::new(),
        )
        .unwrap();
        assert_eq!(
            protector
                .digest_at(OpaquePurpose::Interaction, b"project-a", b"opaque", 1)
                .unwrap(),
            old.digest(OpaquePurpose::Interaction, b"project-a", b"opaque")
                .unwrap()
        );
        assert_eq!(
            protector.digest_at(OpaquePurpose::Interaction, b"project-a", b"opaque", 99),
            Err(ApplicationError::Integrity)
        );
        let version_one_same_root = SoftwareRuntimeProtector::new(
            "deployment".to_owned(),
            1,
            material(2, 12),
            BTreeMap::new(),
        )
        .unwrap();
        assert_ne!(
            digest.value,
            version_one_same_root
                .digest(OpaquePurpose::Interaction, b"project-a", b"opaque")
                .unwrap()
                .value
        );
        assert_ne!(
            digest.value,
            protector
                .digest(OpaquePurpose::BrowserBinding, b"project-a", b"opaque")
                .unwrap()
                .value
        );
        assert_ne!(
            digest.value,
            protector
                .digest(OpaquePurpose::Interaction, b"project-b", b"opaque")
                .unwrap()
                .value
        );

        let first = protector
            .derive_opaque(OpaquePurpose::InteractionCsrf, b"transaction", Some(1))
            .unwrap();
        assert_eq!(
            first,
            protector
                .derive_opaque(OpaquePurpose::InteractionCsrf, b"transaction", Some(1))
                .unwrap()
        );
        assert_ne!(
            first,
            protector
                .derive_opaque(OpaquePurpose::InteractionCsrf, b"transaction", Some(2))
                .unwrap()
        );
        assert_ne!(
            first,
            protector
                .derive_opaque(OpaquePurpose::OidcNonce, b"transaction", Some(1))
                .unwrap()
        );
        assert_ne!(
            first,
            protector
                .derive_opaque(OpaquePurpose::InteractionCsrf, b"other", Some(1))
                .unwrap()
        );
        assert_eq!(
            protector.derive_opaque(OpaquePurpose::InteractionCsrf, b"transaction", Some(99)),
            Err(ApplicationError::Integrity)
        );
    }

    #[test]
    fn protection_is_context_bound_and_retained_versions_decrypt() {
        let old = SoftwareRuntimeProtector::new(
            "deployment".to_owned(),
            1,
            material(1, 11),
            BTreeMap::new(),
        )
        .unwrap();
        let old_value = old
            .protect(
                ProtectedPurpose::ApplicationState,
                b"application-a",
                b"state",
            )
            .unwrap();
        let rotated = SoftwareRuntimeProtector::new(
            "deployment".to_owned(),
            2,
            material(1, 11),
            BTreeMap::from([(1, material(1, 11))]),
        )
        .unwrap();
        assert_eq!(
            &*rotated
                .unprotect(
                    ProtectedPurpose::ApplicationState,
                    b"application-a",
                    &old_value
                )
                .unwrap(),
            b"state"
        );
        assert_eq!(
            rotated.unprotect(ProtectedPurpose::ProviderPkce, b"application-a", &old_value),
            Err(ApplicationError::Integrity)
        );
        assert_eq!(
            rotated.unprotect(
                ProtectedPurpose::ApplicationState,
                b"application-b",
                &old_value
            ),
            Err(ApplicationError::Integrity)
        );

        let mut wrong_version = old_value.clone();
        wrong_version.key_version = 2;
        assert_eq!(
            rotated.unprotect(
                ProtectedPurpose::ApplicationState,
                b"application-a",
                &wrong_version
            ),
            Err(ApplicationError::Integrity)
        );
    }

    #[test]
    fn ciphertext_tampering_is_rejected() {
        let protector = protector();
        let mut protected = protector
            .protect(ProtectedPurpose::ProviderPkce, b"provider", b"verifier")
            .unwrap();
        let last = protected.ciphertext.last_mut().unwrap();
        *last ^= 1;
        assert_eq!(
            protector.unprotect(ProtectedPurpose::ProviderPkce, b"provider", &protected),
            Err(ApplicationError::Integrity)
        );
    }

    #[test]
    fn random_opaque_is_unpadded_base64url() {
        let protector = protector();
        let first = protector.random_opaque(32).unwrap();
        let second = protector.random_opaque(32).unwrap();
        assert_ne!(first, second);
        assert!(!first.contains('='));
        assert_eq!(URL_SAFE_NO_PAD.decode(first.as_bytes()).unwrap().len(), 32);
    }

    #[tokio::test]
    async fn signer_signs_and_strictly_verifies_without_exporting_seed() {
        let root = temporary_root("runtime-signer");
        let store = EncryptedFileStore::new(root.clone(), [31; 32]).unwrap();
        let alias = "signer_opaque_reference".to_owned();
        let seed = [7_u8; 32];
        store
            .put_if_absent(alias.clone(), Zeroizing::new(seed.to_vec()))
            .await
            .unwrap();
        let signer = EncryptedFileRuntimeSigner::new(store);
        let input = b"header.payload";
        let signature = signer.sign(&alias, input).await.unwrap();
        let public = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
        let jwk = json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "alg": "EdDSA",
            "use": "sig",
            "kid": "key-1",
            "x": URL_SAFE_NO_PAD.encode(public),
        });
        signer.verify(&jwk, input, &signature).unwrap();

        let wrong_public = SigningKey::from_bytes(&[8; 32]).verifying_key().to_bytes();
        let wrong_jwk = json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "alg": "EdDSA",
            "use": "sig",
            "kid": "key-2",
            "x": URL_SAFE_NO_PAD.encode(wrong_public),
        });
        assert_eq!(
            signer.verify(&wrong_jwk, input, &signature),
            Err(ApplicationError::InvalidTransition)
        );
        let private_jwk = json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "alg": "EdDSA",
            "use": "sig",
            "x": URL_SAFE_NO_PAD.encode(public),
            "d": URL_SAFE_NO_PAD.encode(seed),
        });
        assert_eq!(
            signer.verify(&private_jwk, input, &signature),
            Err(ApplicationError::Integrity)
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn provider_secret_resolver_reads_the_exact_reference() {
        let root = temporary_root("runtime-secret");
        let store = EncryptedFileStore::new(root.clone(), [41; 32]).unwrap();
        let alias = "provider_secret_reference".to_owned();
        store
            .put_if_absent(
                alias.clone(),
                Zeroizing::new(b"exact-provider-secret".to_vec()),
            )
            .await
            .unwrap();
        let resolver = EncryptedFileProviderSecretResolver::new(store);
        assert_eq!(
            &*resolver.resolve(&alias).await.unwrap(),
            "exact-provider-secret"
        );
        assert_eq!(
            resolver.resolve("provider_secret_other").await,
            Err(ApplicationError::Integrity)
        );
        fs::remove_dir_all(root).unwrap();
    }
}
