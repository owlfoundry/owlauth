use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    sync::Arc,
};

use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use ed25519_dalek::{Signer as _, SigningKey};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use thiserror::Error;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::application::{
    ApplicationError, ConfigurationSecretProvisioner, ConfigurationSecretStore, SignerStore,
};

const FORMAT_VERSION: u8 = 1;
const SIGNING_ALGORITHM: &str = "EdDSA";

#[derive(Clone)]
pub(crate) struct EncryptedFileStore {
    root: Arc<PathBuf>,
    key: Arc<Zeroizing<[u8; 32]>>,
}

impl std::fmt::Debug for EncryptedFileStore {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EncryptedFileStore")
            .field("root", &self.root)
            .field("key", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum StoreWrite {
    Created,
    Existing,
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub(crate) enum StoreError {
    #[error("external store alias is invalid")]
    InvalidAlias,
    #[error("external store value does not exist")]
    NotFound,
    #[error("external store operation failed")]
    Unavailable,
    #[error("external store value is invalid")]
    InvalidValue,
}

#[derive(Deserialize, Serialize)]
struct Envelope {
    version: u8,
    nonce: String,
    ciphertext: String,
}

/// Control-plane wrapper that exposes only encrypted create-if-absent operations. It has no read,
/// decrypt, signing, or Runtime credential-resolution API even though it shares the on-disk format.
#[derive(Clone)]
pub(crate) struct WriteOnlyEncryptedFileProvisioner {
    inner: EncryptedFileStore,
}

impl WriteOnlyEncryptedFileProvisioner {
    pub(crate) fn new(root: PathBuf, key: [u8; 32]) -> Result<Self, StoreError> {
        Ok(Self {
            inner: EncryptedFileStore::new(root, key)?,
        })
    }
}

impl EncryptedFileStore {
    pub(crate) fn new(root: PathBuf, key: [u8; 32]) -> Result<Self, StoreError> {
        if !root.is_absolute() {
            return Err(StoreError::Unavailable);
        }
        Ok(Self {
            root: Arc::new(root),
            key: Arc::new(Zeroizing::new(key)),
        })
    }

    pub(crate) fn request_fingerprint(&self, value: &[u8]) -> [u8; 32] {
        let mut digest = Sha256::new();
        digest.update(b"owlauth-store-request-fingerprint-v1\0");
        digest.update(**self.key);
        digest.update(value);
        digest.finalize().into()
    }

    pub(crate) async fn put_if_absent(
        &self,
        alias: String,
        value: Zeroizing<Vec<u8>>,
    ) -> Result<StoreWrite, StoreError> {
        let store = self.clone();
        tokio::task::spawn_blocking(move || store.put_if_absent_blocking(&alias, &value, false))
            .await
            .map_err(|_| StoreError::Unavailable)?
    }

    async fn put_secret_if_absent(
        &self,
        alias: String,
        value: Zeroizing<Vec<u8>>,
    ) -> Result<StoreWrite, StoreError> {
        let store = self.clone();
        tokio::task::spawn_blocking(move || {
            let write = store.put_if_absent_blocking(&alias, &value, false)?;
            if write == StoreWrite::Existing {
                let existing = store.read_blocking(&alias)?;
                if !bool::from(existing.as_slice().ct_eq(value.as_slice())) {
                    return Err(StoreError::InvalidValue);
                }
            }
            Ok(write)
        })
        .await
        .map_err(|_| StoreError::Unavailable)?
    }

    /// Permanently tombstone an alias before removing its material. Provisioning checks the same
    /// durable marker before and after its atomic create, so a writer that started before cleanup
    /// either loses to the marker or has its just-created material removed.
    pub(crate) async fn erase(&self, alias: String) -> Result<(), StoreError> {
        let store = self.clone();
        tokio::task::spawn_blocking(move || {
            let path = store.path(&alias)?;
            let tombstone = store.tombstone_path(&alias)?;
            fs::create_dir_all(store.root.as_ref()).map_err(|_| StoreError::Unavailable)?;
            let _alias_lock = store.lock_alias(&alias)?;
            match OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&tombstone)
            {
                Ok(file) => file.sync_all().map_err(|_| StoreError::Unavailable)?,
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(_) => return Err(StoreError::Unavailable),
            }
            sync_directory(store.root.as_ref())?;
            match fs::remove_file(path) {
                Ok(()) => sync_directory(store.root.as_ref()),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(_) => Err(StoreError::Unavailable),
            }
        })
        .await
        .map_err(|_| StoreError::Unavailable)?
    }

    async fn read(&self, alias: String) -> Result<Zeroizing<Vec<u8>>, StoreError> {
        let store = self.clone();
        tokio::task::spawn_blocking(move || store.read_blocking(&alias))
            .await
            .map_err(|_| StoreError::Unavailable)?
    }

    pub(super) async fn sign_ed25519(
        &self,
        alias: &str,
        signing_input: &[u8],
    ) -> Result<Vec<u8>, ApplicationError> {
        let stored = self.read(alias.to_owned()).await.map_err(store_error)?;
        let mut seed = Zeroizing::new([0_u8; 32]);
        if stored.len() != seed.len() {
            return Err(ApplicationError::Integrity);
        }
        seed.copy_from_slice(&stored);
        let signing_key = SigningKey::from_bytes(&seed);
        Ok(signing_key.sign(signing_input).to_bytes().to_vec())
    }

    pub(super) async fn read_utf8_secret(
        &self,
        alias: &str,
    ) -> Result<Zeroizing<String>, ApplicationError> {
        let stored = self.read(alias.to_owned()).await.map_err(store_error)?;
        let secret = std::str::from_utf8(&stored).map_err(|_| ApplicationError::Integrity)?;
        Ok(Zeroizing::new(secret.to_owned()))
    }

    fn put_if_absent_blocking(
        &self,
        alias: &str,
        value: &[u8],
        permanent_erase_fence: bool,
    ) -> Result<StoreWrite, StoreError> {
        let final_path = self.path(alias)?;
        let tombstone_path = self.tombstone_path(alias)?;
        fs::create_dir_all(self.root.as_ref()).map_err(|_| StoreError::Unavailable)?;
        // OS advisory locks are released on process loss. Holding this per-alias lock over the
        // complete create orders it atomically with permanent erase across processes and crashes.
        let _alias_lock = permanent_erase_fence
            .then(|| self.lock_alias(alias))
            .transpose()?;
        if permanent_erase_fence && tombstone_path.exists() {
            return Err(StoreError::InvalidValue);
        }
        if final_path.exists() {
            return Ok(StoreWrite::Existing);
        }

        let mut nonce = [0_u8; 24];
        getrandom::fill(&mut nonce).map_err(|_| StoreError::Unavailable)?;
        let cipher = XChaCha20Poly1305::new((&**self.key).into());
        let associated_data = associated_data(alias);
        let nonce_value = XNonce::from(nonce);
        let ciphertext = cipher
            .encrypt(
                &nonce_value,
                Payload {
                    msg: value,
                    aad: associated_data.as_bytes(),
                },
            )
            .map_err(|_| StoreError::Unavailable)?;
        let envelope = Envelope {
            version: FORMAT_VERSION,
            nonce: URL_SAFE_NO_PAD.encode(nonce),
            ciphertext: URL_SAFE_NO_PAD.encode(ciphertext),
        };
        let encoded = serde_json::to_vec(&envelope).map_err(|_| StoreError::Unavailable)?;
        let temporary_path = self.root.join(format!(".{alias}.{}.tmp", Uuid::new_v4()));
        let mut temporary = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary_path)
            .map_err(|_| StoreError::Unavailable)?;
        let result = (|| {
            temporary
                .write_all(&encoded)
                .and_then(|()| temporary.sync_all())
                .map_err(|_| StoreError::Unavailable)?;
            let write = match fs::hard_link(&temporary_path, &final_path) {
                Ok(()) => {
                    fs::remove_file(&temporary_path).map_err(|_| StoreError::Unavailable)?;
                    sync_directory(self.root.as_ref())?;
                    StoreWrite::Created
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    StoreWrite::Existing
                }
                Err(_) => return Err(StoreError::Unavailable),
            };
            // Cleanup may have durably tombstoned after our first check. In that ordering the
            // alias is retired, and this writer is responsible for removing any material it won.
            if permanent_erase_fence && tombstone_path.exists() {
                match fs::remove_file(&final_path) {
                    Ok(()) => sync_directory(self.root.as_ref())?,
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(_) => return Err(StoreError::Unavailable),
                }
                return Err(StoreError::InvalidValue);
            }
            Ok(write)
        })();
        if result.is_err() || final_path.exists() {
            let _ = fs::remove_file(&temporary_path);
        }
        result
    }

    async fn provision_if_not_erased(
        &self,
        alias: String,
        value: Zeroizing<Vec<u8>>,
    ) -> Result<StoreWrite, StoreError> {
        let store = self.clone();
        tokio::task::spawn_blocking(move || store.put_if_absent_blocking(&alias, &value, true))
            .await
            .map_err(|_| StoreError::Unavailable)?
    }

    fn read_blocking(&self, alias: &str) -> Result<Zeroizing<Vec<u8>>, StoreError> {
        let path = self.path(alias)?;
        if self.tombstone_path(alias)?.exists() {
            return Err(StoreError::NotFound);
        }
        let encoded = fs::read(path).map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                StoreError::NotFound
            } else {
                StoreError::Unavailable
            }
        })?;
        let envelope: Envelope =
            serde_json::from_slice(&encoded).map_err(|_| StoreError::InvalidValue)?;
        if envelope.version != FORMAT_VERSION {
            return Err(StoreError::InvalidValue);
        }
        let nonce = URL_SAFE_NO_PAD
            .decode(envelope.nonce)
            .map_err(|_| StoreError::InvalidValue)?;
        let ciphertext = URL_SAFE_NO_PAD
            .decode(envelope.ciphertext)
            .map_err(|_| StoreError::InvalidValue)?;
        let nonce: [u8; 24] = nonce.try_into().map_err(|_| StoreError::InvalidValue)?;
        let cipher = XChaCha20Poly1305::new((&**self.key).into());
        let nonce_value = XNonce::from(nonce);
        let plaintext = cipher
            .decrypt(
                &nonce_value,
                Payload {
                    msg: &ciphertext,
                    aad: associated_data(alias).as_bytes(),
                },
            )
            .map_err(|_| StoreError::InvalidValue)?;
        Ok(Zeroizing::new(plaintext))
    }

    fn path(&self, alias: &str) -> Result<PathBuf, StoreError> {
        validate_alias(alias)?;
        Ok(self.root.join(format!("{alias}.owls")))
    }

    fn tombstone_path(&self, alias: &str) -> Result<PathBuf, StoreError> {
        Ok(self
            .root
            .join(format!(".erased-{}.tombstone", alias_path_digest(alias)?)))
    }

    fn lock_alias(&self, alias: &str) -> Result<fs::File, StoreError> {
        let path = self
            .root
            .join(format!(".alias-{}.lock", alias_path_digest(alias)?));
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)
            .map_err(|_| StoreError::Unavailable)?;
        file.lock().map_err(|_| StoreError::Unavailable)?;
        Ok(file)
    }
}

#[async_trait]
impl SignerStore for EncryptedFileStore {
    async fn put_if_absent(
        &self,
        alias: String,
        seed: Zeroizing<[u8; 32]>,
    ) -> Result<(), ApplicationError> {
        EncryptedFileStore::put_if_absent(self, alias, Zeroizing::new(seed.to_vec()))
            .await
            .map(|_| ())
            .map_err(store_error)
    }

    async fn public_jwk(&self, alias: String, kid: &str) -> Result<Value, ApplicationError> {
        let stored = EncryptedFileStore::read(self, alias)
            .await
            .map_err(store_error)?;
        let mut signing_bytes = Zeroizing::new([0_u8; 32]);
        if stored.len() != signing_bytes.len() {
            return Err(ApplicationError::Integrity);
        }
        signing_bytes.copy_from_slice(&stored);
        let signing = SigningKey::from_bytes(&signing_bytes);
        Ok(json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "alg": SIGNING_ALGORITHM,
            "use": "sig",
            "kid": kid,
            "x": URL_SAFE_NO_PAD.encode(signing.verifying_key().to_bytes()),
        }))
    }

    async fn verify(
        &self,
        alias: String,
        kid: &str,
        public_jwk: &Value,
    ) -> Result<(), ApplicationError> {
        let stored = EncryptedFileStore::read(self, alias)
            .await
            .map_err(store_error)?;
        let mut signing_bytes = Zeroizing::new([0_u8; 32]);
        if stored.len() != signing_bytes.len() {
            return Err(ApplicationError::Integrity);
        }
        signing_bytes.copy_from_slice(&stored);
        let verifying_bytes = SigningKey::from_bytes(&signing_bytes)
            .verifying_key()
            .to_bytes();
        let expected = public_jwk
            .as_object()
            .filter(|jwk| {
                jwk.get("kty").and_then(Value::as_str) == Some("OKP")
                    && jwk.get("crv").and_then(Value::as_str) == Some("Ed25519")
                    && jwk.get("alg").and_then(Value::as_str) == Some(SIGNING_ALGORITHM)
                    && jwk.get("use").and_then(Value::as_str) == Some("sig")
                    && jwk.get("kid").and_then(Value::as_str) == Some(kid)
            })
            .and_then(|jwk| jwk.get("x"))
            .and_then(Value::as_str)
            .and_then(|value| URL_SAFE_NO_PAD.decode(value).ok())
            .ok_or(ApplicationError::InvalidTransition)?;
        if expected.len() != verifying_bytes.len()
            || !bool::from(expected.as_slice().ct_eq(verifying_bytes.as_slice()))
        {
            return Err(ApplicationError::InvalidTransition);
        }
        Ok(())
    }
}

#[async_trait]
impl ConfigurationSecretProvisioner for WriteOnlyEncryptedFileProvisioner {
    fn request_fingerprint(&self, value: &[u8]) -> [u8; 32] {
        self.inner.request_fingerprint(value)
    }

    async fn provision_if_absent(
        &self,
        alias: String,
        value: Zeroizing<Vec<u8>>,
    ) -> Result<(), ApplicationError> {
        EncryptedFileStore::provision_if_not_erased(&self.inner, alias, value)
            .await
            .map(|_| ())
            .map_err(store_error)
    }
}

#[async_trait]
impl ConfigurationSecretProvisioner for EncryptedFileStore {
    fn request_fingerprint(&self, value: &[u8]) -> [u8; 32] {
        EncryptedFileStore::request_fingerprint(self, value)
    }

    async fn provision_if_absent(
        &self,
        alias: String,
        value: Zeroizing<Vec<u8>>,
    ) -> Result<(), ApplicationError> {
        // Do not reconcile by decrypting an existing value. The stable operation alias,
        // PostgreSQL request digest, and keyed safe fingerprint establish retry equivalence.
        EncryptedFileStore::provision_if_not_erased(self, alias, value)
            .await
            .map(|_| ())
            .map_err(store_error)
    }
}

#[async_trait]
impl ConfigurationSecretStore for EncryptedFileStore {
    fn request_fingerprint(&self, value: &[u8]) -> [u8; 32] {
        EncryptedFileStore::request_fingerprint(self, value)
    }

    async fn put_if_absent(
        &self,
        alias: String,
        value: Zeroizing<Vec<u8>>,
    ) -> Result<(), ApplicationError> {
        self.put_secret_if_absent(alias, value)
            .await
            .map(|_| ())
            .map_err(store_error)
    }

    async fn ensure_readable(&self, alias: String) -> Result<(), ApplicationError> {
        EncryptedFileStore::read(self, alias)
            .await
            .map(|_| ())
            .map_err(store_error)
    }
}

fn store_error(error: StoreError) -> ApplicationError {
    match error {
        StoreError::InvalidAlias => ApplicationError::InvalidInput,
        StoreError::NotFound | StoreError::InvalidValue => ApplicationError::Integrity,
        StoreError::Unavailable => ApplicationError::ExternalStore,
    }
}

fn associated_data(alias: &str) -> String {
    format!("owlauth-store-v{FORMAT_VERSION}:{alias}")
}

fn alias_path_digest(alias: &str) -> Result<String, StoreError> {
    validate_alias(alias)?;
    let mut digest = Sha256::new();
    digest.update(b"owlauth-permanent-alias-authority-v1\0");
    digest.update(alias.as_bytes());
    Ok(URL_SAFE_NO_PAD.encode(digest.finalize()))
}

fn validate_alias(alias: &str) -> Result<(), StoreError> {
    if !(8..=128).contains(&alias.len())
        || !alias
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return Err(StoreError::InvalidAlias);
    }
    Ok(())
}

fn sync_directory(path: &Path) -> Result<(), StoreError> {
    OpenOptions::new()
        .read(true)
        .open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| StoreError::Unavailable)
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;

    fn temporary_root() -> PathBuf {
        std::env::temp_dir().join(format!("owlauth-store-test-{}", Uuid::new_v4()))
    }

    #[tokio::test]
    async fn configuration_secret_store_is_restart_safe_and_verifies_existing_aliases() {
        let root = temporary_root();
        let alias = "operation_12345678".to_owned();
        let first = EncryptedFileStore::new(root.clone(), [7; 32]).unwrap();
        ConfigurationSecretStore::put_if_absent(
            &first,
            alias.clone(),
            Zeroizing::new(b"secret".to_vec()),
        )
        .await
        .unwrap();
        let on_disk = fs::read_to_string(root.join(format!("{alias}.owls"))).unwrap();
        assert!(!on_disk.contains("secret"));

        let restarted = EncryptedFileStore::new(root.clone(), [7; 32]).unwrap();
        ConfigurationSecretStore::put_if_absent(
            &restarted,
            alias.clone(),
            Zeroizing::new(b"secret".to_vec()),
        )
        .await
        .expect("the same secret should reconcile after restart");
        assert_eq!(
            ConfigurationSecretStore::put_if_absent(
                &restarted,
                alias.clone(),
                Zeroizing::new(b"different".to_vec()),
            )
            .await,
            Err(ApplicationError::Integrity)
        );
        assert_eq!(&*restarted.read(alias).await.unwrap(), b"secret");
        fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn control_provisioning_is_write_only_while_runtime_resolves_the_exact_reference() {
        let root = temporary_root();
        let provisioner = WriteOnlyEncryptedFileProvisioner::new(root.clone(), [9; 32]).unwrap();
        let runtime = EncryptedFileStore::new(root.clone(), [9; 32]).unwrap();
        let runtime_alias = "runtime_smtp_1234".to_owned();
        ConfigurationSecretProvisioner::provision_if_absent(
            &provisioner,
            runtime_alias.clone(),
            Zeroizing::new(b"runtime-secret".to_vec()),
        )
        .await
        .expect("Control write-only create");
        assert_eq!(
            runtime
                .read_utf8_secret(&runtime_alias)
                .await
                .unwrap()
                .as_str(),
            "runtime-secret"
        );

        let retry_alias = "control_retry_1234".to_owned();
        ConfigurationSecretProvisioner::provision_if_absent(
            &provisioner,
            retry_alias.clone(),
            Zeroizing::new(b"first".to_vec()),
        )
        .await
        .expect("Control write-only first create");
        // A corrupt existing envelope would make any read/decrypt reconciliation fail. The retry
        // still converges because Control only observes create-if-absent; PostgreSQL has already
        // compared the operation request digest and keyed safe fingerprint.
        fs::write(root.join(format!("{retry_alias}.owls")), b"not-an-envelope").unwrap();
        ConfigurationSecretProvisioner::provision_if_absent(
            &provisioner,
            retry_alias,
            Zeroizing::new(b"first".to_vec()),
        )
        .await
        .expect("Control retry performs zero reads or decryptions");
        fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn permanent_alias_tombstone_orders_provision_and_erase_across_restarts() {
        let root = temporary_root();
        let alias = "smtp_tombstone_1234".to_owned();
        let store = EncryptedFileStore::new(root.clone(), [3; 32]).unwrap();

        ConfigurationSecretProvisioner::provision_if_absent(
            &store,
            alias.clone(),
            Zeroizing::new(b"first".to_vec()),
        )
        .await
        .expect("operation-first provision");
        store
            .erase(alias.clone())
            .await
            .expect("durable erase wins");
        assert_eq!(store.read(alias.clone()).await, Err(StoreError::NotFound));

        let restarted = EncryptedFileStore::new(root.clone(), [3; 32]).unwrap();
        assert_eq!(
            ConfigurationSecretProvisioner::provision_if_absent(
                &restarted,
                alias.clone(),
                Zeroizing::new(b"late".to_vec()),
            )
            .await,
            Err(ApplicationError::Integrity),
            "erase-first and restart must reject every delayed writer"
        );
        assert!(!root.join(format!("{alias}.owls")).exists());
        restarted
            .erase(alias.clone())
            .await
            .expect("cleanup tombstone is idempotent");
        assert!(!root.join(format!("{alias}.owls")).exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn ciphertext_is_bound_to_alias_and_master_key() {
        let root = temporary_root();
        let alias = "operation_abcdefgh".to_owned();
        let store = EncryptedFileStore::new(root.clone(), [1; 32]).unwrap();
        store
            .put_if_absent(alias.clone(), Zeroizing::new(b"secret".to_vec()))
            .await
            .unwrap();
        let wrong_key = EncryptedFileStore::new(root.clone(), [2; 32]).unwrap();
        assert_eq!(wrong_key.read(alias).await, Err(StoreError::InvalidValue));
        fs::remove_dir_all(root).unwrap();
    }
}
