use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    sync::Arc,
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;
use zeroize::Zeroizing;

const FORMAT_VERSION: u8 = 1;

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
        tokio::task::spawn_blocking(move || store.put_if_absent_blocking(&alias, &value))
            .await
            .map_err(|_| StoreError::Unavailable)?
    }

    pub(crate) async fn read(&self, alias: String) -> Result<Zeroizing<Vec<u8>>, StoreError> {
        let store = self.clone();
        tokio::task::spawn_blocking(move || store.read_blocking(&alias))
            .await
            .map_err(|_| StoreError::Unavailable)?
    }

    fn put_if_absent_blocking(&self, alias: &str, value: &[u8]) -> Result<StoreWrite, StoreError> {
        let final_path = self.path(alias)?;
        if final_path.exists() {
            return Ok(StoreWrite::Existing);
        }
        fs::create_dir_all(self.root.as_ref()).map_err(|_| StoreError::Unavailable)?;

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
            match fs::hard_link(&temporary_path, &final_path) {
                Ok(()) => {
                    fs::remove_file(&temporary_path).map_err(|_| StoreError::Unavailable)?;
                    sync_directory(self.root.as_ref())?;
                    Ok(StoreWrite::Created)
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    Ok(StoreWrite::Existing)
                }
                Err(_) => Err(StoreError::Unavailable),
            }
        })();
        if result.is_err() || final_path.exists() {
            let _ = fs::remove_file(&temporary_path);
        }
        result
    }

    fn read_blocking(&self, alias: &str) -> Result<Zeroizing<Vec<u8>>, StoreError> {
        let path = self.path(alias)?;
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
}

fn associated_data(alias: &str) -> String {
    format!("owlauth-store-v{FORMAT_VERSION}:{alias}")
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
    async fn encrypted_store_is_restart_safe_and_alias_idempotent() {
        let root = temporary_root();
        let alias = "operation_12345678".to_owned();
        let first = EncryptedFileStore::new(root.clone(), [7; 32]).unwrap();
        assert_eq!(
            first
                .put_if_absent(alias.clone(), Zeroizing::new(b"secret".to_vec()))
                .await
                .unwrap(),
            StoreWrite::Created
        );
        let on_disk = fs::read_to_string(root.join(format!("{alias}.owls"))).unwrap();
        assert!(!on_disk.contains("secret"));

        let restarted = EncryptedFileStore::new(root.clone(), [7; 32]).unwrap();
        assert_eq!(
            restarted
                .put_if_absent(alias.clone(), Zeroizing::new(b"different".to_vec()))
                .await
                .unwrap(),
            StoreWrite::Existing
        );
        assert_eq!(&*restarted.read(alias).await.unwrap(), b"secret");
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
