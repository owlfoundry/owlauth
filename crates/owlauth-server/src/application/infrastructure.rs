use async_trait::async_trait;
use serde_json::Value;
use time::OffsetDateTime;
use zeroize::Zeroizing;

use super::ApplicationError;

pub(crate) trait Clock: Send + Sync {
    fn now(&self) -> OffsetDateTime;
}

pub(crate) trait EntropySource: Send + Sync {
    fn signing_seed(&self) -> Result<Zeroizing<[u8; 32]>, ApplicationError>;
}

pub(crate) trait RequestDigester: Send + Sync {
    fn digest_json(&self, value: &Value) -> Result<Vec<u8>, ApplicationError>;

    fn digest_bytes(&self, value: &[u8]) -> Vec<u8>;
}

#[async_trait]
pub(crate) trait SignerStore: Send + Sync {
    async fn put_if_absent(
        &self,
        alias: String,
        seed: Zeroizing<[u8; 32]>,
    ) -> Result<(), ApplicationError>;

    async fn public_jwk(&self, alias: String, kid: &str) -> Result<Value, ApplicationError>;

    async fn verify(
        &self,
        alias: String,
        kid: &str,
        public_jwk: &Value,
    ) -> Result<(), ApplicationError>;
}

/// Write-only capability used by Control provisioning. Implementations must not read or decrypt
/// an existing value while reconciling an idempotent alias; `PostgreSQL` request digests and safe
/// keyed fingerprints are the authority for whether a retry is the same operation. Provisioning
/// must also share a permanent per-alias ordering fence with Runtime erasure: an erase racing any
/// stale writer must win durably and leave no material that can be recreated later.
#[async_trait]
pub(crate) trait ConfigurationSecretProvisioner: Send + Sync {
    fn request_fingerprint(&self, value: &[u8]) -> [u8; 32];

    async fn provision_if_absent(
        &self,
        alias: String,
        value: Zeroizing<Vec<u8>>,
    ) -> Result<(), ApplicationError>;
}

/// Read-capable configuration store retained for provider provisioning and Runtime resolution.
/// Email Control is deliberately typed against `ConfigurationSecretProvisioner` instead.
#[async_trait]
pub(crate) trait ConfigurationSecretStore: Send + Sync {
    fn request_fingerprint(&self, value: &[u8]) -> [u8; 32];

    async fn put_if_absent(
        &self,
        alias: String,
        value: Zeroizing<Vec<u8>>,
    ) -> Result<(), ApplicationError>;

    async fn ensure_readable(&self, alias: String) -> Result<(), ApplicationError>;
}
