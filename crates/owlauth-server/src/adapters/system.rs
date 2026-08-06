use serde_json::Value;
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
#[cfg(test)]
use zeroize::Zeroizing;

#[cfg(test)]
use crate::application::EntropySource;
use crate::application::{ApplicationError, Clock, RequestDigester};

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> OffsetDateTime {
        OffsetDateTime::now_utc()
    }
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct SystemEntropy;

#[cfg(test)]
impl EntropySource for SystemEntropy {
    fn signing_seed(&self) -> Result<Zeroizing<[u8; 32]>, ApplicationError> {
        let mut seed = Zeroizing::new([0_u8; 32]);
        getrandom::fill(seed.as_mut()).map_err(|_| ApplicationError::ExternalStore)?;
        Ok(seed)
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Sha256RequestDigester;

impl RequestDigester for Sha256RequestDigester {
    fn digest_json(&self, value: &Value) -> Result<Vec<u8>, ApplicationError> {
        let encoded = serde_json::to_vec(value).map_err(|_| ApplicationError::InvalidInput)?;
        Ok(Sha256::digest(encoded).to_vec())
    }

    fn digest_bytes(&self, value: &[u8]) -> Vec<u8> {
        Sha256::digest(value).to_vec()
    }
}
