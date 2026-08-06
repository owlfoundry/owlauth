use crate::application::{ApplicationError, Clock, RequestDigester};
use serde_json::Value;
use sha2::{Digest, Sha256};
use time::OffsetDateTime;

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> OffsetDateTime {
        OffsetDateTime::now_utc()
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Sha256RequestDigester;

impl RequestDigester for Sha256RequestDigester {
    fn digest_json(&self, value: &Value) -> Result<Vec<u8>, ApplicationError> {
        let encoded = serde_json::to_vec(value).map_err(|_| ApplicationError::InvalidInput)?;
        Ok(Sha256::digest(encoded).to_vec())
    }
}
