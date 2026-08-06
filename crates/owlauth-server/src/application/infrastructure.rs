use serde_json::Value;
use time::OffsetDateTime;

use super::ApplicationError;

pub(crate) trait Clock: Send + Sync {
    fn now(&self) -> OffsetDateTime;
}

pub(crate) trait RequestDigester: Send + Sync {
    fn digest_json(&self, value: &Value) -> Result<Vec<u8>, ApplicationError>;
}
