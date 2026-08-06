use std::fmt;

use async_trait::async_trait;
use zeroize::Zeroizing;

use crate::{
    OpaqueEnvelope, ProtectionContext, ProviderError, ProviderFormatVersions, ProviderId,
    RequestFingerprint, ValueError,
};

/// Bounded confidential plaintext that zeroizes its allocation on drop.
pub struct SecretPlaintext(Zeroizing<Vec<u8>>);

impl SecretPlaintext {
    pub const MAX_LEN: usize = 65_536;

    /// Creates non-empty bounded confidential plaintext.
    ///
    /// # Errors
    ///
    /// Returns [`ValueError`] when plaintext is empty or oversized.
    pub fn new(value: impl Into<Vec<u8>>) -> Result<Self, ValueError> {
        Self::from_zeroizing(Zeroizing::new(value.into()))
    }

    /// Adopts an existing zeroizing allocation without copying confidential bytes.
    ///
    /// # Errors
    ///
    /// Returns [`ValueError`] when plaintext is empty or oversized.
    pub fn from_zeroizing(value: Zeroizing<Vec<u8>>) -> Result<Self, ValueError> {
        if value.is_empty() {
            return Err(ValueError::Empty);
        }
        if value.len() > Self::MAX_LEN {
            return Err(ValueError::TooLong);
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Exposes plaintext only for the duration of the supplied closure.
    pub fn expose<R>(&self, operation: impl FnOnce(&[u8]) -> R) -> R {
        operation(self.0.as_slice())
    }

    #[must_use]
    pub fn into_zeroizing(self) -> Zeroizing<Vec<u8>> {
        self.0
    }
}

impl fmt::Debug for SecretPlaintext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretPlaintext([REDACTED])")
    }
}

pub struct SealSecretRequest {
    pub context: ProtectionContext,
    pub plaintext: SecretPlaintext,
}

impl fmt::Debug for SealSecretRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SealSecretRequest")
            .field("context", &self.context)
            .field("plaintext", &"[REDACTED]")
            .finish()
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct SealedSecret {
    pub envelope: OpaqueEnvelope,
    pub request_fingerprint: RequestFingerprint,
}

#[derive(Debug, Eq, PartialEq)]
pub struct OpenSecretRequest {
    pub context: ProtectionContext,
    pub envelope: OpaqueEnvelope,
}

/// Control-only capability that seals new configuration-secret material without opening existing
/// material.
#[async_trait]
pub trait ConfigurationSecretSealer: Send + Sync {
    /// Returns the immutable provider ID authenticated by this capability.
    fn provider_id(&self) -> ProviderId;

    fn supported_format_versions(&self) -> ProviderFormatVersions;

    async fn seal(&self, request: SealSecretRequest) -> Result<SealedSecret, ProviderError>;
}

/// Runtime/worker capability that opens only one supplied envelope under exact context.
#[async_trait]
pub trait ConfigurationSecretOpener: Send + Sync {
    /// Returns the immutable provider ID authenticated by this capability.
    fn provider_id(&self) -> ProviderId;

    fn supported_format_versions(&self) -> ProviderFormatVersions;

    async fn open(&self, request: OpenSecretRequest) -> Result<SecretPlaintext, ProviderError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plaintext_debug_is_redacted() {
        let plaintext = SecretPlaintext::new(b"top-secret".to_vec()).unwrap();
        assert_eq!(format!("{plaintext:?}"), "SecretPlaintext([REDACTED])");
    }

    #[test]
    fn plaintext_is_bounded() {
        assert_eq!(
            SecretPlaintext::new(Vec::new()).unwrap_err(),
            ValueError::Empty
        );
        assert_eq!(
            SecretPlaintext::new(vec![0; SecretPlaintext::MAX_LEN + 1]).unwrap_err(),
            ValueError::TooLong
        );
    }
}
