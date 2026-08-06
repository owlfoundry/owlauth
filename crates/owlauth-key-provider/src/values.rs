use std::{collections::BTreeSet, fmt, num::NonZeroU16};

use crate::ValueError;

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ProviderId(String);

impl ProviderId {
    pub const MAX_LEN: usize = 64;

    /// Creates a provider ID in the closed ASCII grammar `[a-z][a-z0-9_-]*`.
    ///
    /// # Errors
    ///
    /// Returns [`ValueError`] for an empty, oversized, or malformed ID.
    pub fn new(value: impl Into<String>) -> Result<Self, ValueError> {
        let value = value.into();
        if value.is_empty() {
            return Err(ValueError::Empty);
        }
        if value.len() > Self::MAX_LEN {
            return Err(ValueError::TooLong);
        }
        let mut bytes = value.bytes();
        if !bytes.next().is_some_and(|byte| byte.is_ascii_lowercase())
            || !bytes.all(|byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-')
            })
        {
            return Err(ValueError::InvalidCharacter);
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for ProviderId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("ProviderId").field(&self.0).finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ProviderFormatVersion(NonZeroU16);

impl ProviderFormatVersion {
    /// Creates a non-zero provider-owned material format version.
    ///
    /// # Errors
    ///
    /// Returns [`ValueError::InvalidValue`] for zero.
    pub fn new(value: u16) -> Result<Self, ValueError> {
        NonZeroU16::new(value)
            .map(Self)
            .ok_or(ValueError::InvalidValue)
    }

    #[must_use]
    pub const fn get(self) -> u16 {
        self.0.get()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderFormatVersions(Vec<ProviderFormatVersion>);

impl ProviderFormatVersions {
    pub const MAX_COUNT: usize = 16;

    /// Creates a non-empty unique bounded format-version set.
    ///
    /// # Errors
    ///
    /// Returns [`ValueError`] for an empty, oversized, or duplicate set.
    pub fn new(values: &[ProviderFormatVersion]) -> Result<Self, ValueError> {
        if values.is_empty() {
            return Err(ValueError::Empty);
        }
        if values.len() > Self::MAX_COUNT {
            return Err(ValueError::TooLong);
        }
        let unique = values.iter().copied().collect::<BTreeSet<_>>();
        if unique.len() != values.len() {
            return Err(ValueError::InvalidValue);
        }
        Ok(Self(unique.into_iter().collect()))
    }

    #[must_use]
    pub fn as_slice(&self) -> &[ProviderFormatVersion] {
        &self.0
    }

    #[must_use]
    pub fn contains(&self, version: ProviderFormatVersion) -> bool {
        self.0.binary_search(&version).is_ok()
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[non_exhaustive]
pub enum SigningAlgorithm {
    Ed25519,
}

impl SigningAlgorithm {
    #[must_use]
    pub const fn jws_name(self) -> &'static str {
        match self {
            Self::Ed25519 => "EdDSA",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SigningProviderCapabilities {
    algorithms: Vec<SigningAlgorithm>,
    format_versions: ProviderFormatVersions,
}

impl SigningProviderCapabilities {
    pub const MAX_ALGORITHMS: usize = 8;

    /// Creates immutable signing capability metadata used at composition/readiness.
    ///
    /// # Errors
    ///
    /// Returns [`ValueError`] for an empty, oversized, or duplicate algorithm set.
    pub fn new(
        algorithms: &[SigningAlgorithm],
        format_versions: ProviderFormatVersions,
    ) -> Result<Self, ValueError> {
        if algorithms.is_empty() {
            return Err(ValueError::Empty);
        }
        if algorithms.len() > Self::MAX_ALGORITHMS {
            return Err(ValueError::TooLong);
        }
        let unique = algorithms.iter().copied().collect::<BTreeSet<_>>();
        if unique.len() != algorithms.len() {
            return Err(ValueError::InvalidValue);
        }
        Ok(Self {
            algorithms: unique.into_iter().collect(),
            format_versions,
        })
    }

    #[must_use]
    pub fn algorithms(&self) -> &[SigningAlgorithm] {
        &self.algorithms
    }

    #[must_use]
    pub const fn format_versions(&self) -> &ProviderFormatVersions {
        &self.format_versions
    }

    #[must_use]
    pub fn supports_algorithm(&self, algorithm: SigningAlgorithm) -> bool {
        self.algorithms.binary_search(&algorithm).is_ok()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum DestroyOutcome {
    Destroyed,
    AlreadyAbsent,
    Unsupported,
}

macro_rules! bounded_bytes {
    ($name:ident, $max_len:expr, $debug_name:literal) => {
        #[derive(Clone, Eq, PartialEq)]
        pub struct $name(Vec<u8>);

        impl $name {
            pub const MAX_LEN: usize = $max_len;

            /// Creates a non-empty bounded opaque value.
            ///
            /// # Errors
            ///
            /// Returns [`ValueError`] when the value is empty or exceeds the type's bound.
            pub fn new(value: impl Into<Vec<u8>>) -> Result<Self, ValueError> {
                let value = value.into();
                if value.is_empty() {
                    return Err(ValueError::Empty);
                }
                if value.len() > Self::MAX_LEN {
                    return Err(ValueError::TooLong);
                }
                Ok(Self(value))
            }

            #[must_use]
            pub fn as_bytes(&self) -> &[u8] {
                &self.0
            }

            #[must_use]
            pub fn into_bytes(self) -> Vec<u8> {
                self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_struct($debug_name)
                    .field("length", &self.0.len())
                    .finish()
            }
        }
    };
}

macro_rules! bounded_secret_bytes {
    ($name:ident, $max_len:expr, $debug_name:literal) => {
        #[derive(Eq, PartialEq)]
        pub struct $name(Vec<u8>);

        impl $name {
            pub const MAX_LEN: usize = $max_len;

            /// Creates a non-empty bounded opaque secret-bearing value.
            ///
            /// # Errors
            ///
            /// Returns [`ValueError`] when the value is empty or exceeds the type's bound.
            pub fn new(value: impl Into<Vec<u8>>) -> Result<Self, ValueError> {
                let value = value.into();
                if value.is_empty() {
                    return Err(ValueError::Empty);
                }
                if value.len() > Self::MAX_LEN {
                    return Err(ValueError::TooLong);
                }
                Ok(Self(value))
            }

            pub fn expose<R>(&self, expose: impl FnOnce(&[u8]) -> R) -> R {
                expose(&self.0)
            }

            #[must_use]
            pub fn into_zeroizing(mut self) -> zeroize::Zeroizing<Vec<u8>> {
                zeroize::Zeroizing::new(std::mem::take(&mut self.0))
            }
        }

        impl Drop for $name {
            fn drop(&mut self) {
                zeroize::Zeroize::zeroize(&mut self.0);
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_struct($debug_name)
                    .field("length", &self.0.len())
                    .finish()
            }
        }
    };
}

bounded_bytes!(OperationId, 256, "OperationId");
bounded_secret_bytes!(OpaqueHandle, 65_536, "OpaqueHandle");
bounded_secret_bytes!(OpaqueEnvelope, 65_536, "OpaqueEnvelope");
bounded_bytes!(SigningInput, 65_536, "SigningInput");

/// Exact 256-bit keyed request commitment returned by configuration-secret providers.
#[derive(Clone, Eq, PartialEq)]
pub struct RequestFingerprint([u8; 32]);

impl RequestFingerprint {
    pub const LEN: usize = 32;

    /// Creates an exact 32-byte request fingerprint.
    ///
    /// # Errors
    ///
    /// Returns [`ValueError::InvalidLength`] for any non-canonical length.
    pub fn new(value: impl Into<Vec<u8>>) -> Result<Self, ValueError> {
        value
            .into()
            .try_into()
            .map(Self)
            .map_err(|_| ValueError::InvalidLength)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.0.to_vec()
    }
}

impl fmt::Debug for RequestFingerprint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RequestFingerprint")
            .field("length", &Self::LEN)
            .finish()
    }
}

/// Normalized algorithm-tagged public key bytes.
///
/// For [`SigningAlgorithm::Ed25519`] this is exactly the 32 raw RFC 8032 public-key octets. It is
/// never PEM, SPKI DER, JWK JSON, or base64url text.
#[derive(Clone, Eq, PartialEq)]
pub struct SigningPublicKey {
    algorithm: SigningAlgorithm,
    bytes: Vec<u8>,
}

impl SigningPublicKey {
    /// Validates normalized public-key bytes for the exact algorithm.
    ///
    /// # Errors
    ///
    /// Returns [`ValueError::InvalidLength`] when bytes are not in the algorithm's canonical form.
    pub fn new(algorithm: SigningAlgorithm, bytes: Vec<u8>) -> Result<Self, ValueError> {
        match algorithm {
            SigningAlgorithm::Ed25519 if bytes.len() == 32 => Ok(Self { algorithm, bytes }),
            SigningAlgorithm::Ed25519 => Err(ValueError::InvalidLength),
        }
    }

    #[must_use]
    pub const fn algorithm(&self) -> SigningAlgorithm {
        self.algorithm
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl fmt::Debug for SigningPublicKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SigningPublicKey")
            .field("algorithm", &self.algorithm)
            .field("length", &self.bytes.len())
            .finish()
    }
}

/// Normalized algorithm-tagged JWS-ready signature octets.
///
/// For [`SigningAlgorithm::Ed25519`] this is exactly the 64 raw RFC 8032 signature octets. It is
/// never ASN.1 DER, base64url text, or a complete JWS.
#[derive(Clone, Eq, PartialEq)]
pub struct Signature {
    algorithm: SigningAlgorithm,
    bytes: Vec<u8>,
}

impl Signature {
    /// Validates JWS-ready signature bytes for the exact algorithm.
    ///
    /// # Errors
    ///
    /// Returns [`ValueError::InvalidLength`] when bytes are not in the algorithm's canonical form.
    pub fn new(algorithm: SigningAlgorithm, bytes: Vec<u8>) -> Result<Self, ValueError> {
        match algorithm {
            SigningAlgorithm::Ed25519 if bytes.len() == 64 => Ok(Self { algorithm, bytes }),
            SigningAlgorithm::Ed25519 => Err(ValueError::InvalidLength),
        }
    }

    #[must_use]
    pub const fn algorithm(&self) -> SigningAlgorithm {
        self.algorithm
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl fmt::Debug for Signature {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Signature")
            .field("algorithm", &self.algorithm)
            .field("length", &self.bytes.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_ids_are_bounded_and_canonical() {
        assert!(ProviderId::new("software").is_ok());
        assert!(ProviderId::new("deployment_kms-1").is_ok());
        assert_eq!(
            ProviderId::new("DeploymentKms").unwrap_err(),
            ValueError::InvalidCharacter
        );
        assert_eq!(
            ProviderId::new("x".repeat(ProviderId::MAX_LEN + 1)).unwrap_err(),
            ValueError::TooLong
        );
    }

    #[test]
    fn opaque_debug_output_contains_no_bytes() {
        let handle = OpaqueHandle::new(b"secret-handle".to_vec()).unwrap();
        let output = format!("{handle:?}");
        assert!(output.contains("length"));
        assert!(!output.contains("secret-handle"));
    }

    #[test]
    fn normalized_ed25519_values_have_exact_wire_semantics() {
        let public_key = SigningPublicKey::new(SigningAlgorithm::Ed25519, vec![7; 32]).unwrap();
        let signature = Signature::new(SigningAlgorithm::Ed25519, vec![8; 64]).unwrap();
        assert_eq!(public_key.algorithm(), SigningAlgorithm::Ed25519);
        assert_eq!(public_key.as_bytes(), &[7; 32]);
        assert_eq!(signature.algorithm(), SigningAlgorithm::Ed25519);
        assert_eq!(signature.as_bytes(), &[8; 64]);
        assert_eq!(
            SigningPublicKey::new(SigningAlgorithm::Ed25519, vec![0; 33]).unwrap_err(),
            ValueError::InvalidLength
        );
        assert_eq!(
            Signature::new(SigningAlgorithm::Ed25519, vec![0; 63]).unwrap_err(),
            ValueError::InvalidLength
        );
    }

    #[test]
    fn request_fingerprints_are_exactly_256_bits() {
        assert!(RequestFingerprint::new(vec![7; 32]).is_ok());
        assert_eq!(
            RequestFingerprint::new(vec![7; 31]).unwrap_err(),
            ValueError::InvalidLength
        );
        assert_eq!(
            RequestFingerprint::new(vec![7; 33]).unwrap_err(),
            ValueError::InvalidLength
        );
    }

    #[test]
    fn capability_sets_are_non_empty_unique_and_bounded() {
        let formats =
            ProviderFormatVersions::new(&[ProviderFormatVersion::new(1).unwrap()]).unwrap();
        let capabilities =
            SigningProviderCapabilities::new(&[SigningAlgorithm::Ed25519], formats).unwrap();
        assert!(capabilities.supports_algorithm(SigningAlgorithm::Ed25519));
        assert_eq!(
            SigningProviderCapabilities::new(
                &[SigningAlgorithm::Ed25519, SigningAlgorithm::Ed25519],
                ProviderFormatVersions::new(&[ProviderFormatVersion::new(1).unwrap()]).unwrap()
            )
            .unwrap_err(),
            ValueError::InvalidValue
        );
    }
}
