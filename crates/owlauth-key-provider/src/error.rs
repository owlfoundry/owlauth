use std::{error::Error, fmt};

/// Failure while constructing one bounded SPI value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ValueError {
    Empty,
    TooLong,
    InvalidLength,
    InvalidCharacter,
    InvalidValue,
}

impl fmt::Display for ValueError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Empty => "value is empty",
            Self::TooLong => "value exceeds its bound",
            Self::InvalidLength => "value has an invalid length",
            Self::InvalidCharacter => "value contains an invalid character",
            Self::InvalidValue => "value is invalid",
        })
    }
}

impl Error for ValueError {}

/// Closed provider-neutral failure class.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ProviderErrorClass {
    InvalidRequest,
    UnsupportedAlgorithm,
    NotFound,
    Conflict,
    PermissionDenied,
    Unavailable,
    Integrity,
}

/// Whether the exact operation can be retried without changing its identity or input.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum RetryClassification {
    Never,
    ExactInputSafe,
    Reconcile,
}

/// Optional bounded provider-neutral diagnostic code.
#[derive(Clone, Eq, PartialEq)]
pub struct ProviderErrorCode(String);

impl ProviderErrorCode {
    pub const MAX_LEN: usize = 64;

    /// Creates a safe code containing lowercase ASCII letters, digits, `.`, `_`, or `-`.
    ///
    /// # Errors
    ///
    /// Returns [`ValueError`] when the code is empty, oversized, or outside the grammar.
    pub fn new(value: impl Into<String>) -> Result<Self, ValueError> {
        let value = value.into();
        if value.is_empty() {
            return Err(ValueError::Empty);
        }
        if value.len() > Self::MAX_LEN {
            return Err(ValueError::TooLong);
        }
        if !value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        }) {
            return Err(ValueError::InvalidCharacter);
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for ProviderErrorCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("ProviderErrorCode")
            .field(&self.0)
            .finish()
    }
}

/// Redacted provider failure with no arbitrary vendor message or source chain.
#[derive(Clone, Eq, PartialEq)]
pub struct ProviderError {
    class: ProviderErrorClass,
    retry: RetryClassification,
    code: Option<ProviderErrorCode>,
}

impl ProviderError {
    #[must_use]
    pub const fn new(class: ProviderErrorClass, retry: RetryClassification) -> Self {
        Self {
            class,
            retry,
            code: None,
        }
    }

    #[must_use]
    pub fn with_code(mut self, code: ProviderErrorCode) -> Self {
        self.code = Some(code);
        self
    }

    #[must_use]
    pub const fn class(&self) -> ProviderErrorClass {
        self.class
    }

    #[must_use]
    pub const fn retry_classification(&self) -> RetryClassification {
        self.retry
    }

    #[must_use]
    pub fn code(&self) -> Option<&ProviderErrorCode> {
        self.code.as_ref()
    }
}

impl fmt::Debug for ProviderError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderError")
            .field("class", &self.class)
            .field("retry", &self.retry)
            .field("code", &self.code)
            .finish()
    }
}

impl fmt::Display for ProviderError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("key provider operation failed")
    }
}

impl Error for ProviderError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_error_never_formats_vendor_or_secret_data() {
        let error = ProviderError::new(
            ProviderErrorClass::Unavailable,
            RetryClassification::Reconcile,
        )
        .with_code(ProviderErrorCode::new("remote.timeout").unwrap());
        assert_eq!(error.to_string(), "key provider operation failed");
        assert_eq!(error.code().unwrap().as_str(), "remote.timeout");
    }

    #[test]
    fn safe_code_has_a_closed_grammar() {
        assert!(ProviderErrorCode::new("provider.timeout-1").is_ok());
        assert_eq!(
            ProviderErrorCode::new("Vendor said: token=secret").unwrap_err(),
            ValueError::InvalidCharacter
        );
    }
}
