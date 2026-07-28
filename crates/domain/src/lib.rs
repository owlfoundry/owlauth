#![forbid(unsafe_code)]

/// Stable identifier for an `OwlAuth` user.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct UserId(String);

impl UserId {
    /// Creates a user identifier from a non-empty string.
    ///
    /// # Errors
    ///
    /// Returns the original value when it is empty.
    pub fn new(value: String) -> Result<Self, String> {
        if value.is_empty() {
            return Err(value);
        }
        Ok(Self(value))
    }

    /// Returns the identifier as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::UserId;

    #[test]
    fn rejects_empty_identifiers() {
        assert!(UserId::new(String::new()).is_err());
    }
}
