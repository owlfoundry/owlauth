use super::DomainError;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ProviderKey(String);

impl ProviderKey {
    pub(crate) fn parse(value: String) -> Result<Self, DomainError> {
        let valid_length = (1..=64).contains(&value.len());
        let mut bytes = value.bytes();
        let valid_first = bytes.next().is_some_and(|byte| byte.is_ascii_lowercase());
        let valid_rest = bytes.all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-')
        });
        if !valid_length {
            return Err(if value.is_empty() {
                DomainError::Empty
            } else {
                DomainError::TooLong
            });
        }
        if !valid_first || !valid_rest {
            return Err(DomainError::InvalidCharacters);
        }
        Ok(Self(value))
    }

    pub(crate) fn into_inner(self) -> String {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProviderStatus {
    Provisioning,
    Active,
    Disabled,
}

impl ProviderStatus {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Provisioning => "provisioning",
            Self::Active => "active",
            Self::Disabled => "disabled",
        }
    }

    pub(crate) fn provision(&mut self) -> Result<(), DomainError> {
        if *self != Self::Provisioning {
            return Err(DomainError::InvalidTransition);
        }
        *self = Self::Active;
        Ok(())
    }

    pub(crate) fn disable(&mut self) -> Result<(), DomainError> {
        if *self != Self::Active {
            return Err(DomainError::InvalidTransition);
        }
        *self = Self::Disabled;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_keys_are_stable_url_safe_slugs() {
        assert!(ProviderKey::parse("google-workforce".to_owned()).is_ok());
        assert_eq!(
            ProviderKey::parse("Google".to_owned()),
            Err(DomainError::InvalidCharacters)
        );
        assert_eq!(ProviderKey::parse(String::new()), Err(DomainError::Empty));
    }

    #[test]
    fn provider_lifecycle_requires_secret_finalization_before_activation() {
        let mut status = ProviderStatus::Provisioning;
        status.provision().unwrap();
        status.disable().unwrap();
        assert_eq!(status.provision(), Err(DomainError::InvalidTransition));
    }
}
