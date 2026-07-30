use std::fmt;

use super::DomainError;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DisplayName(String);

impl DisplayName {
    pub(crate) fn parse(value: String) -> Result<Self, DomainError> {
        validate_bounded_text(&value, 128)?;
        Ok(Self(value))
    }

    pub(crate) fn into_inner(self) -> String {
        self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct OpaqueOwner(String);

impl OpaqueOwner {
    pub(crate) fn parse(value: String) -> Result<Self, DomainError> {
        validate_bounded_text(&value, 256)?;
        Ok(Self(value))
    }

    pub(crate) fn into_inner(self) -> String {
        self.0
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub(crate) struct PublicId(String);

impl PublicId {
    pub(crate) fn parse(value: String) -> Result<Self, DomainError> {
        if !(8..=96).contains(&value.len()) {
            return Err(if value.is_empty() {
                DomainError::Empty
            } else {
                DomainError::TooLong
            });
        }
        if !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
        {
            return Err(DomainError::InvalidCharacters);
        }
        Ok(Self(value))
    }
}

impl fmt::Display for PublicId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProjectStatus {
    Active,
    Disabled,
}

impl ProjectStatus {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Disabled => "disabled",
        }
    }

    pub(crate) fn disable(&mut self) -> Result<(), DomainError> {
        if *self != Self::Active {
            return Err(DomainError::InvalidTransition);
        }
        *self = Self::Disabled;
        Ok(())
    }
}

fn validate_bounded_text(value: &str, max: usize) -> Result<(), DomainError> {
    if value.is_empty() {
        return Err(DomainError::Empty);
    }
    if value.len() > max {
        return Err(DomainError::TooLong);
    }
    if value.chars().any(char::is_control) {
        return Err(DomainError::InvalidCharacters);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_values_and_public_ids_reject_ambiguous_input() {
        assert_eq!(DisplayName::parse(String::new()), Err(DomainError::Empty));
        assert_eq!(
            DisplayName::parse("a\nb".to_owned()),
            Err(DomainError::InvalidCharacters)
        );
        assert_eq!(
            PublicId::parse("project/unsafe".to_owned()),
            Err(DomainError::InvalidCharacters)
        );
        assert!(PublicId::parse("prj_12345678".to_owned()).is_ok());
    }

    #[test]
    fn project_disable_is_monotonic() {
        let mut status = ProjectStatus::Active;
        status.disable().unwrap();
        assert_eq!(status, ProjectStatus::Disabled);
        assert_eq!(status.disable(), Err(DomainError::InvalidTransition));
    }
}
