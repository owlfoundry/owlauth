use url::Url;

use super::DomainError;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ProviderIssuer(String);

impl ProviderIssuer {
    pub(crate) fn parse(value: String) -> Result<Self, DomainError> {
        validate_bounded_text(&value, 2048)?;
        Ok(Self(value))
    }

    pub(crate) fn into_inner(self) -> String {
        self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ProviderSubject(String);

impl ProviderSubject {
    pub(crate) fn parse(value: String) -> Result<Self, DomainError> {
        validate_bounded_text(&value, 512)?;
        Ok(Self(value))
    }

    pub(crate) fn into_inner(self) -> String {
        self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ProfileDisplayName(String);

impl ProfileDisplayName {
    pub(crate) fn parse(value: String) -> Result<Self, DomainError> {
        validate_bounded_text(&value, 128)?;
        Ok(Self(value))
    }

    pub(crate) fn into_inner(self) -> String {
        self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ProfilePictureUrl(String);

impl ProfilePictureUrl {
    pub(crate) fn parse(value: String) -> Result<Self, DomainError> {
        if !(8..=2048).contains(&value.len())
            || value.contains('\\')
            || value.bytes().any(|byte| byte.is_ascii_whitespace())
        {
            return Err(DomainError::InvalidUrl);
        }
        let url = Url::parse(&value).map_err(|_| DomainError::InvalidUrl)?;
        if url.scheme() != "https"
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.fragment().is_some()
            || url.host_str().is_some_and(|host| host.contains('*'))
        {
            return Err(DomainError::InvalidUrl);
        }
        Ok(Self(value))
    }

    pub(crate) fn into_inner(self) -> String {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProjectUserStatus {
    Active,
    Disabled,
}

impl ProjectUserStatus {
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct UserRevision(i64);

impl UserRevision {
    pub(crate) const fn initial() -> Self {
        Self(1)
    }

    pub(crate) fn parse(value: i64) -> Result<Self, DomainError> {
        if value < 1 {
            return Err(DomainError::InvalidTransition);
        }
        Ok(Self(value))
    }

    pub(crate) const fn value(self) -> i64 {
        self.0
    }

    pub(crate) fn advance(&mut self) -> Result<(), DomainError> {
        self.0 = self
            .0
            .checked_add(1)
            .ok_or(DomainError::InvalidTransition)?;
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
    fn identity_values_are_bounded_without_creating_profile_link_keys() {
        assert!(ProviderIssuer::parse("https://issuer.example/tenant".to_owned()).is_ok());
        assert!(ProviderSubject::parse("provider-subject-1".to_owned()).is_ok());
        assert_eq!(
            ProviderSubject::parse(String::new()),
            Err(DomainError::Empty)
        );
        assert_eq!(
            ProfileDisplayName::parse("name\nspoof".to_owned()),
            Err(DomainError::InvalidCharacters)
        );
        assert_eq!(
            ProviderSubject::parse("s".repeat(513)),
            Err(DomainError::TooLong)
        );
    }

    #[test]
    fn profile_picture_requires_a_bounded_https_url() {
        assert!(
            ProfilePictureUrl::parse("https://cdn.example/avatar.png?size=128".to_owned()).is_ok()
        );
        for value in [
            "http://cdn.example/avatar.png",
            "https://user@cdn.example/avatar.png",
            "https://cdn.example/avatar.png#fragment",
            "https://*.example/avatar.png",
        ] {
            assert_eq!(
                ProfilePictureUrl::parse(value.to_owned()),
                Err(DomainError::InvalidUrl)
            );
        }
    }

    #[test]
    fn user_disable_and_revision_are_monotonic() {
        let mut status = ProjectUserStatus::Active;
        status.disable().unwrap();
        assert_eq!(status.disable(), Err(DomainError::InvalidTransition));

        let mut revision = UserRevision::initial();
        revision.advance().unwrap();
        assert_eq!(revision.value(), 2);
        assert_eq!(UserRevision::parse(0), Err(DomainError::InvalidTransition));
    }
}
