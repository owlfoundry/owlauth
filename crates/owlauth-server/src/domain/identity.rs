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
pub(crate) struct ProfileLocale(String);

impl ProfileLocale {
    pub(crate) fn parse(value: String) -> Result<Self, DomainError> {
        if !(2..=35).contains(&value.len())
            || value.starts_with('-')
            || value.ends_with('-')
            || value.contains("--")
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(DomainError::InvalidCharacters);
        }
        Ok(Self(value))
    }

    pub(crate) fn into_inner(self) -> String {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum IdentitySourceKind {
    Provider,
    Email,
}

impl IdentitySourceKind {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Provider => "provider",
            Self::Email => "email",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LocalProfileField<T> {
    pub(crate) is_set: bool,
    pub(crate) value: Option<T>,
}

impl<T> LocalProfileField<T> {
    pub(crate) const fn inherited() -> Self {
        Self {
            is_set: false,
            value: None,
        }
    }

    pub(crate) const fn explicitly(value: Option<T>) -> Self {
        Self {
            is_set: true,
            value,
        }
    }

    pub(crate) fn resolve(self, source: Option<T>) -> Option<T> {
        if self.is_set { self.value } else { source }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct BoundedProviderProfile {
    pub(crate) display_name: Option<ProfileDisplayName>,
    pub(crate) picture_url: Option<ProfilePictureUrl>,
    pub(crate) locale: Option<ProfileLocale>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct UserProfileInputs {
    pub(crate) primary_source_kind: IdentitySourceKind,
    pub(crate) local_display_name: LocalProfileField<ProfileDisplayName>,
    pub(crate) local_picture_url: LocalProfileField<ProfilePictureUrl>,
    pub(crate) local_locale: LocalProfileField<ProfileLocale>,
    pub(crate) primary_provider: Option<BoundedProviderProfile>,
    pub(crate) verified_email: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct MaterializedUserProfile {
    pub(crate) display_name: Option<ProfileDisplayName>,
    pub(crate) picture_url: Option<ProfilePictureUrl>,
    pub(crate) locale: Option<ProfileLocale>,
    pub(crate) verified_email: Option<String>,
}

impl UserProfileInputs {
    pub(crate) fn materialize(self) -> Result<MaterializedUserProfile, DomainError> {
        if self.verified_email.as_ref().is_some_and(|value| {
            !(3..=320).contains(&value.len()) || value.chars().any(char::is_control)
        }) {
            return Err(DomainError::InvalidCharacters);
        }
        let provider = match self.primary_source_kind {
            IdentitySourceKind::Provider => self.primary_provider,
            IdentitySourceKind::Email => None,
        };
        let (display_name, picture_url, locale) = provider.map_or((None, None, None), |profile| {
            (profile.display_name, profile.picture_url, profile.locale)
        });
        Ok(MaterializedUserProfile {
            display_name: self.local_display_name.resolve(display_name),
            picture_url: self.local_picture_url.resolve(picture_url),
            locale: self.local_locale.resolve(locale),
            verified_email: self.verified_email,
        })
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
    fn local_profile_values_override_only_their_owned_fields() {
        let profile = UserProfileInputs {
            primary_source_kind: IdentitySourceKind::Provider,
            local_display_name: LocalProfileField::explicitly(Some(
                ProfileDisplayName::parse("Local Ada".to_owned()).unwrap(),
            )),
            local_picture_url: LocalProfileField::explicitly(None),
            local_locale: LocalProfileField::inherited(),
            primary_provider: Some(BoundedProviderProfile {
                display_name: Some(ProfileDisplayName::parse("Provider Ada".to_owned()).unwrap()),
                picture_url: Some(
                    ProfilePictureUrl::parse("https://cdn.example/provider.png".to_owned())
                        .unwrap(),
                ),
                locale: Some(ProfileLocale::parse("en-GB".to_owned()).unwrap()),
            }),
            verified_email: Some("ada@example.test".to_owned()),
        }
        .materialize()
        .unwrap();

        assert_eq!(
            profile
                .display_name
                .map(ProfileDisplayName::into_inner)
                .as_deref(),
            Some("Local Ada")
        );
        assert!(profile.picture_url.is_none());
        assert_eq!(
            profile.locale.map(ProfileLocale::into_inner).as_deref(),
            Some("en-GB")
        );
        assert_eq!(profile.verified_email.as_deref(), Some("ada@example.test"));
    }

    #[test]
    fn email_primary_source_does_not_import_provider_display_fields() {
        let profile = UserProfileInputs {
            primary_source_kind: IdentitySourceKind::Email,
            local_display_name: LocalProfileField::inherited(),
            local_picture_url: LocalProfileField::inherited(),
            local_locale: LocalProfileField::inherited(),
            primary_provider: Some(BoundedProviderProfile {
                display_name: Some(ProfileDisplayName::parse("Provider Ada".to_owned()).unwrap()),
                picture_url: None,
                locale: None,
            }),
            verified_email: Some("ada@example.test".to_owned()),
        }
        .materialize()
        .unwrap();

        assert!(profile.display_name.is_none());
        assert_eq!(profile.verified_email.as_deref(), Some("ada@example.test"));
    }

    #[test]
    fn locale_is_bounded_and_structural() {
        assert!(ProfileLocale::parse("zh-Hans-CN".to_owned()).is_ok());
        for invalid in ["e", "-en", "en-", "en--US", "en_US"] {
            assert_eq!(
                ProfileLocale::parse(invalid.to_owned()),
                Err(DomainError::InvalidCharacters)
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
