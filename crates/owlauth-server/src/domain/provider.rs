use super::{DomainError, ManagedProfileCapability};

pub(crate) const GOOGLE_ISSUER: &str = "https://accounts.google.com";
pub(crate) const GITHUB_ISSUER: &str = "https://github.com";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProviderKind {
    Oidc,
    Google,
    Github,
}

#[derive(Clone, Copy)]
pub(crate) struct ManagedProfileCapabilities {
    oidc: &'static ManagedProfileCapability,
    google: &'static ManagedProfileCapability,
}

impl From<&'static ManagedProfileCapability> for ManagedProfileCapabilities {
    fn from(capability: &'static ManagedProfileCapability) -> Self {
        Self::shared(capability)
    }
}

impl ManagedProfileCapabilities {
    pub(crate) const fn new(
        oidc: &'static ManagedProfileCapability,
        google: &'static ManagedProfileCapability,
    ) -> Self {
        Self { oidc, google }
    }

    pub(crate) const fn shared(capability: &'static ManagedProfileCapability) -> Self {
        Self::new(capability, capability)
    }

    pub(crate) const fn for_kind(
        self,
        kind: ProviderKind,
    ) -> Option<&'static ManagedProfileCapability> {
        match kind {
            ProviderKind::Oidc => Some(self.oidc),
            ProviderKind::Google => Some(self.google),
            ProviderKind::Github => None,
        }
    }

    pub(crate) fn for_adapter_key(
        self,
        adapter_key: &str,
    ) -> Option<&'static ManagedProfileCapability> {
        [self.oidc, self.google]
            .into_iter()
            .find(|capability| capability.adapter_key == adapter_key)
    }

    pub(crate) fn validate(self) -> Result<(), DomainError> {
        self.oidc.validate()?;
        self.google.validate()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ProviderCapabilities {
    pub(crate) login: bool,
    pub(crate) identity_proof: bool,
    pub(crate) managed_profile: bool,
    pub(crate) adapter_key: &'static str,
}

impl ProviderKind {
    pub(crate) fn parse(value: &str) -> Result<Self, DomainError> {
        match value {
            "oidc" => Ok(Self::Oidc),
            "google" => Ok(Self::Google),
            "github" => Ok(Self::Github),
            _ => Err(DomainError::InvalidCharacters),
        }
    }

    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Oidc => "oidc",
            Self::Google => "google",
            Self::Github => "github",
        }
    }

    pub(crate) const fn capabilities(self) -> ProviderCapabilities {
        match self {
            Self::Oidc => ProviderCapabilities {
                login: true,
                identity_proof: true,
                managed_profile: true,
                adapter_key: "controlled_oidc_profile_v1",
            },
            Self::Google => ProviderCapabilities {
                login: true,
                identity_proof: true,
                managed_profile: true,
                adapter_key: "google_oidc_profile_v1",
            },
            Self::Github => ProviderCapabilities {
                login: true,
                identity_proof: false,
                managed_profile: false,
                adapter_key: "github_oauth_login_v1",
            },
        }
    }

    pub(crate) fn issuer_matches(self, issuer: &str) -> bool {
        match self {
            Self::Oidc => {
                let canonical_root = issuer.strip_suffix('/').unwrap_or(issuer);
                !matches!(canonical_root, GOOGLE_ISSUER | GITHUB_ISSUER)
            }
            Self::Google => issuer == GOOGLE_ISSUER,
            Self::Github => issuer == GITHUB_ISSUER,
        }
    }
}

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

    pub(crate) fn as_str(&self) -> &str {
        &self.0
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
    fn provider_kind_registry_is_closed_and_prevents_named_fallback() {
        let oidc = ProviderKind::parse("oidc").unwrap();
        let google = ProviderKind::parse("google").unwrap();
        let github = ProviderKind::parse("github").unwrap();
        assert!(oidc.issuer_matches("https://id.example"));
        assert!(!oidc.issuer_matches(GOOGLE_ISSUER));
        assert!(!oidc.issuer_matches("https://accounts.google.com/"));
        assert!(!oidc.issuer_matches("https://github.com/"));
        assert!(google.issuer_matches(GOOGLE_ISSUER));
        assert!(!google.issuer_matches("https://accounts.google.com/"));
        assert!(!google.issuer_matches("https://id.example"));
        assert!(google.capabilities().managed_profile);
        assert!(google.capabilities().identity_proof);
        assert!(github.capabilities().login);
        assert!(!github.capabilities().managed_profile);
        assert!(!github.capabilities().identity_proof);
        assert!(ProviderKind::parse("custom").is_err());
    }

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
