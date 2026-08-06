use std::{collections::BTreeSet, net::IpAddr};

use url::{Host, Url};

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

pub(crate) const MAX_PROVIDER_EGRESS_ORIGINS: usize = 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProviderEgressMode {
    AllowAll,
    ExactOrigins,
}

impl ProviderEgressMode {
    pub(crate) fn parse(value: &str) -> Result<Self, DomainError> {
        match value {
            "allow_all" => Ok(Self::AllowAll),
            "exact_origins" => Ok(Self::ExactOrigins),
            _ => Err(DomainError::InvalidCharacters),
        }
    }

    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::AllowAll => "allow_all",
            Self::ExactOrigins => "exact_origins",
        }
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct ProviderOrigin(String);

impl ProviderOrigin {
    pub(crate) fn parse(value: &str, allow_http_loopback: bool) -> Result<Self, DomainError> {
        if !(8..=512).contains(&value.len())
            || value
                .bytes()
                .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
        {
            return Err(DomainError::InvalidUrl);
        }
        let url = Url::parse(value).map_err(|_| DomainError::InvalidUrl)?;
        if url.path() != "/" || url.query().is_some() || url.fragment().is_some() {
            return Err(DomainError::InvalidUrl);
        }
        let canonical = canonical_provider_origin(&url, allow_http_loopback)?;
        if canonical != value {
            return Err(DomainError::InvalidUrl);
        }
        Ok(Self(canonical))
    }

    pub(crate) fn from_url(url: &Url, allow_http_loopback: bool) -> Result<Self, DomainError> {
        canonical_provider_origin(url, allow_http_loopback).map(Self)
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }

    pub(crate) fn into_inner(self) -> String {
        self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ProviderEgressPolicy {
    mode: ProviderEgressMode,
    exact_origins: BTreeSet<ProviderOrigin>,
}

impl ProviderEgressPolicy {
    pub(crate) fn new(
        mode: ProviderEgressMode,
        exact_origins: Vec<String>,
        allow_http_loopback: bool,
    ) -> Result<Self, DomainError> {
        let exact_origins = exact_origins
            .into_iter()
            .map(|origin| ProviderOrigin::parse(&origin, allow_http_loopback))
            .collect::<Result<BTreeSet<_>, _>>()?;
        match mode {
            ProviderEgressMode::AllowAll if exact_origins.is_empty() => {}
            ProviderEgressMode::ExactOrigins
                if (1..=MAX_PROVIDER_EGRESS_ORIGINS).contains(&exact_origins.len()) => {}
            _ => return Err(DomainError::InvalidValue),
        }
        Ok(Self {
            mode,
            exact_origins,
        })
    }

    pub(crate) const fn mode(&self) -> ProviderEgressMode {
        self.mode
    }

    pub(crate) fn exact_origins(&self) -> impl Iterator<Item = &ProviderOrigin> {
        self.exact_origins.iter()
    }

    #[cfg(test)]
    pub(crate) fn admits(&self, url: &Url, allow_http_loopback: bool) -> Result<bool, DomainError> {
        let origin = ProviderOrigin::from_url(url, allow_http_loopback)?;
        Ok(self.mode == ProviderEgressMode::AllowAll || self.exact_origins.contains(&origin))
    }
}

fn canonical_provider_origin(url: &Url, allow_http_loopback: bool) -> Result<String, DomainError> {
    if url.username() != "" || url.password().is_some() {
        return Err(DomainError::InvalidUrl);
    }
    let host = url.host().ok_or(DomainError::InvalidUrl)?;
    let secure = match url.scheme() {
        "https" => true,
        "http" if allow_http_loopback => match &host {
            Host::Ipv4(address) => IpAddr::V4(*address).is_loopback(),
            Host::Ipv6(address) => IpAddr::V6(*address).is_loopback(),
            Host::Domain(_) => false,
        },
        _ => false,
    };
    if !secure {
        return Err(DomainError::InvalidUrl);
    }
    let host = match host {
        Host::Domain(domain) => domain.to_owned(),
        Host::Ipv4(address) => address.to_string(),
        Host::Ipv6(address) => format!("[{address}]"),
    };
    Ok(format!(
        "{}://{}{}",
        url.scheme(),
        host,
        url.port()
            .map_or_else(String::new, |port| format!(":{port}"))
    ))
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
    fn project_provider_egress_policy_is_canonical_bounded_and_explicit() {
        let allow_all = ProviderEgressPolicy::new(ProviderEgressMode::AllowAll, vec![], false)
            .expect("allow-all stores no origins");
        assert!(
            allow_all
                .admits(&Url::parse("https://private.example/path").unwrap(), false)
                .unwrap()
        );
        assert_eq!(
            ProviderEgressPolicy::new(
                ProviderEgressMode::AllowAll,
                vec!["https://id.example".to_owned()],
                false,
            ),
            Err(DomainError::InvalidValue)
        );
        let exact = ProviderEgressPolicy::new(
            ProviderEgressMode::ExactOrigins,
            vec![
                "https://id.example".to_owned(),
                "https://tokens.example:8443".to_owned(),
            ],
            false,
        )
        .expect("exact origins should parse");
        assert!(
            exact
                .admits(&Url::parse("https://id.example/authorize").unwrap(), false)
                .unwrap()
        );
        assert!(
            !exact
                .admits(&Url::parse("https://other.example/token").unwrap(), false)
                .unwrap()
        );
        assert_eq!(
            ProviderEgressPolicy::new(ProviderEgressMode::ExactOrigins, vec![], false),
            Err(DomainError::InvalidValue)
        );
        for noncanonical in [
            "https://id.example/",
            "https://ID.example",
            "https://id.example:443",
            "https://id.example/path",
        ] {
            assert_eq!(
                ProviderOrigin::parse(noncanonical, false),
                Err(DomainError::InvalidUrl)
            );
        }
        assert!(ProviderOrigin::parse("http://127.0.0.1:8080", false).is_err());
        assert!(ProviderOrigin::parse("http://127.0.0.1:8080", true).is_ok());
        assert!(ProviderOrigin::parse("http://localhost:8080", true).is_err());
    }

    #[test]
    fn provider_lifecycle_requires_secret_finalization_before_activation() {
        let mut status = ProviderStatus::Provisioning;
        status.provision().unwrap();
        status.disable().unwrap();
        assert_eq!(status.provision(), Err(DomainError::InvalidTransition));
    }
}
