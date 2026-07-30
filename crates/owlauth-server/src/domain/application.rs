use std::net::IpAddr;

use url::Url;

use super::DomainError;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ApplicationType {
    Web,
    Native,
}

impl ApplicationType {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Web => "web",
            Self::Native => "native",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ApplicationStatus {
    Active,
    Disabled,
}

impl ApplicationStatus {
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
pub(crate) enum RedirectType {
    Web,
    Loopback,
    CustomScheme,
}

impl RedirectType {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Web => "web",
            Self::Loopback => "loopback",
            Self::CustomScheme => "custom_scheme",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RedirectUri {
    exact: String,
    kind: RedirectType,
}

impl RedirectUri {
    pub(crate) fn parse(
        value: String,
        application_type: ApplicationType,
    ) -> Result<Self, DomainError> {
        if !(8..=2048).contains(&value.len()) || has_ambiguous_url_bytes(&value) {
            return Err(DomainError::InvalidUrl);
        }
        let url = Url::parse(&value).map_err(|_| DomainError::InvalidUrl)?;
        if url.as_str() != value
            || !url.username().is_empty()
            || url.password().is_some()
            || url.fragment().is_some()
            || url.host_str().is_some_and(|host| host.contains('*'))
        {
            return Err(DomainError::InvalidUrl);
        }
        let loopback = url.host_str().is_some_and(|host| {
            host == "localhost" || host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
        });
        let kind = match (application_type, url.scheme(), loopback) {
            (ApplicationType::Web, "https", _) => RedirectType::Web,
            (ApplicationType::Web | ApplicationType::Native, "http", true) => {
                RedirectType::Loopback
            }
            (ApplicationType::Native, scheme, false)
                if is_private_application_scheme(scheme) && url.host_str().is_none() =>
            {
                RedirectType::CustomScheme
            }
            _ => return Err(DomainError::InvalidUrl),
        };
        Ok(Self { exact: value, kind })
    }

    pub(crate) fn into_parts(self) -> (String, RedirectType) {
        (self.exact, self.kind)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct BrowserOrigin(String);

impl BrowserOrigin {
    pub(crate) fn parse(value: String) -> Result<Self, DomainError> {
        if !(8..=512).contains(&value.len()) || has_ambiguous_url_bytes(&value) {
            return Err(DomainError::InvalidUrl);
        }
        let url = Url::parse(&value).map_err(|_| DomainError::InvalidUrl)?;
        let valid = matches!(url.scheme(), "http" | "https")
            && url.host_str().is_some()
            && url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none()
            && url.path() == "/"
            && url.host_str().is_none_or(|host| !host.contains('*'));
        if !valid {
            return Err(DomainError::InvalidUrl);
        }
        let canonical = format!(
            "{}://{}{}",
            url.scheme(),
            url.host_str().expect("validated origin has a host"),
            url.port()
                .map_or_else(String::new, |port| format!(":{port}"))
        );
        if canonical != value {
            return Err(DomainError::InvalidUrl);
        }
        Ok(Self(value))
    }

    pub(crate) fn into_inner(self) -> String {
        self.0
    }
}

fn is_private_application_scheme(scheme: &str) -> bool {
    scheme.contains('.')
        && !matches!(
            scheme,
            "about"
                | "blob"
                | "data"
                | "file"
                | "ftp"
                | "http"
                | "https"
                | "javascript"
                | "mailto"
                | "vbscript"
                | "ws"
                | "wss"
        )
}

fn has_ambiguous_url_bytes(value: &str) -> bool {
    value.contains('\\')
        || value.bytes().any(|byte| byte.is_ascii_whitespace())
        || value.to_ascii_lowercase().contains("%2f")
        || value.to_ascii_lowercase().contains("%5c")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_redirects_reject_prefix_wildcard_and_fragment_semantics() {
        assert!(
            RedirectUri::parse(
                "https://app.example/callback".to_owned(),
                ApplicationType::Web
            )
            .is_ok()
        );
        for value in [
            "https://*.example/callback",
            "https://app.example/callback#fragment",
            "https://app.example/%2fcallback",
            "http://app.example/callback",
        ] {
            assert_eq!(
                RedirectUri::parse(value.to_owned(), ApplicationType::Web),
                Err(DomainError::InvalidUrl)
            );
        }
    }

    #[test]
    fn origins_are_canonical_origin_only_values() {
        assert!(BrowserOrigin::parse("https://app.example".to_owned()).is_ok());
        for value in [
            "https://app.example/",
            "https://app.example/path",
            "https://user@app.example",
            "https://*.example",
        ] {
            assert_eq!(
                BrowserOrigin::parse(value.to_owned()),
                Err(DomainError::InvalidUrl)
            );
        }
    }

    #[test]
    fn native_redirects_allow_loopback_and_private_custom_schemes() {
        assert!(
            RedirectUri::parse(
                "http://127.0.0.1:43123/callback".to_owned(),
                ApplicationType::Native
            )
            .is_ok()
        );
        assert!(
            RedirectUri::parse(
                "com.example.app:/callback".to_owned(),
                ApplicationType::Native
            )
            .is_ok()
        );
        for value in [
            "javascript:alert(1)",
            "data:text/html,hello",
            "file:/private/path",
            "custom:/callback",
        ] {
            assert_eq!(
                RedirectUri::parse(value.to_owned(), ApplicationType::Native),
                Err(DomainError::InvalidUrl)
            );
        }
    }
}
