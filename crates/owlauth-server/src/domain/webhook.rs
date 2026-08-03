use std::collections::BTreeSet;

use url::Url;

use super::DomainError;

pub(crate) const MAX_WEBHOOK_ENDPOINTS_PER_APPLICATION: usize = 8;
pub(crate) const MAX_WEBHOOK_EVENT_TYPES: usize = 3;
pub(crate) const MAX_WEBHOOK_URL_LENGTH: usize = 2048;
pub(crate) const MAX_WEBHOOK_DELIVERY_ATTEMPTS: i32 = 12;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum ApplicationUserEventType {
    Created,
    Updated,
    Disabled,
}

impl ApplicationUserEventType {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Created => "user.projection.created",
            Self::Updated => "user.projection.updated",
            Self::Disabled => "user.projection.disabled",
        }
    }

    pub(crate) fn parse(value: &str) -> Result<Self, DomainError> {
        match value {
            "user.projection.created" => Ok(Self::Created),
            "user.projection.updated" => Ok(Self::Updated),
            "user.projection.disabled" => Ok(Self::Disabled),
            _ => Err(DomainError::InvalidValue),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct WebhookSubscriptions(Vec<ApplicationUserEventType>);

impl WebhookSubscriptions {
    pub(crate) fn parse(values: &[String]) -> Result<Self, DomainError> {
        if values.is_empty() || values.len() > MAX_WEBHOOK_EVENT_TYPES {
            return Err(DomainError::InvalidValue);
        }
        let values = values
            .iter()
            .map(|value| ApplicationUserEventType::parse(value))
            .collect::<Result<BTreeSet<_>, _>>()?;
        if values.is_empty() {
            return Err(DomainError::InvalidValue);
        }
        Ok(Self(values.into_iter().collect()))
    }

    pub(crate) fn into_strings(self) -> Vec<String> {
        self.0
            .into_iter()
            .map(|value| value.as_str().to_owned())
            .collect()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct WebhookEndpointUrl(String);

impl WebhookEndpointUrl {
    pub(crate) fn parse(value: String) -> Result<Self, DomainError> {
        if value.is_empty() || value.len() > MAX_WEBHOOK_URL_LENGTH {
            return Err(DomainError::InvalidUrl);
        }
        let parsed = Url::parse(&value).map_err(|_| DomainError::InvalidUrl)?;
        if parsed.scheme() != "https"
            || parsed.host_str().is_none()
            || !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.fragment().is_some()
            || parsed.as_str() != value
        {
            return Err(DomainError::InvalidUrl);
        }
        Ok(Self(value))
    }

    #[cfg(test)]
    pub(crate) fn expose(&self) -> &str {
        &self.0
    }

    pub(crate) fn into_inner(self) -> String {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WebhookEndpointStatus {
    Pending,
    Active,
    Disabled,
}

impl WebhookEndpointStatus {
    pub(crate) fn parse(value: &str) -> Result<Self, DomainError> {
        match value {
            "pending" => Ok(Self::Pending),
            "active" => Ok(Self::Active),
            "disabled" => Ok(Self::Disabled),
            _ => Err(DomainError::InvalidValue),
        }
    }

    pub(crate) const fn can_activate(self) -> bool {
        matches!(self, Self::Pending)
    }

    pub(crate) const fn can_disable(self) -> bool {
        matches!(self, Self::Pending | Self::Active)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WebhookDeliveryOutcome {
    Accepted,
    Transient,
    Ambiguous,
    Permanent,
}

impl WebhookDeliveryOutcome {
    pub(crate) const fn from_http_status(status: u16) -> Self {
        match status {
            200..=299 => Self::Accepted,
            408 | 425 | 429 | 500 | 502 | 503 | 504 => Self::Transient,
            _ => Self::Permanent,
        }
    }

    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Transient => "transient",
            Self::Ambiguous => "ambiguous",
            Self::Permanent => "permanent",
        }
    }

    pub(crate) const fn retryable(self) -> bool {
        matches!(self, Self::Transient | Self::Ambiguous)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subscriptions_are_closed_bounded_and_canonical() {
        let subscriptions = WebhookSubscriptions::parse(&[
            "user.projection.updated".to_owned(),
            "user.projection.created".to_owned(),
            "user.projection.updated".to_owned(),
        ])
        .unwrap();
        assert_eq!(
            subscriptions.into_strings(),
            vec![
                "user.projection.created".to_owned(),
                "user.projection.updated".to_owned()
            ]
        );
        assert!(WebhookSubscriptions::parse(&[]).is_err());
        assert!(WebhookSubscriptions::parse(&["arbitrary".to_owned()]).is_err());
    }

    #[test]
    fn endpoint_url_is_exact_https_without_embedded_credentials_or_fragment() {
        assert_eq!(
            WebhookEndpointUrl::parse("https://hooks.example.test/events?source=owl".to_owned())
                .unwrap()
                .expose(),
            "https://hooks.example.test/events?source=owl"
        );
        for invalid in [
            "http://hooks.example.test/events",
            "https://user@hooks.example.test/events",
            "https://hooks.example.test/events#fragment",
            "https://hooks.example.test/events ",
        ] {
            assert!(WebhookEndpointUrl::parse(invalid.to_owned()).is_err());
        }
    }

    #[test]
    fn retry_classification_is_closed() {
        assert_eq!(
            WebhookDeliveryOutcome::from_http_status(204),
            WebhookDeliveryOutcome::Accepted
        );
        assert!(WebhookDeliveryOutcome::from_http_status(429).retryable());
        assert!(WebhookDeliveryOutcome::from_http_status(503).retryable());
        assert_eq!(
            WebhookDeliveryOutcome::from_http_status(307),
            WebhookDeliveryOutcome::Permanent
        );
        assert_eq!(
            WebhookDeliveryOutcome::from_http_status(400),
            WebhookDeliveryOutcome::Permanent
        );
    }
}
