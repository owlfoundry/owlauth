#![forbid(unsafe_code)]

/// Client configuration for an `OwlAuth` server.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Client {
    base_url: String,
}

impl Client {
    /// Creates a client for an `OwlAuth` server.
    #[must_use]
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
        }
    }

    /// Returns the configured server URL.
    #[must_use]
    pub fn base_url(&self) -> &str {
        &self.base_url
    }
}

#[cfg(test)]
mod tests {
    use super::Client;

    #[test]
    fn stores_base_url() {
        let client = Client::new("https://auth.example.com");
        assert_eq!(client.base_url(), "https://auth.example.com");
    }
}
