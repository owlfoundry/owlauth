use async_trait::async_trait;

use crate::{
    application::{
        ProviderAuthorization, ProviderAuthorizationRequest, ProviderCallbackRequest,
        ProviderExchangeError, ProviderIdentity, UpstreamProviderClient,
    },
    domain::ProviderKind,
};

use super::{github::GithubOAuthProviderClient, oidc::RestrictedOidcProviderClient};

#[derive(Clone)]
pub(crate) struct ProviderClientRegistry {
    oidc: RestrictedOidcProviderClient,
    google: RestrictedOidcProviderClient,
    github: GithubOAuthProviderClient,
}

impl ProviderClientRegistry {
    pub(crate) fn new(
        oidc: RestrictedOidcProviderClient,
        google: RestrictedOidcProviderClient,
        github: GithubOAuthProviderClient,
    ) -> Self {
        Self {
            oidc,
            google,
            github,
        }
    }
}

#[async_trait]
impl UpstreamProviderClient for ProviderClientRegistry {
    fn issuer_allowed(&self, kind: ProviderKind, issuer: &str) -> bool {
        match kind {
            ProviderKind::Oidc => self.oidc.issuer_allowed(kind, issuer),
            ProviderKind::Google => self.google.issuer_allowed(kind, issuer),
            ProviderKind::Github => self.github.issuer_allowed(kind, issuer),
        }
    }

    async fn authorization_url(
        &self,
        request: ProviderAuthorizationRequest,
    ) -> Result<ProviderAuthorization, ProviderExchangeError> {
        match request.kind {
            ProviderKind::Oidc => self.oidc.authorization_url(request).await,
            ProviderKind::Google => self.google.authorization_url(request).await,
            ProviderKind::Github => self.github.authorization_url(request).await,
        }
    }

    async fn exchange_code(
        &self,
        request: ProviderCallbackRequest,
    ) -> Result<ProviderIdentity, ProviderExchangeError> {
        match request.kind {
            ProviderKind::Oidc => self.oidc.exchange_code(request).await,
            ProviderKind::Google => self.google.exchange_code(request).await,
            ProviderKind::Github => self.github.exchange_code(request).await,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use time::OffsetDateTime;
    use tokio::sync::Semaphore;
    use zeroize::Zeroizing;

    use crate::{
        application::{
            ProviderCallbackRequest, ProviderExchangeError, ProviderRequestProfile,
            UpstreamProviderClient,
        },
        domain::ProviderKind,
    };

    use super::*;

    fn callback(kind: ProviderKind, issuer: &str) -> ProviderCallbackRequest {
        ProviderCallbackRequest {
            kind,
            issuer: issuer.to_owned(),
            client_id: "client-123".to_owned(),
            client_secret: Zeroizing::new("secret-123".to_owned()),
            callback_url: "https://runtime.example/callback".to_owned(),
            code: Zeroizing::new("one-use-code".to_owned()),
            pkce_verifier: Zeroizing::new("v".repeat(43)),
            expected_nonce: Zeroizing::new("nonce-123".to_owned()),
            now: OffsetDateTime::UNIX_EPOCH,
            allowed_clock_skew_seconds: 60,
            profile: ProviderRequestProfile::Login,
        }
    }

    #[tokio::test]
    async fn mixed_provider_callbacks_share_one_fail_fast_process_budget() {
        let budget = Arc::new(Semaphore::new(1));
        let registry = ProviderClientRegistry::new(
            RestrictedOidcProviderClient::new_with_budget(
                ["https://issuer.example"],
                false,
                budget.clone(),
            )
            .unwrap(),
            RestrictedOidcProviderClient::new_with_budget(
                ["https://accounts.google.com"],
                false,
                budget.clone(),
            )
            .unwrap(),
            GithubOAuthProviderClient::new_with_budget(budget.clone()).unwrap(),
        );
        let permit = budget.acquire().await.unwrap();

        assert_eq!(
            registry
                .exchange_code(callback(ProviderKind::Oidc, "https://issuer.example"))
                .await,
            Err(ProviderExchangeError::UnavailableBeforeDispatch)
        );
        assert_eq!(
            registry
                .exchange_code(callback(
                    ProviderKind::Google,
                    "https://accounts.google.com"
                ))
                .await,
            Err(ProviderExchangeError::UnavailableBeforeDispatch)
        );
        assert_eq!(
            registry
                .exchange_code(callback(ProviderKind::Github, "https://github.com"))
                .await,
            Err(ProviderExchangeError::UnavailableBeforeDispatch)
        );

        drop(permit);
    }
}
