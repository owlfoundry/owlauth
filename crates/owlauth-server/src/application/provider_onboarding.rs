use std::sync::Arc;

use async_trait::async_trait;
use url::Url;
use uuid::Uuid;

use crate::domain::{
    NamedProviderProfile, ProviderEgressMode, ProviderEgressPolicy, ProviderKey, ProviderKind,
    provider_callback_url,
};

use super::{ApplicationError, ProviderExchangeError};

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ProviderEgressPolicyRecord {
    pub(crate) project_id: Uuid,
    pub(crate) mode: ProviderEgressMode,
    pub(crate) exact_origins: Vec<String>,
    pub(crate) revision: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct UpdateProviderEgressPolicy {
    pub(crate) mode: ProviderEgressMode,
    pub(crate) exact_origins: Vec<String>,
    pub(crate) expected_revision: i64,
}

#[async_trait]
pub(crate) trait ProviderEgressPolicyPort: Send + Sync {
    async fn get_provider_egress_policy(
        &self,
        project_id: Uuid,
    ) -> Result<ProviderEgressPolicyRecord, ApplicationError>;

    async fn get_active_provider_egress_policy(
        &self,
        project_id: Uuid,
    ) -> Result<ProviderEgressPolicyRecord, ApplicationError>;

    async fn get_active_project_public_id(
        &self,
        project_id: Uuid,
    ) -> Result<String, ApplicationError>;

    async fn update_provider_egress_policy(
        &self,
        project_id: Uuid,
        policy: ProviderEgressPolicy,
        expected_revision: i64,
        correlation_id: Uuid,
    ) -> Result<ProviderEgressPolicyRecord, ApplicationError>;

    async fn record_oidc_preflight_outcome(
        &self,
        project_id: Uuid,
        outcome: &'static str,
        correlation_id: Uuid,
    ) -> Result<(), ApplicationError>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "the internal diagnostic reports four independent reviewed OIDC capabilities"
)]
pub(crate) struct OidcPreflightSummary {
    pub(crate) canonical_issuer: String,
    pub(crate) admitted_endpoint_origins: Vec<String>,
    pub(crate) exact_scopes: Vec<String>,
    pub(crate) authorization_code_supported: bool,
    pub(crate) pkce_s256_supported: bool,
    pub(crate) rs256_id_tokens_supported: bool,
    pub(crate) managed_profile_supported: bool,
}

#[async_trait]
pub(crate) trait OidcPreflightPort: Send + Sync {
    async fn preflight(
        &self,
        issuer: &str,
        policy: &ProviderEgressPolicy,
    ) -> Result<OidcPreflightSummary, ProviderExchangeError>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct NamedProviderPreflight {
    pub(crate) kind: ProviderKind,
    pub(crate) profile: NamedProviderProfile,
    pub(crate) callback_url: String,
}

#[derive(Clone)]
pub(crate) struct ProviderOnboardingService {
    policy: Arc<dyn ProviderEgressPolicyPort>,
    discovery: Arc<dyn OidcPreflightPort>,
    runtime_base: Arc<Url>,
    allow_http_loopback: bool,
}

impl ProviderOnboardingService {
    pub(crate) fn new(
        policy: Arc<dyn ProviderEgressPolicyPort>,
        discovery: Arc<dyn OidcPreflightPort>,
        runtime_base: Arc<Url>,
        allow_http_loopback: bool,
    ) -> Self {
        Self {
            policy,
            discovery,
            runtime_base,
            allow_http_loopback,
        }
    }

    pub(crate) async fn get_policy(
        &self,
        project_id: Uuid,
    ) -> Result<ProviderEgressPolicyRecord, ApplicationError> {
        self.policy.get_provider_egress_policy(project_id).await
    }

    pub(crate) async fn update_policy(
        &self,
        project_id: Uuid,
        command: UpdateProviderEgressPolicy,
        correlation_id: Uuid,
    ) -> Result<ProviderEgressPolicyRecord, ApplicationError> {
        if command.expected_revision <= 0 {
            return Err(ApplicationError::InvalidInput);
        }
        let policy = ProviderEgressPolicy::new(
            command.mode,
            command.exact_origins,
            self.allow_http_loopback,
        )?;
        self.policy
            .update_provider_egress_policy(
                project_id,
                policy,
                command.expected_revision,
                correlation_id,
            )
            .await
    }

    pub(crate) async fn preflight_named(
        &self,
        project_id: Uuid,
        kind: ProviderKind,
        provider_key: String,
    ) -> Result<NamedProviderPreflight, ApplicationError> {
        let profile = kind.named_profile().ok_or(ApplicationError::InvalidInput)?;
        let provider_key = ProviderKey::parse(provider_key)?;
        let project_public_id = self.policy.get_active_project_public_id(project_id).await?;
        let callback_url =
            provider_callback_url(&self.runtime_base, &project_public_id, &provider_key)?;
        Ok(NamedProviderPreflight {
            kind,
            profile,
            callback_url,
        })
    }

    pub(crate) async fn preflight_registration(
        &self,
        project_id: Uuid,
        provider_key: String,
        issuer: String,
        correlation_id: Uuid,
    ) -> Result<(OidcPreflightSummary, ProviderEgressPolicyRecord, String), ApplicationError> {
        let provider_key = ProviderKey::parse(provider_key)?;
        let project_public_id = self.policy.get_active_project_public_id(project_id).await?;
        let (summary, policy) = self.preflight(project_id, issuer, correlation_id).await?;
        let callback_url =
            provider_callback_url(&self.runtime_base, &project_public_id, &provider_key)?;
        Ok((summary, policy, callback_url))
    }

    pub(crate) async fn preflight_for_create(
        &self,
        project_id: Uuid,
        issuer: String,
        managed_profile_enabled: bool,
        correlation_id: Uuid,
    ) -> Result<ProviderEgressPolicyRecord, ApplicationError> {
        let (summary, policy) = self.preflight(project_id, issuer, correlation_id).await?;
        if managed_profile_enabled && !summary.managed_profile_supported {
            return Err(ApplicationError::InvalidInput);
        }
        Ok(policy)
    }

    pub(crate) async fn preflight(
        &self,
        project_id: Uuid,
        issuer: String,
        correlation_id: Uuid,
    ) -> Result<(OidcPreflightSummary, ProviderEgressPolicyRecord), ApplicationError> {
        let record = self
            .policy
            .get_active_provider_egress_policy(project_id)
            .await?;
        let policy = ProviderEgressPolicy::new(
            record.mode,
            record.exact_origins.clone(),
            self.allow_http_loopback,
        )?;
        let result = self.discovery.preflight(&issuer, &policy).await;
        let (outcome, mapped_error) = match result.as_ref() {
            Ok(_) => ("success", None),
            Err(ProviderExchangeError::Rejected | ProviderExchangeError::InvalidProof) => (
                "metadata_rejected",
                Some(ApplicationError::ProviderPreflightRejected),
            ),
            Err(
                ProviderExchangeError::UnavailableBeforeDispatch
                | ProviderExchangeError::AmbiguousAfterDispatch,
            ) => (
                "provider_unavailable",
                Some(ApplicationError::ProviderPreflightUnavailable),
            ),
        };
        self.policy
            .record_oidc_preflight_outcome(project_id, outcome, correlation_id)
            .await?;
        match (result, mapped_error) {
            (Ok(summary), None) => Ok((summary, record)),
            (Err(_), Some(error)) => Err(error),
            _ => Err(ApplicationError::Integrity),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use async_trait::async_trait;

    use super::*;

    #[derive(Clone)]
    struct RecordingPolicy {
        record: ProviderEgressPolicyRecord,
        active_error: Option<ApplicationError>,
        outcomes: Arc<Mutex<Vec<(&'static str, Uuid)>>>,
    }

    #[async_trait]
    impl ProviderEgressPolicyPort for RecordingPolicy {
        async fn get_provider_egress_policy(
            &self,
            project_id: Uuid,
        ) -> Result<ProviderEgressPolicyRecord, ApplicationError> {
            if project_id == self.record.project_id {
                Ok(self.record.clone())
            } else {
                Err(ApplicationError::NotFound)
            }
        }

        async fn get_active_provider_egress_policy(
            &self,
            project_id: Uuid,
        ) -> Result<ProviderEgressPolicyRecord, ApplicationError> {
            match self.active_error {
                Some(error) => Err(error),
                None => self.get_provider_egress_policy(project_id).await,
            }
        }

        async fn get_active_project_public_id(
            &self,
            project_id: Uuid,
        ) -> Result<String, ApplicationError> {
            if project_id != self.record.project_id {
                return Err(ApplicationError::NotFound);
            }
            if let Some(error) = self.active_error {
                return Err(error);
            }
            Ok("prj_provider_test".to_owned())
        }

        async fn update_provider_egress_policy(
            &self,
            _: Uuid,
            _: ProviderEgressPolicy,
            _: i64,
            _: Uuid,
        ) -> Result<ProviderEgressPolicyRecord, ApplicationError> {
            Err(ApplicationError::InvalidTransition)
        }

        async fn record_oidc_preflight_outcome(
            &self,
            project_id: Uuid,
            outcome: &'static str,
            correlation_id: Uuid,
        ) -> Result<(), ApplicationError> {
            if project_id != self.record.project_id {
                return Err(ApplicationError::NotFound);
            }
            self.outcomes
                .lock()
                .expect("outcome recorder should not be poisoned")
                .push((outcome, correlation_id));
            Ok(())
        }
    }

    struct FixedDiscovery(Result<OidcPreflightSummary, ProviderExchangeError>);

    #[async_trait]
    impl OidcPreflightPort for FixedDiscovery {
        async fn preflight(
            &self,
            _: &str,
            _: &ProviderEgressPolicy,
        ) -> Result<OidcPreflightSummary, ProviderExchangeError> {
            self.0.clone()
        }
    }

    fn summary() -> OidcPreflightSummary {
        OidcPreflightSummary {
            canonical_issuer: "https://identity.example".to_owned(),
            admitted_endpoint_origins: vec!["https://identity.example".to_owned()],
            exact_scopes: vec!["openid".to_owned()],
            authorization_code_supported: true,
            pkce_s256_supported: true,
            rs256_id_tokens_supported: true,
            managed_profile_supported: false,
        }
    }

    async fn run_preflight_case(
        discovery_result: Result<OidcPreflightSummary, ProviderExchangeError>,
    ) -> (
        Result<(OidcPreflightSummary, ProviderEgressPolicyRecord), ApplicationError>,
        Vec<(&'static str, Uuid)>,
        Uuid,
    ) {
        let project_id = Uuid::new_v4();
        let correlation_id = Uuid::new_v4();
        let outcomes = Arc::new(Mutex::new(Vec::new()));
        let policy = RecordingPolicy {
            record: ProviderEgressPolicyRecord {
                project_id,
                mode: ProviderEgressMode::AllowAll,
                exact_origins: Vec::new(),
                revision: 7,
            },
            active_error: None,
            outcomes: outcomes.clone(),
        };
        let service = ProviderOnboardingService::new(
            Arc::new(policy),
            Arc::new(FixedDiscovery(discovery_result)),
            Arc::new(Url::parse("https://identity.example/runtime/").expect("runtime base")),
            false,
        );
        let result = service
            .preflight(
                project_id,
                "https://identity.example".to_owned(),
                correlation_id,
            )
            .await;
        let recorded = outcomes
            .lock()
            .expect("outcome recorder should not be poisoned")
            .clone();
        (result, recorded, correlation_id)
    }

    #[tokio::test]
    async fn named_preflight_uses_runtime_registration_authority_without_discovery() {
        let project_id = Uuid::new_v4();
        let service = ProviderOnboardingService::new(
            Arc::new(RecordingPolicy {
                record: ProviderEgressPolicyRecord {
                    project_id,
                    mode: ProviderEgressMode::AllowAll,
                    exact_origins: Vec::new(),
                    revision: 3,
                },
                active_error: None,
                outcomes: Arc::new(Mutex::new(Vec::new())),
            }),
            Arc::new(FixedDiscovery(Ok(summary()))),
            Arc::new(Url::parse("https://identity.example/runtime/").expect("runtime base")),
            false,
        );

        let google = service
            .preflight_named(project_id, ProviderKind::Google, "google-main".to_owned())
            .await
            .expect("Google registration settings");
        assert_eq!(google.profile.issuer, crate::domain::GOOGLE_ISSUER);
        assert_eq!(
            google.callback_url,
            "https://identity.example/runtime/projects/prj_provider_test/auth/callback/google-main"
        );
        assert_eq!(
            google.profile.login.exact_scopes,
            crate::domain::GOOGLE_SCOPES
        );
        assert_eq!(
            service
                .preflight_named(project_id, ProviderKind::Oidc, "custom".to_owned())
                .await,
            Err(ApplicationError::InvalidInput)
        );
        assert_eq!(
            service
                .preflight_named(project_id, ProviderKind::Github, "GitHub".to_owned())
                .await,
            Err(ApplicationError::InvalidInput)
        );
    }

    #[tokio::test]
    async fn custom_preflight_returns_runtime_registration_authority() {
        let project_id = Uuid::new_v4();
        let service = ProviderOnboardingService::new(
            Arc::new(RecordingPolicy {
                record: ProviderEgressPolicyRecord {
                    project_id,
                    mode: ProviderEgressMode::AllowAll,
                    exact_origins: Vec::new(),
                    revision: 3,
                },
                active_error: None,
                outcomes: Arc::new(Mutex::new(Vec::new())),
            }),
            Arc::new(FixedDiscovery(Ok(summary()))),
            Arc::new(Url::parse("https://identity.example/runtime/").expect("runtime base")),
            false,
        );

        let (summary, policy, callback_url) = service
            .preflight_registration(
                project_id,
                "custom-workforce".to_owned(),
                "https://identity.example".to_owned(),
                Uuid::new_v4(),
            )
            .await
            .expect("Custom OIDC registration settings");
        assert_eq!(summary.canonical_issuer, "https://identity.example");
        assert_eq!(policy.revision, 3);
        assert_eq!(
            callback_url,
            "https://identity.example/runtime/projects/prj_provider_test/auth/callback/custom-workforce"
        );
        assert_eq!(
            service
                .preflight_registration(
                    project_id,
                    "Custom".to_owned(),
                    "https://identity.example".to_owned(),
                    Uuid::new_v4(),
                )
                .await,
            Err(ApplicationError::InvalidInput)
        );
    }

    #[tokio::test]
    async fn create_preflight_rejects_unsupported_managed_profile() {
        let project_id = Uuid::new_v4();
        let correlation_id = Uuid::new_v4();
        let outcomes = Arc::new(Mutex::new(Vec::new()));
        let service = ProviderOnboardingService::new(
            Arc::new(RecordingPolicy {
                record: ProviderEgressPolicyRecord {
                    project_id,
                    mode: ProviderEgressMode::AllowAll,
                    exact_origins: Vec::new(),
                    revision: 3,
                },
                active_error: None,
                outcomes: outcomes.clone(),
            }),
            Arc::new(FixedDiscovery(Ok(summary()))),
            Arc::new(Url::parse("https://identity.example/runtime/").expect("runtime base")),
            false,
        );

        assert_eq!(
            service
                .preflight_for_create(
                    project_id,
                    "https://identity.example".to_owned(),
                    true,
                    correlation_id,
                )
                .await,
            Err(ApplicationError::InvalidInput)
        );
        assert_eq!(
            *outcomes.lock().expect("outcome recorder"),
            [("success", correlation_id)]
        );
    }

    struct PanicDiscovery;

    #[async_trait]
    impl OidcPreflightPort for PanicDiscovery {
        async fn preflight(
            &self,
            _: &str,
            _: &ProviderEgressPolicy,
        ) -> Result<OidcPreflightSummary, ProviderExchangeError> {
            panic!("disabled Project must not dispatch provider preflight")
        }
    }

    #[tokio::test]
    async fn disabled_project_is_rejected_before_provider_dispatch() {
        let project_id = Uuid::new_v4();
        let service = ProviderOnboardingService::new(
            Arc::new(RecordingPolicy {
                record: ProviderEgressPolicyRecord {
                    project_id,
                    mode: ProviderEgressMode::AllowAll,
                    exact_origins: Vec::new(),
                    revision: 1,
                },
                active_error: Some(ApplicationError::Disabled),
                outcomes: Arc::new(Mutex::new(Vec::new())),
            }),
            Arc::new(PanicDiscovery),
            Arc::new(Url::parse("https://identity.example/runtime/").expect("runtime base")),
            false,
        );

        assert_eq!(
            service
                .preflight_registration(
                    project_id,
                    "custom".to_owned(),
                    "https://identity.example".to_owned(),
                    Uuid::new_v4(),
                )
                .await,
            Err(ApplicationError::Disabled)
        );
    }

    #[tokio::test]
    async fn preflight_returns_safe_diagnostics_and_audits_every_outcome() {
        let (success, success_audit, success_correlation) = run_preflight_case(Ok(summary())).await;
        let (summary, policy) = success.expect("valid discovery should succeed");
        assert_eq!(summary.canonical_issuer, "https://identity.example");
        assert_eq!(policy.revision, 7);
        assert_eq!(success_audit, [("success", success_correlation)]);

        for (provider_error, application_error, outcome) in [
            (
                ProviderExchangeError::Rejected,
                ApplicationError::ProviderPreflightRejected,
                "metadata_rejected",
            ),
            (
                ProviderExchangeError::InvalidProof,
                ApplicationError::ProviderPreflightRejected,
                "metadata_rejected",
            ),
            (
                ProviderExchangeError::UnavailableBeforeDispatch,
                ApplicationError::ProviderPreflightUnavailable,
                "provider_unavailable",
            ),
            (
                ProviderExchangeError::AmbiguousAfterDispatch,
                ApplicationError::ProviderPreflightUnavailable,
                "provider_unavailable",
            ),
        ] {
            let (result, audit, correlation_id) = run_preflight_case(Err(provider_error)).await;
            assert_eq!(result.unwrap_err(), application_error);
            assert_eq!(audit, [(outcome, correlation_id)]);
        }
    }
}
