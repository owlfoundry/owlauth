use std::sync::Arc;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use time::{Duration, OffsetDateTime};
use url::Url;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::domain::{
    LoginTransactionStatus, ProfileDisplayName, ProfilePictureUrl, ProviderIssuer, ProviderSubject,
};

use super::{
    ApplicationError, AuthenticationRepository, BindBrowserLogout, BindHostedBrowser,
    BrowserLogoutRecord, ClaimProviderCallback, Clock, CommitHandoffExchange,
    CompleteProviderCallback, ConfirmBrowserLogout, ConfirmBrowserSessionReuse,
    CreateLoginTransaction, CurrentSession, FailProviderExchange, HandoffPreparation,
    HostedInteraction, LoginRevisionSnapshot, LogoutApplicationSession, OpaquePurpose,
    PrepareBrowserLogout, PrepareHandoffExchange, PrepareRefreshRotation, ProtectedPurpose,
    ProviderAuthorizationRequest, ProviderCallbackRequest, ProviderExchangeError, ProviderIdentity,
    ProviderSecretResolver, RecoverProviderExchanges, RefreshPreparation, RefreshPreparationResult,
    RefreshRotationResult, RotateRefreshToken, RuntimeAuthorityRepository, RuntimeProtector,
    RuntimeSigner, SelectProviderMethod, SessionAuthorityRepository, UpstreamProviderClient,
    VerifiedProviderIdentity,
};

const LOGIN_TTL: Duration = Duration::minutes(10);
const CLOCK_SKEW_SECONDS: i64 = 60;
const ACCESS_TOKEN_TYP: &str = "at+jwt";
const MAX_ACCESS_TOKEN_BYTES: usize = 16_384;

#[derive(Clone)]
pub(crate) struct RuntimeAuthService {
    authentication: Arc<dyn AuthenticationRepository>,
    sessions: Arc<dyn SessionAuthorityRepository>,
    authority: Arc<dyn RuntimeAuthorityRepository>,
    protector: Arc<dyn RuntimeProtector>,
    signer: Arc<dyn RuntimeSigner>,
    provider_secrets: Arc<dyn ProviderSecretResolver>,
    provider: Arc<dyn UpstreamProviderClient>,
    clock: Arc<dyn Clock>,
    runtime_base: Url,
}

impl RuntimeAuthService {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        authentication: Arc<dyn AuthenticationRepository>,
        sessions: Arc<dyn SessionAuthorityRepository>,
        authority: Arc<dyn RuntimeAuthorityRepository>,
        protector: Arc<dyn RuntimeProtector>,
        signer: Arc<dyn RuntimeSigner>,
        provider_secrets: Arc<dyn ProviderSecretResolver>,
        provider: Arc<dyn UpstreamProviderClient>,
        clock: Arc<dyn Clock>,
        runtime_base: Url,
    ) -> Self {
        Self {
            authentication,
            sessions,
            authority,
            protector,
            signer,
            provider_secrets,
            provider,
            clock,
            runtime_base,
        }
    }

    pub(crate) async fn application_origin_allowed(
        &self,
        project_public_id: &str,
        application_public_id: &str,
        publishable_key: &str,
        origin: &str,
    ) -> Result<bool, ApplicationError> {
        let (project_id, application_id) = self
            .authority
            .resolve_application(project_public_id, application_public_id, publishable_key)
            .await?;
        self.authority
            .exact_application_origin(project_id, application_id, origin)
            .await
    }

    pub(crate) async fn project_origin_allowed(
        &self,
        project_public_id: &str,
        origin: &str,
    ) -> Result<bool, ApplicationError> {
        self.authority
            .project_origin_allowed(project_public_id, origin)
            .await
    }

    pub(crate) async fn begin_login(
        &self,
        request: BeginLogin,
    ) -> Result<PendingInteraction, ApplicationError> {
        if request.application_state.is_empty()
            || request.application_state.len() > 1024
            || request
                .presentation_hint
                .as_ref()
                .is_some_and(|value| value.len() > 64)
            || !is_pkce_challenge(&request.pkce_challenge)
        {
            return Err(ApplicationError::InvalidInput);
        }
        let context = self
            .authority
            .prepare_login_start(
                &request.project_public_id,
                &request.application_public_id,
                &request.publishable_key,
                &request.redirect_uri,
            )
            .await?;
        let id = Uuid::new_v4();
        let interaction = self.credential_with_id(id)?;
        let digest = self.digest_id_credential(OpaquePurpose::Interaction, id, &interaction)?;
        let protected_state = self.protector.protect(
            ProtectedPurpose::ApplicationState,
            id.as_bytes(),
            request.application_state.as_bytes(),
        )?;
        let now = self.clock.now();
        self.authentication
            .create_login_transaction(CreateLoginTransaction {
                id,
                project_id: context.project_id,
                application_id: context.application_id,
                interaction: digest,
                redirect_uri: request.redirect_uri,
                application_pkce_challenge: request.pkce_challenge,
                application_state: protected_state,
                presentation_hint: request.presentation_hint,
                revisions: LoginRevisionSnapshot {
                    project_metadata_revision: context.project_metadata_revision,
                    project_security_revision: context.project_security_revision,
                    application_security_revision: context.application_security_revision,
                    claims_revision: context.claims_revision,
                    session_revision: context.session_revision,
                },
                created_at: now,
                expires_at: now + LOGIN_TTL,
                admitted_providers: context.admitted_providers,
            })
            .await?;
        Ok(PendingInteraction {
            hosted_url: self
                .runtime_base
                .join(&format!("auth/interactions/{}", interaction.as_str()))
                .map_err(|_| ApplicationError::Integrity)?
                .to_string(),
            expires_at: now + LOGIN_TTL,
        })
    }

    pub(crate) async fn bootstrap_interaction(
        &self,
        interaction: &str,
        browser_binding: Option<&str>,
    ) -> Result<HostedBootstrap, ApplicationError> {
        let transaction_id = credential_id(interaction)?;
        let interaction_digest =
            self.digest_id_credential(OpaquePurpose::Interaction, transaction_id, interaction)?;
        let current_binding = browser_binding
            .map(|value| self.binding_digest(transaction_id, value))
            .transpose()?;
        let initial = self
            .authority
            .hosted_interaction(
                &interaction_digest,
                current_binding.as_ref(),
                self.clock.now(),
            )
            .await?;
        let (binding_value, interaction) = if initial.status
            == LoginTransactionStatus::AwaitingBrowserBinding
        {
            let binding_value = match browser_binding {
                Some(value) => Zeroizing::new(value.to_owned()),
                None => self.opaque_credential(32)?,
            };
            let binding_digest = self.binding_digest(transaction_id, &binding_value)?;
            let csrf_value = self.derived_credential(
                OpaquePurpose::InteractionCsrf,
                transaction_id.as_bytes(),
                None,
            )?;
            let csrf_digest = self.csrf_digest(transaction_id, &csrf_value)?;
            self.authentication
                .bind_hosted_browser(BindHostedBrowser {
                    interaction: interaction_digest.clone(),
                    expected_transaction_revision: initial.transaction_revision,
                    browser_binding: binding_digest.clone(),
                    csrf: csrf_digest,
                    now: self.clock.now(),
                })
                .await?;
            let current = self
                .authority
                .hosted_interaction(&interaction_digest, Some(&binding_digest), self.clock.now())
                .await?;
            (binding_value, current)
        } else {
            let binding_value = browser_binding
                .map(|value| Zeroizing::new(value.to_owned()))
                .ok_or(ApplicationError::NotFound)?;
            (binding_value, initial)
        };
        let csrf_version = interaction
            .csrf_key_version
            .ok_or(ApplicationError::Integrity)?;
        let csrf = self.derived_credential(
            OpaquePurpose::InteractionCsrf,
            transaction_id.as_bytes(),
            Some(csrf_version),
        )?;
        Ok(HostedBootstrap {
            interaction,
            browser_binding: binding_value,
            csrf,
        })
    }

    pub(crate) async fn select_provider(
        &self,
        request: SelectProvider,
    ) -> Result<String, ApplicationError> {
        let transaction_id = credential_id(&request.interaction)?;
        let interaction_digest = self.digest_id_credential(
            OpaquePurpose::Interaction,
            transaction_id,
            &request.interaction,
        )?;
        let hosted = self
            .authority
            .hosted_interaction(
                &interaction_digest,
                Some(&self.binding_digest(transaction_id, &request.browser_binding)?),
                self.clock.now(),
            )
            .await?;
        if hosted.status != LoginTransactionStatus::AwaitingMethodSelection
            || hosted.transaction_revision != request.expected_revision
        {
            return Err(ApplicationError::RevisionConflict);
        }
        let provider = self
            .authority
            .provider_runtime_context(hosted.project_id, transaction_id, &request.provider_key)
            .await?;
        let upstream_state = self.credential_with_id(transaction_id)?;
        let state_digest = self.digest_id_credential(
            OpaquePurpose::UpstreamState,
            transaction_id,
            &upstream_state,
        )?;
        let nonce = self.protector.derive_opaque(
            OpaquePurpose::OidcNonce,
            transaction_id.as_bytes(),
            None,
        )?;
        let nonce_digest = self.protector.digest(
            OpaquePurpose::OidcNonce,
            transaction_id.as_bytes(),
            nonce.as_bytes(),
        )?;
        let provider_verifier = self.protector.random_opaque(32)?;
        let provider_challenge = pkce_challenge(&provider_verifier);
        let protected_verifier = self.protector.protect(
            ProtectedPurpose::ProviderPkce,
            transaction_id.as_bytes(),
            provider_verifier.as_bytes(),
        )?;
        let authorization_url = self
            .provider
            .authorization_url(ProviderAuthorizationRequest {
                issuer: provider.issuer,
                client_id: provider.client_id,
                callback_url: provider.callback_url.clone(),
                state: upstream_state.to_string(),
                nonce: nonce.to_string(),
                pkce_challenge: provider_challenge,
            })
            .await
            .map_err(provider_error)?;
        self.authentication
            .select_provider_method(SelectProviderMethod {
                project_id: hosted.project_id,
                transaction_id,
                expected_transaction_revision: request.expected_revision,
                method_key: request.provider_key,
                provider_id: provider.provider_id,
                browser_binding: self.binding_digest(transaction_id, &request.browser_binding)?,
                csrf: self.csrf_digest(transaction_id, &request.csrf)?,
                callback_url: provider.callback_url,
                upstream_state: state_digest,
                oidc_nonce: nonce_digest,
                provider_pkce: protected_verifier,
                now: self.clock.now(),
            })
            .await?;
        Ok(authorization_url)
    }

    pub(crate) async fn complete_provider_callback(
        &self,
        request: ProviderCallback,
    ) -> Result<ProviderCompletion, ApplicationError> {
        if request.code.is_empty() || request.code.len() > 4096 {
            return Err(ApplicationError::InvalidInput);
        }
        let transaction_id = credential_id(&request.state)?;
        let state_digest = self.digest_id_credential(
            OpaquePurpose::UpstreamState,
            transaction_id,
            &request.state,
        )?;
        let browser_binding = self.binding_digest(transaction_id, &request.browser_binding)?;
        let claimed = self
            .authentication
            .claim_provider_callback(ClaimProviderCallback {
                project_public_id: request.project_public_id.clone(),
                provider_key: request.provider_key.clone(),
                upstream_state: state_digest,
                browser_binding,
                now: self.clock.now(),
            })
            .await?;
        let result = self
            .exchange_and_complete_provider(&request, transaction_id, &claimed)
            .await;
        if result.is_err() {
            let _ = self
                .authentication
                .fail_provider_exchange(FailProviderExchange {
                    project_id: claimed.transaction.project_id,
                    transaction_id: claimed.transaction.id,
                    expected_transaction_revision: claimed.transaction.transaction_revision,
                    now: self.clock.now(),
                })
                .await;
        }
        result
    }

    async fn exchange_and_complete_provider(
        &self,
        request: &ProviderCallback,
        transaction_id: Uuid,
        claimed: &super::ClaimedProviderExchange,
    ) -> Result<ProviderCompletion, ApplicationError> {
        let provider = self
            .authority
            .provider_runtime_context(
                claimed.transaction.project_id,
                transaction_id,
                &request.provider_key,
            )
            .await?;
        let secret = self.provider_secrets.resolve(&provider.secret_ref).await?;
        let verifier = self.protector.unprotect(
            ProtectedPurpose::ProviderPkce,
            transaction_id.as_bytes(),
            &claimed.provider_pkce,
        )?;
        let nonce = self.protector.derive_opaque(
            OpaquePurpose::OidcNonce,
            transaction_id.as_bytes(),
            Some(claimed.oidc_nonce.key_version),
        )?;
        let identity = self
            .provider
            .exchange_code(ProviderCallbackRequest {
                issuer: provider.issuer,
                client_id: provider.client_id,
                client_secret: secret,
                callback_url: claimed.callback_url.clone(),
                code: Zeroizing::new(request.code.clone()),
                pkce_verifier: Zeroizing::new(
                    String::from_utf8(verifier.to_vec())
                        .map_err(|_| ApplicationError::Integrity)?,
                ),
                expected_nonce: nonce,
                now: self.clock.now(),
                allowed_clock_skew_seconds: CLOCK_SKEW_SECONDS,
            })
            .await
            .map_err(provider_error)?;
        let browser_value = self.opaque_credential(32)?;
        let browser_digest = self.digest_credential(
            OpaquePurpose::BrowserSession,
            claimed.transaction.project_id.as_bytes(),
            &browser_value,
        )?;
        let existing_browser_credential = request
            .existing_browser_session
            .as_ref()
            .map(|value| {
                self.digest_credential(
                    OpaquePurpose::BrowserSession,
                    claimed.transaction.project_id.as_bytes(),
                    value,
                )
            })
            .transpose()?;
        let handoff_id = Uuid::new_v4();
        let handoff_value = self.credential_with_id(handoff_id)?;
        let handoff_digest = self.digest_id_credential_in_context(
            OpaquePurpose::HandoffTicket,
            claimed.transaction.project_id.as_bytes(),
            &handoff_value,
        )?;
        let issued = self
            .sessions
            .complete_provider_callback(CompleteProviderCallback {
                project_id: claimed.transaction.project_id,
                transaction_id,
                expected_transaction_revision: claimed.transaction.transaction_revision,
                identity: verified_provider_identity(identity)?,
                new_user_id: Uuid::new_v4(),
                new_user_public_id: generated_public_id("usr"),
                new_identity_id: Uuid::new_v4(),
                browser_session_id: Uuid::new_v4(),
                existing_browser_credential,
                browser_credential: browser_digest,
                handoff_id,
                handoff_ticket: handoff_digest,
                now: self.clock.now(),
            })
            .await?;
        let application_state = self.protector.unprotect(
            ProtectedPurpose::ApplicationState,
            transaction_id.as_bytes(),
            &issued.application_state,
        )?;
        let redirect_url = provider_redirect_url(
            &issued.redirect_uri,
            &handoff_value,
            application_state.as_ref(),
        )?;
        Ok(ProviderCompletion {
            redirect_url,
            project_public_id: request.project_public_id.clone(),
            browser_session: browser_value,
        })
    }

    pub(crate) async fn confirm_session_reuse(
        &self,
        request: ConfirmSessionReuse,
    ) -> Result<ProviderCompletion, ApplicationError> {
        let transaction_id = credential_id(&request.interaction)?;
        let interaction_digest = self.digest_id_credential(
            OpaquePurpose::Interaction,
            transaction_id,
            &request.interaction,
        )?;
        let hosted = self
            .authority
            .hosted_interaction(
                &interaction_digest,
                Some(&self.binding_digest(transaction_id, &request.browser_binding)?),
                self.clock.now(),
            )
            .await?;
        let session_digest = self.digest_credential(
            OpaquePurpose::BrowserSession,
            hosted.project_id.as_bytes(),
            &request.browser_session,
        )?;
        let handoff_id = Uuid::new_v4();
        let handoff_value = self.credential_with_id(handoff_id)?;
        let issued = self
            .sessions
            .confirm_browser_session_reuse(ConfirmBrowserSessionReuse {
                project_id: hosted.project_id,
                transaction_id,
                expected_transaction_revision: request.expected_revision,
                browser_binding: self.binding_digest(transaction_id, &request.browser_binding)?,
                csrf: self.csrf_digest(transaction_id, &request.csrf)?,
                browser_credential: session_digest,
                handoff_id,
                handoff_ticket: self.digest_id_credential_in_context(
                    OpaquePurpose::HandoffTicket,
                    hosted.project_id.as_bytes(),
                    &handoff_value,
                )?,
                now: self.clock.now(),
            })
            .await?;
        let state = self.protector.unprotect(
            ProtectedPurpose::ApplicationState,
            transaction_id.as_bytes(),
            &issued.application_state,
        )?;
        let mut redirect =
            Url::parse(&issued.redirect_uri).map_err(|_| ApplicationError::Integrity)?;
        {
            let mut query = redirect.query_pairs_mut();
            query.append_pair("handoff", &handoff_value);
            query.append_pair(
                "state",
                &String::from_utf8(state.to_vec()).map_err(|_| ApplicationError::Integrity)?,
            );
        }
        Ok(ProviderCompletion {
            redirect_url: redirect.to_string(),
            project_public_id: hosted.project_public_id,
            browser_session: Zeroizing::new(request.browser_session),
        })
    }

    pub(crate) async fn exchange_handoff(
        &self,
        request: ExchangeHandoff,
    ) -> Result<CredentialPair, ApplicationError> {
        let (project_id, application_id) = self
            .authority
            .resolve_application(
                &request.project_public_id,
                &request.application_public_id,
                &request.publishable_key,
            )
            .await?;
        let challenge = pkce_challenge_value(&request.pkce_verifier)?;
        let ticket_digest = self.digest_id_credential_in_context(
            OpaquePurpose::HandoffTicket,
            project_id.as_bytes(),
            &request.handoff,
        )?;
        let preparation = self
            .sessions
            .prepare_handoff_exchange(PrepareHandoffExchange {
                project_id,
                application_id,
                handoff_ticket: ticket_digest.clone(),
                application_pkce_challenge: challenge.clone(),
                now: self.clock.now(),
            })
            .await?;
        let application_session_id = Uuid::new_v4();
        let access_token = self
            .sign_access_token(
                &preparation,
                application_session_id,
                preparation.authenticated_at,
            )
            .await?;
        let refresh_value = self.opaque_credential(32)?;
        let refresh_digest = self.digest_credential(
            OpaquePurpose::RefreshToken,
            application_id.as_bytes(),
            &refresh_value,
        )?;
        let committed = self
            .sessions
            .commit_handoff_exchange(CommitHandoffExchange {
                project_id,
                application_id,
                handoff_ticket: ticket_digest,
                application_pkce_challenge: challenge,
                preparation: preparation.clone(),
                binding_id: Uuid::new_v4(),
                projection_id: Uuid::new_v4(),
                application_session_id,
                refresh_family_id: Uuid::new_v4(),
                refresh_generation_id: Uuid::new_v4(),
                refresh_token: refresh_digest,
                allowed_clock_skew_seconds: CLOCK_SKEW_SECONDS,
                now: self.clock.now(),
            })
            .await?;
        Ok(CredentialPair {
            access_token: Zeroizing::new(access_token),
            refresh_token: refresh_value,
            token_type: "Bearer".to_owned(),
            expires_in: preparation.access_token_lifetime_seconds,
            projection: preparation.projection_document,
            projection_revision: committed.projection_revision,
            session_expires_at: committed.absolute_expires_at,
        })
    }

    pub(crate) async fn refresh(
        &self,
        request: RefreshSession,
    ) -> Result<CredentialPair, ApplicationError> {
        let (project_id, application_id) = self
            .authority
            .resolve_application(
                &request.project_public_id,
                &request.application_public_id,
                &request.publishable_key,
            )
            .await?;
        let presented = self.digest_credential(
            OpaquePurpose::RefreshToken,
            application_id.as_bytes(),
            &request.refresh_token,
        )?;
        let preparation = match self
            .sessions
            .prepare_refresh_rotation(PrepareRefreshRotation {
                project_id,
                application_id,
                presented_token: presented.clone(),
                now: self.clock.now(),
            })
            .await?
        {
            RefreshPreparationResult::Ready(preparation) => *preparation,
            RefreshPreparationResult::ReplayRevoked { .. } => {
                return Err(ApplicationError::InvalidTransition);
            }
        };
        let access_token = self.sign_refresh_access_token(&preparation).await?;
        let successor_value = self.opaque_credential(32)?;
        let successor = self.digest_credential(
            OpaquePurpose::RefreshToken,
            application_id.as_bytes(),
            &successor_value,
        )?;
        match self
            .sessions
            .rotate_refresh_token(RotateRefreshToken {
                project_id,
                application_id,
                presented_token: presented,
                preparation: preparation.clone(),
                successor_generation_id: Uuid::new_v4(),
                successor_token: successor,
                now: self.clock.now(),
            })
            .await?
        {
            RefreshRotationResult::Rotated { .. } => Ok(CredentialPair {
                access_token: Zeroizing::new(access_token),
                refresh_token: successor_value,
                token_type: "Bearer".to_owned(),
                expires_in: preparation.access_token_lifetime_seconds,
                projection: preparation.projection_document,
                projection_revision: preparation.projection_revision,
                session_expires_at: preparation.absolute_expires_at,
            }),
            RefreshRotationResult::ReplayRevoked { .. } => Err(ApplicationError::InvalidTransition),
        }
    }

    pub(crate) async fn current_user(
        &self,
        access_token: &str,
    ) -> Result<CurrentSession, ApplicationError> {
        self.authenticate_access_token(access_token).await
    }

    pub(crate) async fn logout_application(
        &self,
        access_token: &str,
    ) -> Result<(), ApplicationError> {
        let current = self.authenticate_access_token(access_token).await?;
        self.sessions
            .logout_application_session(LogoutApplicationSession {
                project_id: current.project_id,
                application_id: current.application_id,
                user_id: current.user_id,
                application_session_id: current.application_session_id,
                now: self.clock.now(),
            })
            .await
    }

    pub(crate) async fn prepare_browser_logout(
        &self,
        access_token: &str,
    ) -> Result<BrowserLogoutTarget, ApplicationError> {
        let current = self.authenticate_access_token(access_token).await?;
        let id = Uuid::new_v4();
        let preparation = self.credential_with_id(id)?;
        let record = self
            .sessions
            .prepare_browser_logout(PrepareBrowserLogout {
                id,
                project_id: current.project_id,
                application_id: current.application_id,
                user_id: current.user_id,
                application_session_id: current.application_session_id,
                browser_session_id: current.browser_session_id,
                preparation: self.digest_id_credential(
                    OpaquePurpose::BrowserLogout,
                    id,
                    &preparation,
                )?,
                now: self.clock.now(),
            })
            .await?;
        Ok(BrowserLogoutTarget {
            hosted_url: self
                .runtime_base
                .join(&format!("auth/browser-logout/{}", preparation.as_str()))
                .map_err(|_| ApplicationError::Integrity)?
                .to_string(),
            expires_at: record.expires_at,
        })
    }

    pub(crate) async fn browser_logout_project(
        &self,
        preparation: &str,
    ) -> Result<String, ApplicationError> {
        let id = credential_id(preparation)?;
        let digest = self.digest_id_credential(OpaquePurpose::BrowserLogout, id, preparation)?;
        Ok(self
            .authority
            .browser_logout_context(&digest, self.clock.now())
            .await?
            .project_public_id)
    }

    pub(crate) async fn bind_browser_logout(
        &self,
        preparation: &str,
        browser_session: &str,
    ) -> Result<BoundBrowserLogout, ApplicationError> {
        let id = credential_id(preparation)?;
        let digest = self.digest_id_credential(OpaquePurpose::BrowserLogout, id, preparation)?;
        let context = self
            .authority
            .browser_logout_context(&digest, self.clock.now())
            .await?;
        let csrf = self.derived_credential(OpaquePurpose::InteractionCsrf, id.as_bytes(), None)?;
        let record = self
            .sessions
            .bind_browser_logout(BindBrowserLogout {
                preparation: digest,
                browser_credential: self.digest_credential(
                    OpaquePurpose::BrowserSession,
                    context.project_id.as_bytes(),
                    browser_session,
                )?,
                expected_interaction_revision: context.interaction_revision,
                csrf: self.csrf_digest(id, &csrf)?,
                now: self.clock.now(),
            })
            .await?;
        Ok(BoundBrowserLogout {
            project_public_id: context.project_public_id,
            csrf,
            revision: record.interaction_revision,
            expires_at: record.expires_at,
        })
    }

    pub(crate) async fn confirm_browser_logout(
        &self,
        request: ConfirmProjectBrowserLogout,
    ) -> Result<BrowserLogoutRecord, ApplicationError> {
        let id = credential_id(&request.preparation)?;
        let preparation =
            self.digest_id_credential(OpaquePurpose::BrowserLogout, id, &request.preparation)?;
        let context = self
            .authority
            .browser_logout_context(&preparation, self.clock.now())
            .await?;
        self.sessions
            .confirm_browser_logout(ConfirmBrowserLogout {
                preparation,
                browser_credential: self.digest_credential(
                    OpaquePurpose::BrowserSession,
                    context.project_id.as_bytes(),
                    &request.browser_session,
                )?,
                csrf: self.csrf_digest(id, &request.csrf)?,
                expected_interaction_revision: request.expected_revision,
                now: self.clock.now(),
            })
            .await
    }

    pub(crate) async fn recover_abandoned_exchanges(
        &self,
        older_than: Duration,
        limit: u64,
    ) -> Result<u64, ApplicationError> {
        let now = self.clock.now();
        self.sessions
            .recover_abandoned_provider_exchanges(RecoverProviderExchanges {
                abandoned_before: now - older_than,
                limit,
                now,
            })
            .await
    }

    async fn sign_access_token(
        &self,
        preparation: &HandoffPreparation,
        session_id: Uuid,
        authenticated_at: OffsetDateTime,
    ) -> Result<String, ApplicationError> {
        self.sign_claims(
            &preparation.project_issuer,
            &preparation.project_public_id,
            &preparation.application_public_id,
            &preparation.user_public_id,
            session_id,
            preparation.claims_revision,
            authenticated_at,
            preparation.access_token_lifetime_seconds,
            &preparation.signing_kid,
            &preparation.signer_ref,
        )
        .await
    }

    async fn sign_refresh_access_token(
        &self,
        preparation: &RefreshPreparation,
    ) -> Result<String, ApplicationError> {
        self.sign_claims(
            &preparation.project_issuer,
            &preparation.project_public_id,
            &preparation.application_public_id,
            &preparation.user_public_id,
            preparation.application_session_id,
            preparation.claims_revision,
            preparation.authenticated_at,
            preparation.access_token_lifetime_seconds,
            &preparation.signing_kid,
            &preparation.signer_ref,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn sign_claims(
        &self,
        issuer: &str,
        audience: &str,
        application_id: &str,
        subject: &str,
        session_id: Uuid,
        claims_revision: i64,
        authenticated_at: OffsetDateTime,
        lifetime_seconds: i64,
        kid: &str,
        signer_ref: &str,
    ) -> Result<String, ApplicationError> {
        let now = self.clock.now();
        let header = AccessTokenHeader {
            alg: "EdDSA".to_owned(),
            typ: ACCESS_TOKEN_TYP.to_owned(),
            kid: kid.to_owned(),
        };
        let claims = AccessTokenClaims {
            iss: issuer.to_owned(),
            aud: audience.to_owned(),
            sub: subject.to_owned(),
            app_id: application_id.to_owned(),
            sid: session_id,
            iat: now.unix_timestamp(),
            nbf: now.unix_timestamp(),
            exp: (now + Duration::seconds(lifetime_seconds)).unix_timestamp(),
            jti: self.protector.random_opaque(16)?.to_string(),
            auth_time: authenticated_at.unix_timestamp(),
            claims_rev: claims_revision,
        };
        let header = URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&header).map_err(|_| ApplicationError::Integrity)?);
        let payload = URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&claims).map_err(|_| ApplicationError::Integrity)?);
        let input = format!("{header}.{payload}");
        let signature = self.signer.sign(signer_ref, input.as_bytes()).await?;
        Ok(format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature)))
    }

    async fn authenticate_access_token(
        &self,
        token: &str,
    ) -> Result<CurrentSession, ApplicationError> {
        if token.len() > MAX_ACCESS_TOKEN_BYTES {
            return Err(ApplicationError::InvalidInput);
        }
        let mut parts = token.split('.');
        let (Some(encoded_header), Some(encoded_claims), Some(encoded_signature), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(ApplicationError::InvalidInput);
        };
        let header: AccessTokenHeader = serde_json::from_slice(
            &URL_SAFE_NO_PAD
                .decode(encoded_header)
                .map_err(|_| ApplicationError::InvalidInput)?,
        )
        .map_err(|_| ApplicationError::InvalidInput)?;
        let claims: AccessTokenClaims = serde_json::from_slice(
            &URL_SAFE_NO_PAD
                .decode(encoded_claims)
                .map_err(|_| ApplicationError::InvalidInput)?,
        )
        .map_err(|_| ApplicationError::InvalidInput)?;
        if header.alg != "EdDSA" || header.typ != ACCESS_TOKEN_TYP || header.kid.len() > 128 {
            return Err(ApplicationError::InvalidInput);
        }
        let key = self
            .authority
            .verification_key(&claims.aud, &header.kid, self.clock.now())
            .await?;
        if claims.iss != key.issuer
            || claims.aud != key.project_public_id
            || claims.claims_rev <= 0
            || claims.jti.is_empty()
            || claims.iat > claims.nbf
            || claims.nbf > claims.exp
        {
            return Err(ApplicationError::InvalidInput);
        }
        let now = self.clock.now().unix_timestamp();
        if claims.exp <= now - CLOCK_SKEW_SECONDS
            || claims.nbf > now + CLOCK_SKEW_SECONDS
            || claims.iat > now + CLOCK_SKEW_SECONDS
            || claims.auth_time > claims.iat
        {
            return Err(ApplicationError::InvalidTransition);
        }
        let signature = URL_SAFE_NO_PAD
            .decode(encoded_signature)
            .map_err(|_| ApplicationError::InvalidInput)?;
        let signing_input = format!("{encoded_header}.{encoded_claims}");
        self.signer
            .verify(&key.public_jwk, signing_input.as_bytes(), &signature)?;
        self.authority
            .current_session(
                key.project_id,
                &claims.app_id,
                &claims.sub,
                claims.sid,
                claims.claims_rev,
                self.clock.now(),
            )
            .await
    }

    fn binding_digest(
        &self,
        transaction_id: Uuid,
        value: &str,
    ) -> Result<super::VersionedDigest, ApplicationError> {
        self.digest_credential(
            OpaquePurpose::BrowserBinding,
            transaction_id.as_bytes(),
            value,
        )
    }

    fn csrf_digest(
        &self,
        transaction_id: Uuid,
        value: &str,
    ) -> Result<super::VersionedDigest, ApplicationError> {
        self.digest_credential(
            OpaquePurpose::InteractionCsrf,
            transaction_id.as_bytes(),
            value,
        )
    }

    fn digest_id_credential(
        &self,
        purpose: OpaquePurpose,
        id: Uuid,
        value: &str,
    ) -> Result<super::VersionedDigest, ApplicationError> {
        let parsed = parse_id_credential(value)?;
        if parsed.id != id {
            return Err(ApplicationError::InvalidInput);
        }
        self.protector
            .digest_at(purpose, id.as_bytes(), value.as_bytes(), parsed.key_version)
    }

    fn digest_id_credential_in_context(
        &self,
        purpose: OpaquePurpose,
        context: &[u8],
        value: &str,
    ) -> Result<super::VersionedDigest, ApplicationError> {
        let parsed = parse_id_credential(value)?;
        self.protector
            .digest_at(purpose, context, value.as_bytes(), parsed.key_version)
    }

    fn digest_credential(
        &self,
        purpose: OpaquePurpose,
        context: &[u8],
        value: &str,
    ) -> Result<super::VersionedDigest, ApplicationError> {
        let key_version = credential_version(value)?;
        self.protector
            .digest_at(purpose, context, value.as_bytes(), key_version)
    }

    fn credential_with_id(&self, id: Uuid) -> Result<Zeroizing<String>, ApplicationError> {
        let secret = self.protector.random_opaque(24)?;
        Ok(Zeroizing::new(format!(
            "{id}.{}.{}",
            self.protector.active_version(),
            secret.as_str()
        )))
    }

    fn opaque_credential(&self, bytes: usize) -> Result<Zeroizing<String>, ApplicationError> {
        let secret = self.protector.random_opaque(bytes)?;
        Ok(version_credential(self.protector.active_version(), &secret))
    }

    fn derived_credential(
        &self,
        purpose: OpaquePurpose,
        context: &[u8],
        key_version: Option<i32>,
    ) -> Result<Zeroizing<String>, ApplicationError> {
        let version = key_version.unwrap_or_else(|| self.protector.active_version());
        let secret = self
            .protector
            .derive_opaque(purpose, context, Some(version))?;
        Ok(version_credential(version, &secret))
    }
}

#[derive(Clone)]
pub(crate) struct BeginLogin {
    pub project_public_id: String,
    pub application_public_id: String,
    pub publishable_key: String,
    pub redirect_uri: String,
    pub pkce_challenge: String,
    pub application_state: String,
    pub presentation_hint: Option<String>,
}

pub(crate) struct PendingInteraction {
    pub hosted_url: String,
    pub expires_at: OffsetDateTime,
}

pub(crate) struct HostedBootstrap {
    pub interaction: HostedInteraction,
    pub browser_binding: Zeroizing<String>,
    pub csrf: Zeroizing<String>,
}

pub(crate) struct SelectProvider {
    pub interaction: String,
    pub browser_binding: String,
    pub csrf: String,
    pub expected_revision: i64,
    pub provider_key: String,
}

pub(crate) struct ProviderCallback {
    pub project_public_id: String,
    pub provider_key: String,
    pub state: String,
    pub code: String,
    pub browser_binding: String,
    pub existing_browser_session: Option<String>,
}

pub(crate) struct ProviderCompletion {
    pub redirect_url: String,
    pub project_public_id: String,
    pub browser_session: Zeroizing<String>,
}

pub(crate) struct ConfirmSessionReuse {
    pub interaction: String,
    pub browser_binding: String,
    pub csrf: String,
    pub browser_session: String,
    pub expected_revision: i64,
}

pub(crate) struct ExchangeHandoff {
    pub project_public_id: String,
    pub application_public_id: String,
    pub publishable_key: String,
    pub handoff: String,
    pub pkce_verifier: String,
}

pub(crate) struct RefreshSession {
    pub project_public_id: String,
    pub application_public_id: String,
    pub publishable_key: String,
    pub refresh_token: String,
}

pub(crate) struct CredentialPair {
    pub access_token: Zeroizing<String>,
    pub refresh_token: Zeroizing<String>,
    pub token_type: String,
    pub expires_in: i64,
    pub projection: Value,
    pub projection_revision: i64,
    pub session_expires_at: OffsetDateTime,
}

pub(crate) struct BrowserLogoutTarget {
    pub hosted_url: String,
    pub expires_at: OffsetDateTime,
}

pub(crate) struct BoundBrowserLogout {
    pub project_public_id: String,
    pub csrf: Zeroizing<String>,
    pub revision: i64,
    pub expires_at: OffsetDateTime,
}

pub(crate) struct ConfirmProjectBrowserLogout {
    pub preparation: String,
    pub browser_session: String,
    pub csrf: String,
    pub expected_revision: i64,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AccessTokenHeader {
    alg: String,
    typ: String,
    kid: String,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AccessTokenClaims {
    iss: String,
    aud: String,
    sub: String,
    app_id: String,
    sid: Uuid,
    iat: i64,
    nbf: i64,
    exp: i64,
    jti: String,
    auth_time: i64,
    claims_rev: i64,
}

fn verified_provider_identity(
    identity: ProviderIdentity,
) -> Result<VerifiedProviderIdentity, ApplicationError> {
    Ok(VerifiedProviderIdentity {
        issuer: ProviderIssuer::parse(identity.issuer)?,
        subject: ProviderSubject::parse(identity.subject)?,
        display_name: identity
            .display_name
            .map(ProfileDisplayName::parse)
            .transpose()?,
        picture_url: identity
            .picture_url
            .map(ProfilePictureUrl::parse)
            .transpose()?,
    })
}

fn provider_redirect_url(
    redirect_uri: &str,
    handoff: &str,
    application_state: &[u8],
) -> Result<String, ApplicationError> {
    let state = std::str::from_utf8(application_state).map_err(|_| ApplicationError::Integrity)?;
    let mut redirect = Url::parse(redirect_uri).map_err(|_| ApplicationError::Integrity)?;
    {
        let mut query = redirect.query_pairs_mut();
        query.append_pair("handoff", handoff);
        query.append_pair("state", state);
    }
    Ok(redirect.to_string())
}

fn provider_error(error: ProviderExchangeError) -> ApplicationError {
    match error {
        ProviderExchangeError::Rejected | ProviderExchangeError::InvalidProof => {
            ApplicationError::InvalidTransition
        }
        ProviderExchangeError::UnavailableBeforeDispatch
        | ProviderExchangeError::AmbiguousAfterDispatch => ApplicationError::ExternalStore,
    }
}

struct ParsedIdCredential {
    id: Uuid,
    key_version: i32,
}

fn credential_id(value: &str) -> Result<Uuid, ApplicationError> {
    Ok(parse_id_credential(value)?.id)
}

fn parse_id_credential(value: &str) -> Result<ParsedIdCredential, ApplicationError> {
    if value.len() > 256 {
        return Err(ApplicationError::InvalidInput);
    }
    let mut parts = value.split('.');
    let (Some(id_text), Some(version), Some(secret), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(ApplicationError::InvalidInput);
    };
    let id = Uuid::parse_str(id_text).map_err(|_| ApplicationError::InvalidInput)?;
    if id.to_string() != id_text {
        return Err(ApplicationError::InvalidInput);
    }
    validate_credential_secret(secret)?;
    Ok(ParsedIdCredential {
        id,
        key_version: parse_credential_version(version)?,
    })
}

fn credential_version(value: &str) -> Result<i32, ApplicationError> {
    if value.len() > 256 {
        return Err(ApplicationError::InvalidInput);
    }
    let mut parts = value.split('.');
    let (Some(version), Some(secret), None) = (parts.next(), parts.next(), parts.next()) else {
        return Err(ApplicationError::InvalidInput);
    };
    validate_credential_secret(secret)?;
    parse_credential_version(version)
}

fn parse_credential_version(value: &str) -> Result<i32, ApplicationError> {
    let version = value
        .parse::<i32>()
        .map_err(|_| ApplicationError::InvalidInput)?;
    if version <= 0 || version.to_string() != value {
        return Err(ApplicationError::InvalidInput);
    }
    Ok(version)
}

fn validate_credential_secret(value: &str) -> Result<(), ApplicationError> {
    if value.len() < 24
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(ApplicationError::InvalidInput);
    }
    Ok(())
}

fn version_credential(version: i32, secret: &str) -> Zeroizing<String> {
    Zeroizing::new(format!("{version}.{secret}"))
}

fn is_pkce_challenge(value: &str) -> bool {
    value.len() == 43
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn pkce_challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

fn pkce_challenge_value(verifier: &str) -> Result<String, ApplicationError> {
    if !(43..=128).contains(&verifier.len())
        || !verifier
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~'))
    {
        return Err(ApplicationError::InvalidInput);
    }
    Ok(pkce_challenge(verifier))
}

fn generated_public_id(prefix: &str) -> String {
    format!(
        "{prefix}_{}",
        URL_SAFE_NO_PAD.encode(Uuid::new_v4().as_bytes())
    )
}

#[cfg(test)]
mod tests {
    use subtle::ConstantTimeEq;

    use super::*;

    #[test]
    fn credential_handle_requires_canonical_uuid_version_and_secret() {
        let id = Uuid::new_v4();
        assert_eq!(
            credential_id(&format!("{id}.2.abcdefghijklmnopqrstuvwxyz")),
            Ok(id)
        );
        assert_eq!(
            credential_id("missing"),
            Err(ApplicationError::InvalidInput)
        );
        assert_eq!(
            credential_id(&format!("{id}.02.abcdefghijklmnopqrstuvwxyz")),
            Err(ApplicationError::InvalidInput)
        );
        assert_eq!(
            credential_id(&format!("{id}.0.abcdefghijklmnopqrstuvwxyz")),
            Err(ApplicationError::InvalidInput)
        );
    }

    #[test]
    fn opaque_credential_requires_canonical_version_and_secret() {
        assert_eq!(credential_version("2.abcdefghijklmnopqrstuvwxyz"), Ok(2));
        assert_eq!(
            credential_version("02.abcdefghijklmnopqrstuvwxyz"),
            Err(ApplicationError::InvalidInput)
        );
        assert_eq!(
            credential_version("2.not.valid.secret"),
            Err(ApplicationError::InvalidInput)
        );
    }

    #[test]
    fn pkce_is_strict_s256() {
        let verifier = "a".repeat(43);
        let challenge = pkce_challenge_value(&verifier).unwrap();
        assert_eq!(challenge.len(), 43);
        assert!(bool::from(
            challenge
                .as_bytes()
                .ct_eq(pkce_challenge(&verifier).as_bytes())
        ));
        assert_eq!(
            pkce_challenge_value("short"),
            Err(ApplicationError::InvalidInput)
        );
    }
}
