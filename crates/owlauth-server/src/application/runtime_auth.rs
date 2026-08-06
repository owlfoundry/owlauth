use std::sync::Arc;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use time::{Duration, OffsetDateTime};
use url::Url;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::domain::{
    LoginTransactionStatus, ManagedProfileCapabilities, ManagedProfileCapability,
    ProfileDisplayName, ProfilePictureUrl, ProviderIssuer, ProviderSubject,
};

use super::{
    AccessTokenSessionLookup, ApplicationError, AuthenticatedIdentityEvidence,
    AuthenticationRepository, BindBrowserLogout, BindHostedBrowser, BrowserLogoutRecord,
    ClaimProviderCallback, Clock, CommitHandoffExchange, CompleteAuthenticatedIdentity,
    ConfirmBrowserLogout, ConfirmBrowserSessionReuse, CreateLoginTransaction, CurrentSession,
    DenyProviderCallback, EmailIdentityAliasAuthority, EmailProofDecision, EmailProofKind,
    FailProviderExchange, HandoffPreparation, HostedInteraction, LoginRevisionSnapshot,
    LogoutApplicationSession, ManagedCredentialCapability, OpaquePurpose,
    PasswordlessEmailRepository, PrepareBrowserLogout, PrepareHandoffExchange,
    PrepareRefreshRotation, ProtectedPurpose, ProviderAuthorizationRequest,
    ProviderCallbackRequest, ProviderExchangeError, ProviderIdentity, ProviderRequestProfile,
    ProviderSecretResolver, RecoverProviderExchanges, RefreshPreparation, RefreshPreparationResult,
    RefreshRotationResult, RotateRefreshToken, RuntimeAuthorityRepository, RuntimeProtector,
    RuntimeSigner, SelectEmailMethod, SelectProviderMethod, SessionAuthorityRepository,
    UpstreamProviderClient, VerifiedProviderIdentity, VerifyEmailProof, VersionedDigest,
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
    email: Arc<dyn PasswordlessEmailRepository>,
    mail_worker: Arc<super::MailWorker>,
    protector: Arc<dyn RuntimeProtector>,
    signer: Arc<dyn RuntimeSigner>,
    provider_secrets: Arc<dyn ProviderSecretResolver>,
    provider: Arc<dyn UpstreamProviderClient>,
    managed_capabilities: ManagedProfileCapabilities,
    clock: Arc<dyn Clock>,
    runtime_base: Url,
}

impl RuntimeAuthService {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        authentication: Arc<dyn AuthenticationRepository>,
        sessions: Arc<dyn SessionAuthorityRepository>,
        authority: Arc<dyn RuntimeAuthorityRepository>,
        email: Arc<dyn PasswordlessEmailRepository>,
        mail_worker: Arc<super::MailWorker>,
        protector: Arc<dyn RuntimeProtector>,
        signer: Arc<dyn RuntimeSigner>,
        provider_secrets: Arc<dyn ProviderSecretResolver>,
        provider: Arc<dyn UpstreamProviderClient>,
        managed_capabilities: impl Into<ManagedProfileCapabilities>,
        clock: Arc<dyn Clock>,
        runtime_base: Url,
    ) -> Self {
        Self {
            authentication,
            sessions,
            authority,
            email,
            mail_worker,
            protector,
            signer,
            provider_secrets,
            provider,
            managed_capabilities: managed_capabilities.into(),
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

    pub(crate) async fn public_application_origin_allowed(
        &self,
        project_public_id: &str,
        application_public_id: &str,
        origin: &str,
    ) -> Result<bool, ApplicationError> {
        let (project_id, application_id) = self
            .authority
            .resolve_public_application(project_public_id, application_public_id)
            .await?;
        self.authority
            .exact_application_origin(project_id, application_id, origin)
            .await
    }

    pub(crate) fn provider_issuer_allowed(&self, kind: &str, issuer: &str) -> bool {
        crate::domain::ProviderKind::parse(kind)
            .is_ok_and(|kind| self.provider.issuer_allowed(kind, issuer))
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

    pub(crate) async fn application_session_origin_allowed(
        &self,
        project_id: Uuid,
        application_id: Uuid,
        origin: &str,
    ) -> Result<bool, ApplicationError> {
        self.authority
            .exact_application_origin(project_id, application_id, origin)
            .await
    }

    pub(crate) async fn browser_session_reuse_available(
        &self,
        project_id: Uuid,
        browser_session: &str,
    ) -> Result<bool, ApplicationError> {
        let credential = self.digest_credential(
            OpaquePurpose::BrowserSession,
            project_id.as_bytes(),
            browser_session,
        )?;
        self.authority
            .browser_session_reuse_available(project_id, &credential, self.clock.now())
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
        let mut context = self
            .authority
            .prepare_login_start(
                &request.project_public_id,
                &request.application_public_id,
                &request.publishable_key,
                &request.redirect_uri,
            )
            .await?;
        context.admitted_providers.retain(|provider| {
            self.provider
                .issuer_allowed(provider.kind, &provider.issuer)
        });
        if context.admitted_providers.is_empty() && context.admitted_email.is_none() {
            return Err(ApplicationError::Disabled);
        }
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
                admitted_email: context.admitted_email,
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
            // Never adopt a caller-supplied cookie when first binding an interaction. A fresh
            // browser credential prevents pre-seeding from fixing another browser's binding.
            let binding_value = self.opaque_credential(32)?;
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

    pub(crate) async fn email_admission_scope(
        &self,
        project_public_id: &str,
        interaction: &str,
        browser_binding: &str,
    ) -> Result<EmailAdmissionScope, ApplicationError> {
        let transaction_id = credential_id(interaction)?;
        let interaction_digest =
            self.digest_id_credential(OpaquePurpose::Interaction, transaction_id, interaction)?;
        let binding = self.binding_digest(transaction_id, browser_binding)?;
        let hosted = self
            .authority
            .hosted_interaction(&interaction_digest, Some(&binding), self.clock.now())
            .await?;
        if hosted.project_public_id != project_public_id {
            return Err(ApplicationError::NotFound);
        }
        Ok(EmailAdmissionScope {
            project_id: hosted.project_id,
            application_id: hosted.application_id,
        })
    }

    pub(crate) async fn select_email(&self, request: SelectEmail) -> Result<(), ApplicationError> {
        let transaction_id = credential_id(&request.interaction)?;
        let interaction_digest = self.digest_id_credential(
            OpaquePurpose::Interaction,
            transaction_id,
            &request.interaction,
        )?;
        let binding = self.binding_digest(transaction_id, &request.browser_binding)?;
        let hosted = self
            .authority
            .hosted_interaction(&interaction_digest, Some(&binding), self.clock.now())
            .await?;
        if hosted.project_public_id != request.project_public_id {
            return Err(ApplicationError::NotFound);
        }
        if !hosted.email_available {
            return Err(ApplicationError::InvalidTransition);
        }
        self.email
            .select_email_method(SelectEmailMethod {
                project_id: hosted.project_id,
                transaction_id,
                expected_transaction_revision: request.expected_revision,
                browser_binding: binding,
                csrf: self.csrf_digest(transaction_id, &request.csrf)?,
                now: self.clock.now(),
            })
            .await
    }

    #[allow(
        clippy::too_many_lines,
        reason = "challenge cryptographic generation keeps all purpose bindings visible"
    )]
    pub(crate) async fn begin_email_challenge(
        &self,
        request: BeginEmailChallenge,
    ) -> Result<EmailChallengeAccepted, ApplicationError> {
        let transaction_id = credential_id(&request.interaction)?;
        let canonical = crate::domain::CanonicalEmail::parse_v1(&request.email)
            .map_err(|_| ApplicationError::InvalidInput)?;
        let binding = self.binding_digest(transaction_id, &request.browser_binding)?;
        let interaction_digest = self.digest_id_credential(
            OpaquePurpose::Interaction,
            transaction_id,
            &request.interaction,
        )?;
        let hosted = self
            .authority
            .hosted_interaction(&interaction_digest, Some(&binding), self.clock.now())
            .await?;
        if hosted.project_public_id != request.project_public_id {
            return Err(ApplicationError::NotFound);
        }
        let csrf = self.csrf_digest(transaction_id, &request.csrf)?;
        let preparation = self
            .email
            .prepare_email_generation(
                hosted.project_id,
                transaction_id,
                request.expected_revision,
                &binding,
                &csrf,
                self.clock.now(),
            )
            .await?;
        let challenge_id = Uuid::new_v4();
        let outbox_id = Uuid::new_v4();
        let context = email_challenge_context(
            preparation.project_id,
            transaction_id,
            challenge_id,
            preparation.next_generation,
        );
        let lookup = self.protector.digest(
            OpaquePurpose::EmailIdentityLookup,
            preparation.project_id.as_bytes(),
            canonical.expose().as_bytes(),
        )?;
        let protected_address = self.protector.protect(
            ProtectedPurpose::EmailChallengeAddress,
            &context,
            canonical.expose().as_bytes(),
        )?;
        let otp = preparation
            .policy
            .otp_enabled
            .then(|| {
                u8::try_from(preparation.policy.otp_digits)
                    .map_err(|_| crate::domain::DomainError::InvalidValue)
                    .and_then(crate::domain::generate_decimal_otp)
            })
            .transpose()
            .map_err(ApplicationError::from)?;
        let magic = preparation
            .policy
            .magic_link_enabled
            .then(|| self.protector.random_opaque(24))
            .transpose()?;
        let otp_digest = otp
            .as_ref()
            .map(|proof| {
                self.protector
                    .digest(OpaquePurpose::EmailOtpProof, &context, proof.as_bytes())
            })
            .transpose()?;
        let magic_digest = magic
            .as_ref()
            .map(|proof| {
                self.protector
                    .digest(OpaquePurpose::EmailMagicProof, &context, proof.as_bytes())
            })
            .transpose()?;
        let now = self.clock.now();
        let otp_expires_at = otp.as_ref().map(|_| {
            std::cmp::min(
                now + Duration::seconds(i64::from(preparation.policy.otp_validity_seconds)),
                preparation.transaction_expires_at,
            )
        });
        let magic_expires_at = magic.as_ref().map(|_| {
            std::cmp::min(
                now + Duration::seconds(i64::from(preparation.policy.magic_validity_seconds)),
                preparation.transaction_expires_at,
            )
        });
        let expires_at = otp_expires_at
            .into_iter()
            .chain(magic_expires_at)
            .max()
            .ok_or(ApplicationError::Integrity)?;
        if expires_at <= now {
            return Err(ApplicationError::InvalidTransition);
        }
        let magic_url = magic
            .as_ref()
            .map(|proof| {
                self.runtime_base
                    .join(&format!("auth/email/confirm/{challenge_id}"))
                    .map(|mut url| {
                        // All authority remains in the fragment: scanners and the GET shell
                        // never receive it. The browser scrubs this value before rendering and
                        // submits it only after an explicit user action.
                        let fragment = url::form_urlencoded::Serializer::new(String::new())
                            .append_pair("proof", proof.as_str())
                            .append_pair("project", &request.project_public_id)
                            .append_pair("transaction", &transaction_id.to_string())
                            .append_pair("generation", &preparation.next_generation.to_string())
                            .append_pair("revision", &(request.expected_revision + 1).to_string())
                            .finish();
                        url.set_fragment(Some(&fragment));
                        url.to_string()
                    })
                    .map_err(|_| ApplicationError::Integrity)
            })
            .transpose()?;
        let envelope_plaintext = Zeroizing::new(
            serde_json::to_vec(&serde_json::json!({"to": canonical.expose()}))
                .map_err(|_| ApplicationError::Integrity)?,
        );
        let mut message = String::from(
            "OwlAuth email sign-in\r\n\r\nUse only the newest code or link for this sign-in.\r\n",
        );
        if let Some(otp) = otp.as_deref() {
            message.push_str("\r\nOne-time code: ");
            message.push_str(otp);
            message.push_str("\r\n");
        }
        if let Some(magic_url) = magic_url.as_deref() {
            message.push_str("\r\nSign-in link: ");
            message.push_str(magic_url);
            message.push_str("\r\n");
        }
        message.push_str("\r\nIf you did not request this sign-in, ignore this message.\r\n");
        let body_plaintext = Zeroizing::new(message.into_bytes());
        let envelope = self.protector.protect(
            ProtectedPurpose::EmailOutboxEnvelope,
            &context,
            envelope_plaintext.as_slice(),
        )?;
        let body = self.protector.protect(
            ProtectedPurpose::EmailOutboxBody,
            &context,
            body_plaintext.as_slice(),
        )?;
        self.email
            .commit_email_generation(super::CommitEmailGeneration {
                project_id: preparation.project_id,
                application_id: preparation.application_id,
                transaction_id,
                expected_transaction_revision: request.expected_revision,
                expected_generation: preparation.next_generation,
                challenge_id,
                outbox_id,
                canonicalization_version: crate::domain::CanonicalEmail::version(),
                lookup_digest: lookup,
                address: protected_address,
                otp_digest,
                magic_digest,
                envelope,
                body,
                message_id: format!("<{outbox_id}@mail.owlauth.invalid>"),
                suppress_delivery: request.suppress_delivery,
                issued_at: now,
                otp_expires_at,
                magic_expires_at,
                expires_at,
            })
            .await?;
        Ok(EmailChallengeAccepted {
            accepted: true,
            revision: request.expected_revision + 1,
            challenge_id,
            generation: preparation.next_generation,
            otp_enabled: preparation.policy.otp_enabled,
            magic_link_enabled: preparation.policy.magic_link_enabled,
            expires_at,
        })
    }

    #[allow(
        clippy::too_many_lines,
        reason = "proof completion keeps short- and long-term protection transitions visible"
    )]
    pub(crate) async fn verify_email_proof(
        &self,
        request: SubmitEmailProof,
    ) -> Result<EmailCompletion, ApplicationError> {
        validate_email_proof(request.kind, request.proof.as_str())?;
        let transaction_id = credential_id(&request.interaction)?;
        let binding = request
            .browser_binding
            .as_deref()
            .map(|value| self.binding_digest(transaction_id, value))
            .transpose()?;
        let interaction_digest = self.digest_id_credential(
            OpaquePurpose::Interaction,
            transaction_id,
            &request.interaction,
        )?;
        let hosted = match self
            .authority
            .hosted_interaction(&interaction_digest, binding.as_ref(), self.clock.now())
            .await
        {
            Ok(hosted) => hosted,
            Err(error) if is_email_proof_terminal(error) => return Ok(EmailCompletion::Invalid),
            Err(error) => return Err(error),
        };
        if hosted.project_public_id != request.project_public_id {
            return Ok(EmailCompletion::Invalid);
        }
        self.complete_resolved_email_proof(
            ResolvedEmailAuthority {
                project_id: hosted.project_id,
                project_public_id: hosted.project_public_id,
                transaction_id,
                application_type: hosted.application_type,
                binding,
                csrf: self.csrf_digest(transaction_id, &request.csrf)?,
                transfer_context: None,
            },
            request,
        )
        .await
    }

    pub(crate) async fn establish_magic_transfer_context(
        &self,
        challenge_id: Uuid,
    ) -> Result<MagicTransferGate, ApplicationError> {
        let context = self.protector.random_opaque(32)?;
        let csrf = self.protector.random_opaque(24)?;
        let digest_context = self.protector.digest(
            OpaquePurpose::EmailMagicTransferContext,
            challenge_id.as_bytes(),
            context.as_bytes(),
        )?;
        let digest_csrf = self.protector.digest(
            OpaquePurpose::EmailMagicTransferCsrf,
            challenge_id.as_bytes(),
            csrf.as_bytes(),
        )?;
        self.email
            .establish_magic_transfer_context(super::EstablishMagicTransferContext {
                id: Uuid::new_v4(),
                challenge_id,
                context: digest_context,
                csrf: digest_csrf,
                now: self.clock.now(),
            })
            .await?;
        Ok(MagicTransferGate { context, csrf })
    }

    pub(crate) async fn verify_magic_transfer(
        &self,
        request: SubmitMagicTransferProof,
    ) -> Result<EmailCompletion, ApplicationError> {
        validate_email_proof(EmailProofKind::MagicLink, request.proof.as_str())?;
        let transfer_context = self.protector.digest(
            OpaquePurpose::EmailMagicTransferContext,
            request.challenge_id.as_bytes(),
            request.transfer_context.as_bytes(),
        )?;
        let csrf = self.protector.digest(
            OpaquePurpose::EmailMagicTransferCsrf,
            request.challenge_id.as_bytes(),
            request.csrf.as_bytes(),
        )?;
        let resolved = match self
            .email
            .resolve_magic_transfer_context(super::ResolveMagicTransferContext {
                challenge_id: request.challenge_id,
                project_public_id: request.project_public_id.clone(),
                transaction_id: request.transaction_id,
                context: transfer_context.clone(),
                csrf: csrf.clone(),
                now: self.clock.now(),
            })
            .await
        {
            Ok(resolved) => resolved,
            Err(error) if is_email_proof_terminal(error) => return Ok(EmailCompletion::Invalid),
            Err(error) => return Err(error),
        };
        let binding = request
            .browser_binding
            .as_deref()
            .map(|value| self.binding_digest(request.transaction_id, value))
            .transpose()?;
        if resolved.browser_binding_required && binding.is_none() {
            return Ok(EmailCompletion::Invalid);
        }
        self.complete_resolved_email_proof(
            ResolvedEmailAuthority {
                project_id: resolved.project_id,
                project_public_id: resolved.project_public_id,
                transaction_id: resolved.transaction_id,
                application_type: resolved.application_type,
                binding,
                csrf,
                transfer_context: Some(transfer_context),
            },
            SubmitEmailProof {
                project_public_id: request.project_public_id,
                interaction: String::new(),
                challenge_id: request.challenge_id,
                generation: request.generation,
                browser_binding: None,
                existing_browser_session: request.existing_browser_session,
                csrf: String::new(),
                expected_revision: request.expected_revision,
                kind: EmailProofKind::MagicLink,
                proof: request.proof,
            },
        )
        .await
    }

    #[allow(
        clippy::too_many_lines,
        reason = "proof completion keeps short- and long-term protection transitions visible"
    )]
    async fn complete_resolved_email_proof(
        &self,
        authority: ResolvedEmailAuthority,
        request: SubmitEmailProof,
    ) -> Result<EmailCompletion, ApplicationError> {
        let transaction_id = authority.transaction_id;
        let context = email_challenge_context(
            authority.project_id,
            transaction_id,
            request.challenge_id,
            request.generation,
        );
        let purpose = match request.kind {
            EmailProofKind::Otp => OpaquePurpose::EmailOtpProof,
            EmailProofKind::MagicLink => OpaquePurpose::EmailMagicProof,
        };
        let proof_key_version = match self
            .email
            .email_proof_key_version(
                authority.project_id,
                transaction_id,
                request.challenge_id,
                request.kind,
            )
            .await
        {
            Ok(Some(version)) => version,
            Ok(None) => return Ok(EmailCompletion::Invalid),
            Err(error) if is_email_proof_terminal(error) => return Ok(EmailCompletion::Invalid),
            Err(error) => return Err(error),
        };
        let proof = self.protector.digest_at(
            purpose,
            &context,
            request.proof.as_bytes(),
            proof_key_version,
        )?;
        let verification = VerifyEmailProof {
            project_id: authority.project_id,
            transaction_id,
            challenge_id: request.challenge_id,
            proof_kind: request.kind,
            proof_digest: proof,
            browser_binding: authority.binding,
            csrf: authority.csrf,
            transfer_context: authority.transfer_context,
            expected_transaction_revision: request.expected_revision,
            now: self.clock.now(),
        };
        let candidate = match self.email.verify_email_proof(verification.clone()).await {
            Ok(candidate) => candidate,
            Err(error) if is_email_proof_terminal(error) => return Ok(EmailCompletion::Invalid),
            Err(error) => return Err(error),
        };
        let EmailProofDecision::Accepted(candidate) = candidate else {
            return Ok(EmailCompletion::Invalid);
        };
        let address = self.protector.unprotect(
            ProtectedPurpose::EmailChallengeAddress,
            &context,
            &candidate.address,
        )?;
        let address =
            std::str::from_utf8(address.as_slice()).map_err(|_| ApplicationError::Integrity)?;
        let canonical = crate::domain::CanonicalEmail::parse_v1(address)
            .map_err(|_| ApplicationError::Integrity)?;
        if crate::domain::CanonicalEmail::version() != candidate.canonicalization_version {
            return Err(ApplicationError::Integrity);
        }
        // A challenge owns the lookup-key version that was active when it was created. Verify
        // that authority independently of the durable identity alias roster: cutover may not yet
        // accept a newly configured challenge version, and retirement may no longer accept the
        // predecessor version of an otherwise-live challenge.
        let verified_challenge_lookup = verify_email_challenge_lookup(
            self.protector.as_ref(),
            authority.project_id,
            &canonical,
            &candidate.lookup_digest,
        )?;
        let alias_authority = self.email.identity_alias_authority().await?;
        let (lookup_aliases, active_alias) = derive_email_identity_aliases(
            self.protector.as_ref(),
            authority.project_id,
            &canonical,
            &alias_authority,
        )?;
        let new_identity_id = Uuid::new_v4();
        let durable_address = self.protector.protect(
            ProtectedPurpose::EmailIdentityAddress,
            &email_identity_context(authority.project_id, new_identity_id),
            canonical.expose().as_bytes(),
        )?;
        let browser_value = self.opaque_credential(32)?;
        let browser_credential = self.digest_credential(
            OpaquePurpose::BrowserSession,
            authority.project_id.as_bytes(),
            &browser_value,
        )?;
        let existing_browser_credential = request
            .existing_browser_session
            .as_deref()
            .map(|value| {
                self.digest_credential(
                    OpaquePurpose::BrowserSession,
                    authority.project_id.as_bytes(),
                    value,
                )
            })
            .transpose()?;
        let handoff_id = Uuid::new_v4();
        let handoff_value = self.credential_with_id(handoff_id)?;
        let handoff_ticket = self.digest_id_credential_in_context(
            OpaquePurpose::HandoffTicket,
            authority.project_id.as_bytes(),
            &handoff_value,
        )?;
        let issued = self
            .email
            .complete_email_proof(super::CompleteEmailProof {
                verification,
                new_user_id: Uuid::new_v4(),
                new_user_public_id: generated_public_id("usr"),
                new_identity_id,
                durable_address,
                verified_challenge_lookup,
                lookup_aliases,
                active_alias,
                alias_authority_revision: alias_authority.revision,
                browser_session_id: Uuid::new_v4(),
                existing_browser_credential,
                browser_credential,
                handoff_id,
                handoff_ticket,
            })
            .await;
        let issued = match issued {
            Ok(issued) => issued,
            Err(error) if is_email_proof_terminal(error) => return Ok(EmailCompletion::Invalid),
            Err(error) => return Err(error),
        };
        let application_state = self.protector.unprotect(
            ProtectedPurpose::ApplicationState,
            transaction_id.as_bytes(),
            &issued.application_state,
        )?;
        let redirect_url = provider_redirect_url(
            &issued.redirect_uri,
            &handoff_value,
            application_state.as_slice(),
        )?;
        Ok(EmailCompletion::Completed(ProviderCompletion {
            redirect_url,
            project_public_id: authority.project_public_id,
            application_type: Some(authority.application_type),
            browser_session: browser_value,
        }))
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
        if hosted.project_public_id != request.project_public_id {
            return Err(ApplicationError::NotFound);
        }
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
        let authorization = self
            .provider
            .authorization_url(ProviderAuthorizationRequest {
                kind: provider.provider_kind,
                issuer: provider.issuer,
                client_id: provider.client_id,
                callback_url: provider.callback_url.clone(),
                state: upstream_state.to_string(),
                nonce: nonce.to_string(),
                pkce_challenge: provider_challenge,
                profile: if provider.managed_profile_enabled {
                    ProviderRequestProfile::ManagedProfile
                } else {
                    ProviderRequestProfile::Login
                },
                egress_policy: provider.egress_policy.clone(),
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
        Ok(authorization.url)
    }

    pub(crate) async fn deny_provider_callback(
        &self,
        request: ProviderCallbackDenial,
    ) -> Result<(), ApplicationError> {
        let transaction_id = credential_id(&request.state)?;
        let state_digest = self.digest_id_credential(
            OpaquePurpose::UpstreamState,
            transaction_id,
            &request.state,
        )?;
        let browser_binding = self.binding_digest(transaction_id, &request.browser_binding)?;
        self.authentication
            .deny_provider_callback(DenyProviderCallback {
                transaction_id,
                project_public_id: request.project_public_id,
                provider_key: request.provider_key,
                upstream_state: state_digest,
                browser_binding,
                safe_outcome: request.safe_outcome,
                now: self.clock.now(),
            })
            .await?;
        Ok(())
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
                transaction_id,
                project_public_id: request.project_public_id.clone(),
                provider_key: request.provider_key.clone(),
                upstream_state: state_digest,
                browser_binding,
                readable_key_versions: self.protector.readable_key_versions(),
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

    #[allow(
        clippy::too_many_lines,
        reason = "provider exchange keeps ordered secret use and authoritative completion visible"
    )]
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
                kind: provider.provider_kind,
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
                profile: if provider.managed_profile_enabled {
                    ProviderRequestProfile::ManagedProfile
                } else {
                    ProviderRequestProfile::Login
                },
                egress_policy: provider.egress_policy,
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
            .complete_authenticated_identity(CompleteAuthenticatedIdentity {
                project_id: claimed.transaction.project_id,
                transaction_id,
                expected_transaction_revision: claimed.transaction.transaction_revision,
                evidence: AuthenticatedIdentityEvidence::Provider(verified_provider_identity(
                    identity,
                    self.managed_capabilities.for_kind(provider.provider_kind),
                )?),
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
            application_type: None,
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
        if hosted.project_public_id != request.project_public_id {
            return Err(ApplicationError::NotFound);
        }
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
            application_type: Some(hosted.application_type),
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
            project_public_id: preparation.project_public_id,
            application_public_id: preparation.application_public_id,
            user_public_id: preparation.user_public_id,
            application_session_id: committed.application_session_id,
            refresh_generation: committed.refresh_generation,
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
            RefreshRotationResult::Rotated { generation, .. } => Ok(CredentialPair {
                project_public_id: preparation.project_public_id,
                application_public_id: preparation.application_public_id,
                user_public_id: preparation.user_public_id,
                application_session_id: preparation.application_session_id,
                refresh_generation: generation,
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

    pub(crate) async fn application_logout_target(
        &self,
        access_token: &str,
    ) -> Result<CurrentSession, ApplicationError> {
        self.authenticate_access_token_for_logout(access_token)
            .await
    }

    pub(crate) async fn logout_application(
        &self,
        current: CurrentSession,
    ) -> Result<(), ApplicationError> {
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
        if context.project_public_id != request.project_public_id {
            return Err(ApplicationError::NotFound);
        }
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

    pub(crate) async fn run_mail_once(&self) -> Result<bool, ApplicationError> {
        self.mail_worker.run_once(self.clock.as_ref()).await
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
            &preparation.signing_public_jwk,
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
            &preparation.signing_public_jwk,
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
        public_jwk: &serde_json::Value,
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
        finish_signed_token(self.signer.as_ref(), public_jwk, &input, signature)
    }

    async fn authenticate_access_token(
        &self,
        token: &str,
    ) -> Result<CurrentSession, ApplicationError> {
        self.authenticate_access_token_with_mode(token, false).await
    }

    async fn authenticate_access_token_for_logout(
        &self,
        token: &str,
    ) -> Result<CurrentSession, ApplicationError> {
        self.authenticate_access_token_with_mode(token, true).await
    }

    async fn authenticate_access_token_with_mode(
        &self,
        token: &str,
        allow_revoked: bool,
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
                AccessTokenSessionLookup {
                    project_id: key.project_id,
                    application_public_id: claims.app_id,
                    user_public_id: claims.sub,
                    application_session_id: claims.sid,
                    claims_revision: claims.claims_rev,
                    now: self.clock.now(),
                },
                allow_revoked,
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct EmailAdmissionScope {
    pub project_id: Uuid,
    pub application_id: Uuid,
}

pub(crate) struct SelectEmail {
    pub project_public_id: String,
    pub interaction: String,
    pub browser_binding: String,
    pub csrf: String,
    pub expected_revision: i64,
}

pub(crate) struct BeginEmailChallenge {
    pub project_public_id: String,
    pub interaction: String,
    pub browser_binding: String,
    pub csrf: String,
    pub expected_revision: i64,
    pub email: String,
    /// Internal admission outcome; it is never accepted from the wire.
    pub suppress_delivery: bool,
}

pub(crate) struct EmailChallengeAccepted {
    pub accepted: bool,
    pub revision: i64,
    pub challenge_id: Uuid,
    pub generation: i16,
    pub otp_enabled: bool,
    pub magic_link_enabled: bool,
    pub expires_at: OffsetDateTime,
}

pub(crate) struct SubmitEmailProof {
    pub project_public_id: String,
    pub interaction: String,
    pub challenge_id: Uuid,
    pub generation: i16,
    pub browser_binding: Option<String>,
    pub existing_browser_session: Option<String>,
    pub csrf: String,
    pub expected_revision: i64,
    pub kind: EmailProofKind,
    pub proof: Zeroizing<String>,
}

pub(crate) struct SubmitMagicTransferProof {
    pub project_public_id: String,
    pub transaction_id: Uuid,
    pub challenge_id: Uuid,
    pub generation: i16,
    pub browser_binding: Option<String>,
    pub existing_browser_session: Option<String>,
    pub transfer_context: Zeroizing<String>,
    pub csrf: Zeroizing<String>,
    pub expected_revision: i64,
    pub proof: Zeroizing<String>,
}

pub(crate) struct MagicTransferGate {
    pub context: Zeroizing<String>,
    pub csrf: Zeroizing<String>,
}

struct ResolvedEmailAuthority {
    project_id: Uuid,
    project_public_id: String,
    transaction_id: Uuid,
    application_type: crate::domain::ApplicationType,
    binding: Option<VersionedDigest>,
    csrf: VersionedDigest,
    transfer_context: Option<VersionedDigest>,
}

pub(crate) enum EmailCompletion {
    Completed(ProviderCompletion),
    Invalid,
}

pub(crate) struct SelectProvider {
    pub project_public_id: String,
    pub interaction: String,
    pub browser_binding: String,
    pub csrf: String,
    pub expected_revision: i64,
    pub provider_key: String,
}

pub(crate) struct ProviderCallbackDenial {
    pub project_public_id: String,
    pub provider_key: String,
    pub state: String,
    pub browser_binding: String,
    pub safe_outcome: &'static str,
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
    pub application_type: Option<crate::domain::ApplicationType>,
    pub browser_session: Zeroizing<String>,
}

pub(crate) struct ConfirmSessionReuse {
    pub project_public_id: String,
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
    pub project_public_id: String,
    pub application_public_id: String,
    pub user_public_id: String,
    pub application_session_id: Uuid,
    pub refresh_generation: i64,
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
    pub project_public_id: String,
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

fn verified_provider_identity<'a>(
    identity: ProviderIdentity,
    capability: impl Into<Option<&'a ManagedProfileCapability>>,
) -> Result<VerifiedProviderIdentity, ApplicationError> {
    let capability = capability.into();
    let managed_capability = identity
        .renewable_credential
        .as_ref()
        .map(|credential| {
            let capability = capability.ok_or(ApplicationError::InvalidTransition)?;
            if !capability.scopes_match(&credential.granted_scopes) {
                return Err(ApplicationError::InvalidTransition);
            }
            ManagedCredentialCapability::from_adapter(capability, credential.supports_revocation)
        })
        .transpose()?;
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
        locale: None,
        renewable_credential: identity.renewable_credential,
        managed_capability,
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

fn email_identity_context(project_id: Uuid, identity_id: Uuid) -> Vec<u8> {
    let mut context = Vec::with_capacity(32 + 35);
    context.extend_from_slice(b"owlauth-email-identity-v1\0");
    context.extend_from_slice(project_id.as_bytes());
    context.extend_from_slice(identity_id.as_bytes());
    context
}

fn email_challenge_context(
    project_id: Uuid,
    transaction_id: Uuid,
    challenge_id: Uuid,
    generation: i16,
) -> Vec<u8> {
    let mut context = Vec::with_capacity(16 * 3 + 2 + 32);
    context.extend_from_slice(b"owlauth-email-challenge-v1\0");
    context.extend_from_slice(project_id.as_bytes());
    context.extend_from_slice(transaction_id.as_bytes());
    context.extend_from_slice(challenge_id.as_bytes());
    context.extend_from_slice(&generation.to_be_bytes());
    context
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

fn finish_signed_token(
    signer: &dyn RuntimeSigner,
    public_jwk: &Value,
    signing_input: &str,
    signature: Vec<u8>,
) -> Result<String, ApplicationError> {
    signer.verify(public_jwk, signing_input.as_bytes(), &signature)?;
    Ok(format!(
        "{signing_input}.{}",
        URL_SAFE_NO_PAD.encode(signature)
    ))
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

fn validate_email_proof(kind: EmailProofKind, proof: &str) -> Result<(), ApplicationError> {
    let valid = match kind {
        EmailProofKind::Otp => {
            (6..=10).contains(&proof.len()) && proof.as_bytes().iter().all(u8::is_ascii_digit)
        }
        EmailProofKind::MagicLink => {
            (22..=128).contains(&proof.len())
                && URL_SAFE_NO_PAD
                    .decode(proof)
                    .is_ok_and(|decoded| URL_SAFE_NO_PAD.encode(decoded) == proof)
        }
    };
    if valid {
        Ok(())
    } else {
        Err(ApplicationError::InvalidInput)
    }
}

fn is_email_proof_terminal(error: ApplicationError) -> bool {
    matches!(
        error,
        ApplicationError::NotFound
            | ApplicationError::RevisionConflict
            | ApplicationError::InvalidTransition
            | ApplicationError::Disabled
    )
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

fn verify_email_challenge_lookup(
    protector: &dyn RuntimeProtector,
    project_id: Uuid,
    canonical: &crate::domain::CanonicalEmail,
    persisted: &VersionedDigest,
) -> Result<VersionedDigest, ApplicationError> {
    let derived = protector.digest_at(
        OpaquePurpose::EmailIdentityLookup,
        project_id.as_bytes(),
        canonical.expose().as_bytes(),
        persisted.key_version,
    )?;
    if derived.key_version != persisted.key_version
        || !bool::from(derived.value.ct_eq(persisted.value.as_slice()))
    {
        return Err(ApplicationError::Integrity);
    }
    Ok(derived)
}

fn derive_email_identity_aliases(
    protector: &dyn RuntimeProtector,
    project_id: Uuid,
    canonical: &crate::domain::CanonicalEmail,
    authority: &EmailIdentityAliasAuthority,
) -> Result<(Vec<VersionedDigest>, VersionedDigest), ApplicationError> {
    if authority.accepted_versions.is_empty()
        || authority.accepted_versions.len() > 16
        || !authority
            .accepted_versions
            .contains(&authority.write_version)
    {
        return Err(ApplicationError::Integrity);
    }
    let aliases = authority
        .accepted_versions
        .iter()
        .copied()
        .map(|version| {
            protector.digest_at(
                OpaquePurpose::EmailIdentityLookup,
                project_id.as_bytes(),
                canonical.expose().as_bytes(),
                version,
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    let active = aliases
        .iter()
        .find(|alias| alias.key_version == authority.write_version)
        .cloned()
        .ok_or(ApplicationError::Integrity)?;
    Ok((aliases, active))
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
    use crate::adapters::runtime_security::{
        RuntimeKeyMaterial, SoftwareRuntimeProtector, SplitRuntimeProtector,
    };

    struct RejectingGeneratedSignature;

    #[async_trait::async_trait]
    impl RuntimeSigner for RejectingGeneratedSignature {
        async fn sign(
            &self,
            _signer_ref: &str,
            _signing_input: &[u8],
        ) -> Result<Vec<u8>, ApplicationError> {
            Ok(vec![7; 64])
        }

        fn verify(
            &self,
            _public_jwk: &Value,
            _signing_input: &[u8],
            _signature: &[u8],
        ) -> Result<(), ApplicationError> {
            Err(ApplicationError::Integrity)
        }
    }

    fn split_email_protector() -> SplitRuntimeProtector {
        let material = |seed| RuntimeKeyMaterial::new([seed; 32], [seed + 32; 32]);
        let short_term = SoftwareRuntimeProtector::new(
            "challenge-test".to_owned(),
            7,
            material(7),
            std::collections::BTreeMap::new(),
        )
        .expect("short-term protector");
        let durable = SoftwareRuntimeProtector::new(
            "identity-test".to_owned(),
            2,
            material(2),
            std::collections::BTreeMap::from([(1, material(1))]),
        )
        .expect("durable email identity protector");
        SplitRuntimeProtector::new(short_term, Some(durable))
    }

    #[test]
    fn generated_signature_must_verify_before_a_compact_jwt_is_returned() {
        assert_eq!(
            finish_signed_token(
                &RejectingGeneratedSignature,
                &serde_json::json!({ "kty": "OKP" }),
                "header.payload",
                vec![7; 64],
            ),
            Err(ApplicationError::Integrity)
        );
    }

    #[test]
    fn challenge_lookup_verification_is_independent_of_durable_alias_authority() {
        let protector = split_email_protector();
        let project_id = Uuid::new_v4();
        let canonical = crate::domain::CanonicalEmail::parse_v1("person@example.test")
            .expect("canonical address");

        // A staged key rollout creates the challenge with configured active v2 while durable
        // alias authority still writes and accepts only v1.
        let new_v2_challenge = protector
            .digest(
                OpaquePurpose::EmailIdentityLookup,
                project_id.as_bytes(),
                canonical.expose().as_bytes(),
            )
            .expect("active challenge lookup");
        let verified_v2 =
            verify_email_challenge_lookup(&protector, project_id, &canonical, &new_v2_challenge)
                .expect("v2 challenge remains independently verifiable");
        let staged_authority = EmailIdentityAliasAuthority {
            revision: 1,
            write_version: 1,
            accepted_versions: vec![1],
        };
        let (staged_aliases, staged_active) =
            derive_email_identity_aliases(&protector, project_id, &canonical, &staged_authority)
                .expect("staged durable v1 authority");
        assert_eq!(verified_v2.key_version, 2);
        assert_eq!(
            staged_aliases
                .iter()
                .map(|alias| alias.key_version)
                .collect::<Vec<_>>(),
            vec![1]
        );
        assert_eq!(staged_active.key_version, 1);

        // During overlap, a predecessor v1 challenge remains verifiable while durable identity
        // resolution derives both accepted v1/v2 aliases and writes v2.
        let predecessor_v1 = staged_active.clone();
        assert_eq!(
            verify_email_challenge_lookup(&protector, project_id, &canonical, &predecessor_v1),
            Ok(predecessor_v1.clone())
        );
        let overlap_authority = EmailIdentityAliasAuthority {
            revision: 2,
            write_version: 2,
            accepted_versions: vec![1, 2],
        };
        let (overlap_aliases, overlap_active) =
            derive_email_identity_aliases(&protector, project_id, &canonical, &overlap_authority)
                .expect("cutover overlap aliases");
        assert_eq!(
            overlap_aliases
                .iter()
                .map(|alias| alias.key_version)
                .collect::<Vec<_>>(),
            vec![1, 2]
        );
        assert_eq!(overlap_active.key_version, 2);

        // Retirement collapses durable accepted/write authority to v2, but it does not invalidate
        // an otherwise-live v1 challenge while the predecessor key remains readable.
        let retired_authority = EmailIdentityAliasAuthority {
            revision: 3,
            write_version: 2,
            accepted_versions: vec![2],
        };
        let (retired_aliases, retired_active) =
            derive_email_identity_aliases(&protector, project_id, &canonical, &retired_authority)
                .expect("retired durable v2 authority");
        assert_eq!(
            retired_aliases
                .iter()
                .map(|alias| alias.key_version)
                .collect::<Vec<_>>(),
            vec![2]
        );
        assert_eq!(retired_active.key_version, 2);
        assert_eq!(
            verify_email_challenge_lookup(&protector, project_id, &canonical, &predecessor_v1),
            Ok(predecessor_v1.clone())
        );

        let mut tampered_value = predecessor_v1.clone();
        tampered_value.value[0] ^= 1;
        assert_eq!(
            verify_email_challenge_lookup(&protector, project_id, &canonical, &tampered_value),
            Err(ApplicationError::Integrity)
        );
        let mislabeled_version = VersionedDigest {
            key_version: 2,
            ..predecessor_v1
        };
        assert_eq!(
            verify_email_challenge_lookup(&protector, project_id, &canonical, &mislabeled_version),
            Err(ApplicationError::Integrity)
        );
    }

    #[test]
    fn proof_terminal_races_are_generic_but_infrastructure_and_integrity_are_not() {
        for terminal in [
            ApplicationError::NotFound,
            ApplicationError::RevisionConflict,
            ApplicationError::InvalidTransition,
            ApplicationError::Disabled,
        ] {
            assert!(is_email_proof_terminal(terminal));
        }
        for preserved in [
            ApplicationError::Integrity,
            ApplicationError::Persistence,
            ApplicationError::ExternalStore,
            ApplicationError::InvalidInput,
            ApplicationError::IdempotencyConflict,
            ApplicationError::OperationInProgress,
            ApplicationError::PublicationPending,
        ] {
            assert!(!is_email_proof_terminal(preserved));
        }
    }

    #[test]
    fn email_proofs_require_exact_public_grammar_before_authority() {
        for valid in ["000000", "1234567890"] {
            assert_eq!(validate_email_proof(EmailProofKind::Otp, valid), Ok(()));
        }
        for invalid in ["", "12345", "12345678901", "１２３４５６", "12345a"] {
            assert_eq!(
                validate_email_proof(EmailProofKind::Otp, invalid),
                Err(ApplicationError::InvalidInput)
            );
        }

        let canonical = URL_SAFE_NO_PAD.encode([7_u8; 16]);
        assert_eq!(canonical.len(), 22);
        assert_eq!(
            validate_email_proof(EmailProofKind::MagicLink, &canonical),
            Ok(())
        );
        for invalid in [
            "",
            "abcdefghijklmnopqrstu",
            "abcdefghijklmnopqrstu=",
            "abcdefghijklmnopqrstu+",
            "A".repeat(129).as_str(),
        ] {
            assert_eq!(
                validate_email_proof(EmailProofKind::MagicLink, invalid),
                Err(ApplicationError::InvalidInput)
            );
        }
    }

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
