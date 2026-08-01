use async_trait::async_trait;
use sea_orm::sea_query::{LockBehavior, LockType};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, DatabaseConnection, DbBackend, EntityTrait,
    IntoActiveModel, QueryFilter, QueryOrder, QuerySelect, Set, Statement, TransactionTrait,
};
use serde_json::Value;
use subtle::ConstantTimeEq;
use time::{Duration, OffsetDateTime};

use crate::{
    application::{
        ApplicationError, AuthenticatedIdentityEvidence, BindBrowserLogout, BrowserLogoutRecord,
        CommitHandoffExchange, CompleteAuthenticatedIdentity, ConfirmBrowserLogout,
        ConfirmBrowserSessionReuse, HandoffPreparation, HandoffSessionRecord, IssuedHandoff,
        LogoutApplicationSession, PrepareBrowserLogout, PrepareHandoffExchange,
        PrepareRefreshRotation, ProtectedValue, RecoverProviderExchanges, RefreshPreparation,
        RefreshPreparationResult, RefreshRotationResult, RotateRefreshToken,
        SessionAuthorityRepository, VersionedDigest,
    },
    domain::{
        LoginTransactionStatus, ProfileDisplayName, ProfilePictureUrl, PublicId,
        USER_PROJECTION_SCHEMA_V1,
    },
};

const MAX_APPLICATION_BINDINGS_PER_USER: usize = 64;

use super::{
    audit::append_runtime_audit,
    authentication::{
        expire_login, is_pkce_s256_challenge, optional_digest_matches, parse_login_status,
        persistence, revalidate_login_owners, validate_digest,
    },
    entity::{
        application, application_provider_assignment, application_session,
        application_user_binding, application_user_projection, handoff_ticket, linked_identity,
        login_transaction, login_transaction_method, project, project_browser_logout_interaction,
        project_browser_session, project_key_ring, project_policy, project_signing_key,
        project_user, provider_configuration, refresh_family, refresh_token_generation,
    },
};

#[derive(Clone, Debug)]
pub(crate) struct PostgresSessionAuthorityRepository {
    database: DatabaseConnection,
}

impl PostgresSessionAuthorityRepository {
    pub(crate) fn new(database: DatabaseConnection) -> Self {
        Self { database }
    }
}

#[async_trait]
#[allow(
    clippy::single_match_else,
    clippy::too_many_lines,
    reason = "each method keeps one security-sensitive PostgreSQL transaction visible"
)]
impl SessionAuthorityRepository for PostgresSessionAuthorityRepository {
    async fn complete_authenticated_identity(
        &self,
        command: CompleteAuthenticatedIdentity,
    ) -> Result<IssuedHandoff, ApplicationError> {
        let AuthenticatedIdentityEvidence::Provider(identity) = command.evidence.clone();
        let issuer = identity.issuer.into_inner();
        let subject = identity.subject.into_inner();
        let display_name = identity.display_name.map(ProfileDisplayName::into_inner);
        let picture_url = identity.picture_url.map(ProfilePictureUrl::into_inner);
        let locale = identity
            .locale
            .map(crate::domain::ProfileLocale::into_inner);
        let source_profile_digest = base_profile_digest(
            display_name.as_deref(),
            picture_url.as_deref(),
            locale.as_deref(),
            None,
        )?;

        let transaction = self.database.begin().await.map_err(persistence)?;
        let login = login_transaction::Entity::find_by_id(command.transaction_id)
            .filter(login_transaction::Column::ProjectId.eq(command.project_id))
            .lock_exclusive()
            .one(&transaction)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        if login.expires_at <= command.now {
            expire_login(&transaction, login, command.now).await?;
            transaction.commit().await.map_err(persistence)?;
            return Err(ApplicationError::InvalidTransition);
        }
        let mut login_status = parse_login_status(&login.status)?;
        if login_status != LoginTransactionStatus::ProviderExchangeInProgress {
            return Err(ApplicationError::InvalidTransition);
        }
        if login.transaction_revision != command.expected_transaction_revision {
            return fail_provider_completion(
                transaction,
                &login,
                command.now,
                ApplicationError::RevisionConflict,
            )
            .await;
        }
        let digest_validation = validate_digest(&command.browser_credential)
            .and_then(|()| validate_digest(&command.handoff_ticket))
            .and_then(|()| {
                command
                    .existing_browser_credential
                    .as_ref()
                    .map_or(Ok(()), validate_digest)
            });
        if let Err(error) = digest_validation {
            return fail_provider_completion(transaction, &login, command.now, error).await;
        }
        let Some(provider_id) = login.provider_configuration_id else {
            return fail_provider_completion(
                transaction,
                &login,
                command.now,
                ApplicationError::Integrity,
            )
            .await;
        };
        let method = login_transaction_method::Entity::find()
            .filter(login_transaction_method::Column::ProjectId.eq(login.project_id))
            .filter(login_transaction_method::Column::TransactionId.eq(login.id))
            .filter(login_transaction_method::Column::ProviderConfigurationId.eq(provider_id))
            .lock_shared()
            .one(&transaction)
            .await
            .map_err(persistence)?;
        let Some(method) = method else {
            return fail_provider_completion(
                transaction,
                &login,
                command.now,
                ApplicationError::Integrity,
            )
            .await;
        };
        if let Err(error) =
            revalidate_login_owners(&transaction, &login, provider_id, &method).await
        {
            if error == ApplicationError::Persistence {
                return Err(error);
            }
            return fail_provider_completion(transaction, &login, command.now, error).await;
        }
        let provider = provider_configuration::Entity::find_by_id(provider_id)
            .filter(provider_configuration::Column::ProjectId.eq(command.project_id))
            .one(&transaction)
            .await
            .map_err(persistence)?;
        let Some(provider) = provider else {
            return fail_provider_completion(
                transaction,
                &login,
                command.now,
                ApplicationError::Integrity,
            )
            .await;
        };
        if provider.issuer != issuer {
            return fail_provider_completion(
                transaction,
                &login,
                command.now,
                ApplicationError::InvalidInput,
            )
            .await;
        }

        lock_identity_namespace(&transaction, command.project_id, &issuer, &subject).await?;
        let (user, user_projection_changed) = match linked_identity::Entity::find()
            .filter(linked_identity::Column::ProjectId.eq(command.project_id))
            .filter(linked_identity::Column::Issuer.eq(&issuer))
            .filter(linked_identity::Column::Subject.eq(&subject))
            .lock_exclusive()
            .one(&transaction)
            .await
            .map_err(persistence)?
        {
            Some(identity) => {
                if identity.status != "active" {
                    return fail_provider_completion(
                        transaction,
                        &login,
                        command.now,
                        ApplicationError::Disabled,
                    )
                    .await;
                }
                let user = project_user::Entity::find_by_id(identity.user_id)
                    .filter(project_user::Column::ProjectId.eq(command.project_id))
                    .lock_exclusive()
                    .one(&transaction)
                    .await
                    .map_err(persistence)?;
                let Some(user) = user else {
                    return fail_provider_completion(
                        transaction,
                        &login,
                        command.now,
                        ApplicationError::Integrity,
                    )
                    .await;
                };
                if user.status != "active" {
                    return fail_provider_completion(
                        transaction,
                        &login,
                        command.now,
                        ApplicationError::Disabled,
                    )
                    .await;
                }
                let identity_id = identity.id;
                let profile_changed = identity.display_name != display_name
                    || identity.picture_url != picture_url
                    || identity.locale != locale;
                let source_digest_changed =
                    identity
                        .source_profile_digest
                        .as_deref()
                        .is_none_or(|digest| {
                            !bool::from(digest.ct_eq(source_profile_digest.as_slice()))
                        });
                let mut identity_active = identity.into_active_model();
                if profile_changed {
                    identity_active.identity_revision =
                        Set(identity_active.identity_revision.take().unwrap_or(1) + 1);
                    identity_active.display_name = Set(display_name.clone());
                    identity_active.picture_url = Set(picture_url.clone());
                    identity_active.locale = Set(locale.clone());
                    identity_active.updated_at = Set(command.now);
                }
                if profile_changed || source_digest_changed {
                    identity_active.source_profile_digest =
                        Set(Some(source_profile_digest.clone()));
                }
                identity_active.observed_at = Set(command.now);
                identity_active
                    .update(&transaction)
                    .await
                    .map_err(persistence)?;

                let mut user_active = user.clone().into_active_model();
                let primary_provider = user.primary_source_kind == "provider"
                    && user.primary_profile_identity_id == Some(identity_id);
                let effective_display_name = if user.local_display_name_set {
                    user.local_display_name.clone()
                } else if primary_provider {
                    display_name.clone()
                } else {
                    user.display_name.clone()
                };
                let effective_picture_url = if user.local_picture_url_set {
                    user.local_picture_url.clone()
                } else if primary_provider {
                    picture_url.clone()
                } else {
                    user.picture_url.clone()
                };
                let effective_locale = if user.local_locale_set {
                    user.local_locale.clone()
                } else if primary_provider {
                    locale.clone()
                } else {
                    user.locale.clone()
                };
                let canonical_base_digest = base_profile_digest(
                    effective_display_name.as_deref(),
                    effective_picture_url.as_deref(),
                    effective_locale.as_deref(),
                    None,
                )?;
                let materialized_profile_changed = user.display_name != effective_display_name
                    || user.picture_url != effective_picture_url
                    || user.locale != effective_locale;
                let base_digest_changed = !bool::from(
                    user.base_profile_digest
                        .as_slice()
                        .ct_eq(canonical_base_digest.as_slice()),
                );
                if primary_provider && (materialized_profile_changed || base_digest_changed) {
                    user_active.base_profile_digest = Set(canonical_base_digest);
                    if materialized_profile_changed {
                        user_active.user_revision =
                            Set(user_active.user_revision.take().unwrap_or(1) + 1);
                        user_active.display_name = Set(effective_display_name);
                        user_active.picture_url = Set(effective_picture_url);
                        user_active.locale = Set(effective_locale);
                        user_active.updated_at = Set(command.now);
                    }
                    (
                        user_active
                            .update(&transaction)
                            .await
                            .map_err(persistence)?,
                        materialized_profile_changed,
                    )
                } else {
                    (user, false)
                }
            }
            None => {
                let Ok(public_id) = PublicId::parse(command.new_user_public_id.clone()) else {
                    return fail_provider_completion(
                        transaction,
                        &login,
                        command.now,
                        ApplicationError::InvalidInput,
                    )
                    .await;
                };
                let canonical_base_digest = base_profile_digest(
                    display_name.as_deref(),
                    picture_url.as_deref(),
                    locale.as_deref(),
                    None,
                )?;
                let user = project_user::ActiveModel {
                    id: Set(command.new_user_id),
                    project_id: Set(command.project_id),
                    public_id: Set(public_id.to_string()),
                    status: Set("active".to_owned()),
                    user_revision: Set(1),
                    security_revision: Set(1),
                    primary_profile_identity_id: Set(None),
                    primary_source_kind: Set("provider".to_owned()),
                    base_profile_digest: Set(canonical_base_digest),
                    local_display_name_set: Set(false),
                    local_display_name: Set(None),
                    local_picture_url_set: Set(false),
                    local_picture_url: Set(None),
                    local_locale_set: Set(false),
                    local_locale: Set(None),
                    display_name: Set(display_name.clone()),
                    picture_url: Set(picture_url.clone()),
                    locale: Set(locale.clone()),
                    created_at: Set(command.now),
                    updated_at: Set(command.now),
                }
                .insert(&transaction)
                .await
                .map_err(persistence)?;
                linked_identity::ActiveModel {
                    id: Set(command.new_identity_id),
                    project_id: Set(command.project_id),
                    user_id: Set(user.id),
                    created_via_provider_configuration_id: Set(provider_id),
                    issuer: Set(issuer.clone()),
                    subject: Set(subject.clone()),
                    status: Set("active".to_owned()),
                    identity_revision: Set(1),
                    source_kind: Set("provider".to_owned()),
                    source_schema: Set("owlauth.provider-profile.v1".to_owned()),
                    source_profile_digest: Set(Some(source_profile_digest)),
                    display_name: Set(display_name.clone()),
                    picture_url: Set(picture_url.clone()),
                    locale: Set(locale),
                    observed_at: Set(command.now),
                    created_at: Set(command.now),
                    updated_at: Set(command.now),
                }
                .insert(&transaction)
                .await
                .map_err(persistence)?;
                let mut active = user.into_active_model();
                active.primary_profile_identity_id = Set(Some(command.new_identity_id));
                (
                    active.update(&transaction).await.map_err(persistence)?,
                    false,
                )
            }
        };
        if user_projection_changed {
            fan_out_user_projections(&transaction, &user, command.now).await?;
        }

        let browser_session =
            rotate_or_create_browser_session(&transaction, &command, &login, &user).await?;
        let expires_at = std::cmp::min(command.now + Duration::seconds(60), login.expires_at);
        if expires_at <= command.now {
            return Err(ApplicationError::InvalidTransition);
        }
        let handoff = insert_handoff(
            &transaction,
            command.handoff_id,
            &command.handoff_ticket,
            &login,
            user.id,
            browser_session.id,
            "provider",
            command.now,
            command.now,
            expires_at,
            user.security_revision,
        )
        .await?;

        login_status
            .authenticate()
            .map_err(ApplicationError::from)?;
        login_status
            .issue_handoff()
            .map_err(ApplicationError::from)?;
        let application_state = ProtectedValue {
            ciphertext: login.application_state_ciphertext.clone(),
            key_version: login.application_state_key_version,
        };
        let redirect_uri = login.redirect_uri.clone();
        let next_revision = login.transaction_revision + 1;
        let mut active = login.into_active_model();
        active.status = Set(login_status.as_str().to_owned());
        active.transaction_revision = Set(next_revision);
        active.user_id = Set(Some(user.id));
        active.authenticated_at = Set(Some(command.now));
        active.updated_at = Set(command.now);
        active.update(&transaction).await.map_err(persistence)?;
        append_runtime_audit(
            &transaction,
            command.project_id,
            "system",
            "auth.callback.completed",
            "project_user",
            Some(user.id),
            command.transaction_id,
        )
        .await?;

        transaction.commit().await.map_err(persistence)?;
        Ok(IssuedHandoff {
            project_id: command.project_id,
            application_id: handoff.application_id,
            user_id: user.id,
            user_public_id: user.public_id,
            browser_session_id: browser_session.id,
            handoff_id: handoff.id,
            redirect_uri,
            application_state,
            expires_at,
        })
    }

    async fn confirm_browser_session_reuse(
        &self,
        command: ConfirmBrowserSessionReuse,
    ) -> Result<IssuedHandoff, ApplicationError> {
        validate_digest(&command.browser_binding)?;
        validate_digest(&command.csrf)?;
        validate_digest(&command.browser_credential)?;
        validate_digest(&command.handoff_ticket)?;

        let routed_session = project_browser_session::Entity::find()
            .filter(
                project_browser_session::Column::CredentialDigest
                    .eq(command.browser_credential.value.to_vec()),
            )
            .filter(
                project_browser_session::Column::CredentialDigestKeyVersion
                    .eq(command.browser_credential.key_version),
            )
            .one(&self.database)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;

        let transaction = self.database.begin().await.map_err(persistence)?;
        let login = login_transaction::Entity::find_by_id(command.transaction_id)
            .filter(login_transaction::Column::ProjectId.eq(command.project_id))
            .lock_exclusive()
            .one(&transaction)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        if login.expires_at <= command.now {
            expire_login(&transaction, login, command.now).await?;
            transaction.commit().await.map_err(persistence)?;
            return Err(ApplicationError::InvalidTransition);
        }
        if login.transaction_revision != command.expected_transaction_revision {
            return Err(ApplicationError::RevisionConflict);
        }
        if !optional_digest_matches(
            login.browser_binding_digest.as_deref(),
            login.browser_binding_digest_key_version,
            &command.browser_binding,
        ) || !optional_digest_matches(
            login.csrf_digest.as_deref(),
            login.csrf_digest_key_version,
            &command.csrf,
        ) {
            return Err(ApplicationError::NotFound);
        }
        let mut status = parse_login_status(&login.status)?;
        status
            .confirm_session_reuse()
            .map_err(ApplicationError::from)?;

        let (project, application, policy) =
            lock_login_application_owners(&transaction, &login).await?;
        let user = project_user::Entity::find_by_id(routed_session.user_id)
            .filter(project_user::Column::ProjectId.eq(command.project_id))
            .lock_shared()
            .one(&transaction)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        let session = project_browser_session::Entity::find_by_id(routed_session.id)
            .filter(project_browser_session::Column::ProjectId.eq(command.project_id))
            .lock_exclusive()
            .one(&transaction)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        if !digest_matches(
            &session.credential_digest,
            session.credential_digest_key_version,
            &command.browser_credential,
        ) || session.status != "active"
            || session.idle_expires_at <= command.now
            || session.absolute_expires_at <= command.now
            || user.status != "active"
            || session.project_security_revision != project.security_revision
            || session.user_security_revision != user.security_revision
            || session.policy_session_revision != policy.session_revision
        {
            return Err(ApplicationError::Disabled);
        }
        let reuse_enabled = policy
            .session_policy
            .get("browser_session_reuse")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);
        let reuse_max_age = policy
            .session_policy
            .get("browser_session_reuse_max_age_seconds")
            .and_then(serde_json::Value::as_i64)
            .ok_or(ApplicationError::Integrity)?;
        if !reuse_enabled
            || reuse_max_age < 0
            || command.now < session.authenticated_at
            || command.now - session.authenticated_at > Duration::seconds(reuse_max_age)
        {
            return Err(ApplicationError::Disabled);
        }

        let activity_at = std::cmp::max(session.last_activity_at, command.now);
        let mut session_active = session.clone().into_active_model();
        session_active.session_revision = Set(session.session_revision + 1);
        session_active.last_activity_at = Set(activity_at);
        session_active.idle_expires_at = Set(std::cmp::min(
            activity_at + Duration::hours(8),
            session.absolute_expires_at,
        ));
        session_active.updated_at = Set(command.now);
        session_active
            .update(&transaction)
            .await
            .map_err(persistence)?;

        let expires_at = std::cmp::min(command.now + Duration::seconds(60), login.expires_at);
        if expires_at <= command.now {
            return Err(ApplicationError::InvalidTransition);
        }
        let handoff = insert_handoff(
            &transaction,
            command.handoff_id,
            &command.handoff_ticket,
            &login,
            user.id,
            session.id,
            "session_reuse",
            session.authenticated_at,
            command.now,
            expires_at,
            user.security_revision,
        )
        .await?;
        let application_state = ProtectedValue {
            ciphertext: login.application_state_ciphertext.clone(),
            key_version: login.application_state_key_version,
        };
        let redirect_uri = login.redirect_uri.clone();
        let mut login_active = login.into_active_model();
        login_active.status = Set(status.as_str().to_owned());
        login_active.transaction_revision = Set(command.expected_transaction_revision + 1);
        login_active.user_id = Set(Some(user.id));
        login_active.authenticated_at = Set(Some(session.authenticated_at));
        login_active.updated_at = Set(command.now);
        login_active
            .update(&transaction)
            .await
            .map_err(persistence)?;
        append_runtime_audit(
            &transaction,
            command.project_id,
            "project_user",
            "auth.login.session_reused",
            "project_user",
            Some(user.id),
            command.transaction_id,
        )
        .await?;

        transaction.commit().await.map_err(persistence)?;
        Ok(IssuedHandoff {
            project_id: command.project_id,
            application_id: application.id,
            user_id: user.id,
            user_public_id: user.public_id,
            browser_session_id: session.id,
            handoff_id: handoff.id,
            redirect_uri,
            application_state,
            expires_at,
        })
    }

    async fn prepare_handoff_exchange(
        &self,
        command: PrepareHandoffExchange,
    ) -> Result<HandoffPreparation, ApplicationError> {
        validate_digest(&command.handoff_ticket)?;
        if !is_pkce_s256_challenge(&command.application_pkce_challenge) {
            return Err(ApplicationError::InvalidInput);
        }
        let transaction = self.database.begin().await.map_err(persistence)?;
        let ticket = handoff_ticket::Entity::find()
            .filter(handoff_ticket::Column::ProjectId.eq(command.project_id))
            .filter(handoff_ticket::Column::ApplicationId.eq(command.application_id))
            .filter(handoff_ticket::Column::TicketDigest.eq(command.handoff_ticket.value.to_vec()))
            .filter(
                handoff_ticket::Column::TicketDigestKeyVersion
                    .eq(command.handoff_ticket.key_version),
            )
            .lock_shared()
            .one(&transaction)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        if !digest_matches(
            &ticket.ticket_digest,
            ticket.ticket_digest_key_version,
            &command.handoff_ticket,
        ) || !bool::from(
            ticket
                .application_pkce_challenge
                .as_bytes()
                .ct_eq(command.application_pkce_challenge.as_bytes()),
        ) {
            return Err(ApplicationError::NotFound);
        }
        if ticket.status != "issued" || ticket.expires_at <= command.now {
            return Err(ApplicationError::InvalidTransition);
        }
        let login = login_transaction::Entity::find_by_id(ticket.login_transaction_id)
            .filter(login_transaction::Column::ProjectId.eq(command.project_id))
            .lock_shared()
            .one(&transaction)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::Integrity)?;
        let project = project::Entity::find_by_id(command.project_id)
            .lock_shared()
            .one(&transaction)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        let application = application::Entity::find_by_id(command.application_id)
            .filter(application::Column::ProjectId.eq(command.project_id))
            .lock_shared()
            .one(&transaction)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        let user = project_user::Entity::find_by_id(ticket.user_id)
            .filter(project_user::Column::ProjectId.eq(command.project_id))
            .lock_shared()
            .one(&transaction)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        let policy = project_policy::Entity::find_by_id(command.project_id)
            .lock_shared()
            .one(&transaction)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::Integrity)?;
        let browser = project_browser_session::Entity::find_by_id(ticket.browser_session_id)
            .filter(project_browser_session::Column::ProjectId.eq(command.project_id))
            .filter(project_browser_session::Column::UserId.eq(ticket.user_id))
            .lock_shared()
            .one(&transaction)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::Integrity)?;
        if login.status != LoginTransactionStatus::HandoffIssued.as_str()
            || login.user_id != Some(ticket.user_id)
            || login.application_id != ticket.application_id
            || project.status != "active"
            || application.status != "active"
            || user.status != "active"
            || browser.status != "active"
            || browser.idle_expires_at <= command.now
            || browser.absolute_expires_at <= command.now
            || project.security_revision != ticket.project_security_revision
            || application.security_revision != ticket.application_security_revision
            || user.security_revision != ticket.user_security_revision
            || policy.claims_revision != ticket.claims_revision
            || policy.session_revision != ticket.policy_session_revision
            || browser.project_security_revision != project.security_revision
            || browser.user_security_revision != user.security_revision
            || browser.policy_session_revision != policy.session_revision
        {
            return Err(ApplicationError::RevisionConflict);
        }
        if ticket.authentication_method == "provider" {
            let provider_id = ticket
                .provider_configuration_id
                .ok_or(ApplicationError::Integrity)?;
            let provider = provider_configuration::Entity::find_by_id(provider_id)
                .filter(provider_configuration::Column::ProjectId.eq(command.project_id))
                .lock_shared()
                .one(&transaction)
                .await
                .map_err(persistence)?
                .ok_or(ApplicationError::NotFound)?;
            let assignment = application_provider_assignment::Entity::find_by_id((
                command.project_id,
                command.application_id,
                provider_id,
            ))
            .lock_shared()
            .one(&transaction)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
            if provider.status != "active"
                || Some(provider.revision) != ticket.provider_revision
                || assignment.status != "active"
                || Some(assignment.security_revision) != ticket.assignment_security_revision
            {
                return Err(ApplicationError::RevisionConflict);
            }
        }
        let binding = application_user_binding::Entity::find()
            .filter(application_user_binding::Column::ProjectId.eq(command.project_id))
            .filter(application_user_binding::Column::ApplicationId.eq(command.application_id))
            .filter(application_user_binding::Column::UserId.eq(user.id))
            .lock_shared()
            .one(&transaction)
            .await
            .map_err(persistence)?;
        if binding
            .as_ref()
            .is_some_and(|value| value.status != "active")
        {
            return Err(ApplicationError::Disabled);
        }
        let projection = if let Some(binding) = &binding {
            application_user_projection::Entity::find()
                .filter(application_user_projection::Column::ProjectId.eq(command.project_id))
                .filter(application_user_projection::Column::BindingId.eq(binding.id))
                .lock_shared()
                .one(&transaction)
                .await
                .map_err(persistence)?
        } else {
            None
        };
        if binding.is_some() && projection.is_none() {
            return Err(ApplicationError::Integrity);
        }
        let (projection_revision, projection_document, _) = authoritative_projection_material(
            projection.as_ref(),
            &user,
            policy.projection_revision,
            application.projection_revision,
        )?;
        let signing =
            active_signing_snapshot(&transaction, command.project_id, command.now).await?;
        let preparation = HandoffPreparation {
            ticket_id: ticket.id,
            project_public_id: project.public_id,
            project_issuer: signing.issuer,
            application_public_id: application.public_id,
            user_id: user.id,
            user_public_id: user.public_id,
            user_revision: user.user_revision,
            user_security_revision: user.security_revision,
            project_security_revision: project.security_revision,
            application_security_revision: application.security_revision,
            claims_revision: policy.claims_revision,
            session_revision: policy.session_revision,
            project_projection_revision: policy.projection_revision,
            application_projection_revision: application.projection_revision,
            projection_revision,
            projection_document,
            signing_ring_id: signing.ring_id,
            signing_key_id: signing.key_id,
            signing_kid: signing.kid,
            signer_ref: signing.signer_ref,
            signing_epoch: signing.epoch,
            access_token_lifetime_seconds: access_token_lifetime(&policy)?,
            authenticated_at: ticket.authenticated_at,
        };
        transaction.commit().await.map_err(persistence)?;
        Ok(preparation)
    }

    async fn commit_handoff_exchange(
        &self,
        command: CommitHandoffExchange,
    ) -> Result<HandoffSessionRecord, ApplicationError> {
        validate_digest(&command.handoff_ticket)?;
        validate_digest(&command.refresh_token)?;
        if !is_pkce_s256_challenge(&command.application_pkce_challenge)
            || command.preparation.user_revision <= 0
            || command.preparation.signing_epoch <= 0
            || !(0..=300).contains(&command.allowed_clock_skew_seconds)
        {
            return Err(ApplicationError::InvalidInput);
        }

        let transaction = self.database.begin().await.map_err(persistence)?;
        let ticket = handoff_ticket::Entity::find()
            .filter(handoff_ticket::Column::ProjectId.eq(command.project_id))
            .filter(handoff_ticket::Column::ApplicationId.eq(command.application_id))
            .filter(handoff_ticket::Column::TicketDigest.eq(command.handoff_ticket.value.to_vec()))
            .filter(
                handoff_ticket::Column::TicketDigestKeyVersion
                    .eq(command.handoff_ticket.key_version),
            )
            .lock_exclusive()
            .one(&transaction)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        if !digest_matches(
            &ticket.ticket_digest,
            ticket.ticket_digest_key_version,
            &command.handoff_ticket,
        ) {
            return Err(ApplicationError::NotFound);
        }
        if ticket.id != command.preparation.ticket_id
            || ticket.status != "issued"
            || ticket.expires_at <= command.now
        {
            if ticket.status == "issued" && ticket.expires_at <= command.now {
                let ticket_id = ticket.id;
                let mut active = ticket.into_active_model();
                active.status = Set("expired".to_owned());
                active.update(&transaction).await.map_err(persistence)?;
                append_runtime_audit(
                    &transaction,
                    command.project_id,
                    "system",
                    "auth.handoff.expired",
                    "handoff_ticket",
                    Some(ticket_id),
                    ticket_id,
                )
                .await?;
                transaction.commit().await.map_err(persistence)?;
            }
            return Err(ApplicationError::InvalidTransition);
        }
        if !bool::from(
            ticket
                .application_pkce_challenge
                .as_bytes()
                .ct_eq(command.application_pkce_challenge.as_bytes()),
        ) {
            return Err(ApplicationError::NotFound);
        }

        let login = login_transaction::Entity::find_by_id(ticket.login_transaction_id)
            .filter(login_transaction::Column::ProjectId.eq(command.project_id))
            .lock_exclusive()
            .one(&transaction)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::Integrity)?;
        if login.status != LoginTransactionStatus::HandoffIssued.as_str()
            || login.user_id != Some(ticket.user_id)
            || login.application_id != ticket.application_id
            || login.redirect_uri != ticket.redirect_uri
            || login.application_pkce_challenge != ticket.application_pkce_challenge
            || ticket.expires_at
                != std::cmp::min(ticket.issued_at + Duration::seconds(60), login.expires_at)
        {
            return Err(ApplicationError::Integrity);
        }

        let project = project::Entity::find_by_id(command.project_id)
            .lock_shared()
            .one(&transaction)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        let application = application::Entity::find_by_id(command.application_id)
            .filter(application::Column::ProjectId.eq(command.project_id))
            .lock_shared()
            .one(&transaction)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        let user = project_user::Entity::find_by_id(ticket.user_id)
            .filter(project_user::Column::ProjectId.eq(command.project_id))
            .lock_exclusive()
            .one(&transaction)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        let policy = project_policy::Entity::find_by_id(command.project_id)
            .lock_shared()
            .one(&transaction)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::Integrity)?;
        let browser_session =
            project_browser_session::Entity::find_by_id(ticket.browser_session_id)
                .filter(project_browser_session::Column::ProjectId.eq(command.project_id))
                .filter(project_browser_session::Column::UserId.eq(ticket.user_id))
                .lock_shared()
                .one(&transaction)
                .await
                .map_err(persistence)?
                .ok_or(ApplicationError::Integrity)?;
        if project.status != "active"
            || application.status != "active"
            || user.status != "active"
            || browser_session.status != "active"
            || browser_session.idle_expires_at <= command.now
            || browser_session.absolute_expires_at <= command.now
            || project.security_revision != ticket.project_security_revision
            || application.security_revision != ticket.application_security_revision
            || user.id != command.preparation.user_id
            || user.public_id != command.preparation.user_public_id
            || project.security_revision != command.preparation.project_security_revision
            || application.security_revision != command.preparation.application_security_revision
            || user.security_revision != ticket.user_security_revision
            || user.security_revision != command.preparation.user_security_revision
            || user.user_revision != command.preparation.user_revision
            || policy.claims_revision != ticket.claims_revision
            || policy.claims_revision != command.preparation.claims_revision
            || policy.session_revision != ticket.policy_session_revision
            || policy.session_revision != command.preparation.session_revision
            || policy.projection_revision != command.preparation.project_projection_revision
            || application.projection_revision
                != command.preparation.application_projection_revision
            || ticket.authenticated_at != command.preparation.authenticated_at
            || access_token_lifetime(&policy)? != command.preparation.access_token_lifetime_seconds
            || browser_session.project_security_revision != project.security_revision
            || browser_session.user_security_revision != user.security_revision
            || browser_session.policy_session_revision != policy.session_revision
        {
            return Err(ApplicationError::RevisionConflict);
        }
        if ticket.authentication_method == "provider" {
            let provider_id = ticket
                .provider_configuration_id
                .ok_or(ApplicationError::Integrity)?;
            let provider = provider_configuration::Entity::find_by_id(provider_id)
                .filter(provider_configuration::Column::ProjectId.eq(command.project_id))
                .lock_shared()
                .one(&transaction)
                .await
                .map_err(persistence)?
                .ok_or(ApplicationError::NotFound)?;
            let assignment = application_provider_assignment::Entity::find_by_id((
                command.project_id,
                command.application_id,
                provider_id,
            ))
            .lock_shared()
            .one(&transaction)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
            if provider.status != "active"
                || Some(provider.revision) != ticket.provider_revision
                || assignment.status != "active"
                || Some(assignment.security_revision) != ticket.assignment_security_revision
            {
                return Err(ApplicationError::RevisionConflict);
            }
        }
        lock_signing_epoch(
            &transaction,
            command.project_id,
            command.preparation.signing_ring_id,
            command.preparation.signing_key_id,
            command.preparation.signing_epoch,
            command.now,
        )
        .await?;

        let binding = match application_user_binding::Entity::find()
            .filter(application_user_binding::Column::ProjectId.eq(command.project_id))
            .filter(application_user_binding::Column::ApplicationId.eq(command.application_id))
            .filter(application_user_binding::Column::UserId.eq(user.id))
            .lock_exclusive()
            .one(&transaction)
            .await
            .map_err(persistence)?
        {
            Some(binding) if binding.status == "active" => binding,
            Some(_) => return Err(ApplicationError::Disabled),
            None => {
                let existing_bindings = application_user_binding::Entity::find()
                    .filter(application_user_binding::Column::ProjectId.eq(command.project_id))
                    .filter(application_user_binding::Column::UserId.eq(user.id))
                    .limit(MAX_APPLICATION_BINDINGS_PER_USER as u64)
                    .all(&transaction)
                    .await
                    .map_err(persistence)?;
                if existing_bindings.len() >= MAX_APPLICATION_BINDINGS_PER_USER {
                    return Err(ApplicationError::InvalidTransition);
                }
                application_user_binding::ActiveModel {
                    id: Set(command.binding_id),
                    project_id: Set(command.project_id),
                    application_id: Set(command.application_id),
                    user_id: Set(user.id),
                    status: Set("active".to_owned()),
                    binding_revision: Set(1),
                    created_at: Set(command.now),
                    updated_at: Set(command.now),
                }
                .insert(&transaction)
                .await
                .map_err(persistence)?
            }
        };
        let existing_projection = application_user_projection::Entity::find()
            .filter(application_user_projection::Column::ProjectId.eq(command.project_id))
            .filter(application_user_projection::Column::BindingId.eq(binding.id))
            .lock_exclusive()
            .one(&transaction)
            .await
            .map_err(persistence)?;
        let (projection_revision, projection_document, projection_digest) =
            authoritative_projection_material(
                existing_projection.as_ref(),
                &user,
                policy.projection_revision,
                application.projection_revision,
            )?;
        if projection_revision != command.preparation.projection_revision
            || projection_document != command.preparation.projection_document
        {
            return Err(ApplicationError::RevisionConflict);
        }
        let projection = match existing_projection {
            Some(projection) => {
                super::projection::repair_projection(
                    &transaction,
                    projection,
                    &user,
                    policy.projection_revision,
                    application.projection_revision,
                    command.now,
                )
                .await?
                .0
            }
            None => application_user_projection::ActiveModel {
                id: Set(command.projection_id),
                project_id: Set(command.project_id),
                binding_id: Set(binding.id),
                application_id: Set(command.application_id),
                user_id: Set(user.id),
                schema_name: Set(USER_PROJECTION_SCHEMA_V1.to_owned()),
                projection_revision: Set(projection_revision),
                source_user_revision: Set(user.user_revision),
                project_policy_revision: Set(policy.projection_revision),
                application_policy_revision: Set(application.projection_revision),
                canonical_digest: Set(projection_digest),
                source_base_profile_digest: Set(Some(user.base_profile_digest.clone())),
                document: Set(projection_document),
                created_at: Set(command.now),
                updated_at: Set(command.now),
            }
            .insert(&transaction)
            .await
            .map_err(persistence)?,
        };

        let absolute_expires_at = command.now + Duration::days(30);
        let refresh_retain_until =
            absolute_expires_at + Duration::seconds(command.allowed_clock_skew_seconds);
        let allowed_clock_skew_seconds = i32::try_from(command.allowed_clock_skew_seconds)
            .map_err(|_| ApplicationError::InvalidInput)?;
        application_session::ActiveModel {
            id: Set(command.application_session_id),
            project_id: Set(command.project_id),
            application_id: Set(command.application_id),
            user_id: Set(user.id),
            binding_id: Set(binding.id),
            browser_session_id: Set(Some(browser_session.id)),
            status: Set("active".to_owned()),
            session_revision: Set(1),
            project_security_revision: Set(project.security_revision),
            application_security_revision: Set(application.security_revision),
            user_security_revision: Set(user.security_revision),
            claims_revision: Set(policy.claims_revision),
            policy_session_revision: Set(policy.session_revision),
            authenticated_at: Set(ticket.authenticated_at),
            absolute_expires_at: Set(absolute_expires_at),
            revoked_at: Set(None),
            created_at: Set(command.now),
            updated_at: Set(command.now),
        }
        .insert(&transaction)
        .await
        .map_err(persistence)?;
        refresh_family::ActiveModel {
            id: Set(command.refresh_family_id),
            project_id: Set(command.project_id),
            application_id: Set(command.application_id),
            user_id: Set(user.id),
            application_session_id: Set(command.application_session_id),
            status: Set("active".to_owned()),
            family_revision: Set(1),
            current_generation: Set(1),
            allowed_clock_skew_seconds: Set(allowed_clock_skew_seconds),
            absolute_expires_at: Set(absolute_expires_at),
            revoked_at: Set(None),
            revocation_reason: Set(None),
            created_at: Set(command.now),
            updated_at: Set(command.now),
        }
        .insert(&transaction)
        .await
        .map_err(persistence)?;
        refresh_token_generation::ActiveModel {
            id: Set(command.refresh_generation_id),
            project_id: Set(command.project_id),
            family_id: Set(command.refresh_family_id),
            application_id: Set(command.application_id),
            user_id: Set(user.id),
            generation: Set(1),
            token_digest: Set(command.refresh_token.value.to_vec()),
            token_digest_key_version: Set(command.refresh_token.key_version),
            status: Set("current".to_owned()),
            consumed_at: Set(None),
            replay_detected_at: Set(None),
            retain_until: Set(refresh_retain_until),
            created_at: Set(command.now),
        }
        .insert(&transaction)
        .await
        .map_err(persistence)?;

        let mut ticket_active = ticket.into_active_model();
        ticket_active.status = Set("consumed".to_owned());
        ticket_active.consumed_at = Set(Some(command.now));
        ticket_active
            .update(&transaction)
            .await
            .map_err(persistence)?;
        let mut login_status = parse_login_status(&login.status)?;
        login_status.complete().map_err(ApplicationError::from)?;
        let mut login_active = login.into_active_model();
        login_active.status = Set(login_status.as_str().to_owned());
        login_active.transaction_revision =
            Set(login_active.transaction_revision.take().unwrap_or(1) + 1);
        login_active.terminal_at = Set(Some(command.now));
        login_active.updated_at = Set(command.now);
        login_active
            .update(&transaction)
            .await
            .map_err(persistence)?;
        append_runtime_audit(
            &transaction,
            command.project_id,
            "project_user",
            "auth.handoff.exchanged",
            "application_session",
            Some(command.application_session_id),
            command.application_session_id,
        )
        .await?;

        transaction.commit().await.map_err(persistence)?;
        Ok(HandoffSessionRecord {
            project_id: command.project_id,
            application_id: command.application_id,
            user_id: user.id,
            user_public_id: user.public_id,
            binding_id: binding.id,
            projection_revision: projection.projection_revision,
            application_session_id: command.application_session_id,
            refresh_family_id: command.refresh_family_id,
            refresh_generation: 1,
            absolute_expires_at,
        })
    }

    async fn prepare_refresh_rotation(
        &self,
        command: PrepareRefreshRotation,
    ) -> Result<RefreshPreparationResult, ApplicationError> {
        validate_digest(&command.presented_token)?;
        let routed_generation = refresh_token_generation::Entity::find()
            .filter(refresh_token_generation::Column::ProjectId.eq(command.project_id))
            .filter(refresh_token_generation::Column::ApplicationId.eq(command.application_id))
            .filter(
                refresh_token_generation::Column::TokenDigest
                    .eq(command.presented_token.value.to_vec()),
            )
            .filter(
                refresh_token_generation::Column::TokenDigestKeyVersion
                    .eq(command.presented_token.key_version),
            )
            .one(&self.database)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        let routed_family = refresh_family::Entity::find_by_id(routed_generation.family_id)
            .filter(refresh_family::Column::ProjectId.eq(command.project_id))
            .one(&self.database)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        let transaction = self.database.begin().await.map_err(persistence)?;
        let session = application_session::Entity::find_by_id(routed_family.application_session_id)
            .filter(application_session::Column::ProjectId.eq(command.project_id))
            .filter(application_session::Column::ApplicationId.eq(command.application_id))
            .lock_exclusive()
            .one(&transaction)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        let family = refresh_family::Entity::find_by_id(routed_family.id)
            .filter(refresh_family::Column::ProjectId.eq(command.project_id))
            .filter(refresh_family::Column::ApplicationId.eq(command.application_id))
            .lock_exclusive()
            .one(&transaction)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        let generation = refresh_token_generation::Entity::find_by_id(routed_generation.id)
            .filter(refresh_token_generation::Column::ProjectId.eq(command.project_id))
            .filter(refresh_token_generation::Column::FamilyId.eq(family.id))
            .lock_exclusive()
            .one(&transaction)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        if !digest_matches(
            &generation.token_digest,
            generation.token_digest_key_version,
            &command.presented_token,
        ) {
            return Err(ApplicationError::NotFound);
        }
        if generation.status == "consumed" {
            record_refresh_replay(
                &transaction,
                &generation,
                &family,
                command.project_id,
                command.now,
            )
            .await?;
            transaction.commit().await.map_err(persistence)?;
            return Ok(RefreshPreparationResult::ReplayRevoked {
                family_id: family.id,
            });
        }
        if generation.status != "current"
            || family.status != "active"
            || session.status != "active"
            || generation.generation != family.current_generation
            || family.absolute_expires_at <= command.now
            || session.absolute_expires_at <= command.now
            || family.absolute_expires_at != session.absolute_expires_at
        {
            return Err(ApplicationError::InvalidTransition);
        }
        let project = project::Entity::find_by_id(command.project_id)
            .lock_shared()
            .one(&transaction)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        let application = application::Entity::find_by_id(command.application_id)
            .filter(application::Column::ProjectId.eq(command.project_id))
            .lock_shared()
            .one(&transaction)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        let user = project_user::Entity::find_by_id(session.user_id)
            .filter(project_user::Column::ProjectId.eq(command.project_id))
            .lock_shared()
            .one(&transaction)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        let policy = project_policy::Entity::find_by_id(command.project_id)
            .lock_shared()
            .one(&transaction)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::Integrity)?;
        if project.status != "active"
            || application.status != "active"
            || user.status != "active"
            || project.security_revision != session.project_security_revision
            || application.security_revision != session.application_security_revision
            || user.security_revision != session.user_security_revision
            || policy.claims_revision != session.claims_revision
            || policy.session_revision != session.policy_session_revision
        {
            return Err(ApplicationError::RevisionConflict);
        }
        if let Some(browser_session_id) = session.browser_session_id {
            let browser = project_browser_session::Entity::find_by_id(browser_session_id)
                .filter(project_browser_session::Column::ProjectId.eq(command.project_id))
                .filter(project_browser_session::Column::UserId.eq(user.id))
                .lock_shared()
                .one(&transaction)
                .await
                .map_err(persistence)?
                .ok_or(ApplicationError::Integrity)?;
            if browser.status != "active"
                || browser.idle_expires_at <= command.now
                || browser.absolute_expires_at <= command.now
                || browser.project_security_revision != project.security_revision
                || browser.user_security_revision != user.security_revision
                || browser.policy_session_revision != policy.session_revision
            {
                return Err(ApplicationError::Disabled);
            }
        }
        let binding = application_user_binding::Entity::find_by_id(session.binding_id)
            .filter(application_user_binding::Column::ProjectId.eq(command.project_id))
            .filter(application_user_binding::Column::ApplicationId.eq(command.application_id))
            .filter(application_user_binding::Column::UserId.eq(user.id))
            .lock_shared()
            .one(&transaction)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::Integrity)?;
        if binding.status != "active" {
            return Err(ApplicationError::Disabled);
        }
        let projection = application_user_projection::Entity::find()
            .filter(application_user_projection::Column::ProjectId.eq(command.project_id))
            .filter(application_user_projection::Column::BindingId.eq(binding.id))
            .lock_exclusive()
            .one(&transaction)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::Integrity)?;
        let (_, projection_material) = super::projection::repair_projection(
            &transaction,
            projection,
            &user,
            policy.projection_revision,
            application.projection_revision,
            command.now,
        )
        .await?;
        let projection_revision = projection_material.revision;
        let projection_document = projection_material.document;
        let signing =
            active_signing_snapshot(&transaction, command.project_id, command.now).await?;
        let preparation = RefreshPreparation {
            generation_id: generation.id,
            family_id: family.id,
            project_public_id: project.public_id,
            project_issuer: signing.issuer,
            application_public_id: application.public_id,
            family_revision: family.family_revision,
            generation: generation.generation,
            application_session_id: session.id,
            session_revision: session.session_revision,
            binding_id: binding.id,
            binding_revision: binding.binding_revision,
            user_id: user.id,
            user_public_id: user.public_id,
            user_revision: user.user_revision,
            claims_revision: policy.claims_revision,
            project_projection_revision: policy.projection_revision,
            application_projection_revision: application.projection_revision,
            projection_revision,
            projection_document,
            signing_ring_id: signing.ring_id,
            signing_key_id: signing.key_id,
            signing_kid: signing.kid,
            signer_ref: signing.signer_ref,
            signing_epoch: signing.epoch,
            access_token_lifetime_seconds: access_token_lifetime(&policy)?,
            authenticated_at: session.authenticated_at,
            absolute_expires_at: family.absolute_expires_at,
        };
        transaction.commit().await.map_err(persistence)?;
        Ok(RefreshPreparationResult::Ready(Box::new(preparation)))
    }

    async fn rotate_refresh_token(
        &self,
        command: RotateRefreshToken,
    ) -> Result<RefreshRotationResult, ApplicationError> {
        validate_digest(&command.presented_token)?;
        validate_digest(&command.successor_token)?;
        if command.preparation.signing_epoch <= 0 {
            return Err(ApplicationError::InvalidInput);
        }
        let routed_generation = refresh_token_generation::Entity::find()
            .filter(refresh_token_generation::Column::ProjectId.eq(command.project_id))
            .filter(refresh_token_generation::Column::ApplicationId.eq(command.application_id))
            .filter(
                refresh_token_generation::Column::TokenDigest
                    .eq(command.presented_token.value.to_vec()),
            )
            .filter(
                refresh_token_generation::Column::TokenDigestKeyVersion
                    .eq(command.presented_token.key_version),
            )
            .one(&self.database)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        let routed_family = refresh_family::Entity::find_by_id(routed_generation.family_id)
            .filter(refresh_family::Column::ProjectId.eq(command.project_id))
            .one(&self.database)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;

        let transaction = self.database.begin().await.map_err(persistence)?;
        let session = application_session::Entity::find_by_id(routed_family.application_session_id)
            .filter(application_session::Column::ProjectId.eq(command.project_id))
            .filter(application_session::Column::ApplicationId.eq(command.application_id))
            .lock_exclusive()
            .one(&transaction)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        let family = refresh_family::Entity::find_by_id(routed_family.id)
            .filter(refresh_family::Column::ProjectId.eq(command.project_id))
            .filter(refresh_family::Column::ApplicationId.eq(command.application_id))
            .lock_exclusive()
            .one(&transaction)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        let generation = refresh_token_generation::Entity::find_by_id(routed_generation.id)
            .filter(refresh_token_generation::Column::ProjectId.eq(command.project_id))
            .filter(refresh_token_generation::Column::FamilyId.eq(family.id))
            .lock_exclusive()
            .one(&transaction)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        if !digest_matches(
            &generation.token_digest,
            generation.token_digest_key_version,
            &command.presented_token,
        ) {
            return Err(ApplicationError::NotFound);
        }
        if generation.status == "consumed" {
            record_refresh_replay(
                &transaction,
                &generation,
                &family,
                command.project_id,
                command.now,
            )
            .await?;
            transaction.commit().await.map_err(persistence)?;
            return Ok(RefreshRotationResult::ReplayRevoked {
                family_id: family.id,
            });
        }
        if generation.status != "current"
            || family.status != "active"
            || session.status != "active"
            || generation.generation != family.current_generation
            || family.absolute_expires_at <= command.now
            || session.absolute_expires_at <= command.now
            || family.absolute_expires_at != session.absolute_expires_at
            || generation.id != command.preparation.generation_id
            || family.id != command.preparation.family_id
            || family.family_revision != command.preparation.family_revision
            || generation.generation != command.preparation.generation
            || session.id != command.preparation.application_session_id
            || session.session_revision != command.preparation.session_revision
            || family.absolute_expires_at != command.preparation.absolute_expires_at
        {
            return Err(ApplicationError::InvalidTransition);
        }

        let project = project::Entity::find_by_id(command.project_id)
            .lock_shared()
            .one(&transaction)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        let application = application::Entity::find_by_id(command.application_id)
            .filter(application::Column::ProjectId.eq(command.project_id))
            .lock_shared()
            .one(&transaction)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        let user = project_user::Entity::find_by_id(session.user_id)
            .filter(project_user::Column::ProjectId.eq(command.project_id))
            .lock_shared()
            .one(&transaction)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        let policy = project_policy::Entity::find_by_id(command.project_id)
            .lock_shared()
            .one(&transaction)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::Integrity)?;
        if project.status != "active"
            || application.status != "active"
            || user.status != "active"
            || project.security_revision != session.project_security_revision
            || application.security_revision != session.application_security_revision
            || user.security_revision != session.user_security_revision
            || policy.claims_revision != session.claims_revision
            || policy.session_revision != session.policy_session_revision
            || user.id != command.preparation.user_id
            || user.public_id != command.preparation.user_public_id
            || user.user_revision != command.preparation.user_revision
            || policy.claims_revision != command.preparation.claims_revision
            || policy.projection_revision != command.preparation.project_projection_revision
            || application.projection_revision
                != command.preparation.application_projection_revision
            || access_token_lifetime(&policy)? != command.preparation.access_token_lifetime_seconds
        {
            return Err(ApplicationError::RevisionConflict);
        }
        let binding = application_user_binding::Entity::find_by_id(session.binding_id)
            .filter(application_user_binding::Column::ProjectId.eq(command.project_id))
            .filter(application_user_binding::Column::ApplicationId.eq(command.application_id))
            .filter(application_user_binding::Column::UserId.eq(user.id))
            .lock_shared()
            .one(&transaction)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::Integrity)?;
        if binding.id != command.preparation.binding_id
            || binding.binding_revision != command.preparation.binding_revision
            || binding.status != "active"
        {
            return Err(ApplicationError::RevisionConflict);
        }
        let projection = application_user_projection::Entity::find()
            .filter(application_user_projection::Column::ProjectId.eq(command.project_id))
            .filter(application_user_projection::Column::BindingId.eq(binding.id))
            .lock_shared()
            .one(&transaction)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::Integrity)?;
        let (projection_document, projection_digest) = super::projection::projection_material(
            &user,
            command.preparation.projection_revision,
            policy.projection_revision,
            application.projection_revision,
        )?;
        if projection.projection_revision != command.preparation.projection_revision
            || projection.source_user_revision != user.user_revision
            || projection.project_policy_revision != policy.projection_revision
            || projection.application_policy_revision != application.projection_revision
            || projection
                .source_base_profile_digest
                .as_deref()
                .is_none_or(|digest| !bool::from(digest.ct_eq(user.base_profile_digest.as_slice())))
            || projection.document != projection_document
            || projection_document != command.preparation.projection_document
            || !bool::from(
                projection
                    .canonical_digest
                    .as_slice()
                    .ct_eq(projection_digest.as_slice()),
            )
        {
            return Err(ApplicationError::RevisionConflict);
        }
        if let Some(browser_session_id) = session.browser_session_id {
            let browser = project_browser_session::Entity::find_by_id(browser_session_id)
                .filter(project_browser_session::Column::ProjectId.eq(command.project_id))
                .filter(project_browser_session::Column::UserId.eq(user.id))
                .lock_shared()
                .one(&transaction)
                .await
                .map_err(persistence)?
                .ok_or(ApplicationError::Integrity)?;
            if browser.status != "active"
                || browser.idle_expires_at <= command.now
                || browser.absolute_expires_at <= command.now
                || browser.project_security_revision != project.security_revision
                || browser.user_security_revision != user.security_revision
                || browser.policy_session_revision != policy.session_revision
            {
                return Err(ApplicationError::Disabled);
            }
        }
        lock_signing_epoch(
            &transaction,
            command.project_id,
            command.preparation.signing_ring_id,
            command.preparation.signing_key_id,
            command.preparation.signing_epoch,
            command.now,
        )
        .await?;

        let successor_generation = generation.generation + 1;
        let mut generation_active = generation.into_active_model();
        generation_active.status = Set("consumed".to_owned());
        generation_active.consumed_at = Set(Some(command.now));
        generation_active
            .update(&transaction)
            .await
            .map_err(persistence)?;
        refresh_token_generation::ActiveModel {
            id: Set(command.successor_generation_id),
            project_id: Set(command.project_id),
            family_id: Set(family.id),
            application_id: Set(command.application_id),
            user_id: Set(user.id),
            generation: Set(successor_generation),
            token_digest: Set(command.successor_token.value.to_vec()),
            token_digest_key_version: Set(command.successor_token.key_version),
            status: Set("current".to_owned()),
            consumed_at: Set(None),
            replay_detected_at: Set(None),
            retain_until: Set(family.absolute_expires_at
                + Duration::seconds(i64::from(family.allowed_clock_skew_seconds))),
            created_at: Set(command.now),
        }
        .insert(&transaction)
        .await
        .map_err(persistence)?;
        let mut family_active = family.clone().into_active_model();
        family_active.current_generation = Set(successor_generation);
        family_active.family_revision = Set(family.family_revision + 1);
        family_active.updated_at = Set(command.now);
        family_active
            .update(&transaction)
            .await
            .map_err(persistence)?;
        append_runtime_audit(
            &transaction,
            command.project_id,
            "project_user",
            "auth.refresh.rotated",
            "refresh_family",
            Some(family.id),
            family.id,
        )
        .await?;

        transaction.commit().await.map_err(persistence)?;
        Ok(RefreshRotationResult::Rotated {
            user_id: user.id,
            application_session_id: session.id,
            family_id: family.id,
            generation: successor_generation,
            absolute_expires_at: family.absolute_expires_at,
        })
    }

    async fn recover_abandoned_provider_exchanges(
        &self,
        command: RecoverProviderExchanges,
    ) -> Result<u64, ApplicationError> {
        if command.limit == 0 || command.limit > 1_000 || command.abandoned_before > command.now {
            return Err(ApplicationError::InvalidInput);
        }
        let transaction = self.database.begin().await.map_err(persistence)?;
        let abandoned = login_transaction::Entity::find()
            .filter(
                login_transaction::Column::Status
                    .eq(LoginTransactionStatus::ProviderExchangeInProgress.as_str()),
            )
            .filter(login_transaction::Column::UpdatedAt.lt(command.abandoned_before))
            .order_by_asc(login_transaction::Column::UpdatedAt)
            .order_by_asc(login_transaction::Column::Id)
            .limit(command.limit)
            .lock_with_behavior(LockType::Update, LockBehavior::SkipLocked)
            .all(&transaction)
            .await
            .map_err(persistence)?;
        for login in &abandoned {
            let mut active = login.clone().into_active_model();
            active.status = Set(LoginTransactionStatus::ProviderExchangeFailed
                .as_str()
                .to_owned());
            active.transaction_revision = Set(login.transaction_revision + 1);
            active.terminal_at = Set(Some(command.now));
            active.updated_at = Set(command.now);
            active.update(&transaction).await.map_err(persistence)?;
            append_runtime_audit(
                &transaction,
                login.project_id,
                "system",
                "auth.provider_exchange.recovered",
                "login_transaction",
                Some(login.id),
                login.id,
            )
            .await?;
        }
        let recovered = abandoned.len() as u64;
        transaction.commit().await.map_err(persistence)?;
        Ok(recovered)
    }

    async fn logout_application_session(
        &self,
        command: LogoutApplicationSession,
    ) -> Result<(), ApplicationError> {
        let transaction = self.database.begin().await.map_err(persistence)?;
        let session = application_session::Entity::find_by_id(command.application_session_id)
            .filter(application_session::Column::ProjectId.eq(command.project_id))
            .filter(application_session::Column::ApplicationId.eq(command.application_id))
            .filter(application_session::Column::UserId.eq(command.user_id))
            .lock_exclusive()
            .one(&transaction)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        let family = refresh_family::Entity::find()
            .filter(refresh_family::Column::ProjectId.eq(command.project_id))
            .filter(refresh_family::Column::ApplicationSessionId.eq(command.application_session_id))
            .lock_exclusive()
            .one(&transaction)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::Integrity)?;
        let session_changed = session.status == "active";
        let family_changed = family.status == "active";
        if session_changed {
            let mut active = session.into_active_model();
            active.status = Set("revoked".to_owned());
            active.session_revision = Set(active.session_revision.take().unwrap_or(1) + 1);
            active.revoked_at = Set(Some(command.now));
            active.updated_at = Set(command.now);
            active.update(&transaction).await.map_err(persistence)?;
        }
        if family_changed {
            let mut active = family.into_active_model();
            active.status = Set("revoked".to_owned());
            active.family_revision = Set(active.family_revision.take().unwrap_or(1) + 1);
            active.revoked_at = Set(Some(command.now));
            active.revocation_reason = Set(Some("logout".to_owned()));
            active.updated_at = Set(command.now);
            active.update(&transaction).await.map_err(persistence)?;
        }
        if session_changed || family_changed {
            append_runtime_audit(
                &transaction,
                command.project_id,
                "project_user",
                "auth.application_session.logged_out",
                "application_session",
                Some(command.application_session_id),
                command.application_session_id,
            )
            .await?;
        }
        transaction.commit().await.map_err(persistence)?;
        Ok(())
    }

    async fn prepare_browser_logout(
        &self,
        command: PrepareBrowserLogout,
    ) -> Result<BrowserLogoutRecord, ApplicationError> {
        validate_digest(&command.preparation)?;
        let transaction = self.database.begin().await.map_err(persistence)?;
        let owners = lock_logout_owners(
            &transaction,
            command.project_id,
            command.application_id,
            command.user_id,
            command.application_session_id,
            None,
            command.now,
        )
        .await?;
        let session = owners.session;
        let browser = project_browser_session::Entity::find_by_id(command.browser_session_id)
            .filter(project_browser_session::Column::ProjectId.eq(command.project_id))
            .filter(project_browser_session::Column::UserId.eq(command.user_id))
            .lock_shared()
            .one(&transaction)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        if session.browser_session_id != Some(browser.id)
            || browser.status != "active"
            || browser.idle_expires_at <= command.now
            || browser.absolute_expires_at <= command.now
            || browser.project_security_revision != owners.project.security_revision
            || browser.user_security_revision != owners.user.security_revision
            || browser.policy_session_revision != owners.policy.session_revision
        {
            return Err(ApplicationError::InvalidTransition);
        }
        let expires_at = std::cmp::min(
            command.now + Duration::seconds(60),
            std::cmp::min(
                session.absolute_expires_at,
                std::cmp::min(browser.idle_expires_at, browser.absolute_expires_at),
            ),
        );
        if expires_at <= command.now {
            return Err(ApplicationError::InvalidTransition);
        }
        let interaction = project_browser_logout_interaction::ActiveModel {
            id: Set(command.id),
            project_id: Set(command.project_id),
            application_id: Set(command.application_id),
            user_id: Set(command.user_id),
            application_session_id: Set(command.application_session_id),
            browser_session_id: Set(command.browser_session_id),
            preparation_digest: Set(command.preparation.value.to_vec()),
            preparation_digest_key_version: Set(command.preparation.key_version),
            status: Set("prepared".to_owned()),
            interaction_revision: Set(1),
            csrf_digest: Set(None),
            csrf_digest_key_version: Set(None),
            application_session_revision: Set(session.session_revision),
            browser_session_revision: Set(browser.session_revision),
            expires_at: Set(expires_at),
            csrf_bound_at: Set(None),
            consumed_at: Set(None),
            created_at: Set(command.now),
            updated_at: Set(command.now),
        }
        .insert(&transaction)
        .await
        .map_err(persistence)?;
        append_runtime_audit(
            &transaction,
            command.project_id,
            "project_user",
            "auth.browser_logout.prepared",
            "browser_logout_interaction",
            Some(interaction.id),
            command.application_session_id,
        )
        .await?;
        transaction.commit().await.map_err(persistence)?;
        Ok(browser_logout_record(&interaction))
    }

    async fn bind_browser_logout(
        &self,
        command: BindBrowserLogout,
    ) -> Result<BrowserLogoutRecord, ApplicationError> {
        validate_digest(&command.preparation)?;
        validate_digest(&command.browser_credential)?;
        validate_digest(&command.csrf)?;
        let transaction = self.database.begin().await.map_err(persistence)?;
        let interaction = project_browser_logout_interaction::Entity::find()
            .filter(
                project_browser_logout_interaction::Column::PreparationDigest
                    .eq(command.preparation.value.to_vec()),
            )
            .filter(
                project_browser_logout_interaction::Column::PreparationDigestKeyVersion
                    .eq(command.preparation.key_version),
            )
            .lock_exclusive()
            .one(&transaction)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        if interaction.expires_at <= command.now {
            let expired = expire_browser_logout(&transaction, &interaction, command.now).await?;
            transaction.commit().await.map_err(persistence)?;
            return Err(if expired {
                ApplicationError::InvalidTransition
            } else {
                ApplicationError::NotFound
            });
        }
        if interaction.status != "prepared"
            || interaction.interaction_revision != command.expected_interaction_revision
        {
            return Err(ApplicationError::RevisionConflict);
        }
        let owners = lock_logout_owners(
            &transaction,
            interaction.project_id,
            interaction.application_id,
            interaction.user_id,
            interaction.application_session_id,
            Some(interaction.application_session_revision),
            command.now,
        )
        .await?;
        let browser = project_browser_session::Entity::find_by_id(interaction.browser_session_id)
            .filter(project_browser_session::Column::ProjectId.eq(interaction.project_id))
            .filter(project_browser_session::Column::UserId.eq(interaction.user_id))
            .lock_shared()
            .one(&transaction)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        if !digest_matches(
            &browser.credential_digest,
            browser.credential_digest_key_version,
            &command.browser_credential,
        ) || owners.session.browser_session_id != Some(browser.id)
            || browser.status != "active"
            || browser.session_revision != interaction.browser_session_revision
            || browser.idle_expires_at <= command.now
            || browser.absolute_expires_at <= command.now
            || browser.project_security_revision != owners.project.security_revision
            || browser.user_security_revision != owners.user.security_revision
            || browser.policy_session_revision != owners.policy.session_revision
        {
            return Err(ApplicationError::NotFound);
        }
        let mut active = interaction.into_active_model();
        active.status = Set("csrf_bound".to_owned());
        active.interaction_revision = Set(active.interaction_revision.take().unwrap_or(1) + 1);
        active.csrf_digest = Set(Some(command.csrf.value.to_vec()));
        active.csrf_digest_key_version = Set(Some(command.csrf.key_version));
        active.csrf_bound_at = Set(Some(command.now));
        active.updated_at = Set(command.now);
        let interaction = active.update(&transaction).await.map_err(persistence)?;
        append_runtime_audit(
            &transaction,
            interaction.project_id,
            "project_user",
            "auth.browser_logout.csrf_bound",
            "browser_logout_interaction",
            Some(interaction.id),
            interaction.application_session_id,
        )
        .await?;
        transaction.commit().await.map_err(persistence)?;
        Ok(browser_logout_record(&interaction))
    }

    async fn confirm_browser_logout(
        &self,
        command: ConfirmBrowserLogout,
    ) -> Result<BrowserLogoutRecord, ApplicationError> {
        validate_digest(&command.preparation)?;
        validate_digest(&command.browser_credential)?;
        validate_digest(&command.csrf)?;
        let transaction = self.database.begin().await.map_err(persistence)?;
        let interaction = project_browser_logout_interaction::Entity::find()
            .filter(
                project_browser_logout_interaction::Column::PreparationDigest
                    .eq(command.preparation.value.to_vec()),
            )
            .filter(
                project_browser_logout_interaction::Column::PreparationDigestKeyVersion
                    .eq(command.preparation.key_version),
            )
            .lock_exclusive()
            .one(&transaction)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        if interaction.expires_at <= command.now {
            expire_browser_logout(&transaction, &interaction, command.now).await?;
            transaction.commit().await.map_err(persistence)?;
            return Err(ApplicationError::InvalidTransition);
        }
        if interaction.status != "csrf_bound"
            || interaction.interaction_revision != command.expected_interaction_revision
            || !optional_digest_matches(
                interaction.csrf_digest.as_deref(),
                interaction.csrf_digest_key_version,
                &command.csrf,
            )
        {
            return Err(ApplicationError::NotFound);
        }
        let owners = lock_logout_owners(
            &transaction,
            interaction.project_id,
            interaction.application_id,
            interaction.user_id,
            interaction.application_session_id,
            Some(interaction.application_session_revision),
            command.now,
        )
        .await?;
        let browser = project_browser_session::Entity::find_by_id(interaction.browser_session_id)
            .filter(project_browser_session::Column::ProjectId.eq(interaction.project_id))
            .filter(project_browser_session::Column::UserId.eq(interaction.user_id))
            .lock_exclusive()
            .one(&transaction)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        if !digest_matches(
            &browser.credential_digest,
            browser.credential_digest_key_version,
            &command.browser_credential,
        ) || owners.session.browser_session_id != Some(browser.id)
            || browser.status != "active"
            || browser.session_revision != interaction.browser_session_revision
            || browser.idle_expires_at <= command.now
            || browser.absolute_expires_at <= command.now
            || browser.project_security_revision != owners.project.security_revision
            || browser.user_security_revision != owners.user.security_revision
            || browser.policy_session_revision != owners.policy.session_revision
        {
            return Err(ApplicationError::NotFound);
        }
        let mut browser_active = browser.into_active_model();
        browser_active.status = Set("terminated".to_owned());
        browser_active.session_revision =
            Set(browser_active.session_revision.take().unwrap_or(1) + 1);
        browser_active.terminated_at = Set(Some(command.now));
        browser_active.updated_at = Set(command.now);
        browser_active
            .update(&transaction)
            .await
            .map_err(persistence)?;

        let mut active = interaction.into_active_model();
        active.status = Set("consumed".to_owned());
        active.interaction_revision = Set(active.interaction_revision.take().unwrap_or(1) + 1);
        active.consumed_at = Set(Some(command.now));
        active.updated_at = Set(command.now);
        let interaction = active.update(&transaction).await.map_err(persistence)?;
        append_runtime_audit(
            &transaction,
            interaction.project_id,
            "project_user",
            "auth.browser_logout.confirmed",
            "project_browser_session",
            Some(interaction.browser_session_id),
            interaction.application_session_id,
        )
        .await?;
        transaction.commit().await.map_err(persistence)?;
        Ok(browser_logout_record(&interaction))
    }
}

async fn lock_identity_namespace(
    transaction: &sea_orm::DatabaseTransaction,
    project_id: uuid::Uuid,
    issuer: &str,
    subject: &str,
) -> Result<(), ApplicationError> {
    let namespace = format!("{project_id}\u{1f}{issuer}\u{1f}{subject}");
    transaction
        .execute_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))",
            [namespace.into()],
        ))
        .await
        .map_err(persistence)?;
    Ok(())
}

#[allow(
    clippy::collapsible_if,
    reason = "the outer credential option and inner locked lookup have distinct semantics"
)]
async fn rotate_or_create_browser_session(
    transaction: &sea_orm::DatabaseTransaction,
    command: &CompleteAuthenticatedIdentity,
    login: &login_transaction::Model,
    user: &project_user::Model,
) -> Result<project_browser_session::Model, ApplicationError> {
    if let Some(existing_credential) = &command.existing_browser_credential {
        if let Some(existing) = project_browser_session::Entity::find()
            .filter(
                project_browser_session::Column::CredentialDigest
                    .eq(existing_credential.value.to_vec()),
            )
            .filter(
                project_browser_session::Column::CredentialDigestKeyVersion
                    .eq(existing_credential.key_version),
            )
            .lock_exclusive()
            .one(transaction)
            .await
            .map_err(persistence)?
        {
            if digest_matches(
                &existing.credential_digest,
                existing.credential_digest_key_version,
                existing_credential,
            ) && existing.project_id == command.project_id
                && existing.user_id == user.id
                && existing.status == "active"
            {
                let mut active = existing.into_active_model();
                active.credential_digest = Set(command.browser_credential.value.to_vec());
                active.credential_digest_key_version = Set(command.browser_credential.key_version);
                active.session_revision = Set(active.session_revision.take().unwrap_or(1) + 1);
                active.project_security_revision = Set(login.project_security_revision);
                active.user_security_revision = Set(user.security_revision);
                active.policy_session_revision = Set(login.session_revision);
                active.authenticated_at = Set(command.now);
                active.last_activity_at = Set(command.now);
                active.idle_expires_at = Set(command.now + Duration::hours(8));
                active.absolute_expires_at = Set(command.now + Duration::hours(24));
                active.updated_at = Set(command.now);
                return active.update(transaction).await.map_err(persistence);
            }
            if existing.project_id == command.project_id && existing.status == "active" {
                let mut active = existing.into_active_model();
                active.status = Set("terminated".to_owned());
                active.session_revision = Set(active.session_revision.take().unwrap_or(1) + 1);
                active.terminated_at = Set(Some(command.now));
                active.updated_at = Set(command.now);
                active.update(transaction).await.map_err(persistence)?;
            }
        }
    }

    project_browser_session::ActiveModel {
        id: Set(command.browser_session_id),
        project_id: Set(command.project_id),
        user_id: Set(user.id),
        credential_digest: Set(command.browser_credential.value.to_vec()),
        credential_digest_key_version: Set(command.browser_credential.key_version),
        status: Set("active".to_owned()),
        session_revision: Set(1),
        project_security_revision: Set(login.project_security_revision),
        user_security_revision: Set(user.security_revision),
        policy_session_revision: Set(login.session_revision),
        authenticated_at: Set(command.now),
        last_activity_at: Set(command.now),
        idle_expires_at: Set(command.now + Duration::hours(8)),
        absolute_expires_at: Set(command.now + Duration::hours(24)),
        terminated_at: Set(None),
        created_at: Set(command.now),
        updated_at: Set(command.now),
    }
    .insert(transaction)
    .await
    .map_err(persistence)
}

#[allow(clippy::too_many_arguments)]
async fn insert_handoff(
    transaction: &sea_orm::DatabaseTransaction,
    id: uuid::Uuid,
    digest: &VersionedDigest,
    login: &login_transaction::Model,
    user_id: uuid::Uuid,
    browser_session_id: uuid::Uuid,
    authentication_method: &str,
    authenticated_at: OffsetDateTime,
    issued_at: OffsetDateTime,
    expires_at: OffsetDateTime,
    user_security_revision: i64,
) -> Result<handoff_ticket::Model, ApplicationError> {
    if expires_at <= issued_at
        || expires_at != std::cmp::min(issued_at + Duration::seconds(60), login.expires_at)
    {
        return Err(ApplicationError::Integrity);
    }
    let provider = if authentication_method == "provider" {
        Some(
            login
                .provider_configuration_id
                .ok_or(ApplicationError::Integrity)?,
        )
    } else {
        None
    };
    handoff_ticket::ActiveModel {
        id: Set(id),
        project_id: Set(login.project_id),
        login_transaction_id: Set(login.id),
        application_id: Set(login.application_id),
        user_id: Set(user_id),
        browser_session_id: Set(browser_session_id),
        provider_configuration_id: Set(provider),
        ticket_digest: Set(digest.value.to_vec()),
        ticket_digest_key_version: Set(digest.key_version),
        status: Set("issued".to_owned()),
        redirect_uri: Set(login.redirect_uri.clone()),
        application_pkce_challenge: Set(login.application_pkce_challenge.clone()),
        authentication_method: Set(authentication_method.to_owned()),
        authenticated_at: Set(authenticated_at),
        project_security_revision: Set(login.project_security_revision),
        application_security_revision: Set(login.application_security_revision),
        user_security_revision: Set(user_security_revision),
        provider_revision: Set(provider.and(login.provider_revision)),
        assignment_security_revision: Set(provider.and(login.assignment_security_revision)),
        claims_revision: Set(login.claims_revision),
        policy_session_revision: Set(login.session_revision),
        issued_at: Set(issued_at),
        expires_at: Set(expires_at),
        consumed_at: Set(None),
        created_at: Set(issued_at),
    }
    .insert(transaction)
    .await
    .map_err(persistence)
}

async fn lock_login_application_owners(
    transaction: &sea_orm::DatabaseTransaction,
    login: &login_transaction::Model,
) -> Result<(project::Model, application::Model, project_policy::Model), ApplicationError> {
    let project = project::Entity::find_by_id(login.project_id)
        .lock_shared()
        .one(transaction)
        .await
        .map_err(persistence)?
        .ok_or(ApplicationError::NotFound)?;
    let application = application::Entity::find_by_id(login.application_id)
        .filter(application::Column::ProjectId.eq(login.project_id))
        .lock_shared()
        .one(transaction)
        .await
        .map_err(persistence)?
        .ok_or(ApplicationError::NotFound)?;
    let policy = project_policy::Entity::find_by_id(login.project_id)
        .lock_shared()
        .one(transaction)
        .await
        .map_err(persistence)?
        .ok_or(ApplicationError::Integrity)?;
    if project.status != "active"
        || application.status != "active"
        || project.metadata_revision != login.project_metadata_revision
        || project.security_revision != login.project_security_revision
        || application.security_revision != login.application_security_revision
        || policy.claims_revision != login.claims_revision
        || policy.session_revision != login.session_revision
    {
        return Err(ApplicationError::RevisionConflict);
    }
    Ok((project, application, policy))
}

async fn fail_provider_completion<T>(
    transaction: sea_orm::DatabaseTransaction,
    login: &login_transaction::Model,
    now: OffsetDateTime,
    error: ApplicationError,
) -> Result<T, ApplicationError> {
    terminalize_claimed_provider_exchange(&transaction, login, now).await?;
    transaction.commit().await.map_err(persistence)?;
    Err(error)
}

async fn terminalize_claimed_provider_exchange(
    transaction: &sea_orm::DatabaseTransaction,
    login: &login_transaction::Model,
    now: OffsetDateTime,
) -> Result<(), ApplicationError> {
    if login.status != LoginTransactionStatus::ProviderExchangeInProgress.as_str() {
        return Err(ApplicationError::InvalidTransition);
    }
    let mut active = login.clone().into_active_model();
    active.status = Set(LoginTransactionStatus::ProviderExchangeFailed
        .as_str()
        .to_owned());
    active.transaction_revision = Set(login.transaction_revision + 1);
    active.terminal_at = Set(Some(now));
    active.updated_at = Set(now);
    active.update(transaction).await.map_err(persistence)?;
    append_runtime_audit(
        transaction,
        login.project_id,
        "system",
        "auth.provider_exchange.failed",
        "login_transaction",
        Some(login.id),
        login.id,
    )
    .await
}

async fn record_refresh_replay(
    transaction: &sea_orm::DatabaseTransaction,
    generation: &refresh_token_generation::Model,
    family: &refresh_family::Model,
    project_id: uuid::Uuid,
    now: OffsetDateTime,
) -> Result<(), ApplicationError> {
    let mut generation_active = generation.clone().into_active_model();
    if generation.replay_detected_at.is_none() {
        generation_active.replay_detected_at = Set(Some(now));
        generation_active
            .update(transaction)
            .await
            .map_err(persistence)?;
    }
    if family.status == "active" {
        let mut family_active = family.clone().into_active_model();
        family_active.status = Set("revoked".to_owned());
        family_active.family_revision = Set(family.family_revision + 1);
        family_active.revoked_at = Set(Some(now));
        family_active.revocation_reason = Set(Some("replay".to_owned()));
        family_active.updated_at = Set(now);
        family_active
            .update(transaction)
            .await
            .map_err(persistence)?;
    }
    append_runtime_audit(
        transaction,
        project_id,
        "system",
        "auth.refresh.replay_detected",
        "refresh_family",
        Some(family.id),
        family.id,
    )
    .await
}

async fn fan_out_user_projections(
    transaction: &sea_orm::DatabaseTransaction,
    user: &project_user::Model,
    now: OffsetDateTime,
) -> Result<(), ApplicationError> {
    super::projection::fan_out_user_projections(transaction, user, now).await
}

struct SigningSnapshot {
    ring_id: uuid::Uuid,
    key_id: uuid::Uuid,
    issuer: String,
    kid: String,
    signer_ref: String,
    epoch: i64,
}

async fn active_signing_snapshot(
    transaction: &sea_orm::DatabaseTransaction,
    project_id: uuid::Uuid,
    now: OffsetDateTime,
) -> Result<SigningSnapshot, ApplicationError> {
    let ring = project_key_ring::Entity::find()
        .filter(project_key_ring::Column::ProjectId.eq(project_id))
        .filter(project_key_ring::Column::Purpose.eq("application_tokens"))
        .filter(project_key_ring::Column::Algorithm.eq("EdDSA"))
        .lock_shared()
        .one(transaction)
        .await
        .map_err(persistence)?
        .ok_or(ApplicationError::NotFound)?;
    let key = project_signing_key::Entity::find()
        .filter(project_signing_key::Column::ProjectId.eq(project_id))
        .filter(project_signing_key::Column::RingId.eq(ring.id))
        .filter(project_signing_key::Column::State.eq("active"))
        .order_by_desc(project_signing_key::Column::ActivatedAt)
        .order_by_asc(project_signing_key::Column::Id)
        .lock_shared()
        .one(transaction)
        .await
        .map_err(persistence)?
        .ok_or(ApplicationError::NotFound)?;
    if key.sign_not_before.is_none_or(|value| value > now) {
        return Err(ApplicationError::RevisionConflict);
    }
    Ok(SigningSnapshot {
        ring_id: ring.id,
        key_id: key.id,
        issuer: ring.issuer,
        kid: key.kid,
        signer_ref: key.signer_ref,
        epoch: ring.signing_epoch,
    })
}

fn access_token_lifetime(policy: &project_policy::Model) -> Result<i64, ApplicationError> {
    policy
        .claims_policy
        .get("access_token_lifetime_seconds")
        .and_then(Value::as_i64)
        .filter(|value| (60..=3600).contains(value))
        .ok_or(ApplicationError::Integrity)
}

fn base_profile_digest(
    display_name: Option<&str>,
    picture_url: Option<&str>,
    locale: Option<&str>,
    verified_email: Option<&str>,
) -> Result<Vec<u8>, ApplicationError> {
    super::projection::base_profile_digest(display_name, picture_url, locale, verified_email)
}

fn authoritative_projection_material(
    projection: Option<&application_user_projection::Model>,
    user: &project_user::Model,
    project_projection_revision: i64,
    application_projection_revision: i64,
) -> Result<(i64, Value, Vec<u8>), ApplicationError> {
    let material = super::projection::authoritative_projection_material(
        projection,
        user,
        project_projection_revision,
        application_projection_revision,
    )?;
    Ok((material.revision, material.document, material.digest))
}

async fn lock_signing_epoch(
    transaction: &sea_orm::DatabaseTransaction,
    project_id: uuid::Uuid,
    ring_id: uuid::Uuid,
    key_id: uuid::Uuid,
    signing_epoch: i64,
    now: OffsetDateTime,
) -> Result<(), ApplicationError> {
    let ring = project_key_ring::Entity::find_by_id(ring_id)
        .filter(project_key_ring::Column::ProjectId.eq(project_id))
        .lock_shared()
        .one(transaction)
        .await
        .map_err(persistence)?
        .ok_or(ApplicationError::NotFound)?;
    let key = project_signing_key::Entity::find_by_id(key_id)
        .filter(project_signing_key::Column::ProjectId.eq(project_id))
        .filter(project_signing_key::Column::RingId.eq(ring_id))
        .lock_shared()
        .one(transaction)
        .await
        .map_err(persistence)?
        .ok_or(ApplicationError::NotFound)?;
    if ring.signing_epoch != signing_epoch
        || ring.purpose != "application_tokens"
        || ring.algorithm != "EdDSA"
        || key.state != "active"
        || key.sign_not_before.is_none_or(|value| value > now)
    {
        return Err(ApplicationError::RevisionConflict);
    }
    Ok(())
}

struct LogoutOwners {
    project: project::Model,
    user: project_user::Model,
    policy: project_policy::Model,
    session: application_session::Model,
}

#[allow(clippy::too_many_arguments)]
async fn lock_logout_owners(
    transaction: &sea_orm::DatabaseTransaction,
    project_id: uuid::Uuid,
    application_id: uuid::Uuid,
    user_id: uuid::Uuid,
    application_session_id: uuid::Uuid,
    expected_session_revision: Option<i64>,
    now: OffsetDateTime,
) -> Result<LogoutOwners, ApplicationError> {
    let project = project::Entity::find_by_id(project_id)
        .lock_shared()
        .one(transaction)
        .await
        .map_err(persistence)?
        .ok_or(ApplicationError::NotFound)?;
    let application = application::Entity::find_by_id(application_id)
        .filter(application::Column::ProjectId.eq(project_id))
        .lock_shared()
        .one(transaction)
        .await
        .map_err(persistence)?
        .ok_or(ApplicationError::NotFound)?;
    let user = project_user::Entity::find_by_id(user_id)
        .filter(project_user::Column::ProjectId.eq(project_id))
        .lock_shared()
        .one(transaction)
        .await
        .map_err(persistence)?
        .ok_or(ApplicationError::NotFound)?;
    let policy = project_policy::Entity::find_by_id(project_id)
        .lock_shared()
        .one(transaction)
        .await
        .map_err(persistence)?
        .ok_or(ApplicationError::Integrity)?;
    let session = application_session::Entity::find_by_id(application_session_id)
        .filter(application_session::Column::ProjectId.eq(project_id))
        .filter(application_session::Column::ApplicationId.eq(application_id))
        .filter(application_session::Column::UserId.eq(user_id))
        .lock_shared()
        .one(transaction)
        .await
        .map_err(persistence)?
        .ok_or(ApplicationError::NotFound)?;
    if project.status != "active"
        || application.status != "active"
        || user.status != "active"
        || session.status != "active"
        || session.absolute_expires_at <= now
        || project.security_revision != session.project_security_revision
        || application.security_revision != session.application_security_revision
        || user.security_revision != session.user_security_revision
        || policy.claims_revision != session.claims_revision
        || policy.session_revision != session.policy_session_revision
        || expected_session_revision.is_some_and(|revision| revision != session.session_revision)
    {
        return Err(ApplicationError::RevisionConflict);
    }
    Ok(LogoutOwners {
        project,
        user,
        policy,
        session,
    })
}

async fn expire_browser_logout(
    transaction: &sea_orm::DatabaseTransaction,
    interaction: &project_browser_logout_interaction::Model,
    now: OffsetDateTime,
) -> Result<bool, ApplicationError> {
    if !matches!(interaction.status.as_str(), "prepared" | "csrf_bound") {
        return Ok(false);
    }
    let mut active = interaction.clone().into_active_model();
    active.status = Set("expired".to_owned());
    active.interaction_revision = Set(active.interaction_revision.take().unwrap_or(1) + 1);
    active.updated_at = Set(now);
    active.update(transaction).await.map_err(persistence)?;
    append_runtime_audit(
        transaction,
        interaction.project_id,
        "system",
        "auth.browser_logout.expired",
        "browser_logout_interaction",
        Some(interaction.id),
        interaction.application_session_id,
    )
    .await?;
    Ok(true)
}

fn browser_logout_record(
    interaction: &project_browser_logout_interaction::Model,
) -> BrowserLogoutRecord {
    BrowserLogoutRecord {
        id: interaction.id,
        project_id: interaction.project_id,
        browser_session_id: interaction.browser_session_id,
        interaction_revision: interaction.interaction_revision,
        expires_at: interaction.expires_at,
    }
}

fn digest_matches(stored: &[u8], stored_key_version: i32, supplied: &VersionedDigest) -> bool {
    stored_key_version == supplied.key_version
        && stored.len() == supplied.value.len()
        && bool::from(stored.ct_eq(supplied.value.as_slice()))
}
