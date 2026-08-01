use async_trait::async_trait;
use sea_orm::{
    ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, QueryOrder, QuerySelect,
    TransactionTrait,
};
use subtle::ConstantTimeEq;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::{
    application::{
        AccessTokenSessionLookup, AdmittedProviderMethod, ApplicationError, BrowserLogoutContext,
        CurrentSession, HostedInteraction, HostedProviderMethod, LoginStartContext,
        ProviderRuntimeContext, RuntimeAuthorityRepository, VerificationKey, VersionedDigest,
    },
    domain::LoginTransactionStatus,
};

use super::{
    authentication::{optional_digest_matches, parse_login_status, persistence},
    entity::{
        application, application_origin, application_provider_assignment,
        application_publishable_key, application_redirect, application_session,
        application_user_binding, application_user_projection, login_transaction,
        login_transaction_method, project, project_browser_logout_interaction,
        project_browser_session, project_key_ring, project_policy, project_signing_key,
        project_user, provider_configuration, refresh_family,
    },
};

#[derive(Clone, Debug)]
pub(crate) struct PostgresRuntimeAuthorityRepository {
    database: DatabaseConnection,
}

impl PostgresRuntimeAuthorityRepository {
    pub(crate) fn new(database: DatabaseConnection) -> Self {
        Self { database }
    }
}

#[async_trait]
#[allow(
    clippy::too_many_lines,
    reason = "security read models keep their complete PostgreSQL qualification visible"
)]
impl RuntimeAuthorityRepository for PostgresRuntimeAuthorityRepository {
    async fn prepare_login_start(
        &self,
        project_public_id: &str,
        application_public_id: &str,
        publishable_key: &str,
        redirect_uri: &str,
    ) -> Result<LoginStartContext, ApplicationError> {
        let transaction = self.database.begin().await.map_err(persistence)?;
        let project = project::Entity::find()
            .filter(project::Column::PublicId.eq(project_public_id))
            .filter(project::Column::Status.eq("active"))
            .lock_shared()
            .one(&transaction)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        let application = application::Entity::find()
            .filter(application::Column::ProjectId.eq(project.id))
            .filter(application::Column::PublicId.eq(application_public_id))
            .filter(application::Column::Status.eq("active"))
            .lock_shared()
            .one(&transaction)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        application_publishable_key::Entity::find()
            .filter(application_publishable_key::Column::ProjectId.eq(project.id))
            .filter(application_publishable_key::Column::ApplicationId.eq(application.id))
            .filter(application_publishable_key::Column::PublicId.eq(publishable_key))
            .filter(application_publishable_key::Column::Status.eq("active"))
            .lock_shared()
            .one(&transaction)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        application_redirect::Entity::find_by_id((
            project.id,
            application.id,
            redirect_uri.to_owned(),
        ))
        .lock_shared()
        .one(&transaction)
        .await
        .map_err(persistence)?
        .ok_or(ApplicationError::InvalidInput)?;
        let policy = project_policy::Entity::find_by_id(project.id)
            .lock_shared()
            .one(&transaction)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::Integrity)?;
        let assignments = application_provider_assignment::Entity::find()
            .filter(application_provider_assignment::Column::ProjectId.eq(project.id))
            .filter(application_provider_assignment::Column::ApplicationId.eq(application.id))
            .filter(application_provider_assignment::Column::Status.eq("active"))
            .order_by_asc(application_provider_assignment::Column::ProviderId)
            .lock_shared()
            .all(&transaction)
            .await
            .map_err(persistence)?;
        if assignments.is_empty() || assignments.len() > 50 {
            return Err(if assignments.is_empty() {
                ApplicationError::Disabled
            } else {
                ApplicationError::Integrity
            });
        }
        let mut admitted_providers = Vec::with_capacity(assignments.len());
        for assignment in assignments {
            let provider = provider_configuration::Entity::find_by_id(assignment.provider_id)
                .filter(provider_configuration::Column::ProjectId.eq(project.id))
                .filter(provider_configuration::Column::Status.eq("active"))
                .lock_shared()
                .one(&transaction)
                .await
                .map_err(persistence)?
                .ok_or(ApplicationError::Integrity)?;
            if provider.kind != "oidc" || provider.secret_ref.is_none() {
                return Err(ApplicationError::Integrity);
            }
            admitted_providers.push(AdmittedProviderMethod {
                method_key: provider.provider_key,
                provider_id: provider.id,
                display_name: provider.display_name,
                issuer: provider.issuer,
                provider_revision: provider.revision,
                assignment_security_revision: assignment.security_revision,
            });
        }
        let result = LoginStartContext {
            project_id: project.id,
            project_public_id: project.public_id,
            project_display_name: project.display_name,
            project_metadata_revision: project.metadata_revision,
            project_security_revision: project.security_revision,
            application_id: application.id,
            application_public_id: application.public_id,
            application_display_name: application.display_name,
            application_security_revision: application.security_revision,
            claims_revision: policy.claims_revision,
            session_revision: policy.session_revision,
            admitted_providers,
        };
        transaction.commit().await.map_err(persistence)?;
        Ok(result)
    }

    async fn hosted_interaction(
        &self,
        interaction: &VersionedDigest,
        browser_binding: Option<&VersionedDigest>,
        now: OffsetDateTime,
    ) -> Result<HostedInteraction, ApplicationError> {
        let transaction = self.database.begin().await.map_err(persistence)?;
        let login = login_transaction::Entity::find()
            .filter(login_transaction::Column::InteractionDigest.eq(interaction.value.to_vec()))
            .filter(
                login_transaction::Column::InteractionDigestKeyVersion.eq(interaction.key_version),
            )
            .lock_shared()
            .one(&transaction)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        if login.expires_at <= now {
            return Err(ApplicationError::InvalidTransition);
        }
        let status = parse_login_status(&login.status)?;
        match status {
            LoginTransactionStatus::AwaitingBrowserBinding if browser_binding.is_none() => {}
            LoginTransactionStatus::AwaitingBrowserBinding => {}
            _ => {
                let binding = browser_binding.ok_or(ApplicationError::NotFound)?;
                if !optional_digest_matches(
                    login.browser_binding_digest.as_deref(),
                    login.browser_binding_digest_key_version,
                    binding,
                ) {
                    return Err(ApplicationError::NotFound);
                }
            }
        }
        let project = project::Entity::find_by_id(login.project_id)
            .filter(project::Column::Status.eq("active"))
            .lock_shared()
            .one(&transaction)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        let application = application::Entity::find_by_id(login.application_id)
            .filter(application::Column::ProjectId.eq(login.project_id))
            .filter(application::Column::Status.eq("active"))
            .lock_shared()
            .one(&transaction)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        if project.metadata_revision != login.project_metadata_revision
            || project.security_revision != login.project_security_revision
            || application.security_revision != login.application_security_revision
        {
            return Err(ApplicationError::RevisionConflict);
        }
        let methods = login_transaction_method::Entity::find()
            .filter(login_transaction_method::Column::ProjectId.eq(login.project_id))
            .filter(login_transaction_method::Column::TransactionId.eq(login.id))
            .filter(login_transaction_method::Column::MethodKind.eq("provider"))
            .order_by_asc(login_transaction_method::Column::MethodKey)
            .limit(51)
            .all(&transaction)
            .await
            .map_err(persistence)?;
        if methods.is_empty() || methods.len() > 50 {
            return Err(ApplicationError::Integrity);
        }
        let result = HostedInteraction {
            transaction_id: login.id,
            project_id: login.project_id,
            project_public_id: project.public_id,
            project_display_name: project.display_name,
            application_id: login.application_id,
            application_public_id: application.public_id,
            application_display_name: application.display_name,
            application_type: match application.application_type.as_str() {
                "web" => crate::domain::ApplicationType::Web,
                "native" => crate::domain::ApplicationType::Native,
                _ => return Err(ApplicationError::Integrity),
            },
            status,
            transaction_revision: login.transaction_revision,
            csrf_key_version: login.csrf_digest_key_version,
            presentation_hint: login.presentation_hint,
            providers: methods
                .into_iter()
                .map(|method| HostedProviderMethod {
                    key: method.method_key,
                    display_name: method.display_name,
                })
                .collect(),
            expires_at: login.expires_at,
        };
        transaction.commit().await.map_err(persistence)?;
        Ok(result)
    }

    async fn provider_runtime_context(
        &self,
        project_id: Uuid,
        transaction_id: Uuid,
        provider_key: &str,
    ) -> Result<ProviderRuntimeContext, ApplicationError> {
        let transaction = self.database.begin().await.map_err(persistence)?;
        let login = login_transaction::Entity::find_by_id(transaction_id)
            .filter(login_transaction::Column::ProjectId.eq(project_id))
            .lock_shared()
            .one(&transaction)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        let method = login_transaction_method::Entity::find_by_id((
            project_id,
            transaction_id,
            provider_key.to_owned(),
        ))
        .lock_shared()
        .one(&transaction)
        .await
        .map_err(persistence)?
        .ok_or(ApplicationError::NotFound)?;
        let provider_id = method
            .provider_configuration_id
            .ok_or(ApplicationError::Integrity)?;
        if method.method_kind != "provider"
            || (login.provider_configuration_id.is_some()
                && login.provider_configuration_id != Some(provider_id))
        {
            return Err(ApplicationError::InvalidTransition);
        }
        let provider = provider_configuration::Entity::find_by_id(provider_id)
            .filter(provider_configuration::Column::ProjectId.eq(project_id))
            .filter(provider_configuration::Column::Status.eq("active"))
            .lock_shared()
            .one(&transaction)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        let assignment = application_provider_assignment::Entity::find_by_id((
            project_id,
            login.application_id,
            provider.id,
        ))
        .lock_shared()
        .one(&transaction)
        .await
        .map_err(persistence)?
        .ok_or(ApplicationError::NotFound)?;
        if assignment.status != "active"
            || Some(provider.revision) != method.provider_revision
            || Some(assignment.security_revision) != method.assignment_security_revision
            || provider.kind != "oidc"
        {
            return Err(ApplicationError::RevisionConflict);
        }
        let result = ProviderRuntimeContext {
            project_id,
            transaction_id,
            provider_id: provider.id,
            provider_key: provider.provider_key,
            issuer: provider.issuer,
            client_id: provider.client_id,
            callback_url: provider.callback_url,
            secret_ref: provider.secret_ref.ok_or(ApplicationError::Integrity)?,
        };
        transaction.commit().await.map_err(persistence)?;
        Ok(result)
    }

    async fn resolve_application(
        &self,
        project_public_id: &str,
        application_public_id: &str,
        publishable_key: &str,
    ) -> Result<(Uuid, Uuid), ApplicationError> {
        let project = project::Entity::find()
            .filter(project::Column::PublicId.eq(project_public_id))
            .filter(project::Column::Status.eq("active"))
            .one(&self.database)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        let application = application::Entity::find()
            .filter(application::Column::ProjectId.eq(project.id))
            .filter(application::Column::PublicId.eq(application_public_id))
            .filter(application::Column::Status.eq("active"))
            .one(&self.database)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        application_publishable_key::Entity::find()
            .filter(application_publishable_key::Column::ProjectId.eq(project.id))
            .filter(application_publishable_key::Column::ApplicationId.eq(application.id))
            .filter(application_publishable_key::Column::PublicId.eq(publishable_key))
            .filter(application_publishable_key::Column::Status.eq("active"))
            .one(&self.database)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        Ok((project.id, application.id))
    }

    async fn resolve_public_application(
        &self,
        project_public_id: &str,
        application_public_id: &str,
    ) -> Result<(Uuid, Uuid), ApplicationError> {
        let project = project::Entity::find()
            .filter(project::Column::PublicId.eq(project_public_id))
            .filter(project::Column::Status.eq("active"))
            .one(&self.database)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        let application = application::Entity::find()
            .filter(application::Column::ProjectId.eq(project.id))
            .filter(application::Column::PublicId.eq(application_public_id))
            .filter(application::Column::Status.eq("active"))
            .one(&self.database)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        Ok((project.id, application.id))
    }

    async fn exact_application_origin(
        &self,
        project_id: Uuid,
        application_id: Uuid,
        origin: &str,
    ) -> Result<bool, ApplicationError> {
        exact_application_origin(&self.database, project_id, application_id, origin).await
    }

    async fn project_origin_allowed(
        &self,
        project_public_id: &str,
        origin: &str,
    ) -> Result<bool, ApplicationError> {
        let project = project::Entity::find()
            .filter(project::Column::PublicId.eq(project_public_id))
            .filter(project::Column::Status.eq("active"))
            .one(&self.database)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        let Some(origin) = application_origin::Entity::find()
            .filter(application_origin::Column::ProjectId.eq(project.id))
            .filter(application_origin::Column::Origin.eq(origin))
            .one(&self.database)
            .await
            .map_err(persistence)?
        else {
            return Ok(false);
        };
        Ok(application::Entity::find_by_id(origin.application_id)
            .filter(application::Column::ProjectId.eq(project.id))
            .filter(application::Column::Status.eq("active"))
            .one(&self.database)
            .await
            .map_err(persistence)?
            .is_some())
    }

    async fn browser_session_reuse_available(
        &self,
        project_id: Uuid,
        browser_credential: &VersionedDigest,
        now: OffsetDateTime,
    ) -> Result<bool, ApplicationError> {
        if browser_credential.value.len() != 32 || browser_credential.key_version <= 0 {
            return Err(ApplicationError::InvalidInput);
        }
        let Some(session) = project_browser_session::Entity::find()
            .filter(project_browser_session::Column::ProjectId.eq(project_id))
            .filter(
                project_browser_session::Column::CredentialDigest
                    .eq(browser_credential.value.to_vec()),
            )
            .filter(
                project_browser_session::Column::CredentialDigestKeyVersion
                    .eq(browser_credential.key_version),
            )
            .one(&self.database)
            .await
            .map_err(persistence)?
        else {
            return Ok(false);
        };
        if !bool::from(
            session
                .credential_digest
                .as_slice()
                .ct_eq(browser_credential.value.as_slice()),
        ) || session.status != "active"
            || session.idle_expires_at <= now
            || session.absolute_expires_at <= now
            || now < session.authenticated_at
        {
            return Ok(false);
        }
        let Some(project) = project::Entity::find_by_id(project_id)
            .one(&self.database)
            .await
            .map_err(persistence)?
        else {
            return Ok(false);
        };
        let Some(policy) = project_policy::Entity::find_by_id(project_id)
            .one(&self.database)
            .await
            .map_err(persistence)?
        else {
            return Ok(false);
        };
        let Some(user) = project_user::Entity::find_by_id(session.user_id)
            .filter(project_user::Column::ProjectId.eq(project_id))
            .one(&self.database)
            .await
            .map_err(persistence)?
        else {
            return Ok(false);
        };
        let reuse_enabled = policy
            .session_policy
            .get("browser_session_reuse")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);
        let reuse_max_age = policy
            .session_policy
            .get("browser_session_reuse_max_age_seconds")
            .and_then(serde_json::Value::as_i64)
            .filter(|value| (0..=86_400).contains(value));
        Ok(project.status == "active"
            && user.status == "active"
            && session.project_security_revision == project.security_revision
            && session.user_security_revision == user.security_revision
            && session.policy_session_revision == policy.session_revision
            && reuse_enabled
            && reuse_max_age.is_some_and(|seconds| {
                now - session.authenticated_at <= Duration::seconds(seconds)
            }))
    }

    async fn verification_key(
        &self,
        project_public_id: &str,
        kid: &str,
        now: OffsetDateTime,
    ) -> Result<VerificationKey, ApplicationError> {
        let project = project::Entity::find()
            .filter(project::Column::PublicId.eq(project_public_id))
            .filter(project::Column::Status.eq("active"))
            .one(&self.database)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        let ring = project_key_ring::Entity::find()
            .filter(project_key_ring::Column::ProjectId.eq(project.id))
            .filter(project_key_ring::Column::Purpose.eq("application_tokens"))
            .filter(project_key_ring::Column::Algorithm.eq("EdDSA"))
            .one(&self.database)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        let key = project_signing_key::Entity::find()
            .filter(project_signing_key::Column::ProjectId.eq(project.id))
            .filter(project_signing_key::Column::RingId.eq(ring.id))
            .filter(project_signing_key::Column::Kid.eq(kid))
            .one(&self.database)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        let usable = key.state == "active"
            || (key.state == "retiring" && key.verify_not_after.is_some_and(|cutoff| cutoff > now));
        if !usable {
            return Err(ApplicationError::Disabled);
        }
        Ok(VerificationKey {
            project_id: project.id,
            project_public_id: project.public_id,
            issuer: ring.issuer,
            public_jwk: key.public_jwk,
        })
    }

    async fn current_session(
        &self,
        lookup: AccessTokenSessionLookup,
        allow_revoked: bool,
    ) -> Result<CurrentSession, ApplicationError> {
        let AccessTokenSessionLookup {
            project_id,
            application_public_id,
            user_public_id,
            application_session_id,
            claims_revision,
            now,
        } = lookup;
        let transaction = self.database.begin().await.map_err(persistence)?;
        let project = project::Entity::find_by_id(project_id)
            .filter(project::Column::Status.eq("active"))
            .lock_shared()
            .one(&transaction)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        let application = application::Entity::find()
            .filter(application::Column::ProjectId.eq(project_id))
            .filter(application::Column::PublicId.eq(application_public_id))
            .filter(application::Column::Status.eq("active"))
            .lock_shared()
            .one(&transaction)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        let user = project_user::Entity::find()
            .filter(project_user::Column::ProjectId.eq(project_id))
            .filter(project_user::Column::PublicId.eq(user_public_id))
            .filter(project_user::Column::Status.eq("active"))
            .lock_shared()
            .one(&transaction)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        let policy = project_policy::Entity::find_by_id(project_id)
            .lock_shared()
            .one(&transaction)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::Integrity)?;
        let application_id = application.id;
        let user_id = user.id;
        let session = application_session::Entity::find_by_id(application_session_id)
            .filter(application_session::Column::ProjectId.eq(project_id))
            .filter(application_session::Column::ApplicationId.eq(application_id))
            .filter(application_session::Column::UserId.eq(user_id))
            .lock_shared()
            .one(&transaction)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        if (!allow_revoked && session.status != "active")
            || (allow_revoked && !matches!(session.status.as_str(), "active" | "revoked"))
            || session.absolute_expires_at <= now
            || session.project_security_revision != project.security_revision
            || session.application_security_revision != application.security_revision
            || session.user_security_revision != user.security_revision
            || session.claims_revision != claims_revision
            || policy.claims_revision != claims_revision
            || session.policy_session_revision != policy.session_revision
        {
            return Err(ApplicationError::Disabled);
        }
        let browser_session_id = session
            .browser_session_id
            .ok_or(ApplicationError::Integrity)?;
        let browser = project_browser_session::Entity::find_by_id(browser_session_id)
            .filter(project_browser_session::Column::ProjectId.eq(project_id))
            .filter(project_browser_session::Column::UserId.eq(user_id))
            .lock_shared()
            .one(&transaction)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::Integrity)?;
        if !allow_revoked
            && (browser.status != "active"
                || browser.idle_expires_at <= now
                || browser.absolute_expires_at <= now
                || browser.project_security_revision != project.security_revision
                || browser.user_security_revision != user.security_revision
                || browser.policy_session_revision != policy.session_revision)
        {
            return Err(ApplicationError::Disabled);
        }
        let family = refresh_family::Entity::find()
            .filter(refresh_family::Column::ProjectId.eq(project_id))
            .filter(refresh_family::Column::ApplicationId.eq(application_id))
            .filter(refresh_family::Column::ApplicationSessionId.eq(application_session_id))
            .lock_shared()
            .one(&transaction)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::Integrity)?;
        if !allow_revoked && (family.status != "active" || family.absolute_expires_at <= now) {
            return Err(ApplicationError::Disabled);
        }
        let binding = application_user_binding::Entity::find_by_id(session.binding_id)
            .filter(application_user_binding::Column::ProjectId.eq(project_id))
            .filter(application_user_binding::Column::ApplicationId.eq(application_id))
            .filter(application_user_binding::Column::UserId.eq(user_id))
            .filter(application_user_binding::Column::Status.eq("active"))
            .lock_shared()
            .one(&transaction)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::Integrity)?;
        let projection = application_user_projection::Entity::find()
            .filter(application_user_projection::Column::ProjectId.eq(project_id))
            .filter(application_user_projection::Column::BindingId.eq(binding.id))
            .lock_exclusive()
            .one(&transaction)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::Integrity)?;
        let (projection, _) = super::projection::repair_projection(
            &transaction,
            projection,
            &user,
            policy.projection_revision,
            application.projection_revision,
            now,
        )
        .await?;
        let result = CurrentSession {
            project_id,
            project_public_id: project.public_id,
            application_id,
            application_public_id: application.public_id,
            user_id,
            user_public_id: user.public_id,
            application_session_id,
            browser_session_id,
            claims_revision,
            projection_revision: projection.projection_revision,
            projection_document: projection.document,
            authenticated_at: session.authenticated_at,
            absolute_expires_at: session.absolute_expires_at,
        };
        transaction.commit().await.map_err(persistence)?;
        Ok(result)
    }

    async fn browser_logout_context(
        &self,
        preparation: &VersionedDigest,
        now: OffsetDateTime,
    ) -> Result<BrowserLogoutContext, ApplicationError> {
        let interaction = project_browser_logout_interaction::Entity::find()
            .filter(
                project_browser_logout_interaction::Column::PreparationDigest
                    .eq(preparation.value.to_vec()),
            )
            .filter(
                project_browser_logout_interaction::Column::PreparationDigestKeyVersion
                    .eq(preparation.key_version),
            )
            .one(&self.database)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        if interaction.expires_at <= now
            || !matches!(interaction.status.as_str(), "prepared" | "csrf_bound")
            || interaction.preparation_digest.len() != preparation.value.len()
            || !bool::from(
                interaction
                    .preparation_digest
                    .as_slice()
                    .ct_eq(preparation.value.as_slice()),
            )
        {
            return Err(ApplicationError::InvalidTransition);
        }
        let project = project::Entity::find_by_id(interaction.project_id)
            .filter(project::Column::Status.eq("active"))
            .one(&self.database)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        Ok(BrowserLogoutContext {
            project_id: project.id,
            project_public_id: project.public_id,
            interaction_revision: interaction.interaction_revision,
            expires_at: interaction.expires_at,
        })
    }
}

pub(crate) async fn exact_application_origin(
    database: &DatabaseConnection,
    project_id: Uuid,
    application_id: Uuid,
    origin: &str,
) -> Result<bool, ApplicationError> {
    application_origin::Entity::find_by_id((project_id, application_id, origin.to_owned()))
        .one(database)
        .await
        .map_err(persistence)
        .map(|row| row.is_some())
}
