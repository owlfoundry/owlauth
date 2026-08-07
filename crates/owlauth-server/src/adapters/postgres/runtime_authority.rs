use std::sync::Arc;

use async_trait::async_trait;
use sea_orm::{
    ColumnTrait, ConnectionTrait, DatabaseConnection, DbBackend, EntityTrait, QueryFilter,
    QueryOrder, QuerySelect, Statement, TransactionTrait,
};
use subtle::ConstantTimeEq;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::{
    application::{
        AccessTokenSessionLookup, AdmittedProviderMethod, ApplicationError, BrowserLogoutContext,
        CurrentSession, HostedInteraction, HostedPendingEmailChallenge, HostedProviderMethod,
        LoginStartContext, ProviderRuntimeContext, RuntimeAuthorityRepository, VerificationKey,
        VersionedDigest,
    },
    domain::{LoginTransactionStatus, ProviderKind},
};

fn validated_login_provider_kind(
    kind: &str,
    issuer: &str,
    managed_profile_enabled: bool,
) -> Result<ProviderKind, ApplicationError> {
    let kind = super::provider_row::effective_provider_kind(kind, issuer)?;
    let capabilities = kind.capabilities();
    if !capabilities.login || (managed_profile_enabled && !capabilities.managed_profile) {
        return Err(ApplicationError::Integrity);
    }
    Ok(kind)
}

use super::{
    auth_incarnation::AuthIncarnationFence,
    authentication::{optional_digest_matches, parse_login_status, persistence},
    entity::{
        application, application_origin, application_provider_assignment,
        application_publishable_key, application_redirect, application_session,
        application_user_binding, application_user_projection, login_transaction,
        login_transaction_method, project, project_browser_logout_interaction,
        project_browser_session, project_key_ring, project_policy, project_provider_egress_policy,
        project_signing_key, project_user, provider_configuration, refresh_family,
    },
    projection::IdentityProjectionMaterializer,
};

#[derive(Clone)]
pub(crate) struct PostgresRuntimeAuthorityRepository {
    database: DatabaseConnection,
    auth_incarnation: AuthIncarnationFence,
    required_auth_process_ids: Vec<String>,
    projection_materializer: Arc<dyn IdentityProjectionMaterializer>,
}

impl PostgresRuntimeAuthorityRepository {
    #[allow(
        dead_code,
        reason = "tests and non-HTTP compositions may omit projection PII authority"
    )]
    pub(crate) fn new_with_runtime_identity(
        database: DatabaseConnection,
        auth_process_id: String,
        auth_incarnation: Uuid,
        required_auth_process_ids: Vec<String>,
        projection_materializer: Arc<dyn IdentityProjectionMaterializer>,
    ) -> Self {
        Self {
            database,
            auth_incarnation: AuthIncarnationFence::new(auth_process_id, auth_incarnation),
            required_auth_process_ids,
            projection_materializer,
        }
    }

    #[cfg(test)]
    pub(crate) fn with_projection_materializer(
        database: DatabaseConnection,
        projection_materializer: Arc<dyn IdentityProjectionMaterializer>,
    ) -> Self {
        Self {
            database,
            auth_incarnation: AuthIncarnationFence::test_default(),
            required_auth_process_ids: vec!["auth-1".to_owned()],
            projection_materializer,
        }
    }

    pub(crate) fn new_with_runtime_identity_and_projection_materializer(
        database: DatabaseConnection,
        auth_process_id: String,
        auth_incarnation: Uuid,
        required_auth_process_ids: Vec<String>,
        projection_materializer: Arc<dyn IdentityProjectionMaterializer>,
    ) -> Self {
        Self {
            database,
            auth_incarnation: AuthIncarnationFence::new(auth_process_id, auth_incarnation),
            required_auth_process_ids,
            projection_materializer,
        }
    }

    async fn lock_local_auth_incarnation<C: ConnectionTrait>(
        &self,
        connection: &C,
    ) -> Result<(), ApplicationError> {
        self.auth_incarnation.lock(connection).await
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
        self.lock_local_auth_incarnation(&transaction).await?;
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
        if assignments.len() > 50 {
            return Err(ApplicationError::Integrity);
        }
        let mut admitted_providers = Vec::with_capacity(assignments.len());
        let mut custom_policy_revision = None;
        for assignment in assignments {
            let provider = provider_configuration::Entity::find_by_id(assignment.provider_id)
                .filter(provider_configuration::Column::ProjectId.eq(project.id))
                .filter(provider_configuration::Column::Status.eq("active"))
                .lock_shared()
                .one(&transaction)
                .await
                .map_err(persistence)?
                .ok_or(ApplicationError::Integrity)?;
            let kind = validated_login_provider_kind(
                &provider.kind,
                &provider.issuer,
                provider.managed_profile_enabled,
            )?;
            let provider_egress_policy_revision = if kind == ProviderKind::Oidc {
                if custom_policy_revision.is_none() {
                    custom_policy_revision = Some(
                        project_provider_egress_policy::Entity::find_by_id(project.id)
                            .lock_shared()
                            .one(&transaction)
                            .await
                            .map_err(persistence)?
                            .ok_or(ApplicationError::Integrity)?
                            .revision,
                    );
                }
                custom_policy_revision
            } else {
                None
            };
            admitted_providers.push(AdmittedProviderMethod {
                kind,
                method_key: provider.provider_key,
                provider_id: provider.id,
                display_name: provider.display_name,
                issuer: provider.issuer,
                provider_revision: provider.revision,
                provider_egress_policy_revision,
                assignment_security_revision: assignment.security_revision,
            });
        }
        let admitted_email = transaction
            .query_one_raw(Statement::from_sql_and_values(
                DbBackend::Postgres,
                "SELECT policy.policy_revision, policy.security_revision, assignment.security_revision AS assignment_security_revision, policy.otp_enabled, policy.magic_link_enabled, policy.otp_digits, policy.otp_validity_seconds, policy.otp_max_attempts, policy.resend_after_seconds, policy.max_generations, policy.magic_validity_seconds, policy.signup_enabled, policy.transferred_magic_link_enabled, CASE WHEN smtp.id IS NOT NULL THEN 'project' ELSE 'deployment_default' END AS smtp_selection_kind, smtp.id AS smtp_configuration_id, COALESCE(smtp.generation, deployment.generation) AS smtp_generation, COALESCE(smtp.security_eligibility_revision, deployment.security_eligibility_revision) AS smtp_security_eligibility_revision FROM project_email_policies policy JOIN application_email_assignments assignment ON assignment.project_id = policy.project_id AND assignment.application_id = $2 LEFT JOIN project_smtp_configurations smtp ON smtp.project_id = policy.project_id AND smtp.status = 'active' LEFT JOIN deployment_smtp_generations deployment ON deployment.status = 'active' AND policy.allow_deployment_default AND smtp.id IS NULL WHERE policy.project_id = $1 AND policy.status = 'enabled' AND assignment.status = 'active' AND EXISTS (SELECT 1 FROM auth_process_incarnations local_runtime WHERE local_runtime.process_id=$4 AND local_runtime.process_incarnation=$5) AND EXISTS (SELECT 1 FROM email_protection_runtime_readiness protection JOIN auth_process_incarnations protection_current ON protection_current.process_id=protection.process_id AND protection_current.process_incarnation=protection.process_incarnation WHERE protection.process_id=$4 AND protection.process_incarnation=$5 AND protection.state='ready' AND protection.lease_expires_at>transaction_timestamp()) AND ((smtp.id IS NOT NULL AND NOT EXISTS (SELECT required.process_id FROM jsonb_array_elements_text($3::jsonb) AS required(process_id) WHERE NOT EXISTS (SELECT 1 FROM project_smtp_runtime_readiness readiness WHERE readiness.project_id=smtp.project_id AND readiness.configuration_id=smtp.id AND readiness.generation=smtp.generation AND readiness.process_id=required.process_id AND readiness.state='ready' AND readiness.lease_expires_at>transaction_timestamp() AND EXISTS (SELECT 1 FROM auth_process_incarnations current WHERE current.process_id=readiness.process_id AND current.process_incarnation=readiness.process_incarnation)))) OR (smtp.id IS NULL AND deployment.generation IS NOT NULL))",
                vec![
                    project.id.into(),
                    application.id.into(),
                    serde_json::json!(self.required_auth_process_ids).into(),
                    self.auth_incarnation.process_id().to_owned().into(),
                    self.auth_incarnation.incarnation().into(),
                ],
            ))
            .await
            .map_err(persistence)?
            .map(|row| -> Result<crate::application::AdmittedEmailMethod, ApplicationError> {
                Ok(crate::application::AdmittedEmailMethod {
                    policy_revision: row.try_get("", "policy_revision").map_err(persistence)?,
                    security_revision: row.try_get("", "security_revision").map_err(persistence)?,
                    assignment_security_revision: row.try_get("", "assignment_security_revision").map_err(persistence)?,
                    otp_enabled: row.try_get("", "otp_enabled").map_err(persistence)?,
                    magic_link_enabled: row.try_get("", "magic_link_enabled").map_err(persistence)?,
                    otp_digits: row.try_get("", "otp_digits").map_err(persistence)?,
                    otp_validity_seconds: row.try_get("", "otp_validity_seconds").map_err(persistence)?,
                    otp_max_attempts: row.try_get("", "otp_max_attempts").map_err(persistence)?,
                    resend_after_seconds: row.try_get("", "resend_after_seconds").map_err(persistence)?,
                    max_generations: row.try_get("", "max_generations").map_err(persistence)?,
                    magic_validity_seconds: row.try_get("", "magic_validity_seconds").map_err(persistence)?,
                    signup_enabled: row.try_get("", "signup_enabled").map_err(persistence)?,
                    transferred_magic_link_enabled: row.try_get("", "transferred_magic_link_enabled").map_err(persistence)?,
                    smtp_selection_kind: row.try_get("", "smtp_selection_kind").map_err(persistence)?,
                    smtp_configuration_id: row.try_get("", "smtp_configuration_id").map_err(persistence)?,
                    smtp_generation: row.try_get("", "smtp_generation").map_err(persistence)?,
                    smtp_security_eligibility_revision: row.try_get("", "smtp_security_eligibility_revision").map_err(persistence)?,
                })
            })
            .transpose()?;
        if admitted_providers.is_empty() && admitted_email.is_none() {
            return Err(ApplicationError::Disabled);
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
            admitted_email,
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
        self.lock_local_auth_incarnation(&transaction).await?;
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
            .order_by_asc(login_transaction_method::Column::MethodKey)
            .limit(51)
            .all(&transaction)
            .await
            .map_err(persistence)?;
        if methods.is_empty() || methods.len() > 50 {
            return Err(ApplicationError::Integrity);
        }
        let email_method_recorded = methods.iter().any(|method| method.method_kind == "email");
        let (email_available, email_otp_enabled, email_magic_link_enabled) =
            if email_method_recorded {
                let snapshot = transaction
                    .query_one_raw(Statement::from_sql_and_values(
                        DbBackend::Postgres,
                        "SELECT snapshot.otp_enabled,snapshot.magic_link_enabled,
                                CASE WHEN snapshot.smtp_selection_kind='deployment_default' THEN TRUE
                                     ELSE NOT EXISTS (
                                       SELECT required.process_id
                                       FROM jsonb_array_elements_text($3::jsonb) AS required(process_id)
                                       WHERE NOT EXISTS (
                                         SELECT 1 FROM project_smtp_runtime_readiness readiness
                                         WHERE readiness.project_id=snapshot.project_id
                                           AND readiness.configuration_id=snapshot.smtp_configuration_id
                                           AND readiness.generation=snapshot.smtp_generation
                                           AND readiness.process_id=required.process_id
                                           AND readiness.state='ready'
                                           AND readiness.lease_expires_at>$4
                                           AND EXISTS (
                                             SELECT 1 FROM auth_process_incarnations current
                                             WHERE current.process_id=readiness.process_id
                                               AND current.process_incarnation=readiness.process_incarnation)))
                                     AND EXISTS (
                                       SELECT 1 FROM auth_process_incarnations local_runtime
                                       WHERE local_runtime.process_id=$5
                                         AND local_runtime.process_incarnation=$6)
                                     AND EXISTS (
                                       SELECT 1 FROM email_protection_runtime_readiness protection
                                       JOIN auth_process_incarnations protection_current
                                         ON protection_current.process_id=protection.process_id
                                        AND protection_current.process_incarnation=protection.process_incarnation
                                       WHERE protection.process_id=$5
                                         AND protection.process_incarnation=$6
                                         AND protection.state='ready'
                                         AND protection.lease_expires_at>$4) END AS smtp_ready
                         FROM login_email_method_snapshots snapshot
                         WHERE snapshot.project_id=$1 AND snapshot.transaction_id=$2",
                        vec![
                            login.project_id.into(),
                            login.id.into(),
                            serde_json::json!(self.required_auth_process_ids).into(),
                            now.into(),
                            self.auth_incarnation.process_id().to_owned().into(),
                            self.auth_incarnation.incarnation().into()
                        ],
                    ))
                    .await
                    .map_err(persistence)?
                    .ok_or(ApplicationError::Integrity)?;
                let smtp_ready: bool = snapshot.try_get("", "smtp_ready").map_err(persistence)?;
                let otp: bool = snapshot.try_get("", "otp_enabled").map_err(persistence)?;
                let magic: bool = snapshot
                    .try_get("", "magic_link_enabled")
                    .map_err(persistence)?;
                (smtp_ready, smtp_ready && otp, smtp_ready && magic)
            } else {
                (false, false, false)
            };
        if email_method_recorded
            && !email_otp_enabled
            && !email_magic_link_enabled
            && email_available
        {
            return Err(ApplicationError::Integrity);
        }
        if !email_available
            && !methods
                .iter()
                .any(|method| method.method_kind == "provider")
        {
            return Err(ApplicationError::Disabled);
        }
        let pending_email_challenge = if status == LoginTransactionStatus::EmailChallengePending {
            let challenge = transaction
                .query_one_raw(Statement::from_sql_and_values(
                    DbBackend::Postgres,
                    "SELECT id,generation,status,expires_at,\
                            (otp_digest IS NOT NULL AND otp_expires_at>$3) AS otp_available,\
                            (magic_digest IS NOT NULL AND magic_expires_at>$3) AS magic_link_available \
                     FROM email_challenges \
                     WHERE project_id=$1 AND transaction_id=$2 AND owner_kind='login' \
                     ORDER BY generation DESC LIMIT 1",
                    vec![login.project_id.into(), login.id.into(), now.into()],
                ))
                .await
                .map_err(persistence)?
                .ok_or(ApplicationError::Integrity)?;
            let challenge_status: String = challenge.try_get("", "status").map_err(persistence)?;
            let expires_at: OffsetDateTime =
                challenge.try_get("", "expires_at").map_err(persistence)?;
            let otp_available: bool = challenge
                .try_get("", "otp_available")
                .map_err(persistence)?;
            let magic_link_available: bool = challenge
                .try_get("", "magic_link_available")
                .map_err(persistence)?;
            if challenge_status != "pending"
                || expires_at <= now
                || (!otp_available && !magic_link_available)
            {
                return Err(ApplicationError::Integrity);
            }
            Some(HostedPendingEmailChallenge {
                challenge_id: challenge.try_get("", "id").map_err(persistence)?,
                generation: challenge.try_get("", "generation").map_err(persistence)?,
                otp_available,
                magic_link_available,
                expires_at,
            })
        } else {
            None
        };
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
                .filter(|method| method.method_kind == "provider")
                .map(|method| {
                    let kind = match method.provider_kind.as_deref() {
                        Some("oidc") => crate::domain::ProviderKind::Oidc,
                        Some("google") => crate::domain::ProviderKind::Google,
                        Some("github") => crate::domain::ProviderKind::Github,
                        _ => return Err(ApplicationError::Integrity),
                    };
                    Ok(HostedProviderMethod {
                        key: method.method_key,
                        display_name: method.display_name,
                        kind,
                    })
                })
                .collect::<Result<Vec<_>, ApplicationError>>()?,
            email_available,
            email_otp_enabled,
            email_magic_link_enabled,
            pending_email_challenge,
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
        self.lock_local_auth_incarnation(&transaction).await?;
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
        {
            return Err(ApplicationError::RevisionConflict);
        }
        let provider_kind = validated_login_provider_kind(
            &provider.kind,
            &provider.issuer,
            provider.managed_profile_enabled,
        )?;
        if method.provider_kind.as_deref() != Some(provider_kind.as_str()) {
            return Err(ApplicationError::Integrity);
        }
        let egress_policy = if provider_kind == ProviderKind::Oidc {
            let expected_revision = method
                .provider_egress_policy_revision
                .ok_or(ApplicationError::Integrity)?;
            let policy = project_provider_egress_policy::Entity::find_by_id(project_id)
                .lock_shared()
                .one(&transaction)
                .await
                .map_err(persistence)?
                .ok_or(ApplicationError::Integrity)?;
            if policy.revision != expected_revision {
                return Err(ApplicationError::RevisionConflict);
            }
            Some(super::provider_row::decode_provider_egress_policy(
                &policy.mode,
                policy.exact_origins,
            )?)
        } else {
            if method.provider_egress_policy_revision.is_some() {
                return Err(ApplicationError::Integrity);
            }
            None
        };
        let result = ProviderRuntimeContext {
            project_id,
            provider_kind,
            transaction_id,
            provider_id: provider.id,
            provider_key: provider.provider_key,
            issuer: provider.issuer,
            client_id: provider.client_id,
            callback_url: provider.callback_url,
            secret_material_id: provider.secret_material_id,
            managed_profile_enabled: provider.managed_profile_enabled,
            managed_profile_revision: provider.managed_profile_revision,
            egress_policy,
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
        let transaction = self.database.begin().await.map_err(persistence)?;
        self.lock_local_auth_incarnation(&transaction).await?;
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
        let result = (project.id, application.id);
        transaction.commit().await.map_err(persistence)?;
        Ok(result)
    }

    async fn resolve_public_application(
        &self,
        project_public_id: &str,
        application_public_id: &str,
    ) -> Result<(Uuid, Uuid), ApplicationError> {
        let transaction = self.database.begin().await.map_err(persistence)?;
        self.lock_local_auth_incarnation(&transaction).await?;
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
        let result = (project.id, application.id);
        transaction.commit().await.map_err(persistence)?;
        Ok(result)
    }

    async fn exact_application_origin(
        &self,
        project_id: Uuid,
        application_id: Uuid,
        origin: &str,
    ) -> Result<bool, ApplicationError> {
        let transaction = self.database.begin().await.map_err(persistence)?;
        self.lock_local_auth_incarnation(&transaction).await?;
        let project = project::Entity::find_by_id(project_id)
            .filter(project::Column::Status.eq("active"))
            .lock_shared()
            .one(&transaction)
            .await
            .map_err(persistence)?;
        let application = application::Entity::find_by_id(application_id)
            .filter(application::Column::ProjectId.eq(project_id))
            .filter(application::Column::Status.eq("active"))
            .lock_shared()
            .one(&transaction)
            .await
            .map_err(persistence)?;
        let result = if project.is_some() && application.is_some() {
            exact_application_origin(&transaction, project_id, application_id, origin).await?
        } else {
            false
        };
        transaction.commit().await.map_err(persistence)?;
        Ok(result)
    }

    async fn project_origin_allowed(
        &self,
        project_public_id: &str,
        origin: &str,
    ) -> Result<bool, ApplicationError> {
        let transaction = self.database.begin().await.map_err(persistence)?;
        self.lock_local_auth_incarnation(&transaction).await?;
        let project = project::Entity::find()
            .filter(project::Column::PublicId.eq(project_public_id))
            .filter(project::Column::Status.eq("active"))
            .lock_shared()
            .one(&transaction)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        // Origins are not globally unique within a Project. Authorize when any exact owner is
        // active; never route through an arbitrary disabled sibling application.
        let result = transaction
            .query_one_raw(Statement::from_sql_and_values(
                DbBackend::Postgres,
                "SELECT application.id
                 FROM applications application
                 JOIN application_origins origin
                   ON origin.project_id=application.project_id
                  AND origin.application_id=application.id
                 WHERE application.project_id=$1 AND application.status='active'
                   AND origin.origin=$2
                 ORDER BY application.id LIMIT 1
                 FOR SHARE OF application,origin",
                vec![project.id.into(), origin.to_owned().into()],
            ))
            .await
            .map_err(persistence)?
            .is_some();
        transaction.commit().await.map_err(persistence)?;
        Ok(result)
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
        let transaction = self.database.begin().await.map_err(persistence)?;
        self.lock_local_auth_incarnation(&transaction).await?;
        let Some(project) = project::Entity::find_by_id(project_id)
            .lock_shared()
            .one(&transaction)
            .await
            .map_err(persistence)?
        else {
            transaction.commit().await.map_err(persistence)?;
            return Ok(false);
        };
        let Some(policy) = project_policy::Entity::find_by_id(project_id)
            .lock_shared()
            .one(&transaction)
            .await
            .map_err(persistence)?
        else {
            transaction.commit().await.map_err(persistence)?;
            return Ok(false);
        };
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
            .lock_shared()
            .one(&transaction)
            .await
            .map_err(persistence)?
        else {
            transaction.commit().await.map_err(persistence)?;
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
            transaction.commit().await.map_err(persistence)?;
            return Ok(false);
        }
        let Some(user) = project_user::Entity::find_by_id(session.user_id)
            .filter(project_user::Column::ProjectId.eq(project_id))
            .lock_shared()
            .one(&transaction)
            .await
            .map_err(persistence)?
        else {
            transaction.commit().await.map_err(persistence)?;
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
        let result = project.status == "active"
            && user.status == "active"
            && session.project_security_revision == project.security_revision
            && session.user_security_revision == user.security_revision
            && session.policy_session_revision == policy.session_revision
            && reuse_enabled
            && reuse_max_age.is_some_and(|seconds| {
                now - session.authenticated_at <= Duration::seconds(seconds)
            });
        transaction.commit().await.map_err(persistence)?;
        Ok(result)
    }

    async fn verification_key(
        &self,
        project_public_id: &str,
        kid: &str,
        now: OffsetDateTime,
    ) -> Result<VerificationKey, ApplicationError> {
        let transaction = self.database.begin().await.map_err(persistence)?;
        self.lock_local_auth_incarnation(&transaction).await?;
        let project = project::Entity::find()
            .filter(project::Column::PublicId.eq(project_public_id))
            .filter(project::Column::Status.eq("active"))
            .lock_shared()
            .one(&transaction)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        let ring = project_key_ring::Entity::find()
            .filter(project_key_ring::Column::ProjectId.eq(project.id))
            .filter(project_key_ring::Column::Purpose.eq("application_tokens"))
            .filter(project_key_ring::Column::Algorithm.eq("EdDSA"))
            .lock_shared()
            .one(&transaction)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        let key = project_signing_key::Entity::find()
            .filter(project_signing_key::Column::ProjectId.eq(project.id))
            .filter(project_signing_key::Column::RingId.eq(ring.id))
            .filter(project_signing_key::Column::Kid.eq(kid))
            .lock_shared()
            .one(&transaction)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        let usable = key.state == "active"
            || (key.state == "retiring" && key.verify_not_after.is_some_and(|cutoff| cutoff > now));
        if !usable {
            return Err(ApplicationError::Disabled);
        }
        let result = VerificationKey {
            project_id: project.id,
            project_public_id: project.public_id,
            issuer: ring.issuer,
            public_jwk: key.public_jwk,
        };
        transaction.commit().await.map_err(persistence)?;
        Ok(result)
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
        self.lock_local_auth_incarnation(&transaction).await?;
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
        let (_projection, material) = super::projection::repair_runtime_projection(
            &transaction,
            projection,
            application.id,
            &user,
            self.projection_materializer.as_ref(),
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
            projection_revision: material.revision,
            projection_document: material.document,
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
        let routed_interaction = project_browser_logout_interaction::Entity::find()
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
            .map_err(persistence)?;
        let transaction = self.database.begin().await.map_err(persistence)?;
        self.lock_local_auth_incarnation(&transaction).await?;
        let routed_interaction = routed_interaction.ok_or(ApplicationError::NotFound)?;
        let project = project::Entity::find_by_id(routed_interaction.project_id)
            .filter(project::Column::Status.eq("active"))
            .lock_shared()
            .one(&transaction)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        let interaction =
            project_browser_logout_interaction::Entity::find_by_id(routed_interaction.id)
                .filter(
                    project_browser_logout_interaction::Column::ProjectId
                        .eq(routed_interaction.project_id),
                )
                .filter(
                    project_browser_logout_interaction::Column::PreparationDigest
                        .eq(preparation.value.to_vec()),
                )
                .filter(
                    project_browser_logout_interaction::Column::PreparationDigestKeyVersion
                        .eq(preparation.key_version),
                )
                .lock_shared()
                .one(&transaction)
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
        let result = BrowserLogoutContext {
            project_id: project.id,
            project_public_id: project.public_id,
            interaction_revision: interaction.interaction_revision,
            expires_at: interaction.expires_at,
        };
        transaction.commit().await.map_err(persistence)?;
        Ok(result)
    }
}

pub(crate) async fn exact_application_origin<C: ConnectionTrait>(
    connection: &C,
    project_id: Uuid,
    application_id: Uuid,
    origin: &str,
) -> Result<bool, ApplicationError> {
    application_origin::Entity::find_by_id((project_id, application_id, origin.to_owned()))
        .lock_shared()
        .one(connection)
        .await
        .map_err(persistence)
        .map(|row| row.is_some())
}
