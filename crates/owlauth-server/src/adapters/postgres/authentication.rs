use async_trait::async_trait;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, IntoActiveModel, QueryFilter,
    QuerySelect, Set, TransactionTrait,
};
use subtle::ConstantTimeEq;

use crate::{
    application::{
        AdmittedProviderMethod, ApplicationError, AuthenticationRepository, BindHostedBrowser,
        ClaimProviderCallback, ClaimedProviderExchange, CreateLoginTransaction,
        FailProviderExchange, LoginRevisionSnapshot, LoginTransactionRecord, ProtectedValue,
        SelectProviderMethod, VersionedDigest,
    },
    domain::LoginTransactionStatus,
};

use super::{
    audit::append_runtime_audit,
    entity::{
        application, application_provider_assignment, application_redirect, login_transaction,
        login_transaction_method, project, project_policy, provider_configuration,
    },
};

#[derive(Clone, Debug)]
pub(crate) struct PostgresAuthenticationRepository {
    database: DatabaseConnection,
}

impl PostgresAuthenticationRepository {
    pub(crate) fn new(database: DatabaseConnection) -> Self {
        Self { database }
    }
}

#[async_trait]
#[allow(
    clippy::too_many_lines,
    reason = "each method keeps one security-sensitive PostgreSQL transaction visible"
)]
impl AuthenticationRepository for PostgresAuthenticationRepository {
    async fn create_login_transaction(
        &self,
        command: CreateLoginTransaction,
    ) -> Result<LoginTransactionRecord, ApplicationError> {
        validate_login_command(&command)?;
        let transaction = self.database.begin().await.map_err(persistence)?;

        let project = project::Entity::find_by_id(command.project_id)
            .lock_shared()
            .one(&transaction)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        if project.status != "active" {
            return Err(ApplicationError::Disabled);
        }
        if project.metadata_revision != command.revisions.project_metadata_revision
            || project.security_revision != command.revisions.project_security_revision
        {
            return Err(ApplicationError::RevisionConflict);
        }

        let application = application::Entity::find_by_id(command.application_id)
            .filter(application::Column::ProjectId.eq(command.project_id))
            .lock_shared()
            .one(&transaction)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        if application.status != "active" {
            return Err(ApplicationError::Disabled);
        }
        if application.security_revision != command.revisions.application_security_revision {
            return Err(ApplicationError::RevisionConflict);
        }

        let redirect_exists = application_redirect::Entity::find_by_id((
            command.project_id,
            command.application_id,
            command.redirect_uri.clone(),
        ))
        .lock_shared()
        .one(&transaction)
        .await
        .map_err(persistence)?
        .is_some();
        if !redirect_exists {
            return Err(ApplicationError::InvalidInput);
        }

        let policy = project_policy::Entity::find_by_id(command.project_id)
            .lock_shared()
            .one(&transaction)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::Integrity)?;
        if policy.claims_revision != command.revisions.claims_revision
            || policy.session_revision != command.revisions.session_revision
        {
            return Err(ApplicationError::RevisionConflict);
        }

        let assignments = application_provider_assignment::Entity::find()
            .filter(application_provider_assignment::Column::ProjectId.eq(command.project_id))
            .filter(
                application_provider_assignment::Column::ApplicationId.eq(command.application_id),
            )
            .filter(application_provider_assignment::Column::Status.eq("active"))
            .lock_shared()
            .all(&transaction)
            .await
            .map_err(persistence)?;
        if assignments.len() != command.admitted_providers.len() {
            return Err(ApplicationError::RevisionConflict);
        }

        for method in &command.admitted_providers {
            validate_admitted_provider(method)?;
            let assignment = assignments
                .iter()
                .find(|assignment| assignment.provider_id == method.provider_id)
                .ok_or(ApplicationError::RevisionConflict)?;
            if assignment.security_revision != method.assignment_security_revision {
                return Err(ApplicationError::RevisionConflict);
            }
            let provider = provider_configuration::Entity::find_by_id(method.provider_id)
                .filter(provider_configuration::Column::ProjectId.eq(command.project_id))
                .lock_shared()
                .one(&transaction)
                .await
                .map_err(persistence)?
                .ok_or(ApplicationError::RevisionConflict)?;
            if provider.status != "active"
                || provider.revision != method.provider_revision
                || provider.provider_key != method.method_key
                || provider.display_name != method.display_name
            {
                return Err(ApplicationError::RevisionConflict);
            }
        }

        let model = login_transaction::ActiveModel {
            id: Set(command.id),
            project_id: Set(command.project_id),
            application_id: Set(command.application_id),
            interaction_digest: Set(command.interaction.value.to_vec()),
            interaction_digest_key_version: Set(command.interaction.key_version),
            status: Set(LoginTransactionStatus::AwaitingBrowserBinding
                .as_str()
                .to_owned()),
            transaction_revision: Set(1),
            redirect_uri: Set(command.redirect_uri),
            application_pkce_challenge: Set(command.application_pkce_challenge),
            application_state_ciphertext: Set(command.application_state.ciphertext),
            application_state_key_version: Set(command.application_state.key_version),
            presentation_hint: Set(command.presentation_hint),
            browser_binding_digest: Set(None),
            browser_binding_digest_key_version: Set(None),
            csrf_digest: Set(None),
            csrf_digest_key_version: Set(None),
            selected_method: Set(None),
            provider_configuration_id: Set(None),
            user_id: Set(None),
            callback_url: Set(None),
            upstream_state_digest: Set(None),
            upstream_state_digest_key_version: Set(None),
            oidc_nonce_digest: Set(None),
            oidc_nonce_digest_key_version: Set(None),
            provider_pkce_ciphertext: Set(None),
            provider_pkce_key_version: Set(None),
            project_metadata_revision: Set(command.revisions.project_metadata_revision),
            project_security_revision: Set(command.revisions.project_security_revision),
            application_security_revision: Set(command.revisions.application_security_revision),
            provider_revision: Set(None),
            assignment_security_revision: Set(None),
            claims_revision: Set(command.revisions.claims_revision),
            session_revision: Set(command.revisions.session_revision),
            authenticated_at: Set(None),
            expires_at: Set(command.expires_at),
            terminal_at: Set(None),
            created_at: Set(command.created_at),
            updated_at: Set(command.created_at),
        }
        .insert(&transaction)
        .await
        .map_err(persistence)?;

        if !command.admitted_providers.is_empty() {
            login_transaction_method::Entity::insert_many(
                command.admitted_providers.into_iter().map(|method| {
                    login_transaction_method::ActiveModel {
                        project_id: Set(model.project_id),
                        transaction_id: Set(model.id),
                        method_key: Set(method.method_key),
                        method_kind: Set("provider".to_owned()),
                        provider_configuration_id: Set(Some(method.provider_id)),
                        display_name: Set(method.display_name),
                        provider_revision: Set(Some(method.provider_revision)),
                        assignment_security_revision: Set(Some(
                            method.assignment_security_revision,
                        )),
                        created_at: Set(command.created_at),
                    }
                }),
            )
            .exec(&transaction)
            .await
            .map_err(persistence)?;
        }

        append_runtime_audit(
            &transaction,
            model.project_id,
            "system",
            "auth.login.started",
            "login_transaction",
            Some(model.id),
            model.id,
        )
        .await?;
        transaction.commit().await.map_err(persistence)?;
        login_record(&model)
    }

    async fn bind_hosted_browser(
        &self,
        command: BindHostedBrowser,
    ) -> Result<LoginTransactionRecord, ApplicationError> {
        validate_digest(&command.interaction)?;
        validate_digest(&command.browser_binding)?;
        validate_digest(&command.csrf)?;
        let transaction = self.database.begin().await.map_err(persistence)?;
        let model = login_transaction::Entity::find()
            .filter(
                login_transaction::Column::InteractionDigest.eq(command.interaction.value.to_vec()),
            )
            .filter(
                login_transaction::Column::InteractionDigestKeyVersion
                    .eq(command.interaction.key_version),
            )
            .lock_exclusive()
            .one(&transaction)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        if model.expires_at <= command.now {
            expire_login(&transaction, model, command.now).await?;
            transaction.commit().await.map_err(persistence)?;
            return Err(ApplicationError::InvalidTransition);
        }
        if model.transaction_revision != command.expected_transaction_revision {
            return Err(ApplicationError::RevisionConflict);
        }
        let mut status = parse_login_status(&model.status)?;
        status
            .bind_browser()
            .map_err(|_| ApplicationError::InvalidTransition)?;
        let mut active = model.into_active_model();
        active.status = Set(status.as_str().to_owned());
        active.transaction_revision = Set(command.expected_transaction_revision + 1);
        active.browser_binding_digest = Set(Some(command.browser_binding.value.to_vec()));
        active.browser_binding_digest_key_version = Set(Some(command.browser_binding.key_version));
        active.csrf_digest = Set(Some(command.csrf.value.to_vec()));
        active.csrf_digest_key_version = Set(Some(command.csrf.key_version));
        active.updated_at = Set(command.now);
        let updated = active.update(&transaction).await.map_err(persistence)?;
        append_runtime_audit(
            &transaction,
            updated.project_id,
            "system",
            "auth.login.browser_bound",
            "login_transaction",
            Some(updated.id),
            updated.id,
        )
        .await?;
        transaction.commit().await.map_err(persistence)?;
        login_record(&updated)
    }

    async fn select_provider_method(
        &self,
        command: SelectProviderMethod,
    ) -> Result<LoginTransactionRecord, ApplicationError> {
        validate_digest(&command.browser_binding)?;
        validate_digest(&command.csrf)?;
        validate_digest(&command.upstream_state)?;
        validate_digest(&command.oidc_nonce)?;
        validate_protected(&command.provider_pkce)?;
        let transaction = self.database.begin().await.map_err(persistence)?;
        let model = login_transaction::Entity::find_by_id(command.transaction_id)
            .filter(login_transaction::Column::ProjectId.eq(command.project_id))
            .lock_exclusive()
            .one(&transaction)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        if model.expires_at <= command.now {
            expire_login(&transaction, model, command.now).await?;
            transaction.commit().await.map_err(persistence)?;
            return Err(ApplicationError::InvalidTransition);
        }
        if model.transaction_revision != command.expected_transaction_revision {
            return Err(ApplicationError::RevisionConflict);
        }
        if !optional_digest_matches(
            model.browser_binding_digest.as_deref(),
            model.browser_binding_digest_key_version,
            &command.browser_binding,
        ) || !optional_digest_matches(
            model.csrf_digest.as_deref(),
            model.csrf_digest_key_version,
            &command.csrf,
        ) {
            return Err(ApplicationError::NotFound);
        }
        let mut status = parse_login_status(&model.status)?;
        status
            .select_provider()
            .map_err(|_| ApplicationError::InvalidTransition)?;

        let method = login_transaction_method::Entity::find_by_id((
            command.project_id,
            command.transaction_id,
            command.method_key,
        ))
        .lock_shared()
        .one(&transaction)
        .await
        .map_err(persistence)?
        .ok_or(ApplicationError::InvalidTransition)?;
        if method.method_kind != "provider"
            || method.provider_configuration_id != Some(command.provider_id)
        {
            return Err(ApplicationError::InvalidTransition);
        }
        revalidate_login_owners(&transaction, &model, command.provider_id, &method).await?;
        let provider = provider_configuration::Entity::find_by_id(command.provider_id)
            .filter(provider_configuration::Column::ProjectId.eq(command.project_id))
            .one(&transaction)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::RevisionConflict)?;
        if provider.callback_url != command.callback_url {
            return Err(ApplicationError::InvalidInput);
        }

        let mut active = model.into_active_model();
        active.status = Set(status.as_str().to_owned());
        active.transaction_revision = Set(command.expected_transaction_revision + 1);
        active.selected_method = Set(Some("provider".to_owned()));
        active.provider_configuration_id = Set(Some(command.provider_id));
        active.callback_url = Set(Some(provider.callback_url));
        active.upstream_state_digest = Set(Some(command.upstream_state.value.to_vec()));
        active.upstream_state_digest_key_version = Set(Some(command.upstream_state.key_version));
        active.oidc_nonce_digest = Set(Some(command.oidc_nonce.value.to_vec()));
        active.oidc_nonce_digest_key_version = Set(Some(command.oidc_nonce.key_version));
        active.provider_pkce_ciphertext = Set(Some(command.provider_pkce.ciphertext));
        active.provider_pkce_key_version = Set(Some(command.provider_pkce.key_version));
        active.provider_revision = Set(method.provider_revision);
        active.assignment_security_revision = Set(method.assignment_security_revision);
        active.updated_at = Set(command.now);
        let updated = active.update(&transaction).await.map_err(persistence)?;
        append_runtime_audit(
            &transaction,
            updated.project_id,
            "system",
            "auth.login.provider_selected",
            "login_transaction",
            Some(updated.id),
            updated.id,
        )
        .await?;
        transaction.commit().await.map_err(persistence)?;
        login_record(&updated)
    }

    async fn claim_provider_callback(
        &self,
        command: ClaimProviderCallback,
    ) -> Result<ClaimedProviderExchange, ApplicationError> {
        validate_digest(&command.upstream_state)?;
        validate_digest(&command.browser_binding)?;

        // Resolve the public callback route without taking row locks. Every competing
        // transition locks the login transaction first; owner rows are then fenced in the
        // common order by `revalidate_login_owners`.
        let project = project::Entity::find()
            .filter(project::Column::PublicId.eq(command.project_public_id))
            .one(&self.database)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        let provider = provider_configuration::Entity::find()
            .filter(provider_configuration::Column::ProjectId.eq(project.id))
            .filter(provider_configuration::Column::ProviderKey.eq(command.provider_key))
            .one(&self.database)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;

        let transaction = self.database.begin().await.map_err(persistence)?;
        let model = login_transaction::Entity::find()
            .filter(login_transaction::Column::ProjectId.eq(project.id))
            .filter(login_transaction::Column::ProviderConfigurationId.eq(provider.id))
            .filter(
                login_transaction::Column::UpstreamStateDigest
                    .eq(command.upstream_state.value.to_vec()),
            )
            .filter(
                login_transaction::Column::UpstreamStateDigestKeyVersion
                    .eq(command.upstream_state.key_version),
            )
            .lock_exclusive()
            .one(&transaction)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        if model.expires_at <= command.now {
            expire_login(&transaction, model, command.now).await?;
            transaction.commit().await.map_err(persistence)?;
            return Err(ApplicationError::InvalidTransition);
        }
        if !optional_digest_matches(
            model.browser_binding_digest.as_deref(),
            model.browser_binding_digest_key_version,
            &command.browser_binding,
        ) {
            return Err(ApplicationError::NotFound);
        }
        let mut status = parse_login_status(&model.status)?;
        status
            .claim_provider_callback()
            .map_err(|_| ApplicationError::InvalidTransition)?;
        let method = login_transaction_method::Entity::find_by_id((
            model.project_id,
            model.id,
            provider.provider_key.clone(),
        ))
        .lock_shared()
        .one(&transaction)
        .await
        .map_err(persistence)?
        .ok_or(ApplicationError::Integrity)?;
        revalidate_login_owners(&transaction, &model, provider.id, &method).await?;

        let callback_url = model
            .callback_url
            .clone()
            .ok_or(ApplicationError::Integrity)?;
        let oidc_nonce = VersionedDigest {
            value: digest_array(model.oidc_nonce_digest.as_deref())?,
            key_version: model
                .oidc_nonce_digest_key_version
                .ok_or(ApplicationError::Integrity)?,
        };
        let provider_pkce = ProtectedValue {
            ciphertext: model
                .provider_pkce_ciphertext
                .clone()
                .ok_or(ApplicationError::Integrity)?,
            key_version: model
                .provider_pkce_key_version
                .ok_or(ApplicationError::Integrity)?,
        };
        let next_revision = model.transaction_revision + 1;
        let mut active = model.into_active_model();
        active.status = Set(status.as_str().to_owned());
        active.transaction_revision = Set(next_revision);
        active.updated_at = Set(command.now);
        let updated = active.update(&transaction).await.map_err(persistence)?;
        append_runtime_audit(
            &transaction,
            updated.project_id,
            "system",
            "auth.callback.claimed",
            "login_transaction",
            Some(updated.id),
            updated.id,
        )
        .await?;
        transaction.commit().await.map_err(persistence)?;
        Ok(ClaimedProviderExchange {
            transaction: login_record(&updated)?,
            provider_id: provider.id,
            callback_url,
            oidc_nonce,
            provider_pkce,
        })
    }

    async fn fail_provider_exchange(
        &self,
        command: FailProviderExchange,
    ) -> Result<LoginTransactionRecord, ApplicationError> {
        let transaction = self.database.begin().await.map_err(persistence)?;
        let model = login_transaction::Entity::find_by_id(command.transaction_id)
            .filter(login_transaction::Column::ProjectId.eq(command.project_id))
            .lock_exclusive()
            .one(&transaction)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        if model.transaction_revision != command.expected_transaction_revision {
            return Err(ApplicationError::RevisionConflict);
        }
        let mut status = parse_login_status(&model.status)?;
        status
            .fail_provider_exchange()
            .map_err(ApplicationError::from)?;
        let mut active = model.into_active_model();
        active.status = Set(status.as_str().to_owned());
        active.transaction_revision = Set(command.expected_transaction_revision + 1);
        active.terminal_at = Set(Some(command.now));
        active.updated_at = Set(command.now);
        let updated = active.update(&transaction).await.map_err(persistence)?;
        append_runtime_audit(
            &transaction,
            updated.project_id,
            "system",
            "auth.callback.failed",
            "login_transaction",
            Some(updated.id),
            updated.id,
        )
        .await?;
        transaction.commit().await.map_err(persistence)?;
        login_record(&updated)
    }
}

fn validate_login_command(command: &CreateLoginTransaction) -> Result<(), ApplicationError> {
    validate_digest(&command.interaction)?;
    validate_protected(&command.application_state)?;
    validate_revisions(&command.revisions)?;
    if !is_pkce_s256_challenge(&command.application_pkce_challenge)
        || command.redirect_uri.len() < 8
        || command.admitted_providers.is_empty()
        || command.expires_at != command.created_at + time::Duration::minutes(10)
    {
        return Err(ApplicationError::InvalidInput);
    }
    Ok(())
}

pub(super) fn is_pkce_s256_challenge(value: &str) -> bool {
    value.len() == 43
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn validate_revisions(revisions: &LoginRevisionSnapshot) -> Result<(), ApplicationError> {
    if revisions.project_metadata_revision <= 0
        || revisions.project_security_revision <= 0
        || revisions.application_security_revision <= 0
        || revisions.claims_revision <= 0
        || revisions.session_revision <= 0
    {
        return Err(ApplicationError::InvalidInput);
    }
    Ok(())
}

fn validate_admitted_provider(method: &AdmittedProviderMethod) -> Result<(), ApplicationError> {
    if method.method_key.is_empty()
        || method.display_name.is_empty()
        || method.provider_revision <= 0
        || method.assignment_security_revision <= 0
    {
        return Err(ApplicationError::InvalidInput);
    }
    Ok(())
}

pub(super) fn validate_digest(digest: &VersionedDigest) -> Result<(), ApplicationError> {
    if digest.key_version <= 0 {
        return Err(ApplicationError::InvalidInput);
    }
    Ok(())
}

fn validate_protected(value: &ProtectedValue) -> Result<(), ApplicationError> {
    if value.key_version <= 0 || !(17..=4096).contains(&value.ciphertext.len()) {
        return Err(ApplicationError::InvalidInput);
    }
    Ok(())
}

pub(super) async fn revalidate_login_owners(
    transaction: &sea_orm::DatabaseTransaction,
    login: &login_transaction::Model,
    provider_id: uuid::Uuid,
    method: &login_transaction_method::Model,
) -> Result<(), ApplicationError> {
    let project = project::Entity::find_by_id(login.project_id)
        .lock_shared()
        .one(transaction)
        .await
        .map_err(persistence)?
        .ok_or(ApplicationError::NotFound)?;
    if project.status != "active"
        || project.metadata_revision != login.project_metadata_revision
        || project.security_revision != login.project_security_revision
    {
        return Err(ApplicationError::RevisionConflict);
    }
    let application = application::Entity::find_by_id(login.application_id)
        .filter(application::Column::ProjectId.eq(login.project_id))
        .lock_shared()
        .one(transaction)
        .await
        .map_err(persistence)?
        .ok_or(ApplicationError::NotFound)?;
    if application.status != "active"
        || application.security_revision != login.application_security_revision
    {
        return Err(ApplicationError::RevisionConflict);
    }
    let provider = provider_configuration::Entity::find_by_id(provider_id)
        .filter(provider_configuration::Column::ProjectId.eq(login.project_id))
        .lock_shared()
        .one(transaction)
        .await
        .map_err(persistence)?
        .ok_or(ApplicationError::NotFound)?;
    if provider.status != "active" || Some(provider.revision) != method.provider_revision {
        return Err(ApplicationError::RevisionConflict);
    }
    let assignment = application_provider_assignment::Entity::find_by_id((
        login.project_id,
        login.application_id,
        provider_id,
    ))
    .lock_shared()
    .one(transaction)
    .await
    .map_err(persistence)?
    .ok_or(ApplicationError::RevisionConflict)?;
    if assignment.status != "active"
        || Some(assignment.security_revision) != method.assignment_security_revision
    {
        return Err(ApplicationError::RevisionConflict);
    }
    let policy = project_policy::Entity::find_by_id(login.project_id)
        .lock_shared()
        .one(transaction)
        .await
        .map_err(persistence)?
        .ok_or(ApplicationError::Integrity)?;
    if policy.claims_revision != login.claims_revision
        || policy.session_revision != login.session_revision
    {
        return Err(ApplicationError::RevisionConflict);
    }
    Ok(())
}

pub(super) async fn expire_login(
    transaction: &sea_orm::DatabaseTransaction,
    model: login_transaction::Model,
    now: time::OffsetDateTime,
) -> Result<(), ApplicationError> {
    let status = parse_login_status(&model.status)?;
    if matches!(
        status,
        LoginTransactionStatus::Completed
            | LoginTransactionStatus::ProviderExchangeFailed
            | LoginTransactionStatus::Expired
            | LoginTransactionStatus::Cancelled
    ) {
        return Ok(());
    }
    let project_id = model.project_id;
    let login_id = model.id;
    let next_revision = model.transaction_revision + 1;
    let mut active = model.into_active_model();
    active.status = Set(LoginTransactionStatus::Expired.as_str().to_owned());
    active.transaction_revision = Set(next_revision);
    active.terminal_at = Set(Some(now));
    active.updated_at = Set(now);
    active.update(transaction).await.map_err(persistence)?;
    append_runtime_audit(
        transaction,
        project_id,
        "system",
        "auth.login.expired",
        "login_transaction",
        Some(login_id),
        login_id,
    )
    .await?;
    Ok(())
}

pub(super) fn optional_digest_matches(
    stored: Option<&[u8]>,
    stored_key_version: Option<i32>,
    supplied: &VersionedDigest,
) -> bool {
    stored_key_version == Some(supplied.key_version)
        && stored.is_some_and(|value| {
            value.len() == supplied.value.len()
                && bool::from(value.ct_eq(supplied.value.as_slice()))
        })
}

fn digest_array(value: Option<&[u8]>) -> Result<[u8; 32], ApplicationError> {
    value
        .and_then(|value| value.try_into().ok())
        .ok_or(ApplicationError::Integrity)
}

fn login_record(
    model: &login_transaction::Model,
) -> Result<LoginTransactionRecord, ApplicationError> {
    Ok(LoginTransactionRecord {
        id: model.id,
        project_id: model.project_id,
        application_id: model.application_id,
        status: parse_login_status(&model.status)?,
        transaction_revision: model.transaction_revision,
        expires_at: model.expires_at,
    })
}

pub(super) fn parse_login_status(value: &str) -> Result<LoginTransactionStatus, ApplicationError> {
    match value {
        "awaiting_browser_binding" => Ok(LoginTransactionStatus::AwaitingBrowserBinding),
        "awaiting_method_selection" => Ok(LoginTransactionStatus::AwaitingMethodSelection),
        "provider_authorization_started" => {
            Ok(LoginTransactionStatus::ProviderAuthorizationStarted)
        }
        "provider_exchange_in_progress" => Ok(LoginTransactionStatus::ProviderExchangeInProgress),
        "provider_exchange_failed" => Ok(LoginTransactionStatus::ProviderExchangeFailed),
        "authenticated" => Ok(LoginTransactionStatus::Authenticated),
        "handoff_issued" => Ok(LoginTransactionStatus::HandoffIssued),
        "completed" => Ok(LoginTransactionStatus::Completed),
        "expired" => Ok(LoginTransactionStatus::Expired),
        "cancelled" => Ok(LoginTransactionStatus::Cancelled),
        _ => Err(ApplicationError::Integrity),
    }
}

pub(super) fn persistence(_: sea_orm::DbErr) -> ApplicationError {
    ApplicationError::Persistence
}

#[cfg(test)]
mod tests {
    use std::env;

    use sea_orm::Database;
    use sqlx::postgres::PgPoolOptions;
    use testcontainers::{
        GenericImage, ImageExt,
        core::{IntoContainerPort, WaitFor, wait::LogWaitStrategy},
        runners::AsyncRunner,
    };
    use time::{Duration, OffsetDateTime};
    use uuid::Uuid;

    use super::*;
    use crate::application::{AdmittedProviderMethod, LoginRevisionSnapshot};

    const POSTGRES_PORT: u16 = 5432;
    static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

    fn docker_is_required() -> bool {
        env::var("OWLAUTH_REQUIRE_DOCKER").is_ok_and(|value| value == "1")
    }

    fn digest(value: u8) -> VersionedDigest {
        VersionedDigest {
            value: [value; 32],
            key_version: 1,
        }
    }

    fn protected(value: u8) -> ProtectedValue {
        ProtectedValue {
            ciphertext: vec![value; 32],
            key_version: 1,
        }
    }

    async fn start_postgres() -> Option<(testcontainers::ContainerAsync<GenericImage>, String)> {
        let wait = WaitFor::log(LogWaitStrategy::stderr(
            "database system is ready to accept connections",
        ));
        let container = match GenericImage::new("postgres", "17-bookworm")
            .with_exposed_port(POSTGRES_PORT.tcp())
            .with_wait_for(wait)
            .with_env_var("POSTGRES_DB", "owlauth_auth_test")
            .with_env_var("POSTGRES_USER", "owlauth")
            .with_env_var("POSTGRES_PASSWORD", "owlauth_test")
            .start()
            .await
        {
            Ok(container) => container,
            Err(error) => {
                assert!(
                    !docker_is_required(),
                    "PostgreSQL authentication test container is required: {error}"
                );
                eprintln!("skipping authentication repository test: Docker unavailable: {error}");
                return None;
            }
        };
        let host = container.get_host().await.expect("container host");
        let port = container
            .get_host_port_ipv4(POSTGRES_PORT)
            .await
            .expect("container port");
        Some((
            container,
            format!("postgres://owlauth:owlauth_test@{host}:{port}/owlauth_auth_test"),
        ))
    }

    #[test]
    fn application_pkce_challenge_is_exact_unpadded_base64url() {
        assert!(is_pkce_s256_challenge(&"A".repeat(43)));
        assert!(!is_pkce_s256_challenge(&"A".repeat(42)));
        assert!(!is_pkce_s256_challenge(&format!("{}=", "A".repeat(42))));
        assert!(!is_pkce_s256_challenge(&format!("{}+", "A".repeat(42))));
    }

    #[tokio::test]
    #[allow(
        clippy::too_many_lines,
        reason = "the integration test keeps one complete concurrent login journey readable"
    )]
    async fn login_browser_selection_and_callback_are_one_winner_in_postgres() {
        let Some((_container, url)) = start_postgres().await else {
            return;
        };
        let pool = PgPoolOptions::new()
            .max_connections(8)
            .connect(&url)
            .await
            .expect("test PostgreSQL pool");
        MIGRATOR.run(&pool).await.expect("authentication migration");

        let project_id = Uuid::new_v4();
        let application_id = Uuid::new_v4();
        let provider_id = Uuid::new_v4();
        let callback_url = "https://runtime.example/projects/prj_test01/auth/callback/oidc-main";
        sqlx::query(
            "INSERT INTO projects
                (id, public_id, belongs_to, display_name, status, metadata_revision, security_revision)
             VALUES ($1, 'prj_test01', NULL, 'Test Project', 'active', 1, 1)",
        )
        .bind(project_id)
        .execute(&pool)
        .await
        .expect("seed Project");
        sqlx::query(
            "INSERT INTO applications
                (id, project_id, public_id, display_name, application_type, status,
                 revision, metadata_revision, security_revision)
             VALUES ($1, $2, 'app_test01', 'Test App', 'web', 'active', 1, 1, 1)",
        )
        .bind(application_id)
        .bind(project_id)
        .execute(&pool)
        .await
        .expect("seed Application");
        sqlx::query(
            "INSERT INTO application_redirects
                (project_id, application_id, redirect_uri, redirect_type)
             VALUES ($1, $2, 'https://app.example/callback', 'web')",
        )
        .bind(project_id)
        .bind(application_id)
        .execute(&pool)
        .await
        .expect("seed redirect");
        sqlx::query(
            "INSERT INTO project_policies
                (project_id, claims_revision, session_revision, claims_policy, session_policy)
             VALUES ($1, 1, 1,
                '{\"access_token_lifetime_seconds\":900}'::jsonb,
                '{\"browser_session_reuse\":false,\"browser_session_reuse_max_age_seconds\":28800}'::jsonb)",
        )
        .bind(project_id)
        .execute(&pool)
        .await
        .expect("seed policy");
        sqlx::query(
            "INSERT INTO provider_configurations
                (id, project_id, provider_key, kind, display_name, issuer, client_id,
                 callback_url, secret_ref, status, revision)
             VALUES ($1, $2, 'oidc-main', 'oidc', 'OIDC', 'https://issuer.example',
                 'client', $3, 'secret/ref/oidc-main', 'active', 1)",
        )
        .bind(provider_id)
        .bind(project_id)
        .bind(callback_url)
        .execute(&pool)
        .await
        .expect("seed provider");
        sqlx::query(
            "INSERT INTO application_provider_assignments
                (project_id, application_id, provider_id, status, security_revision)
             VALUES ($1, $2, $3, 'active', 1)",
        )
        .bind(project_id)
        .bind(application_id)
        .bind(provider_id)
        .execute(&pool)
        .await
        .expect("seed assignment");

        let database = Database::connect(&url).await.expect("SeaORM test pool");
        let repository = PostgresAuthenticationRepository::new(database.clone());
        let created_at = OffsetDateTime::now_utc()
            .replace_nanosecond(0)
            .expect("whole-second test time");
        let created = repository
            .create_login_transaction(CreateLoginTransaction {
                id: Uuid::new_v4(),
                project_id,
                application_id,
                interaction: digest(1),
                redirect_uri: "https://app.example/callback".to_owned(),
                application_pkce_challenge: "A".repeat(43),
                application_state: protected(2),
                presentation_hint: None,
                revisions: LoginRevisionSnapshot {
                    project_metadata_revision: 1,
                    project_security_revision: 1,
                    application_security_revision: 1,
                    claims_revision: 1,
                    session_revision: 1,
                },
                created_at,
                expires_at: created_at + Duration::minutes(10),
                admitted_providers: vec![AdmittedProviderMethod {
                    method_key: "oidc-main".to_owned(),
                    provider_id,
                    display_name: "OIDC".to_owned(),
                    provider_revision: 1,
                    assignment_security_revision: 1,
                }],
            })
            .await
            .expect("create generic login");
        assert_eq!(
            created.status,
            LoginTransactionStatus::AwaitingBrowserBinding
        );

        let bind_a = BindHostedBrowser {
            interaction: digest(1),
            expected_transaction_revision: 1,
            browser_binding: digest(3),
            csrf: digest(4),
            now: created_at + Duration::seconds(1),
        };
        let bind_b = BindHostedBrowser {
            browser_binding: digest(5),
            csrf: digest(6),
            ..bind_a.clone()
        };
        let (bound_a, bound_b) = tokio::join!(
            repository.bind_hosted_browser(bind_a),
            repository.bind_hosted_browser(bind_b)
        );
        let (browser_binding, csrf) = match (&bound_a, &bound_b) {
            (Ok(record), Err(_)) => {
                assert_eq!(record.transaction_revision, 2);
                (digest(3), digest(4))
            }
            (Err(_), Ok(record)) => {
                assert_eq!(record.transaction_revision, 2);
                (digest(5), digest(6))
            }
            outcomes => panic!("exactly one browser bind must win: {outcomes:?}"),
        };

        let select_a = SelectProviderMethod {
            project_id,
            transaction_id: created.id,
            expected_transaction_revision: 2,
            method_key: "oidc-main".to_owned(),
            provider_id,
            browser_binding: browser_binding.clone(),
            csrf: csrf.clone(),
            callback_url: callback_url.to_owned(),
            upstream_state: digest(7),
            oidc_nonce: digest(8),
            provider_pkce: protected(9),
            now: created_at + Duration::seconds(2),
        };
        let select_b = SelectProviderMethod {
            upstream_state: digest(10),
            oidc_nonce: digest(11),
            provider_pkce: protected(12),
            ..select_a.clone()
        };
        let (selected_a, selected_b) = tokio::join!(
            repository.select_provider_method(select_a),
            repository.select_provider_method(select_b)
        );
        let upstream_state = match (&selected_a, &selected_b) {
            (Ok(record), Err(_)) => {
                assert_eq!(record.transaction_revision, 3);
                digest(7)
            }
            (Err(_), Ok(record)) => {
                assert_eq!(record.transaction_revision, 3);
                digest(10)
            }
            outcomes => panic!("exactly one provider selection must win: {outcomes:?}"),
        };

        let callback = ClaimProviderCallback {
            project_public_id: "prj_test01".to_owned(),
            provider_key: "oidc-main".to_owned(),
            upstream_state,
            browser_binding,
            now: created_at + Duration::seconds(3),
        };
        let (claimed_a, claimed_b) = tokio::join!(
            repository.claim_provider_callback(callback.clone()),
            repository.claim_provider_callback(callback)
        );
        assert!(
            matches!((&claimed_a, &claimed_b), (Ok(_), Err(_)) | (Err(_), Ok(_))),
            "exactly one callback claim must win: {claimed_a:?} {claimed_b:?}"
        );
        let claimed = claimed_a.or(claimed_b).expect("one callback claim");
        assert_eq!(
            claimed.transaction.status,
            LoginTransactionStatus::ProviderExchangeInProgress
        );
        assert_eq!(claimed.transaction.transaction_revision, 4);
        let failed = repository
            .fail_provider_exchange(FailProviderExchange {
                project_id,
                transaction_id: created.id,
                expected_transaction_revision: 4,
                now: created_at + Duration::seconds(4),
            })
            .await
            .expect("terminalize provider exchange failure");
        assert_eq!(
            failed.status,
            LoginTransactionStatus::ProviderExchangeFailed
        );
        assert_eq!(failed.transaction_revision, 5);
        assert!(
            repository
                .fail_provider_exchange(FailProviderExchange {
                    project_id,
                    transaction_id: created.id,
                    expected_transaction_revision: 5,
                    now: created_at + Duration::seconds(5),
                })
                .await
                .is_err(),
            "terminal exchange failure must not be replayed"
        );

        database.close().await.expect("close SeaORM pool");
        pool.close().await;
    }
}
