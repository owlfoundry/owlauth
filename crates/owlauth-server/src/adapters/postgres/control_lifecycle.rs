use std::{collections::BTreeMap, sync::Arc};

use async_trait::async_trait;
use sea_orm::sea_query::LockType;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, DatabaseConnection, DbBackend, EntityTrait,
    IntoActiveModel, QueryFilter, QueryOrder, QueryResult, QuerySelect, Set, Statement,
    TransactionTrait,
};
use uuid::Uuid;

use crate::application::{
    ApplicationError, ApplicationSessionRecord, BrowserSessionRecord, ControlLifecyclePort,
    DisableProjectUser, ManagedSessionStatus, ProjectUserIdentityKind, ProjectUserIdentityRecord,
    ProjectUserIdentityStatus, ProjectUserRecord, ProjectUserSessions, ProjectUserStatus,
    RevokeApplicationSession, RevokeBrowserSession,
};

use super::{
    audit::append_runtime_audit,
    authentication::persistence,
    entity::{application, application_session, project, project_browser_session, project_user},
    projection::IdentityProjectionMaterializer,
};

#[derive(Clone)]
pub(crate) struct PostgresControlLifecycleRepository {
    database: DatabaseConnection,
    projection_materializer: Option<Arc<dyn IdentityProjectionMaterializer>>,
}

impl PostgresControlLifecycleRepository {
    #[cfg(test)]
    pub(crate) fn new(database: DatabaseConnection) -> Self {
        Self {
            database,
            projection_materializer: None,
        }
    }

    pub(crate) fn new_with_projection_materializer(
        database: DatabaseConnection,
        projection_materializer: Arc<dyn IdentityProjectionMaterializer>,
    ) -> Self {
        Self {
            database,
            projection_materializer: Some(projection_materializer),
        }
    }

    async fn fan_out_user(
        &self,
        transaction: &sea_orm::DatabaseTransaction,
        user: &project_user::Model,
        now: time::OffsetDateTime,
    ) -> Result<(), ApplicationError> {
        if let Some(materializer) = &self.projection_materializer {
            materializer.fan_out_user(transaction, user, now).await
        } else {
            #[cfg(test)]
            {
                super::projection::fan_out_user_projections(transaction, user, now).await
            }
            #[cfg(not(test))]
            {
                Err(ApplicationError::Integrity)
            }
        }
    }
}

#[async_trait]
impl ControlLifecyclePort for PostgresControlLifecycleRepository {
    async fn list_project_users(
        &self,
        project_id: Uuid,
        limit: usize,
    ) -> Result<Vec<ProjectUserRecord>, ApplicationError> {
        bounded_limit(limit)?;
        require_project(&self.database, project_id).await?;
        let users = project_user::Entity::find()
            .filter(project_user::Column::ProjectId.eq(project_id))
            .order_by_asc(project_user::Column::CreatedAt)
            .order_by_asc(project_user::Column::Id)
            .limit((limit + 1) as u64)
            .all(&self.database)
            .await
            .map_err(persistence)?;
        enforce_bound(&users, limit)?;
        users.into_iter().map(project_user_record).collect()
    }

    async fn get_project_user(
        &self,
        project_id: Uuid,
        user_id: Uuid,
    ) -> Result<ProjectUserRecord, ApplicationError> {
        require_project(&self.database, project_id).await?;
        project_user::Entity::find_by_id(user_id)
            .filter(project_user::Column::ProjectId.eq(project_id))
            .one(&self.database)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)
            .and_then(project_user_record)
    }

    async fn list_project_user_identities(
        &self,
        project_id: Uuid,
        user_id: Uuid,
        limit: usize,
    ) -> Result<Vec<ProjectUserIdentityRecord>, ApplicationError> {
        bounded_limit(limit)?;
        require_project_user(&self.database, project_id, user_id).await?;
        let probe_limit = i64::try_from(limit)
            .ok()
            .and_then(|value| value.checked_add(1))
            .ok_or(ApplicationError::InvalidInput)?;
        // This SELECT is intentionally a closed safe-column allowlist. In particular, it does
        // not read issuer, subject, address ciphertext, aliases/digests, client/secret material,
        // credentials, receipts, or candidate evidence.
        let rows = self
            .database
            .query_all_raw(Statement::from_sql_and_values(
                DbBackend::Postgres,
                "SELECT identity_id, project_id, user_id, identity_kind, status,
                        identity_revision, is_primary_source, provider_key,
                        verified_or_observed_at, created_at, updated_at
                   FROM (
                     SELECT identity.id AS identity_id, identity.project_id, identity.user_id,
                            'provider'::TEXT AS identity_kind, identity.status,
                            identity.identity_revision,
                            (user_record.primary_source_kind='provider'
                             AND user_record.primary_profile_identity_id=identity.id)
                                AS is_primary_source,
                            provider.provider_key AS provider_key,
                            identity.observed_at AS verified_or_observed_at,
                            identity.created_at, identity.updated_at
                       FROM linked_identities AS identity
                       JOIN project_users AS user_record
                         ON user_record.project_id=identity.project_id
                        AND user_record.id=identity.user_id
                       JOIN provider_configurations AS provider
                         ON provider.project_id=identity.project_id
                        AND provider.id=identity.created_via_provider_configuration_id
                      WHERE identity.project_id=$1 AND identity.user_id=$2
                     UNION ALL
                     SELECT identity.id, identity.project_id, identity.user_id,
                            'email'::TEXT, identity.status, identity.identity_revision,
                            (user_record.primary_source_kind='email'
                             AND user_record.primary_email_identity_id=identity.id),
                            NULL::TEXT, identity.verified_at,
                            identity.created_at, identity.updated_at
                       FROM email_identities AS identity
                       JOIN project_users AS user_record
                         ON user_record.project_id=identity.project_id
                        AND user_record.id=identity.user_id
                      WHERE identity.project_id=$1 AND identity.user_id=$2
                   ) AS safe_identities
                  ORDER BY created_at, identity_id, identity_kind
                  LIMIT $3",
                [project_id.into(), user_id.into(), probe_limit.into()],
            ))
            .await
            .map_err(persistence)?;
        enforce_bound(&rows, limit)?;
        rows.iter().map(project_user_identity_record).collect()
    }

    async fn disable_project_user(
        &self,
        command: DisableProjectUser,
    ) -> Result<ProjectUserRecord, ApplicationError> {
        let transaction = self.database.begin().await.map_err(persistence)?;
        lock_active_project(&transaction, command.project_id).await?;
        let user = project_user::Entity::find_by_id(command.user_id)
            .filter(project_user::Column::ProjectId.eq(command.project_id))
            .lock(LockType::Update)
            .one(&transaction)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        if user.security_revision != command.expected_security_revision {
            return Err(ApplicationError::RevisionConflict);
        }
        let user = match user.status.as_str() {
            "active" => {
                let mut active = user.into_active_model();
                active.status = Set("disabled".to_owned());
                active.user_revision = Set(next_revision(active.user_revision.take())?);
                active.security_revision = Set(next_revision(active.security_revision.take())?);
                active.updated_at = Set(command.now);
                let updated = active.update(&transaction).await.map_err(persistence)?;
                self.fan_out_user(&transaction, &updated, command.now)
                    .await?;
                append_runtime_audit(
                    &transaction,
                    command.project_id,
                    "deployment_operator",
                    "project_user.disabled",
                    "project_user",
                    Some(command.user_id),
                    command.correlation_id,
                )
                .await?;
                updated
            }
            "disabled" => user,
            _ => return Err(ApplicationError::Integrity),
        };
        transaction.commit().await.map_err(persistence)?;
        project_user_record(user)
    }

    async fn list_project_user_sessions(
        &self,
        project_id: Uuid,
        user_id: Uuid,
        limit: usize,
        now: time::OffsetDateTime,
    ) -> Result<ProjectUserSessions, ApplicationError> {
        bounded_limit(limit)?;
        require_user(&self.database, project_id, user_id).await?;
        let application_sessions = application_session::Entity::find()
            .filter(application_session::Column::ProjectId.eq(project_id))
            .filter(application_session::Column::UserId.eq(user_id))
            .order_by_desc(application_session::Column::CreatedAt)
            .order_by_asc(application_session::Column::Id)
            .limit((limit + 1) as u64)
            .all(&self.database)
            .await
            .map_err(persistence)?;
        enforce_bound(&application_sessions, limit)?;
        let browser_sessions = project_browser_session::Entity::find()
            .filter(project_browser_session::Column::ProjectId.eq(project_id))
            .filter(project_browser_session::Column::UserId.eq(user_id))
            .order_by_desc(project_browser_session::Column::CreatedAt)
            .order_by_asc(project_browser_session::Column::Id)
            .limit((limit + 1) as u64)
            .all(&self.database)
            .await
            .map_err(persistence)?;
        enforce_bound(&browser_sessions, limit)?;

        let application_ids = application_sessions
            .iter()
            .map(|session| session.application_id)
            .collect::<Vec<_>>();
        let applications = if application_ids.is_empty() {
            Vec::new()
        } else {
            application::Entity::find()
                .filter(application::Column::ProjectId.eq(project_id))
                .filter(application::Column::Id.is_in(application_ids))
                .all(&self.database)
                .await
                .map_err(persistence)?
        };
        let applications = applications
            .into_iter()
            .map(|application| (application.id, application))
            .collect::<BTreeMap<_, _>>();

        Ok(ProjectUserSessions {
            application_sessions: application_sessions
                .into_iter()
                .map(|session| {
                    let application = applications
                        .get(&session.application_id)
                        .ok_or(ApplicationError::Integrity)?;
                    application_session_record(&session, application, now)
                })
                .collect::<Result<_, _>>()?,
            browser_sessions: browser_sessions
                .into_iter()
                .map(|session| browser_session_record(&session, now))
                .collect::<Result<_, _>>()?,
        })
    }

    async fn revoke_application_session(
        &self,
        command: RevokeApplicationSession,
    ) -> Result<ApplicationSessionRecord, ApplicationError> {
        let transaction = self.database.begin().await.map_err(persistence)?;
        require_user(&transaction, command.project_id, command.user_id).await?;
        let session = application_session::Entity::find_by_id(command.session_id)
            .filter(application_session::Column::ProjectId.eq(command.project_id))
            .filter(application_session::Column::UserId.eq(command.user_id))
            .lock(LockType::Update)
            .one(&transaction)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        if session.session_revision != command.expected_session_revision {
            return Err(ApplicationError::RevisionConflict);
        }
        let session = match session.status.as_str() {
            "active" => {
                let mut active = session.into_active_model();
                active.status = Set("revoked".to_owned());
                active.session_revision = Set(next_revision(active.session_revision.take())?);
                active.revoked_at = Set(Some(command.now));
                active.updated_at = Set(command.now);
                let updated = active.update(&transaction).await.map_err(persistence)?;
                append_runtime_audit(
                    &transaction,
                    command.project_id,
                    "deployment_operator",
                    "application_session.revoked",
                    "application_session",
                    Some(command.session_id),
                    command.correlation_id,
                )
                .await?;
                updated
            }
            "revoked" => session,
            _ => return Err(ApplicationError::Integrity),
        };
        let application = application::Entity::find_by_id(session.application_id)
            .filter(application::Column::ProjectId.eq(command.project_id))
            .one(&transaction)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::Integrity)?;
        transaction.commit().await.map_err(persistence)?;
        application_session_record(&session, &application, command.now)
    }

    async fn revoke_browser_session(
        &self,
        command: RevokeBrowserSession,
    ) -> Result<BrowserSessionRecord, ApplicationError> {
        let transaction = self.database.begin().await.map_err(persistence)?;
        require_user(&transaction, command.project_id, command.user_id).await?;
        let session = project_browser_session::Entity::find_by_id(command.session_id)
            .filter(project_browser_session::Column::ProjectId.eq(command.project_id))
            .filter(project_browser_session::Column::UserId.eq(command.user_id))
            .lock(LockType::Update)
            .one(&transaction)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        if session.session_revision != command.expected_session_revision {
            return Err(ApplicationError::RevisionConflict);
        }
        let session = match session.status.as_str() {
            "active" => {
                let mut active = session.into_active_model();
                active.status = Set("terminated".to_owned());
                active.session_revision = Set(next_revision(active.session_revision.take())?);
                active.terminated_at = Set(Some(command.now));
                active.updated_at = Set(command.now);
                let updated = active.update(&transaction).await.map_err(persistence)?;
                append_runtime_audit(
                    &transaction,
                    command.project_id,
                    "deployment_operator",
                    "project_browser_session.revoked",
                    "project_browser_session",
                    Some(command.session_id),
                    command.correlation_id,
                )
                .await?;
                updated
            }
            "terminated" => session,
            _ => return Err(ApplicationError::Integrity),
        };
        transaction.commit().await.map_err(persistence)?;
        browser_session_record(&session, command.now)
    }
}

fn bounded_limit(limit: usize) -> Result<(), ApplicationError> {
    if !(1..=100).contains(&limit) {
        return Err(ApplicationError::InvalidInput);
    }
    Ok(())
}

fn enforce_bound<T>(items: &[T], limit: usize) -> Result<(), ApplicationError> {
    if items.len() > limit {
        return Err(ApplicationError::Integrity);
    }
    Ok(())
}

fn next_revision(revision: Option<i64>) -> Result<i64, ApplicationError> {
    revision
        .filter(|revision| *revision > 0)
        .and_then(|revision| revision.checked_add(1))
        .ok_or(ApplicationError::Integrity)
}

async fn require_project_user<C>(
    database: &C,
    project_id: Uuid,
    user_id: Uuid,
) -> Result<(), ApplicationError>
where
    C: ConnectionTrait,
{
    project_user::Entity::find_by_id(user_id)
        .filter(project_user::Column::ProjectId.eq(project_id))
        .one(database)
        .await
        .map_err(persistence)?
        .map(|_| ())
        .ok_or(ApplicationError::NotFound)
}

async fn lock_active_project<C>(
    database: &C,
    project_id: Uuid,
) -> Result<project::Model, ApplicationError>
where
    C: ConnectionTrait,
{
    let project = project::Entity::find_by_id(project_id)
        .lock_shared()
        .one(database)
        .await
        .map_err(persistence)?
        .ok_or(ApplicationError::NotFound)?;
    if project.status != "active" {
        return Err(ApplicationError::Disabled);
    }
    Ok(project)
}

async fn require_project<C>(database: &C, project_id: Uuid) -> Result<(), ApplicationError>
where
    C: ConnectionTrait,
{
    project::Entity::find_by_id(project_id)
        .one(database)
        .await
        .map_err(persistence)?
        .ok_or(ApplicationError::NotFound)?;
    Ok(())
}

async fn require_user<C>(
    database: &C,
    project_id: Uuid,
    user_id: Uuid,
) -> Result<project_user::Model, ApplicationError>
where
    C: sea_orm::ConnectionTrait,
{
    require_project(database, project_id).await?;
    project_user::Entity::find_by_id(user_id)
        .filter(project_user::Column::ProjectId.eq(project_id))
        .one(database)
        .await
        .map_err(persistence)?
        .ok_or(ApplicationError::NotFound)
}

fn project_user_identity_record(
    row: &QueryResult,
) -> Result<ProjectUserIdentityRecord, ApplicationError> {
    let kind = match row
        .try_get::<String>("", "identity_kind")
        .map_err(persistence)?
        .as_str()
    {
        "provider" => ProjectUserIdentityKind::Provider,
        "email" => ProjectUserIdentityKind::Email,
        _ => return Err(ApplicationError::Integrity),
    };
    let status = match row
        .try_get::<String>("", "status")
        .map_err(persistence)?
        .as_str()
    {
        "active" => ProjectUserIdentityStatus::Active,
        "disabled" => ProjectUserIdentityStatus::Disabled,
        _ => return Err(ApplicationError::Integrity),
    };
    let identity_revision = row
        .try_get::<i64>("", "identity_revision")
        .map_err(persistence)?;
    let provider_key = row
        .try_get::<Option<String>>("", "provider_key")
        .map_err(persistence)?;
    if identity_revision <= 0
        || matches!(kind, ProjectUserIdentityKind::Provider) != provider_key.is_some()
    {
        return Err(ApplicationError::Integrity);
    }
    Ok(ProjectUserIdentityRecord {
        id: row.try_get("", "identity_id").map_err(persistence)?,
        project_id: row.try_get("", "project_id").map_err(persistence)?,
        user_id: row.try_get("", "user_id").map_err(persistence)?,
        kind,
        status,
        identity_revision,
        is_primary_source: row.try_get("", "is_primary_source").map_err(persistence)?,
        provider_key,
        verified_or_observed_at: row
            .try_get("", "verified_or_observed_at")
            .map_err(persistence)?,
        created_at: row.try_get("", "created_at").map_err(persistence)?,
        updated_at: row.try_get("", "updated_at").map_err(persistence)?,
    })
}

fn project_user_record(model: project_user::Model) -> Result<ProjectUserRecord, ApplicationError> {
    let status = match model.status.as_str() {
        "active" => ProjectUserStatus::Active,
        "disabled" => ProjectUserStatus::Disabled,
        "merged" => ProjectUserStatus::Merged,
        _ => return Err(ApplicationError::Integrity),
    };
    if model.user_revision <= 0 || model.security_revision <= 0 {
        return Err(ApplicationError::Integrity);
    }
    Ok(ProjectUserRecord {
        id: model.id,
        project_id: model.project_id,
        public_id: model.public_id,
        status,
        user_revision: model.user_revision,
        security_revision: model.security_revision,
        display_name: model.display_name,
        picture_url: model.picture_url,
        created_at: model.created_at,
        updated_at: model.updated_at,
    })
}

fn application_session_record(
    model: &application_session::Model,
    application: &application::Model,
    now: time::OffsetDateTime,
) -> Result<ApplicationSessionRecord, ApplicationError> {
    let status = session_status(&model.status, model.absolute_expires_at <= now)?;
    if model.session_revision <= 0 || application.project_id != model.project_id {
        return Err(ApplicationError::Integrity);
    }
    Ok(ApplicationSessionRecord {
        id: model.id,
        project_id: model.project_id,
        user_id: model.user_id,
        application_id: model.application_id,
        application_public_id: application.public_id.clone(),
        application_display_name: application.display_name.clone(),
        browser_session_id: model.browser_session_id,
        status,
        session_revision: model.session_revision,
        authenticated_at: model.authenticated_at,
        absolute_expires_at: model.absolute_expires_at,
        revoked_at: model.revoked_at,
        created_at: model.created_at,
        updated_at: model.updated_at,
    })
}

fn browser_session_record(
    model: &project_browser_session::Model,
    now: time::OffsetDateTime,
) -> Result<BrowserSessionRecord, ApplicationError> {
    let expired = model.idle_expires_at <= now || model.absolute_expires_at <= now;
    let status = session_status(&model.status, expired)?;
    if model.session_revision <= 0 {
        return Err(ApplicationError::Integrity);
    }
    Ok(BrowserSessionRecord {
        id: model.id,
        project_id: model.project_id,
        user_id: model.user_id,
        status,
        session_revision: model.session_revision,
        authenticated_at: model.authenticated_at,
        last_activity_at: model.last_activity_at,
        idle_expires_at: model.idle_expires_at,
        absolute_expires_at: model.absolute_expires_at,
        terminated_at: model.terminated_at,
        created_at: model.created_at,
        updated_at: model.updated_at,
    })
}

fn session_status(
    persisted: &str,
    expired: bool,
) -> Result<ManagedSessionStatus, ApplicationError> {
    match persisted {
        "active" if expired => Ok(ManagedSessionStatus::Expired),
        "active" => Ok(ManagedSessionStatus::Active),
        "revoked" | "terminated" => Ok(ManagedSessionStatus::Revoked),
        _ => Err(ApplicationError::Integrity),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_session_status_is_bounded_and_expiry_aware() {
        assert_eq!(
            session_status("active", false),
            Ok(ManagedSessionStatus::Active)
        );
        assert_eq!(
            session_status("active", true),
            Ok(ManagedSessionStatus::Expired)
        );
        assert_eq!(
            session_status("terminated", false),
            Ok(ManagedSessionStatus::Revoked)
        );
        assert_eq!(
            session_status("unknown", false),
            Err(ApplicationError::Integrity)
        );
    }

    #[test]
    fn control_result_bounds_and_revision_overflow_fail_closed() {
        assert_eq!(bounded_limit(0), Err(ApplicationError::InvalidInput));
        assert_eq!(bounded_limit(100), Ok(()));
        assert_eq!(bounded_limit(101), Err(ApplicationError::InvalidInput));
        assert_eq!(next_revision(Some(1)), Ok(2));
        assert_eq!(
            next_revision(Some(i64::MAX)),
            Err(ApplicationError::Integrity)
        );
    }
}
