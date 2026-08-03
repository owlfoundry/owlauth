use std::sync::Arc;

use async_trait::async_trait;
use time::OffsetDateTime;
use uuid::Uuid;

use super::{ApplicationError, Clock};

const MAX_CONTROL_RESULTS: usize = 100;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProjectUserStatus {
    Active,
    Disabled,
    Merged,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ProjectUserRecord {
    pub id: Uuid,
    pub project_id: Uuid,
    pub public_id: String,
    pub status: ProjectUserStatus,
    pub user_revision: i64,
    pub security_revision: i64,
    pub display_name: Option<String>,
    pub picture_url: Option<String>,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProjectUserIdentityKind {
    Provider,
    Email,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProjectUserIdentityStatus {
    Active,
    Disabled,
}

/// Bounded Control read model. `provider_key` is creation provenance only; no provider subject,
/// issuer, email material, alias, digest, credential, receipt, or evidence enters this record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ProjectUserIdentityRecord {
    pub id: Uuid,
    pub project_id: Uuid,
    pub user_id: Uuid,
    pub kind: ProjectUserIdentityKind,
    pub status: ProjectUserIdentityStatus,
    pub identity_revision: i64,
    pub is_primary_source: bool,
    pub provider_key: Option<String>,
    pub verified_or_observed_at: OffsetDateTime,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ManagedSessionStatus {
    Active,
    Revoked,
    Expired,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ApplicationSessionRecord {
    pub id: Uuid,
    pub project_id: Uuid,
    pub user_id: Uuid,
    pub application_id: Uuid,
    pub application_public_id: String,
    pub application_display_name: String,
    pub browser_session_id: Option<Uuid>,
    pub status: ManagedSessionStatus,
    pub session_revision: i64,
    pub authenticated_at: OffsetDateTime,
    pub absolute_expires_at: OffsetDateTime,
    pub revoked_at: Option<OffsetDateTime>,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct BrowserSessionRecord {
    pub id: Uuid,
    pub project_id: Uuid,
    pub user_id: Uuid,
    pub status: ManagedSessionStatus,
    pub session_revision: i64,
    pub authenticated_at: OffsetDateTime,
    pub last_activity_at: OffsetDateTime,
    pub idle_expires_at: OffsetDateTime,
    pub absolute_expires_at: OffsetDateTime,
    pub terminated_at: Option<OffsetDateTime>,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ProjectUserSessions {
    pub application_sessions: Vec<ApplicationSessionRecord>,
    pub browser_sessions: Vec<BrowserSessionRecord>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DisableProjectUser {
    pub project_id: Uuid,
    pub user_id: Uuid,
    pub expected_security_revision: i64,
    pub correlation_id: Uuid,
    pub now: OffsetDateTime,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RevokeApplicationSession {
    pub project_id: Uuid,
    pub user_id: Uuid,
    pub session_id: Uuid,
    pub expected_session_revision: i64,
    pub correlation_id: Uuid,
    pub now: OffsetDateTime,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RevokeBrowserSession {
    pub project_id: Uuid,
    pub user_id: Uuid,
    pub session_id: Uuid,
    pub expected_session_revision: i64,
    pub correlation_id: Uuid,
    pub now: OffsetDateTime,
}

#[async_trait]
pub(crate) trait ControlLifecyclePort: Send + Sync {
    async fn list_project_users(
        &self,
        project_id: Uuid,
        limit: usize,
    ) -> Result<Vec<ProjectUserRecord>, ApplicationError>;

    async fn get_project_user(
        &self,
        project_id: Uuid,
        user_id: Uuid,
    ) -> Result<ProjectUserRecord, ApplicationError>;

    async fn list_project_user_identities(
        &self,
        project_id: Uuid,
        user_id: Uuid,
        limit: usize,
    ) -> Result<Vec<ProjectUserIdentityRecord>, ApplicationError>;

    async fn disable_project_user(
        &self,
        command: DisableProjectUser,
    ) -> Result<ProjectUserRecord, ApplicationError>;

    async fn list_project_user_sessions(
        &self,
        project_id: Uuid,
        user_id: Uuid,
        limit: usize,
        now: OffsetDateTime,
    ) -> Result<ProjectUserSessions, ApplicationError>;

    async fn revoke_application_session(
        &self,
        command: RevokeApplicationSession,
    ) -> Result<ApplicationSessionRecord, ApplicationError>;

    async fn revoke_browser_session(
        &self,
        command: RevokeBrowserSession,
    ) -> Result<BrowserSessionRecord, ApplicationError>;
}

#[derive(Clone)]
pub(crate) struct ControlLifecycleService {
    port: Arc<dyn ControlLifecyclePort>,
    clock: Arc<dyn Clock>,
}

impl ControlLifecycleService {
    pub(crate) fn new(port: Arc<dyn ControlLifecyclePort>, clock: Arc<dyn Clock>) -> Self {
        Self { port, clock }
    }

    pub(crate) async fn list_project_users(
        &self,
        project_id: Uuid,
    ) -> Result<Vec<ProjectUserRecord>, ApplicationError> {
        self.port
            .list_project_users(project_id, MAX_CONTROL_RESULTS)
            .await
    }

    pub(crate) async fn get_project_user(
        &self,
        project_id: Uuid,
        user_id: Uuid,
    ) -> Result<ProjectUserRecord, ApplicationError> {
        self.port.get_project_user(project_id, user_id).await
    }

    pub(crate) async fn list_project_user_identities(
        &self,
        project_id: Uuid,
        user_id: Uuid,
    ) -> Result<Vec<ProjectUserIdentityRecord>, ApplicationError> {
        self.port
            .list_project_user_identities(project_id, user_id, MAX_CONTROL_RESULTS)
            .await
    }

    pub(crate) async fn disable_project_user(
        &self,
        project_id: Uuid,
        user_id: Uuid,
        expected_security_revision: i64,
        correlation_id: Uuid,
    ) -> Result<ProjectUserRecord, ApplicationError> {
        positive_revision(expected_security_revision)?;
        self.port
            .disable_project_user(DisableProjectUser {
                project_id,
                user_id,
                expected_security_revision,
                correlation_id,
                now: self.clock.now(),
            })
            .await
    }

    pub(crate) async fn list_project_user_sessions(
        &self,
        project_id: Uuid,
        user_id: Uuid,
    ) -> Result<ProjectUserSessions, ApplicationError> {
        self.port
            .list_project_user_sessions(project_id, user_id, MAX_CONTROL_RESULTS, self.clock.now())
            .await
    }

    pub(crate) async fn revoke_application_session(
        &self,
        project_id: Uuid,
        user_id: Uuid,
        session_id: Uuid,
        expected_session_revision: i64,
        correlation_id: Uuid,
    ) -> Result<ApplicationSessionRecord, ApplicationError> {
        positive_revision(expected_session_revision)?;
        self.port
            .revoke_application_session(RevokeApplicationSession {
                project_id,
                user_id,
                session_id,
                expected_session_revision,
                correlation_id,
                now: self.clock.now(),
            })
            .await
    }

    pub(crate) async fn revoke_browser_session(
        &self,
        project_id: Uuid,
        user_id: Uuid,
        session_id: Uuid,
        expected_session_revision: i64,
        correlation_id: Uuid,
    ) -> Result<BrowserSessionRecord, ApplicationError> {
        positive_revision(expected_session_revision)?;
        self.port
            .revoke_browser_session(RevokeBrowserSession {
                project_id,
                user_id,
                session_id,
                expected_session_revision,
                correlation_id,
                now: self.clock.now(),
            })
            .await
    }
}

fn positive_revision(revision: i64) -> Result<(), ApplicationError> {
    if revision <= 0 {
        return Err(ApplicationError::InvalidInput);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_lifecycle_revisions_are_positive() {
        assert_eq!(positive_revision(1), Ok(()));
        assert_eq!(positive_revision(0), Err(ApplicationError::InvalidInput));
        assert_eq!(positive_revision(-1), Err(ApplicationError::InvalidInput));
    }
}
