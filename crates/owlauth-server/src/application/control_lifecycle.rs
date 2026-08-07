use std::sync::Arc;

use async_trait::async_trait;
use time::OffsetDateTime;
use uuid::Uuid;

use super::{ApplicationError, Clock, EmailIdentityLookupDigester, VersionedDigest};

pub(crate) const MAX_PROJECT_USER_PAGE_LIMIT: usize = 100;
const DEFAULT_PROJECT_USER_PAGE_LIMIT: usize = 50;
const MAX_CONTROL_RESULTS: usize = 100;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProjectUserStatus {
    Active,
    Disabled,
    Merged,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProjectUserSort {
    CreatedNewest,
    CreatedOldest,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ProjectUserIdentityFilter {
    Provider(Option<String>),
    Email,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ProjectUserListCriteria {
    pub status: Option<ProjectUserStatus>,
    pub search: Option<String>,
    pub identity: Option<ProjectUserIdentityFilter>,
    pub sort: ProjectUserSort,
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ProjectUserPage {
    pub items: Vec<ProjectUserRecord>,
    pub next_cursor: Option<Uuid>,
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
pub(crate) struct EnableProjectUser {
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
        criteria: &ProjectUserListCriteria,
        cursor: Option<Uuid>,
        limit: usize,
    ) -> Result<ProjectUserPage, ApplicationError>;

    async fn lookup_project_user_by_email_digests(
        &self,
        project_id: Uuid,
        candidates: &[VersionedDigest],
    ) -> Result<Option<ProjectUserRecord>, ApplicationError>;

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

    async fn enable_project_user(
        &self,
        command: EnableProjectUser,
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
    email_digester: Arc<dyn EmailIdentityLookupDigester>,
    clock: Arc<dyn Clock>,
}

impl ControlLifecycleService {
    pub(crate) fn new(
        port: Arc<dyn ControlLifecyclePort>,
        email_digester: Arc<dyn EmailIdentityLookupDigester>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            port,
            email_digester,
            clock,
        }
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the closed Control query maps one-to-one to independently optional directory criteria"
    )]
    pub(crate) async fn list_project_users(
        &self,
        project_id: Uuid,
        status: Option<ProjectUserStatus>,
        search: Option<&str>,
        identity_kind: Option<ProjectUserIdentityKind>,
        provider_key: Option<&str>,
        sort: Option<ProjectUserSort>,
        cursor: Option<Uuid>,
        limit: Option<usize>,
    ) -> Result<ProjectUserPage, ApplicationError> {
        let limit = limit.unwrap_or(DEFAULT_PROJECT_USER_PAGE_LIMIT);
        if !(1..=MAX_PROJECT_USER_PAGE_LIMIT).contains(&limit) {
            return Err(ApplicationError::InvalidInput);
        }
        let search = search
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(|value| {
                if value.chars().count() > 128 {
                    Err(ApplicationError::InvalidInput)
                } else {
                    Ok(value.to_owned())
                }
            })
            .transpose()?;
        let identity = match (identity_kind, provider_key) {
            (None, None) => None,
            (Some(ProjectUserIdentityKind::Email), None) => Some(ProjectUserIdentityFilter::Email),
            (Some(ProjectUserIdentityKind::Provider), provider_key) => {
                let provider_key = provider_key
                    .map(|value| crate::domain::ProviderKey::parse(value.to_owned()))
                    .transpose()?
                    .map(crate::domain::ProviderKey::into_inner);
                Some(ProjectUserIdentityFilter::Provider(provider_key))
            }
            _ => return Err(ApplicationError::InvalidInput),
        };
        let criteria = ProjectUserListCriteria {
            status,
            search,
            identity,
            sort: sort.unwrap_or(ProjectUserSort::CreatedNewest),
        };
        self.port
            .list_project_users(project_id, &criteria, cursor, limit)
            .await
    }

    pub(crate) async fn lookup_project_user_by_email(
        &self,
        project_id: Uuid,
        email: &str,
    ) -> Result<Option<ProjectUserRecord>, ApplicationError> {
        let canonical = crate::domain::CanonicalEmail::parse_v1(email)
            .map_err(|_| ApplicationError::InvalidInput)?;
        let candidates = self
            .email_digester
            .digest_candidates(project_id, canonical.expose())?;
        if candidates.is_empty() || candidates.len() > 32 {
            return Err(ApplicationError::Integrity);
        }
        self.port
            .lookup_project_user_by_email_digests(project_id, &candidates)
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

    pub(crate) async fn enable_project_user(
        &self,
        project_id: Uuid,
        user_id: Uuid,
        expected_security_revision: i64,
        correlation_id: Uuid,
    ) -> Result<ProjectUserRecord, ApplicationError> {
        positive_revision(expected_security_revision)?;
        self.port
            .enable_project_user(EnableProjectUser {
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
    use std::sync::Mutex;

    use super::*;

    type RecordedListCall = (Uuid, ProjectUserListCriteria, Option<Uuid>, usize);

    #[derive(Default)]
    struct RecordingPort {
        list_call: Mutex<Option<RecordedListCall>>,
        lookup_candidates: Mutex<Vec<VersionedDigest>>,
    }

    #[async_trait]
    impl ControlLifecyclePort for RecordingPort {
        async fn list_project_users(
            &self,
            project_id: Uuid,
            criteria: &ProjectUserListCriteria,
            cursor: Option<Uuid>,
            limit: usize,
        ) -> Result<ProjectUserPage, ApplicationError> {
            *self.list_call.lock().unwrap() = Some((project_id, criteria.clone(), cursor, limit));
            Ok(ProjectUserPage {
                items: Vec::new(),
                next_cursor: None,
            })
        }

        async fn lookup_project_user_by_email_digests(
            &self,
            _project_id: Uuid,
            candidates: &[VersionedDigest],
        ) -> Result<Option<ProjectUserRecord>, ApplicationError> {
            *self.lookup_candidates.lock().unwrap() = candidates.to_vec();
            Ok(None)
        }

        async fn get_project_user(
            &self,
            _project_id: Uuid,
            _user_id: Uuid,
        ) -> Result<ProjectUserRecord, ApplicationError> {
            unreachable!("not used by directory tests")
        }

        async fn list_project_user_identities(
            &self,
            _project_id: Uuid,
            _user_id: Uuid,
            _limit: usize,
        ) -> Result<Vec<ProjectUserIdentityRecord>, ApplicationError> {
            unreachable!("not used by directory tests")
        }

        async fn disable_project_user(
            &self,
            _command: DisableProjectUser,
        ) -> Result<ProjectUserRecord, ApplicationError> {
            unreachable!("not used by directory tests")
        }

        async fn enable_project_user(
            &self,
            _command: EnableProjectUser,
        ) -> Result<ProjectUserRecord, ApplicationError> {
            unreachable!("not used by directory tests")
        }

        async fn list_project_user_sessions(
            &self,
            _project_id: Uuid,
            _user_id: Uuid,
            _limit: usize,
            _now: OffsetDateTime,
        ) -> Result<ProjectUserSessions, ApplicationError> {
            unreachable!("not used by directory tests")
        }

        async fn revoke_application_session(
            &self,
            _command: RevokeApplicationSession,
        ) -> Result<ApplicationSessionRecord, ApplicationError> {
            unreachable!("not used by directory tests")
        }

        async fn revoke_browser_session(
            &self,
            _command: RevokeBrowserSession,
        ) -> Result<BrowserSessionRecord, ApplicationError> {
            unreachable!("not used by directory tests")
        }
    }

    struct RecordingDigester {
        candidates: Vec<VersionedDigest>,
        call: Mutex<Option<(Uuid, String)>>,
    }

    impl RecordingDigester {
        fn with_candidates(candidates: Vec<VersionedDigest>) -> Self {
            Self {
                candidates,
                call: Mutex::new(None),
            }
        }
    }

    impl EmailIdentityLookupDigester for RecordingDigester {
        fn digest_candidates(
            &self,
            project_id: Uuid,
            canonical_email: &str,
        ) -> Result<Vec<VersionedDigest>, ApplicationError> {
            *self.call.lock().unwrap() = Some((project_id, canonical_email.to_owned()));
            Ok(self.candidates.clone())
        }
    }

    struct FixedClock;

    impl Clock for FixedClock {
        fn now(&self) -> OffsetDateTime {
            OffsetDateTime::UNIX_EPOCH
        }
    }

    fn service(
        port: Arc<RecordingPort>,
        digester: Arc<RecordingDigester>,
    ) -> ControlLifecycleService {
        ControlLifecycleService::new(port, digester, Arc::new(FixedClock))
    }

    fn digest(value: u8, key_version: i32) -> VersionedDigest {
        VersionedDigest {
            value: [value; 32],
            key_version,
        }
    }

    #[test]
    fn control_lifecycle_revisions_are_positive() {
        assert_eq!(positive_revision(1), Ok(()));
        assert_eq!(positive_revision(0), Err(ApplicationError::InvalidInput));
        assert_eq!(positive_revision(-1), Err(ApplicationError::InvalidInput));
    }

    #[tokio::test]
    async fn project_user_directory_normalizes_and_forwards_authoritative_criteria() {
        let project_id = Uuid::new_v4();
        let cursor = Uuid::new_v4();
        let port = Arc::new(RecordingPort::default());
        let digester = Arc::new(RecordingDigester::with_candidates(vec![digest(1, 1)]));
        service(Arc::clone(&port), digester)
            .list_project_users(
                project_id,
                Some(ProjectUserStatus::Disabled),
                Some("  Ada  "),
                Some(ProjectUserIdentityKind::Provider),
                Some("workforce"),
                Some(ProjectUserSort::CreatedOldest),
                Some(cursor),
                Some(25),
            )
            .await
            .unwrap();

        assert_eq!(
            *port.list_call.lock().unwrap(),
            Some((
                project_id,
                ProjectUserListCriteria {
                    status: Some(ProjectUserStatus::Disabled),
                    search: Some("Ada".to_owned()),
                    identity: Some(ProjectUserIdentityFilter::Provider(Some(
                        "workforce".to_owned(),
                    ))),
                    sort: ProjectUserSort::CreatedOldest,
                },
                Some(cursor),
                25,
            ))
        );

        service(
            Arc::clone(&port),
            Arc::new(RecordingDigester::with_candidates(vec![digest(1, 1)])),
        )
        .list_project_users(project_id, None, Some("   "), None, None, None, None, None)
        .await
        .unwrap();
        let (_, criteria, cursor, limit) = port.list_call.lock().unwrap().clone().unwrap();
        assert_eq!(criteria.search, None);
        assert_eq!(criteria.sort, ProjectUserSort::CreatedNewest);
        assert_eq!(cursor, None);
        assert_eq!(limit, DEFAULT_PROJECT_USER_PAGE_LIMIT);
    }

    #[tokio::test]
    async fn project_user_directory_bounds_search_by_unicode_characters() {
        let project_id = Uuid::new_v4();
        let port = Arc::new(RecordingPort::default());
        let accepted = "界".repeat(128);
        service(
            Arc::clone(&port),
            Arc::new(RecordingDigester::with_candidates(vec![digest(1, 1)])),
        )
        .list_project_users(
            project_id,
            None,
            Some(&accepted),
            None,
            None,
            None,
            None,
            None,
        )
        .await
        .unwrap();
        let (_, criteria, _, _) = port.list_call.lock().unwrap().clone().unwrap();
        assert_eq!(criteria.search.as_deref(), Some(accepted.as_str()));

        let rejected = "界".repeat(129);
        let result = service(
            Arc::new(RecordingPort::default()),
            Arc::new(RecordingDigester::with_candidates(vec![digest(1, 1)])),
        )
        .list_project_users(
            project_id,
            None,
            Some(&rejected),
            None,
            None,
            None,
            None,
            None,
        )
        .await;
        assert_eq!(result, Err(ApplicationError::InvalidInput));
    }

    #[tokio::test]
    async fn project_user_directory_rejects_invalid_criteria_combinations() {
        let project_id = Uuid::new_v4();
        for (identity_kind, provider_key) in [
            (None, Some("workforce")),
            (Some(ProjectUserIdentityKind::Email), Some("workforce")),
            (Some(ProjectUserIdentityKind::Provider), Some("invalid key")),
        ] {
            let result = service(
                Arc::new(RecordingPort::default()),
                Arc::new(RecordingDigester::with_candidates(vec![digest(1, 1)])),
            )
            .list_project_users(
                project_id,
                None,
                None,
                identity_kind,
                provider_key,
                None,
                None,
                None,
            )
            .await;
            assert_eq!(result, Err(ApplicationError::InvalidInput));
        }

        for (search, limit) in [
            (Some("x".repeat(129)), Some(50)),
            (None, Some(0)),
            (None, Some(101)),
        ] {
            let result = service(
                Arc::new(RecordingPort::default()),
                Arc::new(RecordingDigester::with_candidates(vec![digest(1, 1)])),
            )
            .list_project_users(
                project_id,
                None,
                search.as_deref(),
                None,
                None,
                None,
                None,
                limit,
            )
            .await;
            assert_eq!(result, Err(ApplicationError::InvalidInput));
        }
    }

    #[tokio::test]
    async fn exact_email_lookup_canonicalizes_and_forwards_only_digest_candidates() {
        let project_id = Uuid::new_v4();
        let candidates = vec![digest(1, 1), digest(2, 2)];
        let port = Arc::new(RecordingPort::default());
        let digester = Arc::new(RecordingDigester::with_candidates(candidates.clone()));

        assert_eq!(
            service(Arc::clone(&port), Arc::clone(&digester))
                .lookup_project_user_by_email(project_id, "User.Name+tag@EXAMPLE.COM")
                .await
                .unwrap(),
            None
        );
        assert_eq!(
            *digester.call.lock().unwrap(),
            Some((project_id, "User.Name+tag@example.com".to_owned()))
        );
        assert_eq!(*port.lookup_candidates.lock().unwrap(), candidates);

        let invalid = service(Arc::clone(&port), Arc::clone(&digester))
            .lookup_project_user_by_email(project_id, "not-an-email")
            .await;
        assert_eq!(invalid, Err(ApplicationError::InvalidInput));

        for candidates in [Vec::new(), vec![digest(3, 3); 33]] {
            let result = service(
                Arc::new(RecordingPort::default()),
                Arc::new(RecordingDigester::with_candidates(candidates)),
            )
            .lookup_project_user_by_email(project_id, "user@example.com")
            .await;
            assert_eq!(result, Err(ApplicationError::Integrity));
        }
    }
}
