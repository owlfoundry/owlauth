use std::{
    collections::BTreeSet,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use async_trait::async_trait;
use uuid::Uuid;

use super::ApplicationError;

pub(crate) const MAX_SERVER_DIGEST_VERSIONS: usize = 32;
pub(crate) const MAX_REQUIRED_SERVER_PROCESSES: usize = 64;
pub(crate) const MAX_SERVER_DIGEST_READINESS_LEASE_TTL: Duration = Duration::from_mins(5);

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ServerDigestReadinessClaim {
    pub process_id: String,
    pub process_incarnation: Uuid,
    pub readable_digest_versions: Vec<i32>,
    pub lease_ttl: Duration,
}

impl ServerDigestReadinessClaim {
    pub(crate) fn validate(&self) -> Result<(), ApplicationError> {
        if !valid_server_process_id(&self.process_id)
            || self.process_incarnation.is_nil()
            || self.lease_ttl.is_zero()
            || self.lease_ttl > MAX_SERVER_DIGEST_READINESS_LEASE_TTL
            || self.readable_digest_versions.is_empty()
            || self.readable_digest_versions.len() > MAX_SERVER_DIGEST_VERSIONS
            || self
                .readable_digest_versions
                .iter()
                .any(|version| *version <= 0)
            || !self
                .readable_digest_versions
                .windows(2)
                .all(|versions| versions[0] < versions[1])
        {
            return Err(ApplicationError::InvalidInput);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ServerDigestReadinessState {
    Ready,
    LocalObservationUnavailable,
    RequiredRosterUnavailable,
    ActiveDigestVersionUnavailable,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ServerDigestReadinessSnapshot {
    pub state: ServerDigestReadinessState,
    pub active_digest_versions: Vec<i32>,
}

impl ServerDigestReadinessSnapshot {
    #[must_use]
    pub(crate) const fn is_ready(&self) -> bool {
        matches!(self.state, ServerDigestReadinessState::Ready)
    }
}

#[async_trait]
pub(crate) trait ServerDigestReadinessPort: Send + Sync {
    /// Atomically replaces the current incarnation for `process_id` and records one ready lease
    /// containing exactly `readable_digest_versions`.
    async fn claim(&self, claim: &ServerDigestReadinessClaim) -> Result<(), ApplicationError>;

    /// Renews only the exact current incarnation and exact version set. A replaced incarnation
    /// must fail closed rather than recreating its observation.
    async fn renew(&self, claim: &ServerDigestReadinessClaim) -> Result<(), ApplicationError>;

    /// Reads the authoritative active-key inventory and the complete required verifier roster in
    /// one `PostgreSQL` snapshot. This operation never authorizes a Server request.
    async fn authoritative_snapshot(
        &self,
        claim: &ServerDigestReadinessClaim,
        required_process_ids: &[String],
    ) -> Result<ServerDigestReadinessSnapshot, ApplicationError>;
}

#[derive(Clone)]
pub(crate) struct ServerDigestReadinessService {
    port: Arc<dyn ServerDigestReadinessPort>,
    claim: ServerDigestReadinessClaim,
    required_process_ids: Arc<[String]>,
    renewal_healthy: Arc<AtomicBool>,
}

impl ServerDigestReadinessService {
    pub(crate) fn new(
        port: Arc<dyn ServerDigestReadinessPort>,
        process_id: String,
        process_incarnation: Uuid,
        readable_digest_versions: impl IntoIterator<Item = i32>,
        required_process_ids: impl IntoIterator<Item = String>,
        lease_ttl: Duration,
    ) -> Result<Self, ApplicationError> {
        if !valid_server_process_id(&process_id)
            || process_incarnation.is_nil()
            || lease_ttl.is_zero()
            || lease_ttl > MAX_SERVER_DIGEST_READINESS_LEASE_TTL
        {
            return Err(ApplicationError::InvalidInput);
        }

        let readable_digest_versions = readable_digest_versions
            .into_iter()
            .collect::<BTreeSet<_>>();
        if readable_digest_versions.is_empty()
            || readable_digest_versions.len() > MAX_SERVER_DIGEST_VERSIONS
            || readable_digest_versions.iter().any(|version| *version <= 0)
        {
            return Err(ApplicationError::InvalidInput);
        }

        let required_process_ids = required_process_ids.into_iter().collect::<BTreeSet<_>>();
        if required_process_ids.is_empty()
            || required_process_ids.len() > MAX_REQUIRED_SERVER_PROCESSES
            || required_process_ids
                .iter()
                .any(|required| !valid_server_process_id(required))
            || !required_process_ids.contains(&process_id)
        {
            return Err(ApplicationError::InvalidInput);
        }

        let claim = ServerDigestReadinessClaim {
            process_id,
            process_incarnation,
            readable_digest_versions: readable_digest_versions.into_iter().collect(),
            lease_ttl,
        };
        claim.validate()?;
        Ok(Self {
            port,
            claim,
            required_process_ids: required_process_ids.into_iter().collect(),
            renewal_healthy: Arc::new(AtomicBool::new(false)),
        })
    }

    pub(crate) async fn claim(&self) -> Result<(), ApplicationError> {
        let result = self.port.claim(&self.claim).await;
        self.renewal_healthy
            .store(result.is_ok(), Ordering::Release);
        result
    }

    pub(crate) async fn renew(&self) -> Result<(), ApplicationError> {
        let result = self.port.renew(&self.claim).await;
        // A transient persistence failure makes readiness fail closed immediately. A later
        // successful renewal of the same exact incarnation restores the local observation.
        self.renewal_healthy
            .store(result.is_ok(), Ordering::Release);
        result
    }

    pub(crate) async fn readiness(
        &self,
    ) -> Result<ServerDigestReadinessSnapshot, ApplicationError> {
        if !self.renewal_healthy.load(Ordering::Acquire) {
            return Ok(ServerDigestReadinessSnapshot {
                state: ServerDigestReadinessState::LocalObservationUnavailable,
                active_digest_versions: Vec::new(),
            });
        }
        self.port
            .authoritative_snapshot(&self.claim, &self.required_process_ids)
            .await
    }

    #[must_use]
    pub(crate) fn renewal_interval(&self) -> Duration {
        // The validated TTL is at least one nanosecond. Keep at least one nanosecond between
        // renewals for sub-millisecond test configurations while normally renewing at one third.
        self.claim
            .lease_ttl
            .checked_div(3)
            .filter(|interval| !interval.is_zero())
            .unwrap_or(Duration::from_nanos(1))
    }
}

pub(crate) fn valid_server_process_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicUsize;

    use super::*;

    struct UnusedPort;

    #[async_trait]
    impl ServerDigestReadinessPort for UnusedPort {
        async fn claim(&self, _claim: &ServerDigestReadinessClaim) -> Result<(), ApplicationError> {
            unreachable!()
        }

        async fn renew(&self, _claim: &ServerDigestReadinessClaim) -> Result<(), ApplicationError> {
            unreachable!()
        }

        async fn authoritative_snapshot(
            &self,
            _claim: &ServerDigestReadinessClaim,
            _required_process_ids: &[String],
        ) -> Result<ServerDigestReadinessSnapshot, ApplicationError> {
            unreachable!()
        }
    }

    fn service(
        versions: impl IntoIterator<Item = i32>,
        roster: impl IntoIterator<Item = String>,
        ttl: Duration,
    ) -> Result<ServerDigestReadinessService, ApplicationError> {
        ServerDigestReadinessService::new(
            Arc::new(UnusedPort),
            "server-b".to_owned(),
            Uuid::new_v4(),
            versions,
            roster,
            ttl,
        )
    }

    struct RecoveringPort {
        renewals: AtomicUsize,
    }

    #[async_trait]
    impl ServerDigestReadinessPort for RecoveringPort {
        async fn claim(&self, _claim: &ServerDigestReadinessClaim) -> Result<(), ApplicationError> {
            Ok(())
        }

        async fn renew(&self, _claim: &ServerDigestReadinessClaim) -> Result<(), ApplicationError> {
            if self.renewals.fetch_add(1, Ordering::AcqRel) == 0 {
                Err(ApplicationError::Persistence)
            } else {
                Ok(())
            }
        }

        async fn authoritative_snapshot(
            &self,
            _claim: &ServerDigestReadinessClaim,
            _required_process_ids: &[String],
        ) -> Result<ServerDigestReadinessSnapshot, ApplicationError> {
            Ok(ServerDigestReadinessSnapshot {
                state: ServerDigestReadinessState::Ready,
                active_digest_versions: vec![1],
            })
        }
    }

    #[tokio::test]
    async fn successful_retry_restores_readiness_after_transient_renewal_failure() {
        let service = ServerDigestReadinessService::new(
            Arc::new(RecoveringPort {
                renewals: AtomicUsize::new(0),
            }),
            "server-b".to_owned(),
            Uuid::new_v4(),
            [1],
            ["server-b".to_owned()],
            Duration::from_secs(30),
        )
        .expect("valid service");
        service.claim().await.expect("initial claim");
        assert_eq!(service.renew().await, Err(ApplicationError::Persistence));
        assert_eq!(
            service
                .readiness()
                .await
                .expect("fail-closed readiness")
                .state,
            ServerDigestReadinessState::LocalObservationUnavailable
        );
        service.renew().await.expect("retry should recover");
        assert_eq!(
            service
                .readiness()
                .await
                .expect("recovered readiness")
                .state,
            ServerDigestReadinessState::Ready
        );
    }

    #[test]
    fn normalizes_versions_and_roster_into_canonical_order() {
        let service = service(
            [3, 1, 2, 3],
            [
                "server-b".to_owned(),
                "server-a".to_owned(),
                "server-a".to_owned(),
            ],
            Duration::from_secs(30),
        )
        .expect("valid service");
        assert_eq!(service.claim.readable_digest_versions, [1, 2, 3]);
        assert_eq!(&*service.required_process_ids, ["server-a", "server-b"]);
        assert_eq!(service.renewal_interval(), Duration::from_secs(10));
    }

    #[test]
    fn rejects_invalid_process_identity_and_roster() {
        assert_eq!(
            ServerDigestReadinessService::new(
                Arc::new(UnusedPort),
                " server".to_owned(),
                Uuid::new_v4(),
                [1],
                [" server".to_owned()],
                Duration::from_secs(30),
            )
            .err(),
            Some(ApplicationError::InvalidInput)
        );
        assert_eq!(
            ServerDigestReadinessService::new(
                Arc::new(UnusedPort),
                "server-b".to_owned(),
                Uuid::nil(),
                [1],
                ["server-b".to_owned()],
                Duration::from_secs(30),
            )
            .err(),
            Some(ApplicationError::InvalidInput)
        );
        assert!(service([1], ["server-a".to_owned()], Duration::from_secs(30)).is_err());
    }

    #[test]
    fn rejects_out_of_range_ttl_and_version_sets() {
        assert!(service([1], ["server-b".to_owned()], Duration::ZERO).is_err());
        assert!(
            service(
                [1],
                ["server-b".to_owned()],
                MAX_SERVER_DIGEST_READINESS_LEASE_TTL + Duration::from_nanos(1),
            )
            .is_err()
        );
        assert!(service([], ["server-b".to_owned()], Duration::from_secs(30)).is_err());
        assert!(service([0], ["server-b".to_owned()], Duration::from_secs(30)).is_err());
        assert!(
            service(
                1..=i32::try_from(MAX_SERVER_DIGEST_VERSIONS + 1).expect("small bound"),
                ["server-b".to_owned()],
                Duration::from_secs(30),
            )
            .is_err()
        );
    }
}
