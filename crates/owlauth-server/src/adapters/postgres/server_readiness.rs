use async_trait::async_trait;
use sea_orm::{ConnectionTrait, DatabaseConnection, DbBackend, Statement, TransactionTrait};
use serde_json::json;

use crate::application::{
    ApplicationError, MAX_REQUIRED_SERVER_PROCESSES, ServerDigestReadinessClaim,
    ServerDigestReadinessPort, ServerDigestReadinessSnapshot, ServerDigestReadinessState,
    valid_server_process_id,
};

#[derive(Clone)]
pub(crate) struct PostgresServerDigestReadinessAdapter {
    database: DatabaseConnection,
}

impl PostgresServerDigestReadinessAdapter {
    pub(crate) fn new(database: DatabaseConnection) -> Self {
        Self { database }
    }

    async fn claim(&self, claim: &ServerDigestReadinessClaim) -> Result<(), ApplicationError> {
        claim.validate()?;
        let lease_micros = lease_micros(claim)?;
        let versions = json!(&claim.readable_digest_versions);
        let transaction = self.database.begin().await.map_err(persistence)?;
        lock_process(&transaction, &claim.process_id).await?;

        // Match the Control create lock order: parent incarnation first, readiness child second.
        // The unique Auth startup claim owns the parent identity. A delayed Server readiness phase
        // may publish only while that exact incarnation is still current; it must never reclaim a
        // process ID that a replacement Auth process already fenced.
        let current = transaction
            .query_one_raw(Statement::from_sql_and_values(
                DbBackend::Postgres,
                "SELECT process_id FROM auth_process_incarnations
                  WHERE process_id=$1 AND process_incarnation=$2 FOR UPDATE",
                [
                    claim.process_id.clone().into(),
                    claim.process_incarnation.into(),
                ],
            ))
            .await
            .map_err(persistence)?
            .is_some();
        if !current {
            return Err(ApplicationError::Disabled);
        }

        // A predecessor observation may remain after the parent incarnation changes because it is
        // deliberately not foreign-key authority. Once this exact current parent is locked, replace
        // that stale child without changing the parent claim.
        transaction
            .execute_raw(Statement::from_sql_and_values(
                DbBackend::Postgres,
                "DELETE FROM server_key_digest_readiness WHERE process_id=$1",
                [claim.process_id.clone().into()],
            ))
            .await
            .map_err(persistence)?;
        transaction
            .execute_raw(Statement::from_sql_and_values(
                DbBackend::Postgres,
                "INSERT INTO server_key_digest_readiness(
                       process_id,process_incarnation,state,supported_digest_versions,
                       failure_class,checked_at,lease_expires_at)
                 VALUES(
                       $1,$2,'ready',
                       ARRAY(SELECT value::INTEGER
                               FROM jsonb_array_elements_text($3::jsonb) version(value)),
                       NULL,transaction_timestamp(),
                       transaction_timestamp()+($4::BIGINT*INTERVAL '1 microsecond'))",
                [
                    claim.process_id.clone().into(),
                    claim.process_incarnation.into(),
                    versions.into(),
                    lease_micros.into(),
                ],
            ))
            .await
            .map_err(persistence)?;
        transaction.commit().await.map_err(persistence)
    }

    async fn renew(&self, claim: &ServerDigestReadinessClaim) -> Result<(), ApplicationError> {
        claim.validate()?;
        let lease_micros = lease_micros(claim)?;
        let transaction = self.database.begin().await.map_err(persistence)?;
        lock_process(&transaction, &claim.process_id).await?;
        let renewed = transaction
            .query_one_raw(Statement::from_sql_and_values(
                DbBackend::Postgres,
                "UPDATE server_key_digest_readiness readiness
                    SET checked_at=transaction_timestamp(),
                        lease_expires_at=transaction_timestamp()
                            +($4::BIGINT*INTERVAL '1 microsecond')
                  WHERE readiness.process_id=$1
                    AND readiness.process_incarnation=$2
                    AND readiness.state='ready'
                    AND readiness.failure_class IS NULL
                    AND readiness.supported_digest_versions=
                        ARRAY(SELECT value::INTEGER
                                FROM jsonb_array_elements_text($3::jsonb) version(value))
                    AND EXISTS (
                        SELECT 1 FROM auth_process_incarnations current
                         WHERE current.process_id=readiness.process_id
                           AND current.process_incarnation=readiness.process_incarnation)
              RETURNING readiness.process_incarnation",
                [
                    claim.process_id.clone().into(),
                    claim.process_incarnation.into(),
                    json!(&claim.readable_digest_versions).into(),
                    lease_micros.into(),
                ],
            ))
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::Disabled)?;
        let renewed_incarnation = renewed
            .try_get::<uuid::Uuid>("", "process_incarnation")
            .map_err(persistence)?;
        if renewed_incarnation != claim.process_incarnation {
            return Err(ApplicationError::Integrity);
        }
        transaction.commit().await.map_err(persistence)
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the readiness decision must read local lease, roster, and active digest inventory in one repeatable-read transaction"
    )]
    async fn authoritative_snapshot(
        &self,
        claim: &ServerDigestReadinessClaim,
        required_process_ids: &[String],
    ) -> Result<ServerDigestReadinessSnapshot, ApplicationError> {
        claim.validate()?;
        if required_process_ids.is_empty()
            || required_process_ids.len() > MAX_REQUIRED_SERVER_PROCESSES
            || required_process_ids
                .iter()
                .any(|process_id| !valid_server_process_id(process_id))
            || !required_process_ids
                .windows(2)
                .all(|processes| processes[0] < processes[1])
            || required_process_ids
                .binary_search(&claim.process_id)
                .is_err()
        {
            return Err(ApplicationError::InvalidInput);
        }
        let transaction = self.database.begin().await.map_err(persistence)?;
        transaction
            .execute_raw(Statement::from_string(
                DbBackend::Postgres,
                "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY".to_owned(),
            ))
            .await
            .map_err(persistence)?;

        let active_rows = transaction
            .query_all_raw(Statement::from_string(
                DbBackend::Postgres,
                "SELECT DISTINCT digest_key_version
                   FROM project_server_keys
                  WHERE status='active' AND revoked_at IS NULL
                  ORDER BY digest_key_version
                  LIMIT 33"
                    .to_owned(),
            ))
            .await
            .map_err(persistence)?;
        let active_digest_versions = active_rows
            .into_iter()
            .map(|row| {
                let version = row
                    .try_get::<i32>("", "digest_key_version")
                    .map_err(persistence)?;
                (version > 0)
                    .then_some(version)
                    .ok_or(ApplicationError::Integrity)
            })
            .collect::<Result<Vec<_>, _>>()?;

        let local_ready = transaction
            .query_one_raw(Statement::from_sql_and_values(
                DbBackend::Postgres,
                "SELECT EXISTS(
                     SELECT 1
                       FROM server_key_digest_readiness readiness
                       JOIN auth_process_incarnations current
                         ON current.process_id=readiness.process_id
                        AND current.process_incarnation=readiness.process_incarnation
                      WHERE readiness.process_id=$1
                        AND readiness.process_incarnation=$2
                        AND readiness.state='ready'
                        AND readiness.failure_class IS NULL
                        AND readiness.lease_expires_at>transaction_timestamp()
                        AND readiness.supported_digest_versions=
                            ARRAY(SELECT value::INTEGER
                                    FROM jsonb_array_elements_text($3::jsonb) version(value)))
                    AS local_ready",
                [
                    claim.process_id.clone().into(),
                    claim.process_incarnation.into(),
                    json!(&claim.readable_digest_versions).into(),
                ],
            ))
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::Persistence)?
            .try_get::<bool>("", "local_ready")
            .map_err(persistence)?;

        let roster = transaction
            .query_one_raw(Statement::from_sql_and_values(
                DbBackend::Postgres,
                "SELECT
                   NOT EXISTS(
                     SELECT required.process_id
                       FROM jsonb_array_elements_text($1::jsonb) required(process_id)
                      WHERE NOT EXISTS(
                        SELECT 1
                          FROM server_key_digest_readiness readiness
                          JOIN auth_process_incarnations current
                            ON current.process_id=readiness.process_id
                           AND current.process_incarnation=readiness.process_incarnation
                         WHERE readiness.process_id=required.process_id
                           AND readiness.state='ready'
                           AND readiness.failure_class IS NULL
                           AND readiness.lease_expires_at>transaction_timestamp()))
                     AS roster_ready,
                   NOT EXISTS(
                     SELECT required.process_id
                       FROM jsonb_array_elements_text($1::jsonb) required(process_id)
                      WHERE NOT EXISTS(
                        SELECT 1
                          FROM server_key_digest_readiness readiness
                          JOIN auth_process_incarnations current
                            ON current.process_id=readiness.process_id
                           AND current.process_incarnation=readiness.process_incarnation
                         WHERE readiness.process_id=required.process_id
                           AND readiness.state='ready'
                           AND readiness.failure_class IS NULL
                           AND readiness.lease_expires_at>transaction_timestamp()
                           AND NOT EXISTS(
                             SELECT active.value
                               FROM jsonb_array_elements_text($2::jsonb) active(value)
                              WHERE NOT (active.value::INTEGER =
                                         ANY(readiness.supported_digest_versions)))))
                     AS inventory_ready",
                [
                    json!(required_process_ids).into(),
                    json!(&active_digest_versions).into(),
                ],
            ))
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::Persistence)?;
        let roster_ready = roster
            .try_get::<bool>("", "roster_ready")
            .map_err(persistence)?;
        let inventory_ready = roster
            .try_get::<bool>("", "inventory_ready")
            .map_err(persistence)?;

        let state = if !local_ready {
            ServerDigestReadinessState::LocalObservationUnavailable
        } else if !roster_ready {
            ServerDigestReadinessState::RequiredRosterUnavailable
        } else if !inventory_ready {
            ServerDigestReadinessState::ActiveDigestVersionUnavailable
        } else {
            ServerDigestReadinessState::Ready
        };
        transaction.commit().await.map_err(persistence)?;
        Ok(ServerDigestReadinessSnapshot {
            state,
            active_digest_versions,
        })
    }
}

#[async_trait]
impl ServerDigestReadinessPort for PostgresServerDigestReadinessAdapter {
    async fn claim(&self, claim: &ServerDigestReadinessClaim) -> Result<(), ApplicationError> {
        PostgresServerDigestReadinessAdapter::claim(self, claim).await
    }

    async fn renew(&self, claim: &ServerDigestReadinessClaim) -> Result<(), ApplicationError> {
        PostgresServerDigestReadinessAdapter::renew(self, claim).await
    }

    async fn authoritative_snapshot(
        &self,
        claim: &ServerDigestReadinessClaim,
        required_process_ids: &[String],
    ) -> Result<ServerDigestReadinessSnapshot, ApplicationError> {
        PostgresServerDigestReadinessAdapter::authoritative_snapshot(
            self,
            claim,
            required_process_ids,
        )
        .await
    }
}

async fn lock_process<C: ConnectionTrait>(
    connection: &C,
    process_id: &str,
) -> Result<(), ApplicationError> {
    connection
        .execute_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "SELECT pg_advisory_xact_lock(
                 hashtextextended('owlauth:server-digest-readiness:' || $1,0))",
            [process_id.to_owned().into()],
        ))
        .await
        .map_err(persistence)?;
    Ok(())
}

fn lease_micros(claim: &ServerDigestReadinessClaim) -> Result<i64, ApplicationError> {
    let nanos = claim.lease_ttl.as_nanos();
    let micros = nanos
        .checked_add(999)
        .ok_or(ApplicationError::InvalidInput)?
        / 1_000;
    let micros = i64::try_from(micros).map_err(|_| ApplicationError::InvalidInput)?;
    if micros == 0 || micros > 5 * 60 * 1_000_000 {
        return Err(ApplicationError::InvalidInput);
    }
    Ok(micros)
}

fn persistence(_: impl std::fmt::Debug) -> ApplicationError {
    ApplicationError::Persistence
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use uuid::Uuid;

    use super::*;

    fn claim(ttl: Duration) -> ServerDigestReadinessClaim {
        ServerDigestReadinessClaim {
            process_id: "server-a".to_owned(),
            process_incarnation: Uuid::new_v4(),
            readable_digest_versions: vec![1],
            lease_ttl: ttl,
        }
    }

    #[test]
    fn lease_precision_rounds_up_without_exceeding_the_authoritative_bound() {
        assert_eq!(lease_micros(&claim(Duration::from_nanos(1))), Ok(1));
        assert_eq!(
            lease_micros(&claim(Duration::from_mins(5))),
            Ok(300_000_000)
        );
        assert_eq!(
            lease_micros(&claim(Duration::from_mins(5) + Duration::from_nanos(1))),
            Err(ApplicationError::InvalidInput)
        );
    }
}
