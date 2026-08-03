use async_trait::async_trait;
use sea_orm::{
    ConnectionTrait, DatabaseConnection, DatabaseTransaction, DbBackend, Statement,
    TransactionTrait,
};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;
use zeroize::Zeroizing;

use super::provisioning::insert_audit;

const MAX_LIVE_PROJECT_SMTP_GENERATIONS: i64 = 32;

use crate::application::{
    ApplicationError, ConfigurationSecretProvisioner, EmailControlPort, EmailPolicyRecord,
    PrepareSmtpConfiguration, PreparedSmtpConfiguration, SmtpConfigurationRecord,
    SmtpControlStatus, SmtpControlTlsMode, UpdateEmailPolicy,
};

#[derive(Clone)]
pub(crate) struct PostgresEmailControlRepository {
    database: DatabaseConnection,
    required_runtime_process_ids: Vec<String>,
}

impl PostgresEmailControlRepository {
    #[cfg(test)]
    pub(crate) fn new(database: DatabaseConnection) -> Self {
        Self::new_with_runtime_roster(database, vec!["runtime-1".to_owned()])
    }

    pub(crate) fn new_with_runtime_roster(
        database: DatabaseConnection,
        required_runtime_process_ids: Vec<String>,
    ) -> Self {
        Self {
            database,
            required_runtime_process_ids,
        }
    }
}

#[async_trait]
#[allow(
    clippy::too_many_lines,
    reason = "SMTP preparation keeps owner revision, reference reservation, idempotency, and audit in one transaction"
)]
impl EmailControlPort for PostgresEmailControlRepository {
    async fn get_email_policy(
        &self,
        project_id: Uuid,
    ) -> Result<EmailPolicyRecord, ApplicationError> {
        let row = self
            .database
            .query_one_raw(statement(
                "SELECT * FROM project_email_policies WHERE project_id = $1",
                vec![project_id.into()],
            ))
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        policy_record(&row)
    }

    async fn update_email_policy(
        &self,
        project_id: Uuid,
        update: UpdateEmailPolicy,
        correlation_id: Uuid,
        now: OffsetDateTime,
    ) -> Result<EmailPolicyRecord, ApplicationError> {
        let transaction = self.database.begin().await.map_err(persistence)?;
        let result = transaction.execute_raw(statement(
            "UPDATE project_email_policies SET status = $2, otp_enabled = $3, magic_link_enabled = $4,
             otp_digits = $5, otp_validity_seconds = $6, otp_max_attempts = $7,
             resend_after_seconds = $8, max_generations = $9, magic_validity_seconds = $10,
             signup_enabled = $11, transferred_magic_link_enabled = $12,
             allow_deployment_default = $13, policy_revision = policy_revision + 1,
             security_revision = security_revision + 1, updated_at = $14
             WHERE project_id = $1 AND policy_revision = $15 AND security_revision = $16",
            vec![
                project_id.into(),
                (if update.enabled { "enabled" } else { "disabled" }).into(),
                update.otp_enabled.into(), update.magic_link_enabled.into(), update.otp_digits.into(),
                update.otp_validity_seconds.into(), update.otp_max_attempts.into(),
                update.resend_after_seconds.into(), update.max_generations.into(),
                update.magic_validity_seconds.into(), update.signup_enabled.into(),
                update.transferred_magic_link_enabled.into(), update.allow_deployment_default.into(),
                now.into(), update.expected_policy_revision.into(), update.expected_security_revision.into(),
            ],
        )).await.map_err(persistence)?;
        if result.rows_affected() != 1 {
            return Err(ApplicationError::RevisionConflict);
        }
        insert_audit(
            &transaction,
            Some(project_id),
            "email.policy.updated",
            "email_policy",
            Some(project_id),
            correlation_id,
        )
        .await?;
        let row = transaction
            .query_one_raw(statement(
                "SELECT * FROM project_email_policies WHERE project_id = $1",
                vec![project_id.into()],
            ))
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::Integrity)?;
        let record = policy_record(&row)?;
        transaction.commit().await.map_err(persistence)?;
        Ok(record)
    }

    async fn assign_email_method(
        &self,
        project_id: Uuid,
        application_id: Uuid,
        enabled: bool,
        expected_application_security_revision: i64,
        correlation_id: Uuid,
        now: OffsetDateTime,
    ) -> Result<(), ApplicationError> {
        let transaction = self.database.begin().await.map_err(persistence)?;
        let application = transaction.query_one_raw(statement(
            "SELECT security_revision FROM applications WHERE project_id = $1 AND id = $2 FOR UPDATE",
            vec![project_id.into(), application_id.into()],
        )).await.map_err(persistence)?.ok_or(ApplicationError::NotFound)?;
        if application
            .try_get::<i64>("", "security_revision")
            .map_err(persistence)?
            != expected_application_security_revision
        {
            return Err(ApplicationError::RevisionConflict);
        }
        transaction.execute_raw(statement(
            "INSERT INTO application_email_assignments (project_id, application_id, status, security_revision, created_at, updated_at)
             VALUES ($1, $2, $3, 1, $4, $4)
             ON CONFLICT (project_id, application_id) DO UPDATE SET status = EXCLUDED.status,
             security_revision = application_email_assignments.security_revision + 1, updated_at = EXCLUDED.updated_at",
            vec![project_id.into(), application_id.into(), (if enabled { "active" } else { "disabled" }).into(), now.into()],
        )).await.map_err(persistence)?;
        let result = transaction
            .execute_raw(statement(
                "UPDATE applications SET security_revision = security_revision + 1, updated_at = $3
             WHERE project_id = $1 AND id = $2 AND security_revision = $4",
                vec![
                    project_id.into(),
                    application_id.into(),
                    now.into(),
                    expected_application_security_revision.into(),
                ],
            ))
            .await
            .map_err(persistence)?;
        if result.rows_affected() != 1 {
            return Err(ApplicationError::RevisionConflict);
        }
        insert_audit(
            &transaction,
            Some(project_id),
            if enabled {
                "email.assignment.enabled"
            } else {
                "email.assignment.disabled"
            },
            "application",
            Some(application_id),
            correlation_id,
        )
        .await?;
        transaction.commit().await.map_err(persistence)
    }

    async fn prepare_smtp_configuration(
        &self,
        project_id: Uuid,
        prepared: PrepareSmtpConfiguration,
        now: OffsetDateTime,
    ) -> Result<PreparedSmtpConfiguration, ApplicationError> {
        let transaction = self.database.begin().await.map_err(persistence)?;
        let project = transaction
            .query_one_raw(statement(
                "SELECT security_revision FROM projects WHERE id = $1 FOR UPDATE",
                vec![project_id.into()],
            ))
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        let project_security_revision = project
            .try_get::<i64>("", "security_revision")
            .map_err(persistence)?;
        if let Some(existing) =
            find_prepared_smtp_operation(&transaction, project_id, &prepared).await?
        {
            transaction.commit().await.map_err(persistence)?;
            return Ok(existing);
        }
        if project_security_revision != prepared.expected_project_security_revision {
            return Err(ApplicationError::RevisionConflict);
        }
        let live_generations = transaction
            .query_one_raw(statement(
                "SELECT COUNT(*)::BIGINT AS count FROM project_smtp_configurations
                 WHERE project_id=$1 AND (status IN ('pending','active')
                    OR (status='retained' AND retained_until>$2))",
                vec![project_id.into(), now.into()],
            ))
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::Persistence)?
            .try_get::<i64>("", "count")
            .map_err(persistence)?;
        if live_generations >= MAX_LIVE_PROJECT_SMTP_GENERATIONS {
            return Err(ApplicationError::InvalidTransition);
        }
        lock_smtp_credential_reference(&transaction, &prepared.credential_ref).await?;
        transaction
            .execute_raw(statement(
                "INSERT INTO smtp_credential_reference_reservations
                 (credential_ref,state,created_at,updated_at)
                 VALUES ($1,'live',$2,$2) ON CONFLICT (credential_ref) DO NOTHING",
                vec![prepared.credential_ref.clone().into(), now.into()],
            ))
            .await
            .map_err(persistence)?;
        let reference = transaction
            .query_one_raw(statement(
                "SELECT state FROM smtp_credential_reference_reservations
                 WHERE credential_ref=$1 FOR UPDATE",
                vec![prepared.credential_ref.clone().into()],
            ))
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::Integrity)?;
        if reference
            .try_get::<String>("", "state")
            .map_err(persistence)?
            != "live"
        {
            return Err(ApplicationError::InvalidTransition);
        }
        let generation = transaction.query_one_raw(statement(
            "SELECT COALESCE(MAX(generation), 0) + 1 AS generation FROM project_smtp_configurations WHERE project_id = $1",
            vec![project_id.into()],
        )).await.map_err(persistence)?.ok_or(ApplicationError::Persistence)?
            .try_get::<i32>("", "generation").map_err(persistence)?;
        transaction.execute_raw(statement(
            "INSERT INTO project_smtp_configurations
             (id, project_id, status, generation, revision, security_eligibility_revision, host, port, tls_mode,
              sender_address, sender_name, reply_to, credential_ref, safe_fingerprint, created_at, updated_at)
             VALUES ($1, $2, 'pending', $3, 1, 1, $4, $5, $6, $7, $8, $9, $10, $11, $12, $12)",
            vec![prepared.id.into(), project_id.into(), generation.into(), prepared.host.clone().into(),
                i32::from(prepared.port).into(), prepared.tls_mode.as_str().into(), prepared.sender_address.clone().into(),
                prepared.sender_name.clone().into(), prepared.reply_to.clone().into(), prepared.credential_ref.clone().into(),
                prepared.safe_fingerprint.to_vec().into(), now.into()],
        )).await.map_err(persistence)?;
        transaction.execute_raw(statement(
            "INSERT INTO project_smtp_secret_operations
             (project_id, operation_alias, configuration_id, request_digest, credential_ref, state, created_at)
             VALUES ($1, $2, $3, $4, $5, 'prepared', $6)",
            vec![project_id.into(), prepared.operation_alias.clone().into(), prepared.id.into(),
                prepared.request_digest.clone().into(), prepared.credential_ref.clone().into(), now.into()],
        )).await.map_err(persistence)?;
        let advanced = transaction
            .execute_raw(statement(
                "UPDATE projects SET security_revision = security_revision + 1, updated_at = $3
             WHERE id = $1 AND security_revision = $2",
                vec![
                    project_id.into(),
                    project_security_revision.into(),
                    now.into(),
                ],
            ))
            .await
            .map_err(persistence)?;
        if advanced.rows_affected() != 1 {
            return Err(ApplicationError::RevisionConflict);
        }
        let row = transaction
            .query_one_raw(statement(
                "SELECT * FROM project_smtp_configurations WHERE project_id = $1 AND id = $2",
                vec![project_id.into(), prepared.id.into()],
            ))
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::Persistence)?;
        let record = smtp_record(&row)?;
        insert_audit(
            &transaction,
            Some(project_id),
            "email.smtp.prepared",
            "smtp_configuration",
            Some(prepared.id),
            prepared.correlation_id,
        )
        .await?;
        transaction.commit().await.map_err(persistence)?;
        Ok(PreparedSmtpConfiguration {
            record,
            operation_alias: prepared.operation_alias,
            credential_ref: prepared.credential_ref,
            request_digest: prepared.request_digest,
            correlation_id: prepared.correlation_id,
            external_provisioning_required: true,
        })
    }

    async fn provision_and_finalize_smtp_configuration(
        &self,
        project_id: Uuid,
        prepared: &PreparedSmtpConfiguration,
        provisioner: &dyn ConfigurationSecretProvisioner,
        credential: Zeroizing<Vec<u8>>,
        now: OffsetDateTime,
    ) -> Result<SmtpConfigurationRecord, ApplicationError> {
        let proposed_token = Uuid::new_v4();
        let transaction = self.database.begin().await.map_err(persistence)?;
        let owner = transaction
            .query_one_raw(statement(
                "SELECT operation.state AS operation_state,operation.provisioning_token,
                        configuration.status AS configuration_status
                 FROM project_smtp_secret_operations operation
                 JOIN project_smtp_configurations configuration
                   ON configuration.project_id=operation.project_id
                  AND configuration.id=operation.configuration_id
                 WHERE operation.project_id=$1 AND operation.operation_alias=$2
                   AND operation.configuration_id=$3 AND operation.request_digest=$4
                   AND operation.credential_ref=$5
                 FOR UPDATE OF operation,configuration",
                vec![
                    project_id.into(),
                    prepared.operation_alias.clone().into(),
                    prepared.record.id.into(),
                    prepared.request_digest.clone().into(),
                    prepared.credential_ref.clone().into(),
                ],
            ))
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::InvalidTransition)?;
        lock_smtp_credential_reference(&transaction, &prepared.credential_ref).await?;
        let operation_state: String = owner.try_get("", "operation_state").map_err(persistence)?;
        if operation_state == "completed" {
            let row = transaction
                .query_one_raw(statement(
                    "SELECT * FROM project_smtp_configurations WHERE project_id=$1 AND id=$2",
                    vec![project_id.into(), prepared.record.id.into()],
                ))
                .await
                .map_err(persistence)?
                .ok_or(ApplicationError::Integrity)?;
            let record = smtp_record(&row)?;
            transaction.commit().await.map_err(persistence)?;
            return Ok(record);
        }
        if !matches!(operation_state.as_str(), "prepared" | "provisioning")
            || owner
                .try_get::<String>("", "configuration_status")
                .map_err(persistence)?
                != "pending"
        {
            return Err(ApplicationError::InvalidTransition);
        }
        let reference = transaction
            .query_one_raw(statement(
                "SELECT state FROM smtp_credential_reference_reservations
                 WHERE credential_ref=$1 FOR UPDATE",
                vec![prepared.credential_ref.clone().into()],
            ))
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::Integrity)?;
        if reference
            .try_get::<String>("", "state")
            .map_err(persistence)?
            != "live"
        {
            return Err(ApplicationError::InvalidTransition);
        }
        let token = owner
            .try_get::<Option<Uuid>>("", "provisioning_token")
            .map_err(persistence)?
            .unwrap_or(proposed_token);
        let claimed = transaction
            .execute_raw(statement(
                "UPDATE project_smtp_secret_operations
                 SET state='provisioning',provisioning_token=$6
                 WHERE project_id=$1 AND operation_alias=$2 AND configuration_id=$3
                   AND request_digest=$4 AND credential_ref=$5
                   AND state IN ('prepared','provisioning')",
                vec![
                    project_id.into(),
                    prepared.operation_alias.clone().into(),
                    prepared.record.id.into(),
                    prepared.request_digest.clone().into(),
                    prepared.credential_ref.clone().into(),
                    token.into(),
                ],
            ))
            .await
            .map_err(persistence)?;
        if claimed.rows_affected() != 1 {
            return Err(ApplicationError::InvalidTransition);
        }
        // The durable claim is visible before any external call. No PostgreSQL transaction or
        // business lock survives this commit.
        transaction.commit().await.map_err(persistence)?;

        provisioner
            .provision_if_absent(prepared.credential_ref.clone(), credential)
            .await?;

        let transaction = self.database.begin().await.map_err(persistence)?;
        let owner = transaction
            .query_one_raw(statement(
                "SELECT operation.state AS operation_state,configuration.status AS configuration_status
                 FROM project_smtp_secret_operations operation
                 JOIN project_smtp_configurations configuration
                   ON configuration.project_id=operation.project_id
                  AND configuration.id=operation.configuration_id
                 WHERE operation.project_id=$1 AND operation.operation_alias=$2
                   AND operation.configuration_id=$3 AND operation.request_digest=$4
                   AND operation.credential_ref=$5 FOR UPDATE OF operation,configuration",
                vec![project_id.into(),prepared.operation_alias.clone().into(),prepared.record.id.into(),
                     prepared.request_digest.clone().into(),prepared.credential_ref.clone().into()],
            ))
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::InvalidTransition)?;
        lock_smtp_credential_reference(&transaction, &prepared.credential_ref).await?;
        if owner
            .try_get::<String>("", "operation_state")
            .map_err(persistence)?
            == "completed"
        {
            let row = transaction
                .query_one_raw(statement(
                    "SELECT * FROM project_smtp_configurations WHERE project_id=$1 AND id=$2",
                    vec![project_id.into(), prepared.record.id.into()],
                ))
                .await
                .map_err(persistence)?
                .ok_or(ApplicationError::Integrity)?;
            let record = smtp_record(&row)?;
            transaction.commit().await.map_err(persistence)?;
            return Ok(record);
        }
        if owner
            .try_get::<String>("", "configuration_status")
            .map_err(persistence)?
            != "pending"
        {
            return Err(ApplicationError::InvalidTransition);
        }
        let result = transaction.execute_raw(statement(
            "UPDATE project_smtp_secret_operations operation
             SET state='completed',completed_at=$4,provisioning_token=NULL
             WHERE operation.project_id=$1 AND operation.operation_alias=$2
               AND operation.configuration_id=$3 AND operation.request_digest=$5
               AND operation.credential_ref=$6 AND operation.state='provisioning'
               AND operation.provisioning_token=$7
               AND EXISTS (SELECT 1 FROM smtp_credential_reference_reservations reservation
                           WHERE reservation.credential_ref=operation.credential_ref AND reservation.state='live')",
            vec![project_id.into(),prepared.operation_alias.clone().into(),prepared.record.id.into(),now.into(),
                 prepared.request_digest.clone().into(),prepared.credential_ref.clone().into(),token.into()],
        )).await.map_err(persistence)?;
        if result.rows_affected() != 1 {
            return Err(ApplicationError::InvalidTransition);
        }
        insert_audit(
            &transaction,
            Some(project_id),
            "email.smtp.reconciled",
            "smtp_configuration",
            Some(prepared.record.id),
            prepared.correlation_id,
        )
        .await?;
        let row = transaction
            .query_one_raw(statement(
                "SELECT * FROM project_smtp_configurations WHERE project_id=$1 AND id=$2",
                vec![project_id.into(), prepared.record.id.into()],
            ))
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::Integrity)?;
        let record = smtp_record(&row)?;
        transaction.commit().await.map_err(persistence)?;
        Ok(record)
    }

    async fn list_smtp_configurations(
        &self,
        project_id: Uuid,
    ) -> Result<Vec<SmtpConfigurationRecord>, ApplicationError> {
        let mut rows = self
            .database
            .query_all_raw(statement(
                "SELECT smtp.*,
                        (status IN ('pending','active') OR
                         (status='retained' AND retained_until>transaction_timestamp())) AS is_live
                 FROM project_smtp_configurations smtp WHERE project_id=$1
                 ORDER BY is_live DESC,generation DESC LIMIT 33",
                vec![project_id.into()],
            ))
            .await
            .map_err(persistence)?;
        let live_count = rows
            .iter()
            .map(|row| row.try_get::<bool>("", "is_live").map_err(persistence))
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .filter(|is_live| *is_live)
            .count();
        let bound = usize::try_from(MAX_LIVE_PROJECT_SMTP_GENERATIONS)
            .map_err(|_| ApplicationError::Integrity)?;
        if live_count > bound {
            return Err(ApplicationError::Integrity);
        }
        rows.truncate(bound);
        let mut records = rows
            .iter()
            .map(smtp_record)
            .collect::<Result<Vec<_>, _>>()?;
        records.sort_unstable_by_key(|record| std::cmp::Reverse(record.generation));
        Ok(records)
    }

    async fn prepare_smtp_test(
        &self,
        project_id: Uuid,
        command: crate::application::PrepareSmtpTest,
        now: OffsetDateTime,
    ) -> Result<crate::application::SmtpTestOperationRecord, ApplicationError> {
        let transaction = self.database.begin().await.map_err(persistence)?;
        if let Some(existing) =
            resolve_existing_smtp_test(&transaction, project_id, &command).await?
        {
            transaction.commit().await.map_err(persistence)?;
            return Ok(existing);
        }
        let row = transaction
            .query_one_raw(statement(
                "SELECT * FROM project_smtp_configurations WHERE project_id=$1 AND id=$2 FOR SHARE",
                vec![project_id.into(), command.configuration_id.into()],
            ))
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        let revision: i64 = row.try_get("", "revision").map_err(persistence)?;
        let status: String = row.try_get("", "status").map_err(persistence)?;
        if revision != command.expected_revision
            || matches!(status.as_str(), "disabled" | "compromised" | "retired")
        {
            return Err(ApplicationError::RevisionConflict);
        }
        lock_smtp_credential_reference(&transaction, &command.recipient_ref).await?;
        transaction
            .execute_raw(statement(
                "INSERT INTO smtp_test_recipient_reference_reservations
                 (recipient_ref,state,operation_id,created_at,updated_at)
                 VALUES ($1,'live',$2,$3,$3) ON CONFLICT (recipient_ref) DO NOTHING",
                vec![
                    command.recipient_ref.clone().into(),
                    command.id.into(),
                    now.into(),
                ],
            ))
            .await
            .map_err(persistence)?;
        let recipient_reference = transaction
            .query_one_raw(statement(
                "SELECT state,operation_id FROM smtp_test_recipient_reference_reservations
                 WHERE recipient_ref=$1 FOR UPDATE",
                vec![command.recipient_ref.clone().into()],
            ))
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::Integrity)?;
        if recipient_reference
            .try_get::<String>("", "state")
            .map_err(persistence)?
            != "live"
            || recipient_reference
                .try_get::<Uuid>("", "operation_id")
                .map_err(persistence)?
                != command.id
        {
            return Err(ApplicationError::InvalidTransition);
        }
        let message_id = format!("<{}@runtime-test.owlauth.invalid>", command.id);
        transaction
            .execute_raw(statement(
                "INSERT INTO project_smtp_test_operations
             (id,project_id,idempotency_key,configuration_id,configuration_generation,
              configuration_revision,configuration_security_eligibility_revision,host,port,tls_mode,
              sender_address,credential_ref,request_digest,message_id,recipient_ref,provisioning_token,
              state,correlation_id,created_at,expires_at)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$1,'preparing',$16,$17,$18)",
                vec![
                    command.id.into(), project_id.into(), command.idempotency_key.clone().into(),
                    command.configuration_id.into(), row.try_get::<i32>("", "generation").map_err(persistence)?.into(),
                    revision.into(), row.try_get::<i64>("", "security_eligibility_revision").map_err(persistence)?.into(),
                    row.try_get::<String>("", "host").map_err(persistence)?.into(),
                    row.try_get::<i32>("", "port").map_err(persistence)?.into(),
                    row.try_get::<String>("", "tls_mode").map_err(persistence)?.into(),
                    row.try_get::<String>("", "sender_address").map_err(persistence)?.into(),
                    row.try_get::<String>("", "credential_ref").map_err(persistence)?.into(),
                    command.request_digest.clone().into(), message_id.into(), command.recipient_ref.clone().into(),
                    command.correlation_id.into(), now.into(), (now + Duration::minutes(10)).into(),
                ],
            ))
            .await
            .map_err(persistence)?;
        transaction.commit().await.map_err(persistence)?;
        Ok(crate::application::SmtpTestOperationRecord {
            id: command.id,
            project_id,
            configuration_id: command.configuration_id,
            state: crate::application::SmtpTestState::Preparing,
            outcome: None,
            created_at: now,
            completed_at: None,
            recipient_ref: command.recipient_ref,
        })
    }

    async fn provision_and_finalize_smtp_test_enqueue(
        &self,
        project_id: Uuid,
        operation_id: Uuid,
        request_digest: &[u8],
        provisioner: &dyn ConfigurationSecretProvisioner,
        recipient: Zeroizing<Vec<u8>>,
        now: OffsetDateTime,
    ) -> Result<crate::application::SmtpTestOperationRecord, ApplicationError> {
        // Discovering the alias is non-authoritative. The claim transaction reloads and locks the
        // operation owner first, then takes the shared per-reference lifecycle lock.
        let recipient_ref = self
            .database
            .query_one_raw(statement(
                "SELECT recipient_ref FROM project_smtp_test_operations
             WHERE project_id=$1 AND id=$2 AND request_digest=$3",
                vec![
                    project_id.into(),
                    operation_id.into(),
                    request_digest.to_vec().into(),
                ],
            ))
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::InvalidTransition)?
            .try_get::<String>("", "recipient_ref")
            .map_err(persistence)?;

        let transaction = self.database.begin().await.map_err(persistence)?;
        let owner = transaction
            .query_one_raw(statement(
                "SELECT * FROM project_smtp_test_operations
             WHERE project_id=$1 AND id=$2 AND request_digest=$3 FOR UPDATE",
                vec![
                    project_id.into(),
                    operation_id.into(),
                    request_digest.to_vec().into(),
                ],
            ))
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::InvalidTransition)?;
        let state: String = owner.try_get("", "state").map_err(persistence)?;
        if state != "preparing"
            || owner
                .try_get::<OffsetDateTime>("", "created_at")
                .map_err(persistence)?
                + Duration::minutes(5)
                <= now
            || owner
                .try_get::<String>("", "recipient_ref")
                .map_err(persistence)?
                != recipient_ref
            || owner
                .try_get::<Option<Uuid>>("", "provisioning_token")
                .map_err(persistence)?
                != Some(operation_id)
        {
            return Err(ApplicationError::InvalidTransition);
        }
        lock_smtp_credential_reference(&transaction, &recipient_ref).await?;
        let reference = transaction
            .query_one_raw(statement(
                "SELECT state,operation_id FROM smtp_test_recipient_reference_reservations
             WHERE recipient_ref=$1 FOR UPDATE",
                vec![recipient_ref.clone().into()],
            ))
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::Integrity)?;
        if reference
            .try_get::<String>("", "state")
            .map_err(persistence)?
            != "live"
            || reference
                .try_get::<Uuid>("", "operation_id")
                .map_err(persistence)?
                != operation_id
        {
            return Err(ApplicationError::InvalidTransition);
        }
        // `preparing` plus its stable token is the durable claim/barrier. Commit before touching
        // the external store; retries after a crash repeat the same create-if-absent safely.
        transaction.commit().await.map_err(persistence)?;

        provisioner
            .provision_if_absent(recipient_ref.clone(), recipient)
            .await?;

        let transaction = self.database.begin().await.map_err(persistence)?;
        let owner = transaction
            .query_one_raw(statement(
                "SELECT 1 AS present FROM project_smtp_test_operations
             WHERE project_id=$1 AND id=$2 AND request_digest=$3 AND state='preparing'
               AND provisioning_token=$4 FOR UPDATE",
                vec![
                    project_id.into(),
                    operation_id.into(),
                    request_digest.to_vec().into(),
                    operation_id.into(),
                ],
            ))
            .await
            .map_err(persistence)?;
        if owner.is_none() {
            let completed = transaction
                .query_one_raw(statement(
                    "SELECT * FROM project_smtp_test_operations
                 WHERE project_id=$1 AND id=$2 AND request_digest=$3 AND state='pending' FOR SHARE",
                    vec![
                        project_id.into(),
                        operation_id.into(),
                        request_digest.to_vec().into(),
                    ],
                ))
                .await
                .map_err(persistence)?;
            let Some(completed) = completed else {
                return Err(ApplicationError::InvalidTransition);
            };
            let result = smtp_test_record(&completed)?;
            transaction.commit().await.map_err(persistence)?;
            return Ok(result);
        }
        lock_smtp_credential_reference(&transaction, &recipient_ref).await?;
        let row = transaction
            .query_one_raw(statement(
                "UPDATE project_smtp_test_operations test
             SET state='pending',provisioning_token=NULL
             WHERE test.project_id=$1 AND test.id=$2 AND test.request_digest=$3
               AND test.state='preparing' AND test.provisioning_token=$5
               AND test.created_at + INTERVAL '5 minutes'>$4
               AND EXISTS (SELECT 1 FROM smtp_test_recipient_reference_reservations reservation
                           WHERE reservation.recipient_ref=test.recipient_ref
                             AND reservation.operation_id=test.id AND reservation.state='live')
             RETURNING test.*",
                vec![
                    project_id.into(),
                    operation_id.into(),
                    request_digest.to_vec().into(),
                    now.into(),
                    operation_id.into(),
                ],
            ))
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::InvalidTransition)?;
        let correlation_id: Uuid = row.try_get("", "correlation_id").map_err(persistence)?;
        let configuration_id: Uuid = row.try_get("", "configuration_id").map_err(persistence)?;
        let exists=transaction.query_one_raw(statement(
            "SELECT 1 AS present FROM audit_events WHERE project_id=$1 AND action='email.smtp.test_enqueued' AND correlation_id=$2",
            vec![project_id.into(),correlation_id.into()],
        )).await.map_err(persistence)?;
        if exists.is_none() {
            insert_audit(
                &transaction,
                Some(project_id),
                "email.smtp.test_enqueued",
                "smtp_configuration",
                Some(configuration_id),
                correlation_id,
            )
            .await?;
        }
        let result = smtp_test_record(&row)?;
        transaction.commit().await.map_err(persistence)?;
        Ok(result)
    }

    async fn get_smtp_test(
        &self,
        project_id: Uuid,
        operation_id: Uuid,
    ) -> Result<crate::application::SmtpTestOperationRecord, ApplicationError> {
        let row = self
            .database
            .query_one_raw(statement(
                "SELECT * FROM project_smtp_test_operations WHERE project_id=$1 AND id=$2",
                vec![project_id.into(), operation_id.into()],
            ))
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        smtp_test_record(&row)
    }

    async fn activate_smtp_configuration(
        &self,
        project_id: Uuid,
        configuration_id: Uuid,
        expected_revision: i64,
        retained_until: OffsetDateTime,
        correlation_id: Uuid,
        now: OffsetDateTime,
    ) -> Result<SmtpConfigurationRecord, ApplicationError> {
        let transaction = self.database.begin().await.map_err(persistence)?;
        // Lock the required incarnations in one deterministic process-id order before reading
        // readiness. Replacement UPSERTs cannot invalidate a proof until activation commits.
        let incarnations = transaction
            .query_all_raw(statement(
                "SELECT current.process_id
             FROM runtime_process_incarnations current
             JOIN jsonb_array_elements_text($1::jsonb) required(process_id)
               ON required.process_id=current.process_id
             ORDER BY current.process_id FOR SHARE OF current",
                vec![serde_json::json!(self.required_runtime_process_ids).into()],
            ))
            .await
            .map_err(persistence)?;
        if incarnations.len() != self.required_runtime_process_ids.len() {
            return Err(ApplicationError::InvalidTransition);
        }
        let candidate = transaction.query_one_raw(statement(
            "SELECT status, revision FROM project_smtp_configurations WHERE project_id = $1 AND id = $2 FOR UPDATE",
            vec![project_id.into(), configuration_id.into()],
        )).await.map_err(persistence)?.ok_or(ApplicationError::NotFound)?;
        let status: String = candidate.try_get("", "status").map_err(persistence)?;
        let runtime_ready = transaction
            .query_one_raw(statement(
                "SELECT NOT EXISTS (
                   SELECT required.process_id
                   FROM jsonb_array_elements_text($4::jsonb) AS required(process_id)
                   WHERE NOT EXISTS (
                     SELECT 1 FROM project_smtp_runtime_readiness readiness
                     JOIN project_smtp_configurations smtp
                       ON smtp.project_id=readiness.project_id
                      AND smtp.id=readiness.configuration_id
                      AND smtp.generation=readiness.generation
                     WHERE readiness.project_id=$1 AND readiness.configuration_id=$2
                       AND readiness.process_id=required.process_id
                       AND readiness.state='ready' AND readiness.lease_expires_at>$3
                       AND EXISTS (
                         SELECT 1 FROM runtime_process_incarnations current
                         WHERE current.process_id=readiness.process_id
                           AND current.process_incarnation=readiness.process_incarnation)
                       AND smtp.status='pending')) AS ready",
                vec![
                    project_id.into(),
                    configuration_id.into(),
                    now.into(),
                    serde_json::json!(self.required_runtime_process_ids).into(),
                ],
            ))
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::Integrity)?
            .try_get::<bool>("", "ready")
            .map_err(persistence)?;
        if candidate
            .try_get::<i64>("", "revision")
            .map_err(persistence)?
            != expected_revision
            || status != "pending"
        {
            return Err(ApplicationError::RevisionConflict);
        }
        if !runtime_ready {
            return Err(ApplicationError::InvalidTransition);
        }
        transaction
            .execute_raw(statement(
                "UPDATE project_smtp_configurations SET status = 'retained', retained_until = $2,
             revision = revision + 1, updated_at = $3 WHERE project_id = $1 AND status = 'active'",
                vec![project_id.into(), retained_until.into(), now.into()],
            ))
            .await
            .map_err(persistence)?;
        transaction.execute_raw(statement(
            "UPDATE project_smtp_configurations SET status = 'active', retained_until = NULL,
             revision = revision + 1, updated_at = $4 WHERE project_id = $1 AND id = $2 AND revision = $3",
            vec![project_id.into(), configuration_id.into(), expected_revision.into(), now.into()],
        )).await.map_err(persistence)?;
        insert_audit(
            &transaction,
            Some(project_id),
            "email.smtp.activated",
            "smtp_configuration",
            Some(configuration_id),
            correlation_id,
        )
        .await?;
        let row = transaction
            .query_one_raw(statement(
                "SELECT * FROM project_smtp_configurations WHERE project_id=$1 AND id=$2",
                vec![project_id.into(), configuration_id.into()],
            ))
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::Integrity)?;
        let record = smtp_record(&row)?;
        transaction.commit().await.map_err(persistence)?;
        Ok(record)
    }

    async fn list_deployment_smtp_generations(
        &self,
    ) -> Result<Vec<crate::application::DeploymentSmtpGenerationRecord>, ApplicationError> {
        self.database
            .query_all_raw(statement(
                "SELECT * FROM deployment_smtp_generations ORDER BY generation DESC LIMIT 32",
                vec![],
            ))
            .await
            .map_err(persistence)?
            .iter()
            .map(deployment_smtp_record)
            .collect()
    }

    async fn terminate_deployment_smtp_generation(
        &self,
        generation: i32,
        expected_revision: i64,
        compromised: bool,
        correlation_id: Uuid,
        now: OffsetDateTime,
    ) -> Result<crate::application::DeploymentSmtpGenerationRecord, ApplicationError> {
        let status = if compromised {
            "compromised"
        } else {
            "disabled"
        };
        let action = if compromised {
            "email.deployment_smtp.compromised"
        } else {
            "email.deployment_smtp.disabled"
        };
        let transaction = self.database.begin().await.map_err(persistence)?;
        let updated = transaction.execute_raw(statement(
            "UPDATE deployment_smtp_generations SET status=$2,retained_until=NULL,revision=revision+1,
             security_eligibility_revision=security_eligibility_revision+1,updated_at=$4
             WHERE generation=$1 AND revision=$3 AND status NOT IN ('disabled','compromised','retired')",
            vec![generation.into(), status.into(), expected_revision.into(), now.into()],
        )).await.map_err(persistence)?;
        if updated.rows_affected() != 1 {
            return Err(ApplicationError::RevisionConflict);
        }
        insert_audit(
            &transaction,
            None,
            action,
            "deployment_smtp_generation",
            None,
            correlation_id,
        )
        .await?;
        let row = transaction
            .query_one_raw(statement(
                "SELECT * FROM deployment_smtp_generations WHERE generation=$1",
                vec![generation.into()],
            ))
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::Integrity)?;
        let record = deployment_smtp_record(&row)?;
        transaction.commit().await.map_err(persistence)?;
        Ok(record)
    }

    async fn terminate_smtp_configuration(
        &self,
        project_id: Uuid,
        configuration_id: Uuid,
        expected_revision: i64,
        compromised: bool,
        correlation_id: Uuid,
        now: OffsetDateTime,
    ) -> Result<SmtpConfigurationRecord, ApplicationError> {
        let status = if compromised {
            "compromised"
        } else {
            "disabled"
        };
        let transaction = self.database.begin().await.map_err(persistence)?;
        let result = transaction.execute_raw(statement(
            "UPDATE project_smtp_configurations SET status = $3, retained_until = NULL,
             revision = revision + 1, security_eligibility_revision = security_eligibility_revision + 1,
             updated_at = $4 WHERE project_id = $1 AND id = $2 AND revision = $5
               AND status NOT IN ('disabled','compromised','retired')",
            vec![project_id.into(), configuration_id.into(), status.into(), now.into(), expected_revision.into()],
        )).await.map_err(persistence)?;
        if result.rows_affected() != 1 {
            return Err(ApplicationError::RevisionConflict);
        }
        insert_audit(
            &transaction,
            Some(project_id),
            if compromised {
                "email.smtp.compromised"
            } else {
                "email.smtp.disabled"
            },
            "smtp_configuration",
            Some(configuration_id),
            correlation_id,
        )
        .await?;
        let row = transaction
            .query_one_raw(statement(
                "SELECT * FROM project_smtp_configurations WHERE project_id=$1 AND id=$2",
                vec![project_id.into(), configuration_id.into()],
            ))
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::Integrity)?;
        let record = smtp_record(&row)?;
        transaction.commit().await.map_err(persistence)?;
        Ok(record)
    }
}

fn policy_record(row: &sea_orm::QueryResult) -> Result<EmailPolicyRecord, ApplicationError> {
    Ok(EmailPolicyRecord {
        project_id: row.try_get("", "project_id").map_err(persistence)?,
        enabled: row.try_get::<String>("", "status").map_err(persistence)? == "enabled",
        policy_revision: row.try_get("", "policy_revision").map_err(persistence)?,
        security_revision: row.try_get("", "security_revision").map_err(persistence)?,
        otp_enabled: row.try_get("", "otp_enabled").map_err(persistence)?,
        magic_link_enabled: row.try_get("", "magic_link_enabled").map_err(persistence)?,
        otp_digits: row.try_get("", "otp_digits").map_err(persistence)?,
        otp_validity_seconds: row
            .try_get("", "otp_validity_seconds")
            .map_err(persistence)?,
        otp_max_attempts: row.try_get("", "otp_max_attempts").map_err(persistence)?,
        resend_after_seconds: row
            .try_get("", "resend_after_seconds")
            .map_err(persistence)?,
        max_generations: row.try_get("", "max_generations").map_err(persistence)?,
        magic_validity_seconds: row
            .try_get("", "magic_validity_seconds")
            .map_err(persistence)?,
        signup_enabled: row.try_get("", "signup_enabled").map_err(persistence)?,
        transferred_magic_link_enabled: row
            .try_get("", "transferred_magic_link_enabled")
            .map_err(persistence)?,
        allow_deployment_default: row
            .try_get("", "allow_deployment_default")
            .map_err(persistence)?,
    })
}

fn smtp_record(row: &sea_orm::QueryResult) -> Result<SmtpConfigurationRecord, ApplicationError> {
    let status = match row
        .try_get::<String>("", "status")
        .map_err(persistence)?
        .as_str()
    {
        "pending" => SmtpControlStatus::Pending,
        "active" => SmtpControlStatus::Active,
        "retained" => SmtpControlStatus::Retained,
        "disabled" => SmtpControlStatus::Disabled,
        "compromised" => SmtpControlStatus::Compromised,
        "retired" => SmtpControlStatus::Retired,
        _ => return Err(ApplicationError::Integrity),
    };
    let tls_mode = match row
        .try_get::<String>("", "tls_mode")
        .map_err(persistence)?
        .as_str()
    {
        "implicit_tls" => SmtpControlTlsMode::ImplicitTls,
        "starttls_required" => SmtpControlTlsMode::StarttlsRequired,
        _ => return Err(ApplicationError::Integrity),
    };
    let port = u16::try_from(row.try_get::<i32>("", "port").map_err(persistence)?)
        .map_err(|_| ApplicationError::Integrity)?;
    let fingerprint: Vec<u8> = row.try_get("", "safe_fingerprint").map_err(persistence)?;
    Ok(SmtpConfigurationRecord {
        id: row.try_get("", "id").map_err(persistence)?,
        project_id: row.try_get("", "project_id").map_err(persistence)?,
        generation: row.try_get("", "generation").map_err(persistence)?,
        revision: row.try_get("", "revision").map_err(persistence)?,
        security_eligibility_revision: row
            .try_get("", "security_eligibility_revision")
            .map_err(persistence)?,
        status,
        host: row.try_get("", "host").map_err(persistence)?,
        port,
        tls_mode,
        sender_address: row.try_get("", "sender_address").map_err(persistence)?,
        sender_name: row.try_get("", "sender_name").map_err(persistence)?,
        reply_to: row.try_get("", "reply_to").map_err(persistence)?,
        retained_until: row.try_get("", "retained_until").map_err(persistence)?,
        safe_fingerprint: fingerprint
            .try_into()
            .map_err(|_| ApplicationError::Integrity)?,
    })
}

async fn resolve_existing_smtp_test(
    transaction: &DatabaseTransaction,
    project_id: Uuid,
    command: &crate::application::PrepareSmtpTest,
) -> Result<Option<crate::application::SmtpTestOperationRecord>, ApplicationError> {
    let existing = transaction.query_one_raw(statement(
        "SELECT * FROM project_smtp_test_operations WHERE project_id=$1 AND idempotency_key=$2 FOR UPDATE",
        vec![project_id.into(),command.idempotency_key.clone().into()],
    )).await.map_err(persistence)?;
    let Some(existing) = existing else {
        return Ok(None);
    };
    let digest: Vec<u8> = existing
        .try_get("", "request_digest")
        .map_err(persistence)?;
    let configuration_id: Uuid = existing
        .try_get("", "configuration_id")
        .map_err(persistence)?;
    if digest != command.request_digest || configuration_id != command.configuration_id {
        return Err(ApplicationError::IdempotencyConflict);
    }
    smtp_test_record(&existing).map(Some)
}

fn smtp_test_record(
    row: &sea_orm::QueryResult,
) -> Result<crate::application::SmtpTestOperationRecord, ApplicationError> {
    let state = match row
        .try_get::<String>("", "state")
        .map_err(persistence)?
        .as_str()
    {
        "preparing" => crate::application::SmtpTestState::Preparing,
        "pending" => crate::application::SmtpTestState::Pending,
        "submitting" => crate::application::SmtpTestState::Submitting,
        "delivered" => crate::application::SmtpTestState::Delivered,
        "failed" => crate::application::SmtpTestState::Failed,
        "ambiguous" => crate::application::SmtpTestState::Ambiguous,
        _ => return Err(ApplicationError::Integrity),
    };
    let outcome = match row
        .try_get::<Option<String>>("", "safe_outcome")
        .map_err(persistence)?
        .as_deref()
    {
        None => None,
        Some("delivered") => Some(crate::application::MailTransportOutcome::Delivered),
        Some("transient") => Some(crate::application::MailTransportOutcome::Transient),
        Some("permanent") => Some(crate::application::MailTransportOutcome::Permanent),
        Some("ambiguous") => Some(crate::application::MailTransportOutcome::Ambiguous),
        Some("policy_denied") => Some(crate::application::MailTransportOutcome::PolicyDenied),
        Some(_) => return Err(ApplicationError::Integrity),
    };
    Ok(crate::application::SmtpTestOperationRecord {
        id: row.try_get("", "id").map_err(persistence)?,
        project_id: row.try_get("", "project_id").map_err(persistence)?,
        configuration_id: row.try_get("", "configuration_id").map_err(persistence)?,
        state,
        outcome,
        created_at: row.try_get("", "created_at").map_err(persistence)?,
        completed_at: row.try_get("", "completed_at").map_err(persistence)?,
        recipient_ref: row.try_get("", "recipient_ref").map_err(persistence)?,
    })
}

fn deployment_smtp_record(
    row: &sea_orm::QueryResult,
) -> Result<crate::application::DeploymentSmtpGenerationRecord, ApplicationError> {
    let status = match row
        .try_get::<String>("", "status")
        .map_err(persistence)?
        .as_str()
    {
        "reconciled" => SmtpControlStatus::Reconciled,
        "active" => SmtpControlStatus::Active,
        "retained" => SmtpControlStatus::Retained,
        "disabled" => SmtpControlStatus::Disabled,
        "compromised" => SmtpControlStatus::Compromised,
        "retired" => SmtpControlStatus::Retired,
        _ => return Err(ApplicationError::Integrity),
    };
    let tls_mode = match row
        .try_get::<String>("", "tls_mode")
        .map_err(persistence)?
        .as_str()
    {
        "implicit_tls" => SmtpControlTlsMode::ImplicitTls,
        "starttls_required" => SmtpControlTlsMode::StarttlsRequired,
        _ => return Err(ApplicationError::Integrity),
    };
    let fingerprint: Vec<u8> = row.try_get("", "safe_fingerprint").map_err(persistence)?;
    Ok(crate::application::DeploymentSmtpGenerationRecord {
        generation: row.try_get("", "generation").map_err(persistence)?,
        revision: row.try_get("", "revision").map_err(persistence)?,
        security_eligibility_revision: row
            .try_get("", "security_eligibility_revision")
            .map_err(persistence)?,
        status,
        host: row.try_get("", "host").map_err(persistence)?,
        port: u16::try_from(row.try_get::<i32>("", "port").map_err(persistence)?)
            .map_err(|_| ApplicationError::Integrity)?,
        tls_mode,
        sender_address: row.try_get("", "sender_address").map_err(persistence)?,
        retained_until: row.try_get("", "retained_until").map_err(persistence)?,
        safe_fingerprint: fingerprint
            .try_into()
            .map_err(|_| ApplicationError::Integrity)?,
        explicitly_allowed_private_ips: parse_ip_allowlist(
            &row.try_get("", "explicitly_allowed_private_ips")
                .map_err(persistence)?,
        )?,
    })
}

async fn find_prepared_smtp_operation(
    transaction: &DatabaseTransaction,
    project_id: Uuid,
    prepared: &PrepareSmtpConfiguration,
) -> Result<Option<PreparedSmtpConfiguration>, ApplicationError> {
    let operation = transaction.query_one_raw(statement(
        "SELECT operation.request_digest, operation.credential_ref,
                operation.state AS operation_state,
                reservation.state AS reservation_state, configuration.*
         FROM project_smtp_secret_operations operation
         JOIN project_smtp_configurations configuration ON configuration.project_id = operation.project_id AND configuration.id = operation.configuration_id
         LEFT JOIN smtp_credential_reference_reservations reservation
           ON reservation.credential_ref=operation.credential_ref
         WHERE operation.project_id = $1 AND operation.operation_alias = $2
         FOR UPDATE OF operation,configuration",
        vec![project_id.into(), prepared.operation_alias.clone().into()],
    )).await.map_err(persistence)?;
    let Some(operation) = operation else {
        return Ok(None);
    };
    let digest: Vec<u8> = operation
        .try_get("", "request_digest")
        .map_err(persistence)?;
    let credential_ref: String = operation
        .try_get("", "credential_ref")
        .map_err(persistence)?;
    if digest != prepared.request_digest || credential_ref != prepared.credential_ref {
        return Err(ApplicationError::IdempotencyConflict);
    }
    Ok(Some(PreparedSmtpConfiguration {
        record: smtp_record(&operation)?,
        operation_alias: prepared.operation_alias.clone(),
        credential_ref: prepared.credential_ref.clone(),
        request_digest: prepared.request_digest.clone(),
        correlation_id: prepared.correlation_id,
        external_provisioning_required: matches!(
            operation
                .try_get::<String>("", "operation_state")
                .map_err(persistence)?
                .as_str(),
            "prepared" | "provisioning"
        ) && operation
            .try_get::<Option<String>>("", "reservation_state")
            .map_err(persistence)?
            .as_deref()
            == Some("live")
            && operation
                .try_get::<String>("", "status")
                .map_err(persistence)?
                == "pending",
    }))
}

async fn lock_smtp_credential_reference(
    transaction: &DatabaseTransaction,
    credential_ref: &str,
) -> Result<(), ApplicationError> {
    transaction
        .execute_raw(statement(
            "SELECT pg_advisory_xact_lock(hashtextextended('owlauth:smtp-credential:' || $1,0))",
            vec![credential_ref.to_owned().into()],
        ))
        .await
        .map_err(persistence)?;
    Ok(())
}

fn parse_ip_allowlist(
    value: &serde_json::Value,
) -> Result<Vec<std::net::IpAddr>, ApplicationError> {
    let values = value.as_array().ok_or(ApplicationError::Integrity)?;
    if values.len() > 16 {
        return Err(ApplicationError::Integrity);
    }
    values
        .iter()
        .map(|value| {
            value
                .as_str()
                .ok_or(ApplicationError::Integrity)?
                .parse()
                .map_err(|_| ApplicationError::Integrity)
        })
        .collect()
}

fn statement(sql: &str, values: Vec<sea_orm::Value>) -> Statement {
    Statement::from_sql_and_values(DbBackend::Postgres, sql, values)
}

fn persistence<E: std::fmt::Display>(_error: E) -> ApplicationError {
    ApplicationError::Persistence
}
