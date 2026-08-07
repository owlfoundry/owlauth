use super::{
    custody::{
        MaterialOwnerKind, MaterialPurpose, ProtectedMaterialRepository,
        ProtectedMaterialReservation, finalize_pending_material,
    },
    provisioning::insert_audit,
};
use async_trait::async_trait;
use sea_orm::{
    ConnectionTrait, DatabaseConnection, DatabaseTransaction, DbBackend, Statement,
    TransactionTrait,
};
use subtle::ConstantTimeEq;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

const MAX_LIVE_PROJECT_SMTP_GENERATIONS: i64 = 32;

use crate::application::{
    ApplicationError, EmailAssignmentRecord, EmailControlPort, EmailPolicyRecord,
    PrepareSmtpConfiguration, PreparedDeploymentSmtpGeneration, PreparedSecretMaterial,
    PreparedSmtpConfiguration, PreparedSmtpTest, ReconcileDeploymentSmtpGeneration,
    SealedProtectedMaterial, SmtpConfigurationRecord, SmtpControlStatus, SmtpControlTlsMode,
    UpdateEmailPolicy,
};
use owlauth_key_provider::{MaterialKind, ProviderFormatVersion, ProviderId};

#[derive(Clone)]
pub(crate) struct PostgresEmailControlRepository {
    database: DatabaseConnection,
    required_auth_process_ids: Vec<String>,
    custody: EmailControlCustody,
}

#[derive(Clone)]
struct EmailControlCustody {
    materials: ProtectedMaterialRepository,
    provider_id: ProviderId,
    provider_format_version: ProviderFormatVersion,
}

impl PostgresEmailControlRepository {
    pub(crate) fn new_protected(
        database: DatabaseConnection,
        required_auth_process_ids: Vec<String>,
        deployment_id: &str,
        provider_id: ProviderId,
        provider_format_version: ProviderFormatVersion,
    ) -> Result<Self, ApplicationError> {
        let custody = EmailControlCustody {
            materials: ProtectedMaterialRepository::new(database.clone(), deployment_id)?,
            provider_id,
            provider_format_version,
        };
        Ok(Self {
            database,
            required_auth_process_ids,
            custody,
        })
    }

    #[cfg(test)]
    pub(crate) fn new(database: DatabaseConnection) -> Self {
        Self::new_with_runtime_roster(database, vec!["auth-1".to_owned()])
    }

    #[cfg(test)]
    pub(crate) fn new_with_runtime_roster(
        database: DatabaseConnection,
        required_auth_process_ids: Vec<String>,
    ) -> Self {
        let provider_id = ProviderId::new("software").expect("test provider ID is valid");
        let provider_format_version =
            ProviderFormatVersion::new(1).expect("test provider format is valid");
        Self::new_protected(
            database,
            required_auth_process_ids,
            "test-deployment",
            provider_id,
            provider_format_version,
        )
        .expect("test SMTP custody is valid")
    }

    #[cfg(test)]
    pub(crate) fn with_custody(
        mut self,
        deployment_id: &str,
        provider_id: ProviderId,
        provider_format_version: ProviderFormatVersion,
    ) -> Result<Self, ApplicationError> {
        self.custody = EmailControlCustody {
            materials: ProtectedMaterialRepository::new(self.database.clone(), deployment_id)?,
            provider_id,
            provider_format_version,
        };
        Ok(self)
    }

    fn custody(&self) -> &EmailControlCustody {
        &self.custody
    }

    async fn prepared_smtp_material(
        &self,
        project_id: Uuid,
        configuration_id: Uuid,
        request_digest: &[u8],
    ) -> Result<PreparedSecretMaterial, ApplicationError> {
        let row = self
            .database
            .query_one_raw(statement(
                "SELECT operation.material_id,configuration.generation
             FROM project_smtp_secret_operations operation
             JOIN project_smtp_configurations configuration
               ON configuration.project_id=operation.project_id
              AND configuration.id=operation.configuration_id
             WHERE operation.project_id=$1 AND operation.configuration_id=$2
               AND operation.request_digest=$3",
                vec![
                    project_id.into(),
                    configuration_id.into(),
                    request_digest.to_vec().into(),
                ],
            ))
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        let material_id = row
            .try_get::<Uuid>("", "material_id")
            .map_err(persistence)?;
        let custody = self.custody();
        let reservation = custody
            .materials
            .load_project_reservation(project_id, material_id, MaterialPurpose::SmtpCredential)
            .await?;
        if reservation.owner_kind != MaterialOwnerKind::ProjectSmtp
            || reservation.owner_id != configuration_id
            || reservation.generation
                != i64::from(row.try_get::<i32>("", "generation").map_err(persistence)?)
            || reservation.material_kind != MaterialKind::ConfigurationSecret
        {
            return Err(ApplicationError::Integrity);
        }
        Ok(PreparedSecretMaterial {
            material_id,
            provider_id: reservation.provider_id,
            provider_format_version: reservation.provider_format_version,
            context: reservation.context,
        })
    }

    async fn prepared_smtp_test_material(
        &self,
        project_id: Uuid,
        operation_id: Uuid,
        request_digest: &[u8],
    ) -> Result<PreparedSecretMaterial, ApplicationError> {
        let row = self
            .database
            .query_one_raw(statement(
                "SELECT recipient_material_id FROM project_smtp_test_operations
             WHERE project_id=$1 AND id=$2 AND request_digest=$3",
                vec![
                    project_id.into(),
                    operation_id.into(),
                    request_digest.to_vec().into(),
                ],
            ))
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        let material_id = row
            .try_get::<Uuid>("", "recipient_material_id")
            .map_err(persistence)?;
        let custody = self.custody();
        let reservation = custody
            .materials
            .load_project_reservation(project_id, material_id, MaterialPurpose::SmtpTestRecipient)
            .await?;
        if reservation.owner_kind != MaterialOwnerKind::SmtpTestRecipient
            || reservation.owner_id != operation_id
            || reservation.generation != 1
            || reservation.material_kind != MaterialKind::ConfigurationSecret
        {
            return Err(ApplicationError::Integrity);
        }
        Ok(PreparedSecretMaterial {
            material_id,
            provider_id: reservation.provider_id,
            provider_format_version: reservation.provider_format_version,
            context: reservation.context,
        })
    }
}

#[async_trait]
#[allow(
    clippy::too_many_lines,
    reason = "SMTP preparation keeps owner revision, material reservation, idempotency, and audit in one transaction"
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

    async fn list_email_assignments(
        &self,
        project_id: Uuid,
    ) -> Result<Vec<EmailAssignmentRecord>, ApplicationError> {
        let _ = self.get_email_policy(project_id).await?;
        let rows = self
            .database
            .query_all_raw(statement(
                "SELECT project_id,application_id,status,security_revision
                 FROM application_email_assignments
                 WHERE project_id=$1
                 ORDER BY application_id
                 LIMIT 101",
                vec![project_id.into()],
            ))
            .await
            .map_err(persistence)?;
        if rows.len() > 100 {
            return Err(ApplicationError::Integrity);
        }
        rows.into_iter()
            .map(|row| {
                let status = row.try_get::<String>("", "status").map_err(persistence)?;
                let enabled = match status.as_str() {
                    "active" => true,
                    "disabled" => false,
                    _ => return Err(ApplicationError::Integrity),
                };
                Ok(EmailAssignmentRecord {
                    project_id: row.try_get("", "project_id").map_err(persistence)?,
                    application_id: row.try_get("", "application_id").map_err(persistence)?,
                    enabled,
                    security_revision: row.try_get("", "security_revision").map_err(persistence)?,
                })
            })
            .collect()
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
        if let Some(record) =
            find_prepared_smtp_operation(&transaction, project_id, &prepared).await?
        {
            transaction.commit().await.map_err(persistence)?;
            let material = self
                .prepared_smtp_material(project_id, record.id, &prepared.request_digest)
                .await?;
            return Ok(PreparedSmtpConfiguration {
                record,
                operation_alias: prepared.operation_alias,
                request_digest: prepared.request_digest,
                correlation_id: prepared.correlation_id,
                material,
            });
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
            return Err(ApplicationError::CapacityExceeded);
        }
        let generation = transaction.query_one_raw(statement(
            "SELECT COALESCE(MAX(generation), 0) + 1 AS generation FROM project_smtp_configurations WHERE project_id = $1",
            vec![project_id.into()],
        )).await.map_err(persistence)?.ok_or(ApplicationError::Persistence)?
            .try_get::<i32>("", "generation").map_err(persistence)?;
        let custody = self.custody();
        let reservation = custody
            .materials
            .reserve_project_in_transaction(
                &transaction,
                project_id,
                prepared.credential_material_id,
                MaterialOwnerKind::ProjectSmtp,
                prepared.id,
                i64::from(generation),
                MaterialKind::ConfigurationSecret,
                MaterialPurpose::SmtpCredential,
                custody.provider_id.clone(),
                custody.provider_format_version,
            )
            .await?;
        let material = PreparedSecretMaterial {
            material_id: prepared.credential_material_id,
            provider_id: reservation.provider_id,
            provider_format_version: reservation.provider_format_version,
            context: reservation.context,
        };
        transaction.execute_raw(statement(
            "INSERT INTO project_smtp_configurations
             (id, project_id, status, generation, revision, security_eligibility_revision, host, port, tls_mode,
              sender_address, sender_name, reply_to, safe_fingerprint, credential_material_id,
              created_at, updated_at)
             VALUES ($1, $2, 'pending', $3, 1, 1, $4, $5, $6, $7, $8, $9, $10, $11, $12, $12)",
            vec![prepared.id.into(), project_id.into(), generation.into(), prepared.host.clone().into(),
                i32::from(prepared.port).into(), prepared.tls_mode.as_str().into(), prepared.sender_address.clone().into(),
                prepared.sender_name.clone().into(), prepared.reply_to.clone().into(),
                Option::<Vec<u8>>::None.into(), material.material_id.into(), now.into()],
        )).await.map_err(persistence)?;
        transaction.execute_raw(statement(
            "INSERT INTO project_smtp_secret_operations
             (project_id, operation_alias, configuration_id, request_digest, material_id, state, created_at)
             VALUES ($1, $2, $3, $4, $5, 'prepared', $6)",
            vec![project_id.into(), prepared.operation_alias.clone().into(), prepared.id.into(),
                prepared.request_digest.clone().into(), material.material_id.into(), now.into()],
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
            request_digest: prepared.request_digest,
            correlation_id: prepared.correlation_id,
            material,
        })
    }

    async fn finalize_protected_smtp_configuration(
        &self,
        project_id: Uuid,
        prepared: &PreparedSmtpConfiguration,
        material: SealedProtectedMaterial,
        now: OffsetDateTime,
    ) -> Result<SmtpConfigurationRecord, ApplicationError> {
        if prepared.material.material_id != material.material_id {
            return Err(ApplicationError::Integrity);
        }
        let fingerprint = material.request_fingerprint.into_bytes();
        if fingerprint.len() != 32 {
            return Err(ApplicationError::Integrity);
        }
        let transaction = self.database.begin().await.map_err(persistence)?;
        let owner = transaction
            .query_one_raw(statement(
                "SELECT operation.state AS operation_state,operation.material_id,
                    configuration.status AS configuration_status,
                    configuration.credential_material_id,configuration.generation
             FROM project_smtp_secret_operations operation
             JOIN project_smtp_configurations configuration
               ON configuration.project_id=operation.project_id
              AND configuration.id=operation.configuration_id
             WHERE operation.project_id=$1 AND operation.operation_alias=$2
               AND operation.configuration_id=$3 AND operation.request_digest=$4
             FOR UPDATE OF operation,configuration",
                vec![
                    project_id.into(),
                    prepared.operation_alias.clone().into(),
                    prepared.record.id.into(),
                    prepared.request_digest.clone().into(),
                ],
            ))
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::InvalidTransition)?;
        if owner
            .try_get::<Uuid>("", "material_id")
            .map_err(persistence)?
            != material.material_id
            || owner
                .try_get::<Uuid>("", "credential_material_id")
                .map_err(persistence)?
                != material.material_id
        {
            return Err(ApplicationError::Integrity);
        }
        let operation_state: String = owner.try_get("", "operation_state").map_err(persistence)?;
        if operation_state != "completed"
            && (owner
                .try_get::<String>("", "configuration_status")
                .map_err(persistence)?
                != "pending"
                || !matches!(operation_state.as_str(), "prepared" | "provisioning"))
        {
            return Err(ApplicationError::InvalidTransition);
        }
        let custody = self.custody();
        let reservation = custody
            .materials
            .load_project_reservation_in_transaction(
                &transaction,
                project_id,
                material.material_id,
                MaterialPurpose::SmtpCredential,
            )
            .await?;
        if reservation.owner_kind != MaterialOwnerKind::ProjectSmtp
            || reservation.owner_id != prepared.record.id
            || reservation.generation
                != i64::from(
                    owner
                        .try_get::<i32>("", "generation")
                        .map_err(persistence)?,
                )
            || reservation.provider_id != material.provider_id
            || reservation.provider_format_version != material.provider_format_version
        {
            return Err(ApplicationError::Integrity);
        }
        transaction
            .execute_raw(statement(
                "UPDATE project_smtp_configurations
             SET safe_fingerprint=$4,updated_at=$5
             WHERE project_id=$1 AND id=$2 AND credential_material_id=$3",
                vec![
                    project_id.into(),
                    prepared.record.id.into(),
                    material.material_id.into(),
                    fingerprint.clone().into(),
                    now.into(),
                ],
            ))
            .await
            .map_err(persistence)?;
        finalize_pending_material(
            &transaction,
            material.material_id,
            Some(project_id),
            material.envelope.into_zeroizing().to_vec(),
            Some(fingerprint),
            now,
        )
        .await?;
        if operation_state != "completed" {
            let completed = transaction
                .execute_raw(statement(
                    "UPDATE project_smtp_secret_operations
                 SET state='completed',completed_at=$5,provisioning_token=NULL
                 WHERE project_id=$1 AND operation_alias=$2 AND configuration_id=$3
                   AND material_id=$4 AND state IN ('prepared','provisioning')",
                    vec![
                        project_id.into(),
                        prepared.operation_alias.clone().into(),
                        prepared.record.id.into(),
                        material.material_id.into(),
                        now.into(),
                    ],
                ))
                .await
                .map_err(persistence)?;
            if completed.rows_affected() != 1 {
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
        }
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
    ) -> Result<PreparedSmtpTest, ApplicationError> {
        let transaction = self.database.begin().await.map_err(persistence)?;
        if let Some(existing) =
            resolve_existing_smtp_test(&transaction, project_id, &command).await?
        {
            transaction.commit().await.map_err(persistence)?;
            let material = self
                .prepared_smtp_test_material(project_id, existing.id, &command.request_digest)
                .await?;
            return Ok(PreparedSmtpTest {
                record: existing,
                material,
            });
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
        let custody = self.custody();
        let reservation = custody
            .materials
            .reserve_project_in_transaction(
                &transaction,
                project_id,
                command.recipient_material_id,
                MaterialOwnerKind::SmtpTestRecipient,
                command.id,
                1,
                MaterialKind::ConfigurationSecret,
                MaterialPurpose::SmtpTestRecipient,
                custody.provider_id.clone(),
                custody.provider_format_version,
            )
            .await?;
        let material = PreparedSecretMaterial {
            material_id: command.recipient_material_id,
            provider_id: reservation.provider_id,
            provider_format_version: reservation.provider_format_version,
            context: reservation.context,
        };
        let message_id = format!("<{}@runtime-test.owlauth.invalid>", command.id);
        transaction
            .execute_raw(statement(
                "INSERT INTO project_smtp_test_operations
             (id,project_id,idempotency_key,configuration_id,configuration_generation,
              configuration_revision,configuration_security_eligibility_revision,host,port,tls_mode,
              sender_address,credential_material_id,request_digest,message_id,
              recipient_material_id,provisioning_token,state,correlation_id,created_at,expires_at)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$1,
                     'preparing',$16,$17,$18)",
                vec![
                    command.id.into(),
                    project_id.into(),
                    command.idempotency_key.clone().into(),
                    command.configuration_id.into(),
                    row.try_get::<i32>("", "generation")
                        .map_err(persistence)?
                        .into(),
                    revision.into(),
                    row.try_get::<i64>("", "security_eligibility_revision")
                        .map_err(persistence)?
                        .into(),
                    row.try_get::<String>("", "host")
                        .map_err(persistence)?
                        .into(),
                    row.try_get::<i32>("", "port").map_err(persistence)?.into(),
                    row.try_get::<String>("", "tls_mode")
                        .map_err(persistence)?
                        .into(),
                    row.try_get::<String>("", "sender_address")
                        .map_err(persistence)?
                        .into(),
                    row.try_get::<Uuid>("", "credential_material_id")
                        .map_err(persistence)?
                        .into(),
                    command.request_digest.clone().into(),
                    message_id.into(),
                    material.material_id.into(),
                    command.correlation_id.into(),
                    now.into(),
                    (now + Duration::minutes(10)).into(),
                ],
            ))
            .await
            .map_err(persistence)?;
        transaction.commit().await.map_err(persistence)?;
        Ok(PreparedSmtpTest {
            record: crate::application::SmtpTestOperationRecord {
                id: command.id,
                project_id,
                configuration_id: command.configuration_id,
                state: crate::application::SmtpTestState::Preparing,
                outcome: None,
                created_at: now,
                completed_at: None,
                recipient_material_id: command.recipient_material_id,
            },
            material,
        })
    }

    async fn finalize_protected_smtp_test_enqueue(
        &self,
        project_id: Uuid,
        prepared: &PreparedSmtpTest,
        request_digest: &[u8],
        material: SealedProtectedMaterial,
        now: OffsetDateTime,
    ) -> Result<crate::application::SmtpTestOperationRecord, ApplicationError> {
        if prepared.material.material_id != material.material_id {
            return Err(ApplicationError::Integrity);
        }
        let fingerprint = material.request_fingerprint.into_bytes();
        if fingerprint.len() != 32 {
            return Err(ApplicationError::Integrity);
        }
        let transaction = self.database.begin().await.map_err(persistence)?;
        let owner = transaction
            .query_one_raw(statement(
                "SELECT * FROM project_smtp_test_operations
             WHERE project_id=$1 AND id=$2 AND request_digest=$3 FOR UPDATE",
                vec![
                    project_id.into(),
                    prepared.record.id.into(),
                    request_digest.to_vec().into(),
                ],
            ))
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::InvalidTransition)?;
        if owner
            .try_get::<Uuid>("", "recipient_material_id")
            .map_err(persistence)?
            != material.material_id
        {
            return Err(ApplicationError::Integrity);
        }
        let custody = self.custody();
        let reservation = custody
            .materials
            .load_project_reservation_in_transaction(
                &transaction,
                project_id,
                material.material_id,
                MaterialPurpose::SmtpTestRecipient,
            )
            .await?;
        if reservation.owner_kind != MaterialOwnerKind::SmtpTestRecipient
            || reservation.owner_id != prepared.record.id
            || reservation.generation != 1
            || reservation.provider_id != material.provider_id
            || reservation.provider_format_version != material.provider_format_version
        {
            return Err(ApplicationError::Integrity);
        }
        let state: String = owner.try_get("", "state").map_err(persistence)?;
        if state == "preparing"
            && (owner
                .try_get::<Option<Uuid>>("", "provisioning_token")
                .map_err(persistence)?
                != Some(prepared.record.id)
                || owner
                    .try_get::<OffsetDateTime>("", "created_at")
                    .map_err(persistence)?
                    + Duration::minutes(5)
                    <= now)
        {
            return Err(ApplicationError::InvalidTransition);
        }
        finalize_pending_material(
            &transaction,
            material.material_id,
            Some(project_id),
            material.envelope.into_zeroizing().to_vec(),
            Some(fingerprint),
            now,
        )
        .await?;
        let row = if state == "preparing" {
            let row = transaction
                .query_one_raw(statement(
                    "UPDATE project_smtp_test_operations
                 SET state='pending',provisioning_token=NULL
                 WHERE project_id=$1 AND id=$2 AND request_digest=$3
                   AND recipient_material_id=$4 AND state='preparing'
                 RETURNING *",
                    vec![
                        project_id.into(),
                        prepared.record.id.into(),
                        request_digest.to_vec().into(),
                        material.material_id.into(),
                    ],
                ))
                .await
                .map_err(persistence)?
                .ok_or(ApplicationError::InvalidTransition)?;
            let correlation_id: Uuid = row.try_get("", "correlation_id").map_err(persistence)?;
            let configuration_id: Uuid =
                row.try_get("", "configuration_id").map_err(persistence)?;
            insert_audit(
                &transaction,
                Some(project_id),
                "email.smtp.test_enqueued",
                "smtp_configuration",
                Some(configuration_id),
                correlation_id,
            )
            .await?;
            row
        } else {
            owner
        };
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
             FROM auth_process_incarnations current
             JOIN jsonb_array_elements_text($1::jsonb) required(process_id)
               ON required.process_id=current.process_id
             ORDER BY current.process_id FOR SHARE OF current",
                vec![serde_json::json!(self.required_auth_process_ids).into()],
            ))
            .await
            .map_err(persistence)?;
        if incarnations.len() != self.required_auth_process_ids.len() {
            return Err(ApplicationError::InvalidTransition);
        }
        let candidate = transaction.query_one_raw(statement(
            "SELECT smtp.status, smtp.revision,
                    EXISTS (
                      SELECT 1 FROM project_smtp_test_operations test
                      WHERE test.project_id=smtp.project_id
                        AND test.configuration_id=smtp.id
                        AND test.configuration_generation=smtp.generation
                        AND test.configuration_revision=smtp.revision
                        AND test.configuration_security_eligibility_revision=smtp.security_eligibility_revision
                        AND test.state='delivered' AND test.safe_outcome='delivered'
                        AND test.completed_at IS NOT NULL
                    ) AS delivered_test
             FROM project_smtp_configurations smtp
             WHERE smtp.project_id=$1 AND smtp.id=$2 FOR UPDATE OF smtp",
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
                         SELECT 1 FROM auth_process_incarnations current
                         WHERE current.process_id=readiness.process_id
                           AND current.process_incarnation=readiness.process_incarnation)
                       AND smtp.status='pending')) AS ready",
                vec![
                    project_id.into(),
                    configuration_id.into(),
                    now.into(),
                    serde_json::json!(self.required_auth_process_ids).into(),
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
        if !candidate
            .try_get::<bool>("", "delivered_test")
            .map_err(persistence)?
            || !runtime_ready
        {
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

    async fn prepare_deployment_smtp_generation(
        &self,
        command: &ReconcileDeploymentSmtpGeneration,
        request_digest: &[u8],
        now: OffsetDateTime,
    ) -> Result<PreparedDeploymentSmtpGeneration, ApplicationError> {
        if request_digest.len() != 32 {
            return Err(ApplicationError::InvalidInput);
        }
        let custody = self.custody();
        let transaction = self.database.begin().await.map_err(persistence)?;
        transaction
            .execute_raw(statement(
                "SELECT pg_advisory_xact_lock(hashtextextended('owlauth:deployment-smtp',0))",
                vec![],
            ))
            .await
            .map_err(persistence)?;
        if let Some(existing) = transaction
            .query_one_raw(statement(
                "SELECT operation.id,operation.generation,operation.material_id,
                        operation.request_digest,generation.material_owner_id
                   FROM deployment_smtp_secret_operations operation
                   JOIN deployment_smtp_generations generation
                     ON generation.generation=operation.generation
                  WHERE operation.idempotency_key=$1
                  FOR UPDATE OF operation,generation",
                vec![command.idempotency_key.clone().into()],
            ))
            .await
            .map_err(persistence)?
        {
            if existing
                .try_get::<i32>("", "generation")
                .map_err(persistence)?
                != command.generation
                || !bool::from(
                    existing
                        .try_get::<Vec<u8>>("", "request_digest")
                        .map_err(persistence)?
                        .as_slice()
                        .ct_eq(request_digest),
                )
            {
                return Err(ApplicationError::IdempotencyConflict);
            }
            let operation_id = existing.try_get("", "id").map_err(persistence)?;
            let material_id = existing.try_get("", "material_id").map_err(persistence)?;
            let owner_id = existing
                .try_get("", "material_owner_id")
                .map_err(persistence)?;
            transaction.commit().await.map_err(persistence)?;
            let reservation = custody
                .materials
                .load_deployment_reservation(material_id, MaterialPurpose::SmtpCredential)
                .await?;
            validate_deployment_smtp_reservation(
                &reservation,
                material_id,
                owner_id,
                command.generation,
            )?;
            return Ok(PreparedDeploymentSmtpGeneration {
                operation_id,
                idempotency_key: command.idempotency_key.clone(),
                request_digest: request_digest.to_vec(),
                material: PreparedSecretMaterial {
                    material_id,
                    provider_id: reservation.provider_id,
                    provider_format_version: reservation.provider_format_version,
                    context: reservation.context,
                },
                correlation_id: command.correlation_id,
            });
        }
        if transaction
            .query_one_raw(statement(
                "SELECT 1 AS present FROM deployment_smtp_generations WHERE generation=$1 FOR UPDATE",
                vec![command.generation.into()],
            ))
            .await
            .map_err(persistence)?
            .is_some()
        {
            return Err(ApplicationError::IdempotencyConflict);
        }
        let operation_id = Uuid::new_v4();
        let owner_id = Uuid::new_v4();
        let material_id = Uuid::new_v4();
        let reservation = custody
            .materials
            .reserve_deployment_in_transaction(
                &transaction,
                material_id,
                MaterialOwnerKind::DeploymentSmtp,
                owner_id,
                i64::from(command.generation),
                MaterialKind::ConfigurationSecret,
                MaterialPurpose::SmtpCredential,
                custody.provider_id.clone(),
                custody.provider_format_version,
            )
            .await?;
        transaction
            .execute_raw(statement(
                "INSERT INTO deployment_smtp_generations
                 (generation,status,revision,security_eligibility_revision,host,port,tls_mode,
                  sender_address,safe_fingerprint,explicitly_allowed_private_ips,
                  material_owner_id,credential_material_id,created_at,updated_at)
                 VALUES ($1,'reconciled',1,1,$2,$3,$4,$5,NULL,$6,$7,$8,$9,$9)",
                vec![
                    command.generation.into(),
                    command.host.clone().into(),
                    i32::from(command.port).into(),
                    command.tls_mode.as_str().into(),
                    command.sender_address.clone().into(),
                    serde_json::json!(
                        command
                            .explicitly_allowed_private_ips
                            .iter()
                            .map(ToString::to_string)
                            .collect::<Vec<_>>()
                    )
                    .into(),
                    owner_id.into(),
                    material_id.into(),
                    now.into(),
                ],
            ))
            .await
            .map_err(persistence)?;
        transaction
            .execute_raw(statement(
                "INSERT INTO deployment_smtp_secret_operations
                 (id,idempotency_key,generation,material_id,request_digest,state,correlation_id,created_at)
                 VALUES ($1,$2,$3,$4,$5,'prepared',$6,$7)",
                vec![
                    operation_id.into(),
                    command.idempotency_key.clone().into(),
                    command.generation.into(),
                    material_id.into(),
                    request_digest.to_vec().into(),
                    command.correlation_id.into(),
                    now.into(),
                ],
            ))
            .await
            .map_err(persistence)?;
        transaction.commit().await.map_err(persistence)?;
        Ok(PreparedDeploymentSmtpGeneration {
            operation_id,
            idempotency_key: command.idempotency_key.clone(),
            request_digest: request_digest.to_vec(),
            material: PreparedSecretMaterial {
                material_id,
                provider_id: reservation.provider_id,
                provider_format_version: reservation.provider_format_version,
                context: reservation.context,
            },
            correlation_id: command.correlation_id,
        })
    }

    async fn finalize_protected_deployment_smtp_generation(
        &self,
        prepared: &PreparedDeploymentSmtpGeneration,
        material: SealedProtectedMaterial,
        now: OffsetDateTime,
    ) -> Result<crate::application::DeploymentSmtpGenerationRecord, ApplicationError> {
        if material.material_id != prepared.material.material_id {
            return Err(ApplicationError::Integrity);
        }
        let fingerprint = material.request_fingerprint.into_bytes();
        if fingerprint.len() != 32 {
            return Err(ApplicationError::Integrity);
        }
        let custody = self.custody();
        let transaction = self.database.begin().await.map_err(persistence)?;
        transaction
            .execute_raw(statement(
                "SELECT pg_advisory_xact_lock(hashtextextended('owlauth:deployment-smtp',0))",
                vec![],
            ))
            .await
            .map_err(persistence)?;
        let row = transaction
            .query_one_raw(statement(
                "SELECT operation.state,operation.request_digest,operation.secret_fingerprint,
                        operation.generation,generation.material_owner_id,
                        generation.credential_material_id,generation.safe_fingerprint
                   FROM deployment_smtp_secret_operations operation
                   JOIN deployment_smtp_generations generation
                     ON generation.generation=operation.generation
                  WHERE operation.id=$1 AND operation.idempotency_key=$2
                    AND operation.material_id=$3
                  FOR UPDATE OF operation,generation",
                vec![
                    prepared.operation_id.into(),
                    prepared.idempotency_key.clone().into(),
                    material.material_id.into(),
                ],
            ))
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::InvalidTransition)?;
        if !bool::from(
            row.try_get::<Vec<u8>>("", "request_digest")
                .map_err(persistence)?
                .as_slice()
                .ct_eq(prepared.request_digest.as_slice()),
        ) || row
            .try_get::<Uuid>("", "credential_material_id")
            .map_err(persistence)?
            != material.material_id
        {
            return Err(ApplicationError::IdempotencyConflict);
        }
        let generation: i32 = row.try_get("", "generation").map_err(persistence)?;
        let owner_id: Uuid = row.try_get("", "material_owner_id").map_err(persistence)?;
        let reservation = custody
            .materials
            .load_deployment_reservation_in_transaction(
                &transaction,
                material.material_id,
                MaterialPurpose::SmtpCredential,
            )
            .await?;
        validate_deployment_smtp_reservation(
            &reservation,
            material.material_id,
            owner_id,
            generation,
        )?;
        if reservation.provider_id != material.provider_id
            || reservation.provider_format_version != material.provider_format_version
        {
            return Err(ApplicationError::Integrity);
        }
        finalize_pending_material(
            &transaction,
            material.material_id,
            None,
            material.envelope.into_zeroizing().to_vec(),
            Some(fingerprint.clone()),
            now,
        )
        .await?;
        let state: String = row.try_get("", "state").map_err(persistence)?;
        if state == "prepared" {
            transaction
                .execute_raw(statement(
                    "UPDATE deployment_smtp_generations
                        SET safe_fingerprint=$2,updated_at=$3
                      WHERE generation=$1 AND credential_material_id=$4
                        AND safe_fingerprint IS NULL",
                    vec![
                        generation.into(),
                        fingerprint.clone().into(),
                        now.into(),
                        material.material_id.into(),
                    ],
                ))
                .await
                .map_err(persistence)?;
            transaction
                .execute_raw(statement(
                    "UPDATE deployment_smtp_secret_operations
                        SET state='completed',secret_fingerprint=$2,completed_at=$3
                      WHERE id=$1 AND state='prepared'",
                    vec![prepared.operation_id.into(), fingerprint.into(), now.into()],
                ))
                .await
                .map_err(persistence)?;
            insert_audit(
                &transaction,
                None,
                "email.deployment_smtp.reconciled",
                "deployment_smtp_generation",
                None,
                prepared.correlation_id,
            )
            .await?;
        } else if state != "completed"
            || row
                .try_get::<Option<Vec<u8>>>("", "secret_fingerprint")
                .map_err(persistence)?
                .as_deref()
                != Some(fingerprint.as_slice())
        {
            return Err(ApplicationError::IdempotencyConflict);
        }
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
    let fingerprint: Option<Vec<u8>> = row.try_get("", "safe_fingerprint").map_err(persistence)?;
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
            .map(|value| value.try_into().map_err(|_| ApplicationError::Integrity))
            .transpose()?,
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
        recipient_material_id: row
            .try_get("", "recipient_material_id")
            .map_err(persistence)?,
    })
}

fn validate_deployment_smtp_reservation(
    reservation: &ProtectedMaterialReservation,
    material_id: Uuid,
    owner_id: Uuid,
    generation: i32,
) -> Result<(), ApplicationError> {
    if reservation.id != material_id
        || reservation.owner_kind != MaterialOwnerKind::DeploymentSmtp
        || reservation.owner_id != owner_id
        || reservation.generation != i64::from(generation)
        || reservation.material_kind != MaterialKind::ConfigurationSecret
    {
        return Err(ApplicationError::Integrity);
    }
    Ok(())
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
) -> Result<Option<SmtpConfigurationRecord>, ApplicationError> {
    let operation = transaction.query_one_raw(statement(
        "SELECT operation.request_digest,configuration.*
         FROM project_smtp_secret_operations operation
         JOIN project_smtp_configurations configuration ON configuration.project_id = operation.project_id AND configuration.id = operation.configuration_id
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
    if digest != prepared.request_digest {
        return Err(ApplicationError::IdempotencyConflict);
    }
    smtp_record(&operation).map(Some)
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
