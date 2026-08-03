use async_trait::async_trait;
use sea_orm::{ConnectionTrait, DatabaseConnection, DbBackend, Statement, TransactionTrait};
use serde_json::json;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::application::{
    ApplicationError, ClaimManagedReauthorization, CompletedManagedReauthorization,
    ConnectionGuard, CreateManagedReauthorizationResult, FailManagedReauthorization,
    ManagedReauthorizationDigestVersions, ManagedReauthorizationRecord,
    ManagedReauthorizationRepository, ManagedReauthorizationStatus,
    PreparedManagedReauthorizationCreate, ProtectedValue, VersionedDigest,
};

use super::{audit::append_runtime_audit, authentication::persistence};

const CREATE_OPERATION_KIND: &str = "managed_reauthorization.create";

#[derive(Clone, Debug)]
pub(crate) struct PostgresManagedReauthorizationRepository {
    database: DatabaseConnection,
}

impl PostgresManagedReauthorizationRepository {
    pub(crate) fn new(database: DatabaseConnection) -> Self {
        Self { database }
    }
}

#[async_trait]
#[allow(
    clippy::too_many_lines,
    reason = "managed reauthorization keeps each security transaction and frozen authority visible"
)]
impl ManagedReauthorizationRepository for PostgresManagedReauthorizationRepository {
    async fn create(
        &self,
        prepared: PreparedManagedReauthorizationCreate,
    ) -> Result<CreateManagedReauthorizationResult, ApplicationError> {
        let transaction = self.database.begin().await.map_err(persistence)?;
        transaction
            .execute_raw(statement(
                "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))",
                vec![prepared.command.idempotency_key.clone().into()],
            ))
            .await
            .map_err(persistence)?;
        let request_scope = prepared.command.project_id.to_string();
        if let Some(existing) = transaction
            .query_one_raw(statement(
                r"SELECT project_id, request_digest, state, result_resource_id,
                          operation_kind, request_scope
                     FROM control_idempotency_records
                    WHERE idempotency_key=$1 FOR UPDATE",
                vec![prepared.command.idempotency_key.clone().into()],
            ))
            .await
            .map_err(persistence)?
        {
            let compatible = get::<Option<Uuid>>(&existing, "project_id")?
                == Some(prepared.command.project_id)
                && get::<Vec<u8>>(&existing, "request_digest")? == prepared.request_digest
                && get::<String>(&existing, "operation_kind")? == CREATE_OPERATION_KIND
                && get::<String>(&existing, "request_scope")? == request_scope;
            if !compatible {
                transaction.rollback().await.map_err(persistence)?;
                return Err(ApplicationError::IdempotencyConflict);
            }
            if get::<String>(&existing, "state")? != "completed" {
                transaction.rollback().await.map_err(persistence)?;
                return Err(ApplicationError::OperationInProgress);
            }
            let interaction_id: Uuid = get::<Option<Uuid>>(&existing, "result_resource_id")?
                .ok_or(ApplicationError::Integrity)?;
            expire_by_id(&transaction, interaction_id, prepared.now).await?;
            transaction
                .query_one_raw(statement(
                    "SELECT id FROM managed_provider_reauthorization_interactions WHERE id=$1 FOR UPDATE",
                    vec![interaction_id.into()],
                ))
                .await
                .map_err(persistence)?
                .ok_or(ApplicationError::Integrity)?;
            let interaction = read_record(
                &transaction,
                prepared.command.project_id,
                prepared.command.user_id,
                prepared.command.connection_id,
                interaction_id,
                prepared.now,
                false,
            )
            .await?;
            let result = transaction
                .query_one_raw(statement(
                    r"SELECT project_id, interaction_id, request_digest,
                              create_result_key_version, create_result_ciphertext,
                              expires_at, erased_at
                         FROM managed_reauthorization_create_results
                        WHERE idempotency_key=$1 FOR UPDATE",
                    vec![prepared.command.idempotency_key.clone().into()],
                ))
                .await
                .map_err(persistence)?
                .ok_or(ApplicationError::Integrity)?;
            let result_expires_at = get::<OffsetDateTime>(&result, "expires_at")?;
            if get::<Uuid>(&result, "project_id")? != prepared.command.project_id
                || get::<Uuid>(&result, "interaction_id")? != interaction_id
                || result_expires_at != interaction.expires_at
            {
                transaction.rollback().await.map_err(persistence)?;
                return Err(ApplicationError::Integrity);
            }
            let request_digest = get::<Option<Vec<u8>>>(&result, "request_digest")?;
            let key_version = get::<i32>(&result, "create_result_key_version")?;
            let ciphertext = get::<Option<Vec<u8>>>(&result, "create_result_ciphertext")?;
            let erased_at = get::<Option<OffsetDateTime>>(&result, "erased_at")?;
            let live = request_digest.as_deref() == Some(prepared.request_digest.as_slice())
                && ciphertext.is_some()
                && erased_at.is_none();
            let tombstone = request_digest.is_none()
                && ciphertext.is_none()
                && erased_at.is_some_and(|erased| erased >= result_expires_at);
            let protected = if prepared.now < interaction.expires_at {
                if !live {
                    transaction.rollback().await.map_err(persistence)?;
                    return Err(ApplicationError::Integrity);
                }
                Some(ProtectedValue {
                    ciphertext: ciphertext.ok_or(ApplicationError::Integrity)?,
                    key_version,
                })
            } else if live {
                erase_create_result(
                    &transaction,
                    &prepared.command.idempotency_key,
                    prepared.now,
                )
                .await?;
                None
            } else if tombstone {
                None
            } else {
                transaction.rollback().await.map_err(persistence)?;
                return Err(ApplicationError::Integrity);
            };
            transaction.commit().await.map_err(persistence)?;
            return Ok(CreateManagedReauthorizationResult::Replayed {
                interaction,
                protected_create_result: protected,
            });
        }

        // Canonical lock order. Authority is frozen from these exact current rows.
        let project = transaction
            .query_one_raw(statement(
                r"SELECT id, public_id, security_revision FROM projects
                    WHERE id=$1 AND status='active' FOR SHARE",
                vec![prepared.command.project_id.into()],
            ))
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        let authority = transaction
            .query_one_raw(statement(
                r"SELECT provider.id AS provider_id, provider.kind AS provider_legacy_kind, provider.adapter_kind AS provider_adapter_kind, provider.provider_key, provider.issuer,
                          provider.client_id, provider.secret_ref, provider.callback_url,
                          provider.revision AS provider_revision,
                          provider.managed_profile_revision, application.revision AS application_revision,
                          assignment.security_revision AS assignment_security_revision
                     FROM managed_provider_connections AS connection
                     JOIN provider_configurations AS provider
                       ON provider.project_id=connection.project_id
                      AND provider.id=connection.provider_configuration_id
                     JOIN applications AS application
                       ON application.project_id=connection.project_id AND application.id=$4
                     JOIN application_provider_assignments AS assignment
                       ON assignment.project_id=connection.project_id
                      AND assignment.application_id=application.id AND assignment.provider_id=provider.id
                    WHERE connection.project_id=$1 AND connection.id=$2 AND connection.user_id=$3
                      AND provider.status='active' AND provider.managed_profile_enabled
                      AND application.status='active' AND assignment.status='active'
                    FOR SHARE OF provider, application, assignment",
                vec![
                    prepared.command.project_id.into(),
                    prepared.command.connection_id.into(),
                    prepared.command.user_id.into(),
                    prepared.command.application_id.into(),
                ],
            ))
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        let user = transaction
            .query_one_raw(statement(
                r"SELECT security_revision FROM project_users
                    WHERE project_id=$1 AND id=$2 AND status='active' FOR UPDATE",
                vec![
                    prepared.command.project_id.into(),
                    prepared.command.user_id.into(),
                ],
            ))
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        let identity = transaction
            .query_one_raw(statement(
                r"SELECT identity.id, identity.subject, identity.identity_revision
                     FROM linked_identities AS identity
                     JOIN managed_provider_connections AS connection
                       ON connection.project_id=identity.project_id
                      AND connection.linked_identity_id=identity.id
                    WHERE connection.project_id=$1 AND connection.id=$2
                      AND identity.user_id=$3 AND identity.status='active'
                    FOR UPDATE OF identity",
                vec![
                    prepared.command.project_id.into(),
                    prepared.command.connection_id.into(),
                    prepared.command.user_id.into(),
                ],
            ))
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        let connection = transaction
            .query_one_raw(statement(
                r"SELECT connection.provider_configuration_id, connection.linked_identity_id,
                          connection.revision, connection.generation, connection.credential_generation
                     FROM managed_provider_connections AS connection
                    WHERE connection.project_id=$1 AND connection.id=$2 AND connection.user_id=$3
                      AND connection.state IN ('active','reauth_required','revoked','disconnected')
                      AND connection.revision=$4 AND connection.generation=$5
                      AND connection.credential_generation=$6
                      AND connection.revocation_requested_at IS NULL
                      AND (connection.lease_expires_at IS NULL OR connection.lease_expires_at<=$7)
                    FOR UPDATE",
                vec![
                    prepared.command.project_id.into(),
                    prepared.command.connection_id.into(),
                    prepared.command.user_id.into(),
                    prepared.command.expected_connection_revision.into(),
                    prepared.command.expected_connection_generation.into(),
                    prepared.command.expected_credential_generation.into(),
                    prepared.now.into(),
                ],
            ))
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::RevisionConflict)?;
        let provider_kind = super::effective_provider_kind(
            &get::<String>(&authority, "provider_legacy_kind")?,
            get::<Option<String>>(&authority, "provider_adapter_kind")?.as_deref(),
            &get::<String>(&authority, "issuer")?,
        )?;
        if !provider_kind.capabilities().managed_profile
            || !provider_kind.issuer_matches(&get::<String>(&authority, "issuer")?)
        {
            return Err(ApplicationError::Integrity);
        }
        if get::<Uuid>(&authority, "provider_id")?
            != get::<Uuid>(&connection, "provider_configuration_id")?
            || get::<Uuid>(&identity, "id")? != get::<Uuid>(&connection, "linked_identity_id")?
        {
            transaction.rollback().await.map_err(persistence)?;
            return Err(ApplicationError::RevisionConflict);
        }
        transaction
            .execute_raw(statement(
                r"INSERT INTO managed_provider_reauthorization_interactions
                  (id,project_id,project_public_id,connection_id,linked_identity_id,user_id,
                   provider_configuration_id,provider_key,issuer,subject,client_id,secret_ref,
                   application_id,expected_connection_generation,expected_credential_generation,
                   expected_connection_revision,project_security_revision,user_security_revision,
                   identity_revision,provider_revision,managed_profile_revision,application_revision,
                   assignment_security_revision,callback_url,adapter_key,adapter_capability_revision,
                   supports_revocation,required_scopes,provider_pkce_required,oidc_nonce_required,
                   interaction_digest,interaction_digest_key_version,revision,status,expires_at,created_at,
                   provider_kind)
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,
                         $19,$20,$21,$22,$23,$24,$25,$26,$27,
                         ARRAY(SELECT jsonb_array_elements_text($28::jsonb)),$29,$30,$31,$32,1,
                         'awaiting_browser_binding',$33,$34,$35)",
                vec![
                    prepared.interaction_id.into(),
                    prepared.command.project_id.into(),
                    get::<String>(&project, "public_id")?.into(),
                    prepared.command.connection_id.into(),
                    get::<Uuid>(&identity, "id")?.into(),
                    prepared.command.user_id.into(),
                    get::<Uuid>(&authority, "provider_id")?.into(),
                    get::<String>(&authority, "provider_key")?.into(),
                    get::<String>(&authority, "issuer")?.into(),
                    get::<String>(&identity, "subject")?.into(),
                    get::<String>(&authority, "client_id")?.into(),
                    get::<Option<String>>(&authority, "secret_ref")?
                        .ok_or(ApplicationError::Integrity)?
                        .into(),
                    prepared.command.application_id.into(),
                    prepared.command.expected_connection_generation.into(),
                    prepared.command.expected_credential_generation.into(),
                    prepared.command.expected_connection_revision.into(),
                    get::<i64>(&project, "security_revision")?.into(),
                    get::<i64>(&user, "security_revision")?.into(),
                    get::<i64>(&identity, "identity_revision")?.into(),
                    get::<i64>(&authority, "provider_revision")?.into(),
                    get::<i64>(&authority, "managed_profile_revision")?.into(),
                    get::<i64>(&authority, "application_revision")?.into(),
                    get::<i64>(&authority, "assignment_security_revision")?.into(),
                    get::<String>(&authority, "callback_url")?.into(),
                    prepared.capability.adapter_key.into(),
                    prepared.capability.adapter_revision.into(),
                    prepared.capability.supports_revocation.into(),
                    json!(prepared.capability.exact_scopes).into(),
                    prepared.capability.provider_pkce_required.into(),
                    prepared.capability.oidc_nonce_required.into(),
                    prepared.interaction_digest.value.to_vec().into(),
                    prepared.interaction_digest.key_version.into(),
                    prepared.expires_at.into(),
                    prepared.now.into(),
                    provider_kind.as_str().into(),
                ],
            ))
            .await
            .map_err(persistence)?;
        transaction
            .execute_raw(statement(
                r"INSERT INTO control_idempotency_records
                    (idempotency_key,project_id,request_digest,state,result_resource_id,response,
                     operation_kind,request_scope,created_at,completed_at)
                   VALUES ($1,$2,$3,'completed',$4,$5,$6,$7,$8,$8)",
                vec![
                    prepared.command.idempotency_key.clone().into(),
                    prepared.command.project_id.into(),
                    prepared.request_digest.clone().into(),
                    prepared.interaction_id.into(),
                    json!({"kind":"managed_reauthorization","interaction_id":prepared.interaction_id}).into(),
                    CREATE_OPERATION_KIND.into(),
                    request_scope.into(),
                    prepared.now.into(),
                ],
            ))
            .await
            .map_err(persistence)?;
        transaction
            .execute_raw(statement(
                r"INSERT INTO managed_reauthorization_create_results
                    (idempotency_key,project_id,interaction_id,request_digest,
                     create_result_key_version,create_result_ciphertext,expires_at)
                   VALUES ($1,$2,$3,$4,$5,$6,$7)",
                vec![
                    prepared.command.idempotency_key.into(),
                    prepared.command.project_id.into(),
                    prepared.interaction_id.into(),
                    prepared.request_digest.into(),
                    prepared.protected_create_result.key_version.into(),
                    prepared.protected_create_result.ciphertext.into(),
                    prepared.expires_at.into(),
                ],
            ))
            .await
            .map_err(persistence)?;
        append_runtime_audit(
            &transaction,
            prepared.command.project_id,
            "deployment_operator",
            "managed_reauthorization.created",
            "managed_reauthorization",
            Some(prepared.interaction_id),
            prepared.command.correlation_id,
        )
        .await?;
        let record = read_record(
            &transaction,
            prepared.command.project_id,
            prepared.command.user_id,
            prepared.command.connection_id,
            prepared.interaction_id,
            prepared.now,
            false,
        )
        .await?;
        transaction.commit().await.map_err(persistence)?;
        Ok(CreateManagedReauthorizationResult::Created(record))
    }

    async fn control_read(
        &self,
        project_id: Uuid,
        user_id: Uuid,
        connection_id: Uuid,
        interaction_id: Uuid,
        now: OffsetDateTime,
    ) -> Result<ManagedReauthorizationRecord, ApplicationError> {
        let transaction = self.database.begin().await.map_err(persistence)?;
        let record = read_record(
            &transaction,
            project_id,
            user_id,
            connection_id,
            interaction_id,
            now,
            true,
        )
        .await?;
        transaction.commit().await.map_err(persistence)?;
        Ok(record)
    }

    async fn cancel(
        &self,
        project_id: Uuid,
        user_id: Uuid,
        connection_id: Uuid,
        interaction_id: Uuid,
        expected_revision: i64,
        correlation_id: Uuid,
        now: OffsetDateTime,
    ) -> Result<ManagedReauthorizationRecord, ApplicationError> {
        let transaction = self.database.begin().await.map_err(persistence)?;
        let updated = transaction
            .execute_raw(statement(
                r"UPDATE managed_provider_reauthorization_interactions SET status='cancelled',
                        revision=revision+1,terminal_at=$1,provider_pkce_ciphertext=NULL,
                        provider_pkce_key_version=NULL
                   WHERE project_id=$2 AND user_id=$3 AND connection_id=$4 AND id=$5
                     AND revision=$6 AND status IN ('awaiting_browser_binding','awaiting_provider_start',
                       'provider_authorization_started') AND expires_at>$1",
                vec![
                    now.into(),
                    project_id.into(),
                    user_id.into(),
                    connection_id.into(),
                    interaction_id.into(),
                    expected_revision.into(),
                ],
            ))
            .await
            .map_err(persistence)?;
        if updated.rows_affected() != 1 {
            transaction.rollback().await.map_err(persistence)?;
            return Err(ApplicationError::RevisionConflict);
        }
        scrub_terminal_material(&transaction, interaction_id, now).await?;
        append_runtime_audit(
            &transaction,
            project_id,
            "deployment_operator",
            "managed_reauthorization.cancelled",
            "managed_reauthorization",
            Some(interaction_id),
            correlation_id,
        )
        .await?;
        let record = read_record(
            &transaction,
            project_id,
            user_id,
            connection_id,
            interaction_id,
            now,
            false,
        )
        .await?;
        transaction.commit().await.map_err(persistence)?;
        Ok(record)
    }

    async fn digest_versions(
        &self,
        interaction_id: Uuid,
        now: OffsetDateTime,
    ) -> Result<ManagedReauthorizationDigestVersions, ApplicationError> {
        let transaction = self.database.begin().await.map_err(persistence)?;
        let row = transaction
            .query_one_raw(statement(
                r"SELECT CASE WHEN interaction.status IN ('completed','provider_exchange_failed')
                          THEN interaction.browser_binding_key_version
                          ELSE interaction.interaction_digest_key_version END
                       AS interaction_digest_key_version,
                     CASE WHEN interaction.status IN ('completed','provider_exchange_failed')
                          THEN interaction.csrf_key_version
                          ELSE interaction.browser_binding_key_version END
                       AS browser_binding_key_version,
                     CASE WHEN interaction.status IN ('completed','provider_exchange_failed')
                          THEN interaction.browser_binding_key_version
                          ELSE interaction.upstream_state_key_version END
                       AS upstream_state_key_version,
                     interaction.oidc_nonce_key_version,interaction.provider_pkce_key_version,
                     result.create_result_key_version,interaction.expires_at
                FROM managed_provider_reauthorization_interactions AS interaction
                LEFT JOIN managed_reauthorization_create_results AS result
                  ON result.interaction_id=interaction.id AND result.erased_at IS NULL
               WHERE interaction.id=$1 FOR UPDATE OF interaction",
                vec![interaction_id.into()],
            ))
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        if get::<OffsetDateTime>(&row, "expires_at")? <= now {
            expire_by_id(&transaction, interaction_id, now).await?;
            transaction.commit().await.map_err(persistence)?;
            return Err(ApplicationError::NotFound);
        }
        let versions = ManagedReauthorizationDigestVersions {
            interaction: get(&row, "interaction_digest_key_version")?,
            browser_binding: get(&row, "browser_binding_key_version")?,
            upstream_state: get(&row, "upstream_state_key_version")?,
            oidc_nonce: get(&row, "oidc_nonce_key_version")?,
            provider_pkce: get(&row, "provider_pkce_key_version")?,
            create_result: get(&row, "create_result_key_version")?,
        };
        transaction.commit().await.map_err(persistence)?;
        Ok(versions)
    }

    async fn bind_browser(
        &self,
        interaction: &VersionedDigest,
        browser_binding: &VersionedDigest,
        csrf: &VersionedDigest,
        now: OffsetDateTime,
    ) -> Result<ManagedReauthorizationRecord, ApplicationError> {
        let transaction = self.database.begin().await.map_err(persistence)?;
        if expire_by_digest(&transaction, interaction, now)
            .await?
            .is_some()
        {
            transaction.commit().await.map_err(persistence)?;
            return Err(ApplicationError::NotFound);
        }
        let updated = transaction
            .execute_raw(statement(
                r"UPDATE managed_provider_reauthorization_interactions
                      SET browser_binding_digest=$1,browser_binding_key_version=$2,
                          csrf_digest=$3,csrf_key_version=$4,status='awaiting_provider_start',
                          revision=revision+1
                    WHERE interaction_digest_key_version=$5 AND interaction_digest=$6
                      AND status='awaiting_browser_binding' AND expires_at>$7
                    RETURNING id,project_id,user_id,connection_id",
                vec![
                    browser_binding.value.to_vec().into(),
                    browser_binding.key_version.into(),
                    csrf.value.to_vec().into(),
                    csrf.key_version.into(),
                    interaction.key_version.into(),
                    interaction.value.to_vec().into(),
                    now.into(),
                ],
            ))
            .await
            .map_err(persistence)?;
        if updated.rows_affected() != 1 {
            transaction.rollback().await.map_err(persistence)?;
            return Err(ApplicationError::NotFound);
        }
        let row = transaction
            .query_one_raw(statement(
                r"SELECT project_id,user_id,connection_id,id
                     FROM managed_provider_reauthorization_interactions
                    WHERE interaction_digest_key_version=$1 AND interaction_digest=$2",
                vec![
                    interaction.key_version.into(),
                    interaction.value.to_vec().into(),
                ],
            ))
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::Integrity)?;
        let record = read_record(
            &transaction,
            get(&row, "project_id")?,
            get(&row, "user_id")?,
            get(&row, "connection_id")?,
            get(&row, "id")?,
            now,
            false,
        )
        .await?;
        transaction.commit().await.map_err(persistence)?;
        Ok(record)
    }

    async fn hosted_read(
        &self,
        interaction: &VersionedDigest,
        browser_binding: &VersionedDigest,
        now: OffsetDateTime,
    ) -> Result<ManagedReauthorizationRecord, ApplicationError> {
        let transaction = self.database.begin().await.map_err(persistence)?;
        if expire_by_digest(&transaction, interaction, now)
            .await?
            .is_some()
        {
            transaction.commit().await.map_err(persistence)?;
            return Err(ApplicationError::NotFound);
        }
        let row = transaction
            .query_one_raw(statement(
                r"SELECT project_id,user_id,connection_id,id
                     FROM managed_provider_reauthorization_interactions
                    WHERE interaction_digest_key_version=$1 AND interaction_digest=$2
                      AND browser_binding_key_version=$3 AND browser_binding_digest=$4",
                vec![
                    interaction.key_version.into(),
                    interaction.value.to_vec().into(),
                    browser_binding.key_version.into(),
                    browser_binding.value.to_vec().into(),
                ],
            ))
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        let record = read_record(
            &transaction,
            get(&row, "project_id")?,
            get(&row, "user_id")?,
            get(&row, "connection_id")?,
            get(&row, "id")?,
            now,
            false,
        )
        .await?;
        transaction.commit().await.map_err(persistence)?;
        Ok(record)
    }

    async fn start_provider(
        &self,
        interaction_id: Uuid,
        interaction: &VersionedDigest,
        browser_binding: &VersionedDigest,
        csrf: &VersionedDigest,
        expected_revision: i64,
        upstream_state: VersionedDigest,
        oidc_nonce: VersionedDigest,
        provider_pkce: Option<ProtectedValue>,
        supports_revocation: bool,
        now: OffsetDateTime,
    ) -> Result<ManagedReauthorizationRecord, ApplicationError> {
        let transaction = self.database.begin().await.map_err(persistence)?;
        let frozen = read_record_by_id(&transaction, interaction_id).await?;
        lock_current_authority(&transaction, &frozen, now).await?;
        let (pkce_key, pkce_ciphertext) = provider_pkce.map_or((None, None), |value| {
            (Some(value.key_version), Some(value.ciphertext))
        });
        let updated = transaction
            .execute_raw(statement(
                r"UPDATE managed_provider_reauthorization_interactions
                      SET status='provider_authorization_started',revision=revision+1,
                          upstream_state_digest=$1,upstream_state_key_version=$2,
                          oidc_nonce_digest=$3,oidc_nonce_key_version=$4,
                          provider_pkce_ciphertext=$5,provider_pkce_key_version=$6,
                          provider_started_at=$7,supports_revocation=$16
                    WHERE id=$8 AND interaction_digest_key_version=$9 AND interaction_digest=$10
                      AND browser_binding_key_version=$11 AND browser_binding_digest=$12
                      AND csrf_key_version=$13 AND csrf_digest=$14 AND revision=$15
                      AND status='awaiting_provider_start' AND expires_at>$7",
                vec![
                    upstream_state.value.to_vec().into(),
                    upstream_state.key_version.into(),
                    oidc_nonce.value.to_vec().into(),
                    oidc_nonce.key_version.into(),
                    pkce_ciphertext.into(),
                    pkce_key.into(),
                    now.into(),
                    interaction_id.into(),
                    interaction.key_version.into(),
                    interaction.value.to_vec().into(),
                    browser_binding.key_version.into(),
                    browser_binding.value.to_vec().into(),
                    csrf.key_version.into(),
                    csrf.value.to_vec().into(),
                    expected_revision.into(),
                    supports_revocation.into(),
                ],
            ))
            .await
            .map_err(persistence)?;
        if updated.rows_affected() != 1 {
            transaction.rollback().await.map_err(persistence)?;
            return Err(ApplicationError::RevisionConflict);
        }
        transaction
            .execute_raw(statement(
                r"INSERT INTO provider_callback_owners
                      (state_id,project_id,provider_configuration_id,owner_kind,
                       managed_reauthorization_interaction_id)
                   VALUES ($1,$2,$3,'managed_reauthorization',$1)",
                vec![
                    interaction_id.into(),
                    frozen.project_id.into(),
                    frozen.provider_configuration_id.into(),
                ],
            ))
            .await
            .map_err(persistence)?;
        let record = read_record_by_id(&transaction, interaction_id).await?;
        transaction.commit().await.map_err(persistence)?;
        Ok(record)
    }

    async fn claim_callback(
        &self,
        interaction_id: Uuid,
        project_public_id: &str,
        provider_key: &str,
        upstream_state: &VersionedDigest,
        browser_binding: &VersionedDigest,
        now: OffsetDateTime,
    ) -> Result<ClaimManagedReauthorization, ApplicationError> {
        let transaction = self.database.begin().await.map_err(persistence)?;
        let row = transaction
            .query_one_raw(statement(
                r"SELECT id FROM managed_provider_reauthorization_interactions
                    WHERE id=$7 AND project_public_id=$1 AND provider_key=$2 AND (
                      (status IN ('provider_authorization_started','provider_exchange_in_progress')
                       AND upstream_state_key_version=$3 AND upstream_state_digest=$4
                       AND browser_binding_key_version=$5 AND browser_binding_digest=$6)
                      OR
                      (status IN ('completed','provider_exchange_failed')
                       AND browser_binding_key_version=$3 AND browser_binding_digest=$4
                       AND csrf_key_version=$5 AND csrf_digest=$6))",
                vec![
                    project_public_id.into(),
                    provider_key.into(),
                    upstream_state.key_version.into(),
                    upstream_state.value.to_vec().into(),
                    browser_binding.key_version.into(),
                    browser_binding.value.to_vec().into(),
                    interaction_id.into(),
                ],
            ))
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        let resolved_id: Uuid = get(&row, "id")?;
        if resolved_id != interaction_id {
            return Err(ApplicationError::Integrity);
        }
        let current = read_record_by_id(&transaction, interaction_id).await?;
        if current.expires_at <= now {
            expire_by_id(&transaction, interaction_id, now).await?;
            transaction.commit().await.map_err(persistence)?;
            return Err(ApplicationError::NotFound);
        }
        if current.status != ManagedReauthorizationStatus::ProviderAuthorizationStarted {
            transaction.commit().await.map_err(persistence)?;
            return Ok(ClaimManagedReauthorization::Duplicate(current));
        }
        // Lock every frozen owner in canonical order, ending with the exact interaction row.
        // Missing or drifted authority is an authoritative stale result, not an infrastructure
        // failure: terminalize only this callback owner without touching the current connection.
        let authority_current =
            lock_and_classify_current_authority(&transaction, &current, now).await?;
        let current = read_record_by_id(&transaction, interaction_id).await?;
        if current.status != ManagedReauthorizationStatus::ProviderAuthorizationStarted {
            transaction.commit().await.map_err(persistence)?;
            return Ok(ClaimManagedReauthorization::Duplicate(current));
        }
        if !authority_current {
            let terminal = terminalize_stale_callback(
                &transaction,
                &current,
                "managed_reauthorization.code_authority_stale",
                now,
            )
            .await?;
            transaction.commit().await.map_err(persistence)?;
            drop(terminal);
            return Ok(ClaimManagedReauthorization::TerminalizedStaleAuthority);
        }
        let updated = transaction
            .execute_raw(statement(
                r"UPDATE managed_provider_reauthorization_interactions
                      SET status='provider_exchange_in_progress',revision=revision+1,
                          exchange_claimed_at=$1
                    WHERE id=$2 AND revision=$3 AND status='provider_authorization_started'
                      AND expires_at>$1",
                vec![now.into(), interaction_id.into(), current.revision.into()],
            ))
            .await
            .map_err(persistence)?;
        if updated.rows_affected() != 1 {
            let duplicate = read_record_by_id(&transaction, interaction_id).await?;
            transaction.commit().await.map_err(persistence)?;
            return Ok(ClaimManagedReauthorization::Duplicate(duplicate));
        }
        let claimed = read_record_by_id(&transaction, interaction_id).await?;
        transaction.commit().await.map_err(persistence)?;
        Ok(ClaimManagedReauthorization::Claimed(claimed))
    }

    async fn deny_callback(
        &self,
        project_public_id: &str,
        provider_key: &str,
        upstream_state: &VersionedDigest,
        browser_binding: &VersionedDigest,
        safe_outcome: &'static str,
        now: OffsetDateTime,
    ) -> Result<ManagedReauthorizationRecord, ApplicationError> {
        if safe_outcome.is_empty() || safe_outcome.len() > 64 {
            return Err(ApplicationError::InvalidInput);
        }
        let transaction = self.database.begin().await.map_err(persistence)?;
        let row = transaction
            .query_one_raw(statement(
                r"SELECT id FROM managed_provider_reauthorization_interactions
                    WHERE project_public_id=$1 AND provider_key=$2 AND (
                      (status IN ('provider_authorization_started','provider_exchange_in_progress')
                       AND upstream_state_key_version=$3 AND upstream_state_digest=$4
                       AND browser_binding_key_version=$5 AND browser_binding_digest=$6)
                      OR
                      (status IN ('completed','provider_exchange_failed')
                       AND browser_binding_key_version=$3 AND browser_binding_digest=$4
                       AND csrf_key_version=$5 AND csrf_digest=$6))",
                vec![
                    project_public_id.into(),
                    provider_key.into(),
                    upstream_state.key_version.into(),
                    upstream_state.value.to_vec().into(),
                    browser_binding.key_version.into(),
                    browser_binding.value.to_vec().into(),
                ],
            ))
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        let interaction_id: Uuid = get(&row, "id")?;
        let current = read_record_by_id(&transaction, interaction_id).await?;
        if current.expires_at <= now {
            expire_by_id(&transaction, interaction_id, now).await?;
            transaction.commit().await.map_err(persistence)?;
            return Err(ApplicationError::InvalidTransition);
        }
        // The exact state + browser routing tombstone authenticates a response-loss retry. A
        // terminal row is read-only: never revalidate mutable authority, append another audit,
        // or dispatch provider I/O.
        if current.status.terminal() {
            transaction.commit().await.map_err(persistence)?;
            return Ok(current);
        }
        let authority_current =
            lock_and_classify_current_authority(&transaction, &current, now).await?;
        let current = read_record_by_id(&transaction, interaction_id).await?;
        if current.status != ManagedReauthorizationStatus::ProviderAuthorizationStarted {
            transaction.commit().await.map_err(persistence)?;
            return Err(ApplicationError::InvalidTransition);
        }
        if !authority_current {
            let terminal = terminalize_stale_callback(
                &transaction,
                &current,
                "managed_reauthorization.denial_authority_stale",
                now,
            )
            .await?;
            transaction.commit().await.map_err(persistence)?;
            return Ok(terminal);
        }
        let updated = transaction
            .execute_raw(statement(
                r"UPDATE managed_provider_reauthorization_interactions
                      SET status='provider_exchange_failed',revision=revision+1,terminal_at=$1
                    WHERE id=$2 AND revision=$3 AND status='provider_authorization_started'
                      AND project_public_id=$4 AND provider_key=$5
                      AND upstream_state_key_version=$6 AND upstream_state_digest=$7
                      AND browser_binding_key_version=$8 AND browser_binding_digest=$9",
                vec![
                    now.into(),
                    interaction_id.into(),
                    current.revision.into(),
                    project_public_id.into(),
                    provider_key.into(),
                    upstream_state.key_version.into(),
                    upstream_state.value.to_vec().into(),
                    browser_binding.key_version.into(),
                    browser_binding.value.to_vec().into(),
                ],
            ))
            .await
            .map_err(persistence)?;
        if updated.rows_affected() != 1 {
            transaction.rollback().await.map_err(persistence)?;
            return Err(ApplicationError::RevisionConflict);
        }
        scrub_terminal_material(&transaction, interaction_id, now).await?;
        append_runtime_audit(
            &transaction,
            current.project_id,
            "managed_reauthorization",
            safe_outcome,
            "managed_reauthorization",
            Some(interaction_id),
            Uuid::new_v4(),
        )
        .await?;
        let denied = read_record_by_id(&transaction, interaction_id).await?;
        transaction.commit().await.map_err(persistence)?;
        Ok(denied)
    }

    async fn complete_callback(
        &self,
        claimed: &ManagedReauthorizationRecord,
        protected_successor: ProtectedValue,
        correlation_id: Uuid,
        now: OffsetDateTime,
    ) -> Result<CompletedManagedReauthorization, ApplicationError> {
        if protected_successor.key_version <= 0 || protected_successor.ciphertext.len() < 40 {
            return Err(ApplicationError::InvalidInput);
        }
        let transaction = self.database.begin().await.map_err(persistence)?;
        lock_current_authority(&transaction, claimed, now).await?;
        // Predecessor may already be inaccessible after a destructive lifecycle fence.
        transaction
            .execute_raw(statement(
                r"UPDATE managed_provider_credentials SET ciphertext=NULL,
                        superseded_at=COALESCE(superseded_at,$1),destroyed_at=COALESCE(destroyed_at,$1)
                    WHERE project_id=$2 AND connection_id=$3 AND ciphertext IS NOT NULL",
                vec![
                    now.into(),
                    claimed.project_id.into(),
                    claimed.connection_id.into(),
                ],
            ))
            .await
            .map_err(persistence)?;
        let inserted = transaction
            .execute_raw(statement(
                r"INSERT INTO managed_provider_credentials
                    (project_id,connection_id,connection_generation,credential_generation,
                     key_version,ciphertext,created_at)
                   SELECT $1,$2,$3,$4,$5,$6,$7
                    WHERE EXISTS (SELECT 1 FROM managed_provider_reauthorization_interactions
                       WHERE id=$8 AND revision=$9 AND status='provider_exchange_in_progress'
                         AND expires_at>$7)",
                vec![
                    claimed.project_id.into(),
                    claimed.connection_id.into(),
                    (claimed.expected_connection_generation + 1).into(),
                    (claimed.expected_credential_generation + 1).into(),
                    protected_successor.key_version.into(),
                    protected_successor.ciphertext.into(),
                    now.into(),
                    claimed.id.into(),
                    claimed.revision.into(),
                ],
            ))
            .await
            .map_err(persistence)?;
        if inserted.rows_affected() != 1 {
            transaction.rollback().await.map_err(persistence)?;
            return Err(ApplicationError::RevisionConflict);
        }
        let connection = transaction
            .execute_raw(statement(
                r"UPDATE managed_provider_connections SET state='active',revision=revision+1,
                        generation=$1,credential_generation=$2,last_safe_outcome='reauthorization_succeeded',
                        provider_revision=$3,managed_profile_revision=$4,user_security_revision=$5,
                        identity_revision=$6,project_security_revision=$13,
                        adapter_key=$14,adapter_capability_revision=$15,supports_revocation=$16,
                        required_scopes=ARRAY(SELECT jsonb_array_elements_text($17::jsonb)),
                        next_synchronize_at=$7,next_renewal_at=$7 + INTERVAL '30 days',
                        consecutive_failures=0,lease_owner=NULL,lease_kind=NULL,lease_expires_at=NULL,
                        disconnected_at=NULL,updated_at=$7
                    WHERE project_id=$8 AND id=$9 AND revision=$10 AND generation=$11
                      AND credential_generation=$12
                      AND state IN ('active','reauth_required','revoked','disconnected')",
                vec![
                    (claimed.expected_connection_generation + 1).into(),
                    (claimed.expected_credential_generation + 1).into(),
                    claimed.provider_revision.into(),
                    claimed.managed_profile_revision.into(),
                    claimed.user_security_revision.into(),
                    claimed.identity_revision.into(),
                    now.into(),
                    claimed.project_id.into(),
                    claimed.connection_id.into(),
                    claimed.expected_connection_revision.into(),
                    claimed.expected_connection_generation.into(),
                    claimed.expected_credential_generation.into(),
                    claimed.project_security_revision.into(),
                    claimed.adapter_key.clone().into(),
                    claimed.adapter_capability_revision.into(),
                    claimed.supports_revocation.into(),
                    json!(claimed.required_scopes).into(),
                ],
            ))
            .await
            .map_err(persistence)?;
        let interaction = transaction
            .execute_raw(statement(
                r"UPDATE managed_provider_reauthorization_interactions SET status='completed',
                        revision=revision+1,terminal_at=$1,provider_pkce_ciphertext=NULL,
                        provider_pkce_key_version=NULL
                    WHERE id=$2 AND revision=$3 AND status='provider_exchange_in_progress'",
                vec![now.into(), claimed.id.into(), claimed.revision.into()],
            ))
            .await
            .map_err(persistence)?;
        if connection.rows_affected() != 1 || interaction.rows_affected() != 1 {
            transaction.rollback().await.map_err(persistence)?;
            return Err(ApplicationError::RevisionConflict);
        }
        scrub_terminal_material(&transaction, claimed.id, now).await?;
        append_runtime_audit(
            &transaction,
            claimed.project_id,
            "managed_reauthorization",
            "managed_reauthorization.completed",
            "managed_provider_connection",
            Some(claimed.connection_id),
            correlation_id,
        )
        .await?;
        let interaction = read_record_by_id(&transaction, claimed.id).await?;
        let successor = ConnectionGuard {
            connection_id: claimed.connection_id,
            project_id: claimed.project_id,
            provider_configuration_id: claimed.provider_configuration_id,
            linked_identity_id: claimed.linked_identity_id,
            user_id: claimed.user_id,
            connection_revision: claimed.expected_connection_revision + 1,
            connection_generation: claimed.expected_connection_generation + 1,
            credential_generation: claimed.expected_credential_generation + 1,
            project_security_revision: claimed.project_security_revision,
            provider_revision: claimed.provider_revision,
            managed_profile_revision: claimed.managed_profile_revision,
            provider_kind: claimed.provider_kind,
            adapter_key: claimed.adapter_key.clone(),
            adapter_capability_revision: claimed.adapter_capability_revision,
            required_scopes: claimed.required_scopes.clone(),
            user_security_revision: claimed.user_security_revision,
            identity_revision: claimed.identity_revision,
            consecutive_failures: 0,
            issuer: claimed.issuer.clone(),
            subject: claimed.subject.clone(),
            client_id: claimed.client_id.clone(),
            secret_ref: claimed.secret_ref.clone(),
        };
        transaction.commit().await.map_err(persistence)?;
        Ok(CompletedManagedReauthorization {
            successor,
            interaction,
        })
    }

    async fn fail_callback(
        &self,
        claimed: &ManagedReauthorizationRecord,
        safe_outcome: &'static str,
        now: OffsetDateTime,
    ) -> Result<FailManagedReauthorization, ApplicationError> {
        if safe_outcome.is_empty() || safe_outcome.len() > 64 {
            return Err(ApplicationError::InvalidInput);
        }
        let transaction = self.database.begin().await.map_err(persistence)?;
        let updated = transaction
            .execute_raw(statement(
                r"UPDATE managed_provider_reauthorization_interactions
                      SET status='provider_exchange_failed',revision=revision+1,terminal_at=$1,
                          provider_pkce_ciphertext=NULL,provider_pkce_key_version=NULL
                    WHERE id=$2 AND revision=$3 AND status='provider_exchange_in_progress'",
                vec![now.into(), claimed.id.into(), claimed.revision.into()],
            ))
            .await
            .map_err(persistence)?;
        let outcome = if updated.rows_affected() == 1 {
            scrub_terminal_material(&transaction, claimed.id, now).await?;
            append_runtime_audit(
                &transaction,
                claimed.project_id,
                "managed_reauthorization",
                safe_outcome,
                "managed_reauthorization",
                Some(claimed.id),
                Uuid::new_v4(),
            )
            .await?;
            FailManagedReauthorization::Terminalized(
                read_record_by_id(&transaction, claimed.id).await?,
            )
        } else {
            // The CAS can lose only to another exact terminal owner. Lock and read that row in
            // this transaction; never mutate it and never claim terminal success without proof.
            transaction
                .query_one_raw(statement(
                    r"SELECT id FROM managed_provider_reauthorization_interactions
                        WHERE id=$1 FOR UPDATE",
                    vec![claimed.id.into()],
                ))
                .await
                .map_err(persistence)?
                .ok_or(ApplicationError::NotFound)?;
            let current = read_record_by_id(&transaction, claimed.id).await?;
            if !current.status.terminal() {
                transaction.rollback().await.map_err(persistence)?;
                return Err(ApplicationError::RevisionConflict);
            }
            FailManagedReauthorization::TerminalWinner(current)
        };
        transaction.commit().await.map_err(persistence)?;
        Ok(outcome)
    }
}

async fn lock_current_authority<C: ConnectionTrait>(
    connection: &C,
    record: &ManagedReauthorizationRecord,
    now: OffsetDateTime,
) -> Result<(), ApplicationError> {
    if lock_and_classify_current_authority(connection, record, now).await? {
        Ok(())
    } else {
        Err(ApplicationError::RevisionConflict)
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "the complete canonical lock order and each frozen authority predicate stay visibly adjacent"
)]
async fn lock_and_classify_current_authority<C: ConnectionTrait>(
    connection: &C,
    record: &ManagedReauthorizationRecord,
    now: OffsetDateTime,
) -> Result<bool, ApplicationError> {
    // Always walk the complete canonical lock order. A stale or missing owner row is a truthful
    // false result, while query/decoding failures remain infrastructure or integrity errors.
    let mut current = true;
    current &= locked_validity(
        connection,
        r"SELECT (status='active' AND security_revision=$2) AS valid
             FROM projects WHERE id=$1 FOR SHARE",
        vec![
            record.project_id.into(),
            record.project_security_revision.into(),
        ],
    )
    .await?;
    current &= locked_validity(
        connection,
        r"SELECT (status='active' AND revision=$3 AND managed_profile_enabled
                         AND managed_profile_revision=$4) AS valid
             FROM provider_configurations
            WHERE project_id=$1 AND id=$2 FOR SHARE",
        vec![
            record.project_id.into(),
            record.provider_configuration_id.into(),
            record.provider_revision.into(),
            record.managed_profile_revision.into(),
        ],
    )
    .await?;
    current &= locked_validity(
        connection,
        r"SELECT (status='active' AND revision=$3) AS valid
             FROM applications WHERE project_id=$1 AND id=$2 FOR SHARE",
        vec![
            record.project_id.into(),
            record.application_id.into(),
            record.application_revision.into(),
        ],
    )
    .await?;
    current &= locked_validity(
        connection,
        r"SELECT (status='active' AND security_revision=$4) AS valid
             FROM application_provider_assignments
            WHERE project_id=$1 AND application_id=$2 AND provider_id=$3 FOR SHARE",
        vec![
            record.project_id.into(),
            record.application_id.into(),
            record.provider_configuration_id.into(),
            record.assignment_security_revision.into(),
        ],
    )
    .await?;
    current &= locked_validity(
        connection,
        r"SELECT (status='active' AND security_revision=$3) AS valid
             FROM project_users WHERE project_id=$1 AND id=$2 FOR UPDATE",
        vec![
            record.project_id.into(),
            record.user_id.into(),
            record.user_security_revision.into(),
        ],
    )
    .await?;
    current &= locked_validity(
        connection,
        r"SELECT (user_id=$3 AND status='active' AND identity_revision=$4) AS valid
             FROM linked_identities WHERE project_id=$1 AND id=$2 FOR UPDATE",
        vec![
            record.project_id.into(),
            record.linked_identity_id.into(),
            record.user_id.into(),
            record.identity_revision.into(),
        ],
    )
    .await?;
    current &= locked_validity(
        connection,
        r"SELECT (user_id=$3 AND provider_configuration_id=$4 AND linked_identity_id=$5
                         AND revision=$6 AND generation=$7 AND credential_generation=$8
                         AND state IN ('active','reauth_required','revoked','disconnected')
                         AND revocation_requested_at IS NULL) AS valid
             FROM managed_provider_connections
            WHERE project_id=$1 AND id=$2 FOR UPDATE",
        vec![
            record.project_id.into(),
            record.connection_id.into(),
            record.user_id.into(),
            record.provider_configuration_id.into(),
            record.linked_identity_id.into(),
            record.expected_connection_revision.into(),
            record.expected_connection_generation.into(),
            record.expected_credential_generation.into(),
        ],
    )
    .await?;
    current &= locked_validity(
        connection,
        r"SELECT (project_id=$2 AND connection_id=$3 AND expires_at>$4) AS valid
             FROM managed_provider_reauthorization_interactions WHERE id=$1 FOR UPDATE",
        vec![
            record.id.into(),
            record.project_id.into(),
            record.connection_id.into(),
            now.into(),
        ],
    )
    .await?;
    Ok(current)
}

async fn locked_validity<C: ConnectionTrait>(
    connection: &C,
    sql: &str,
    values: Vec<sea_orm::Value>,
) -> Result<bool, ApplicationError> {
    let row = connection
        .query_one_raw(statement(sql, values))
        .await
        .map_err(persistence)?;
    row.map_or(Ok(false), |row| get(&row, "valid"))
}

async fn terminalize_stale_callback(
    connection: &sea_orm::DatabaseTransaction,
    record: &ManagedReauthorizationRecord,
    safe_action: &'static str,
    now: OffsetDateTime,
) -> Result<ManagedReauthorizationRecord, ApplicationError> {
    let updated = connection
        .execute_raw(statement(
            r"UPDATE managed_provider_reauthorization_interactions
                  SET status='provider_exchange_failed',revision=revision+1,terminal_at=$1,
                      provider_pkce_ciphertext=NULL,provider_pkce_key_version=NULL
                WHERE id=$2 AND revision=$3 AND status='provider_authorization_started'",
            vec![now.into(), record.id.into(), record.revision.into()],
        ))
        .await
        .map_err(persistence)?;
    if updated.rows_affected() != 1 {
        return Err(ApplicationError::RevisionConflict);
    }
    scrub_terminal_material(connection, record.id, now).await?;
    append_runtime_audit(
        connection,
        record.project_id,
        "managed_reauthorization",
        safe_action,
        "managed_reauthorization",
        Some(record.id),
        Uuid::new_v4(),
    )
    .await?;
    read_record_by_id(connection, record.id).await
}

async fn read_record<C: ConnectionTrait>(
    connection: &C,
    project_id: Uuid,
    user_id: Uuid,
    connection_id: Uuid,
    interaction_id: Uuid,
    now: OffsetDateTime,
    expire: bool,
) -> Result<ManagedReauthorizationRecord, ApplicationError> {
    if expire {
        expire_by_id(connection, interaction_id, now).await?;
    }
    let record = read_record_by_id(connection, interaction_id).await?;
    if record.project_id != project_id
        || record.user_id != user_id
        || record.connection_id != connection_id
    {
        return Err(ApplicationError::NotFound);
    }
    Ok(record)
}

async fn read_record_by_id<C: ConnectionTrait>(
    connection: &C,
    interaction_id: Uuid,
) -> Result<ManagedReauthorizationRecord, ApplicationError> {
    let row = connection
        .query_one_raw(statement(
            r"SELECT id,project_id,project_public_id,connection_id,linked_identity_id,user_id,
                      provider_configuration_id,provider_key,
                      COALESCE(provider_kind, CASE issuer WHEN 'https://accounts.google.com' THEN 'google' ELSE 'oidc' END) AS provider_kind,
                      issuer,subject,client_id,secret_ref,
                      application_id,expected_connection_generation,expected_credential_generation,
                      expected_connection_revision,project_security_revision,user_security_revision,
                      identity_revision,provider_revision,managed_profile_revision,application_revision,
                      assignment_security_revision,callback_url,adapter_key,
                      adapter_capability_revision,supports_revocation,
                      to_json(required_scopes) AS required_scopes,
                      provider_pkce_required,oidc_nonce_required,revision,status,csrf_key_version,
                      oidc_nonce_digest,oidc_nonce_key_version,provider_pkce_ciphertext,
                      provider_pkce_key_version,expires_at
                 FROM managed_provider_reauthorization_interactions WHERE id=$1",
            vec![interaction_id.into()],
        ))
        .await
        .map_err(persistence)?
        .ok_or(ApplicationError::NotFound)?;
    record_from_row(&row)
}

fn record_from_row(
    row: &sea_orm::QueryResult,
) -> Result<ManagedReauthorizationRecord, ApplicationError> {
    let scopes: serde_json::Value = get(row, "required_scopes")?;
    let required_scopes = scopes
        .as_array()
        .ok_or(ApplicationError::Integrity)?
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(str::to_owned)
                .ok_or(ApplicationError::Integrity)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let nonce = match (
        get::<Option<Vec<u8>>>(row, "oidc_nonce_digest")?,
        get::<Option<i32>>(row, "oidc_nonce_key_version")?,
    ) {
        (Some(value), Some(key_version)) => Some(VersionedDigest {
            value: value.try_into().map_err(|_| ApplicationError::Integrity)?,
            key_version,
        }),
        (None, None) => None,
        _ => return Err(ApplicationError::Integrity),
    };
    let pkce = match (
        get::<Option<Vec<u8>>>(row, "provider_pkce_ciphertext")?,
        get::<Option<i32>>(row, "provider_pkce_key_version")?,
    ) {
        (Some(ciphertext), Some(key_version)) => Some(ProtectedValue {
            ciphertext,
            key_version,
        }),
        (None, None) => None,
        _ => return Err(ApplicationError::Integrity),
    };
    let provider_kind = crate::domain::ProviderKind::parse(&get::<String>(row, "provider_kind")?)
        .map_err(|_| ApplicationError::Integrity)?;
    let issuer = get::<String>(row, "issuer")?;
    if !provider_kind.capabilities().managed_profile || !provider_kind.issuer_matches(&issuer) {
        return Err(ApplicationError::Integrity);
    }
    Ok(ManagedReauthorizationRecord {
        id: get(row, "id")?,
        project_id: get(row, "project_id")?,
        project_public_id: get(row, "project_public_id")?,
        connection_id: get(row, "connection_id")?,
        linked_identity_id: get(row, "linked_identity_id")?,
        user_id: get(row, "user_id")?,
        provider_configuration_id: get(row, "provider_configuration_id")?,
        provider_key: get(row, "provider_key")?,
        application_id: get(row, "application_id")?,
        expected_connection_generation: get(row, "expected_connection_generation")?,
        expected_credential_generation: get(row, "expected_credential_generation")?,
        expected_connection_revision: get(row, "expected_connection_revision")?,
        provider_kind,
        project_security_revision: get(row, "project_security_revision")?,
        user_security_revision: get(row, "user_security_revision")?,
        identity_revision: get(row, "identity_revision")?,
        provider_revision: get(row, "provider_revision")?,
        managed_profile_revision: get(row, "managed_profile_revision")?,
        application_revision: get(row, "application_revision")?,
        assignment_security_revision: get(row, "assignment_security_revision")?,
        issuer,
        subject: get(row, "subject")?,
        client_id: get(row, "client_id")?,
        secret_ref: get(row, "secret_ref")?,
        callback_url: get(row, "callback_url")?,
        adapter_key: get(row, "adapter_key")?,
        adapter_capability_revision: get(row, "adapter_capability_revision")?,
        supports_revocation: get(row, "supports_revocation")?,
        required_scopes,
        provider_pkce_required: get(row, "provider_pkce_required")?,
        oidc_nonce_required: get(row, "oidc_nonce_required")?,
        revision: get(row, "revision")?,
        status: ManagedReauthorizationStatus::parse(&get::<String>(row, "status")?)?,
        csrf_key_version: get(row, "csrf_key_version")?,
        oidc_nonce: nonce,
        provider_pkce: pkce,
        expires_at: get(row, "expires_at")?,
    })
}

async fn expire_by_digest<C: ConnectionTrait>(
    connection: &C,
    digest: &VersionedDigest,
    now: OffsetDateTime,
) -> Result<Option<Uuid>, ApplicationError> {
    // Capture the durable owner before scrubbing the lookup digest. A second lookup by the
    // now-erased digest would silently miss the create-result row and retain one-use material.
    let expired = connection
        .query_one_raw(statement(
            r"UPDATE managed_provider_reauthorization_interactions SET status='expired',
                    revision=revision+1,terminal_at=$1,provider_pkce_ciphertext=NULL,
                    provider_pkce_key_version=NULL
                WHERE interaction_digest_key_version=$2 AND interaction_digest=$3
                  AND expires_at<=$1 AND status NOT IN ('completed','provider_exchange_failed','expired','cancelled')
            RETURNING id",
            vec![now.into(), digest.key_version.into(), digest.value.to_vec().into()],
        ))
        .await
        .map_err(persistence)?;
    let Some(row) = expired else {
        return Ok(None);
    };
    let interaction_id = get(&row, "id")?;
    scrub_terminal_material(connection, interaction_id, now).await?;
    Ok(Some(interaction_id))
}

async fn expire_by_id<C: ConnectionTrait>(
    connection: &C,
    id: Uuid,
    now: OffsetDateTime,
) -> Result<(), ApplicationError> {
    let updated = connection
        .execute_raw(statement(
            r"UPDATE managed_provider_reauthorization_interactions SET status='expired',
                    revision=revision+1,terminal_at=$1,provider_pkce_ciphertext=NULL,
                    provider_pkce_key_version=NULL
                WHERE id=$2 AND expires_at<=$1
                  AND status NOT IN ('completed','provider_exchange_failed','expired','cancelled')",
            vec![now.into(), id.into()],
        ))
        .await
        .map_err(persistence)?;
    if updated.rows_affected() == 1 {
        scrub_terminal_material(connection, id, now).await?;
        return Ok(());
    }
    // Completed and failed rows retain only authenticated callback routing tombstones until the
    // exact interaction deadline. A callback arriving at/after that deadline owns synchronous
    // erasure and must not wait for the periodic sweep.
    let terminal_due = connection
        .query_one_raw(statement(
            r"SELECT id FROM managed_provider_reauthorization_interactions
                WHERE id=$1 AND expires_at<=$2
                  AND status IN ('completed','provider_exchange_failed')
                  AND (upstream_state_digest IS NOT NULL OR browser_binding_digest IS NOT NULL)
                FOR UPDATE",
            vec![id.into(), now.into()],
        ))
        .await
        .map_err(persistence)?;
    if terminal_due.is_some() {
        scrub_terminal_material(connection, id, now).await?;
    }
    Ok(())
}

async fn erase_create_result<C: ConnectionTrait>(
    connection: &C,
    idempotency_key: &str,
    now: OffsetDateTime,
) -> Result<(), ApplicationError> {
    let erased = connection
        .execute_raw(statement(
            r"UPDATE managed_reauthorization_create_results SET request_digest=NULL,
                    create_result_ciphertext=NULL,erased_at=$1
                  WHERE idempotency_key=$2 AND expires_at<=$1 AND erased_at IS NULL",
            vec![now.into(), idempotency_key.into()],
        ))
        .await
        .map_err(persistence)?;
    if erased.rows_affected() != 1 {
        return Err(ApplicationError::Integrity);
    }
    Ok(())
}

async fn scrub_terminal_material<C: ConnectionTrait>(
    connection: &C,
    interaction_id: Uuid,
    now: OffsetDateTime,
) -> Result<(), ApplicationError> {
    let scrubbed = connection
        .execute_raw(statement(
            r"UPDATE managed_provider_reauthorization_interactions
                  SET interaction_digest=NULL,interaction_digest_key_version=NULL,
                      browser_binding_digest=CASE
                        WHEN status IN ('completed','provider_exchange_failed') AND expires_at>$2
                        THEN upstream_state_digest ELSE NULL END,
                      browser_binding_key_version=CASE
                        WHEN status IN ('completed','provider_exchange_failed') AND expires_at>$2
                        THEN upstream_state_key_version ELSE NULL END,
                      csrf_digest=CASE
                        WHEN status IN ('completed','provider_exchange_failed') AND expires_at>$2
                        THEN browser_binding_digest ELSE NULL END,
                      csrf_key_version=CASE
                        WHEN status IN ('completed','provider_exchange_failed') AND expires_at>$2
                        THEN browser_binding_key_version ELSE NULL END,
                      upstream_state_digest=NULL,upstream_state_key_version=NULL,
                      oidc_nonce_digest=NULL,oidc_nonce_key_version=NULL,
                      provider_pkce_ciphertext=NULL,provider_pkce_key_version=NULL
                WHERE id=$1 AND status IN ('completed','provider_exchange_failed','expired','cancelled')
                  AND terminal_at IS NOT NULL",
            vec![interaction_id.into(), now.into()],
        ))
        .await
        .map_err(persistence)?;
    if scrubbed.rows_affected() != 1 {
        return Err(ApplicationError::Integrity);
    }
    erase_result_for_interaction(connection, interaction_id, now).await
}

async fn erase_result_for_interaction<C: ConnectionTrait>(
    connection: &C,
    interaction_id: Uuid,
    now: OffsetDateTime,
) -> Result<(), ApplicationError> {
    let result = connection
        .query_one_raw(statement(
            r"SELECT expires_at,request_digest,create_result_ciphertext,erased_at
                 FROM managed_reauthorization_create_results
                WHERE interaction_id=$1 FOR UPDATE",
            vec![interaction_id.into()],
        ))
        .await
        .map_err(persistence)?
        .ok_or(ApplicationError::Integrity)?;
    let expires_at = get::<OffsetDateTime>(&result, "expires_at")?;
    let request_digest = get::<Option<Vec<u8>>>(&result, "request_digest")?;
    let ciphertext = get::<Option<Vec<u8>>>(&result, "create_result_ciphertext")?;
    let erased_at = get::<Option<OffsetDateTime>>(&result, "erased_at")?;
    if now < expires_at {
        if request_digest.is_none() || ciphertext.is_none() || erased_at.is_some() {
            return Err(ApplicationError::Integrity);
        }
        return Ok(());
    }
    if request_digest.is_none()
        && ciphertext.is_none()
        && erased_at.is_some_and(|erased| erased >= expires_at)
    {
        return Ok(());
    }
    if request_digest.is_none() || ciphertext.is_none() || erased_at.is_some() {
        return Err(ApplicationError::Integrity);
    }
    let erased = connection
        .execute_raw(statement(
            r"UPDATE managed_reauthorization_create_results SET request_digest=NULL,
                    create_result_ciphertext=NULL,erased_at=$1
                  WHERE interaction_id=$2 AND expires_at<=$1 AND erased_at IS NULL",
            vec![now.into(), interaction_id.into()],
        ))
        .await
        .map_err(persistence)?;
    if erased.rows_affected() != 1 {
        return Err(ApplicationError::Integrity);
    }
    Ok(())
}

fn get<T: sea_orm::TryGetable>(
    row: &sea_orm::QueryResult,
    column: &str,
) -> Result<T, ApplicationError> {
    row.try_get("", column)
        .map_err(|_| ApplicationError::Integrity)
}

fn statement(sql: &str, values: Vec<sea_orm::Value>) -> Statement {
    Statement::from_sql_and_values(DbBackend::Postgres, sql, values)
}
