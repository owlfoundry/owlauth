use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use owlauth_key_provider::{
    ConfigurationSecretSealer, MaterialKind, ProviderFormatVersion, ProviderId, SealSecretRequest,
    SecretPlaintext,
};
use sea_orm::{
    ConnectionTrait, DatabaseConnection, DatabaseTransaction, DbBackend, Statement,
    TransactionTrait,
};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use uuid::Uuid;

use super::custody::{
    CustodyAuthority, CustodyMode, MaterialOwnerKind, MaterialPurpose, ProtectedMaterialRepository,
    ProtectedMaterialReservation, finalize_pending_material,
};
use crate::{
    adapters::{custody::SoftwareCustodyProvider, software_store::EncryptedFileStore},
    application::ApplicationError,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LegacyMaterialKind {
    SigningKey,
    ProviderSecret,
    ProjectSmtp,
    DeploymentSmtp,
    SmtpTestRecipient,
    WebhookSecret,
}

impl LegacyMaterialKind {
    fn parse(value: &str) -> Result<Self, ApplicationError> {
        match value {
            "signing_key" => Ok(Self::SigningKey),
            "provider_secret" => Ok(Self::ProviderSecret),
            "project_smtp" => Ok(Self::ProjectSmtp),
            "deployment_smtp" => Ok(Self::DeploymentSmtp),
            "smtp_test_recipient" => Ok(Self::SmtpTestRecipient),
            "webhook_secret" => Ok(Self::WebhookSecret),
            _ => Err(ApplicationError::Integrity),
        }
    }

    const fn owner_kind(self) -> MaterialOwnerKind {
        match self {
            Self::SigningKey => MaterialOwnerKind::SigningKey,
            Self::ProviderSecret => MaterialOwnerKind::ProviderSecret,
            Self::ProjectSmtp => MaterialOwnerKind::ProjectSmtp,
            Self::DeploymentSmtp => MaterialOwnerKind::DeploymentSmtp,
            Self::SmtpTestRecipient => MaterialOwnerKind::SmtpTestRecipient,
            Self::WebhookSecret => MaterialOwnerKind::WebhookSecret,
        }
    }

    const fn material_kind(self) -> MaterialKind {
        match self {
            Self::SigningKey => MaterialKind::SigningKey,
            Self::ProviderSecret
            | Self::ProjectSmtp
            | Self::DeploymentSmtp
            | Self::SmtpTestRecipient
            | Self::WebhookSecret => MaterialKind::ConfigurationSecret,
        }
    }

    const fn purpose(self) -> MaterialPurpose {
        match self {
            Self::SigningKey => MaterialPurpose::SigningSeed,
            Self::ProviderSecret => MaterialPurpose::ProviderClientSecret,
            Self::ProjectSmtp | Self::DeploymentSmtp => MaterialPurpose::SmtpCredential,
            Self::SmtpTestRecipient => MaterialPurpose::SmtpTestRecipient,
            Self::WebhookSecret => MaterialPurpose::WebhookSigningSecret,
        }
    }
}

#[derive(Clone, Debug)]
struct LegacyCandidate {
    kind: LegacyMaterialKind,
    project_id: Option<Uuid>,
    owner_id: Uuid,
    generation: i64,
    legacy_reference: String,
    public_jwk: Option<serde_json::Value>,
    legacy_fingerprint: Option<Vec<u8>>,
}

#[derive(Clone, Debug)]
struct PreparedImport {
    candidate: LegacyCandidate,
    operation_id: Uuid,
    reservation: ProtectedMaterialReservation,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CustodyImportReport {
    pub imported: usize,
    pub authority: CustodyAuthority,
}

pub(crate) struct PostgresCustodyImporter {
    database: DatabaseConnection,
    materials: ProtectedMaterialRepository,
    signing_store: EncryptedFileStore,
    secret_store: EncryptedFileStore,
    provider_id: ProviderId,
    provider_format_version: ProviderFormatVersion,
    provider: SoftwareCustodyProvider,
}

impl PostgresCustodyImporter {
    pub(crate) fn new(
        database: DatabaseConnection,
        deployment_id: &str,
        signing_store: EncryptedFileStore,
        secret_store: EncryptedFileStore,
        provider: SoftwareCustodyProvider,
    ) -> Result<Self, ApplicationError> {
        let provider_id = owlauth_key_provider::SigningKeyProvisioner::provider_id(&provider);
        let provider_format_version =
            ProviderFormatVersion::new(1).map_err(|_| ApplicationError::Integrity)?;
        Ok(Self {
            materials: ProtectedMaterialRepository::new(database.clone(), deployment_id)?,
            database,
            signing_store,
            secret_store,
            provider_id,
            provider_format_version,
            provider,
        })
    }

    pub(crate) async fn run(&self) -> Result<CustodyImportReport, ApplicationError> {
        let mut authority = self.materials.authority().await?;
        if authority.mode == CustodyMode::Protected {
            self.assert_complete_inventory().await?;
            return Ok(CustodyImportReport {
                imported: 0,
                authority,
            });
        }
        if authority.mode == CustodyMode::Legacy {
            authority = self
                .materials
                .compare_and_set_authority(
                    authority,
                    CustodyMode::Importing,
                    None,
                    OffsetDateTime::now_utc(),
                )
                .await?;
        }
        if authority.mode != CustodyMode::Importing {
            return Err(ApplicationError::InvalidTransition);
        }

        self.reconcile_unmaterialized_provider_operations().await?;
        let mut imported = 0_usize;
        loop {
            let candidates = self.inventory().await?;
            let Some(candidate) = candidates.into_iter().next() else {
                break;
            };
            let prepared = self.prepare(candidate).await?;
            if let Err(error) = self.effect_and_finalize(&prepared).await {
                self.record_failed(&prepared, failure_class(error), OffsetDateTime::now_utc())
                    .await?;
                return Err(error);
            }
            imported = imported.saturating_add(1);
        }

        self.assert_complete_inventory().await?;
        authority = self.materials.authority().await?;
        if authority.mode != CustodyMode::Importing {
            return Err(ApplicationError::RevisionConflict);
        }
        let authority = self.complete_cutover(authority).await?;
        Ok(CustodyImportReport {
            imported,
            authority,
        })
    }

    async fn inventory(&self) -> Result<Vec<LegacyCandidate>, ApplicationError> {
        let rows = self
            .database
            .query_all_raw(Statement::from_string(
                DbBackend::Postgres,
                INVENTORY_SQL.to_owned(),
            ))
            .await
            .map_err(persistence)?;
        rows.into_iter()
            .map(|row| {
                Ok(LegacyCandidate {
                    kind: LegacyMaterialKind::parse(
                        &row.try_get::<String>("", "owner_kind")
                            .map_err(persistence)?,
                    )?,
                    project_id: row
                        .try_get::<Option<Uuid>>("", "project_id")
                        .map_err(persistence)?,
                    owner_id: row.try_get("", "owner_id").map_err(persistence)?,
                    generation: row.try_get("", "generation").map_err(persistence)?,
                    legacy_reference: legacy_reference(
                        row.try_get::<Option<String>>("", "legacy_reference")
                            .map_err(persistence)?,
                        row.try_get::<Option<String>>("", "operation_alias")
                            .map_err(persistence)?,
                        row.try_get::<Option<Uuid>>("", "project_id")
                            .map_err(persistence)?,
                    )?,
                    public_jwk: row
                        .try_get::<Option<serde_json::Value>>("", "public_jwk")
                        .map_err(persistence)?,
                    legacy_fingerprint: row
                        .try_get::<Option<Vec<u8>>>("", "legacy_fingerprint")
                        .map_err(persistence)?,
                })
            })
            .collect()
    }

    async fn reconcile_unmaterialized_provider_operations(&self) -> Result<(), ApplicationError> {
        let rows = self
            .database
            .query_all_raw(Statement::from_string(
                DbBackend::Postgres,
                "SELECT operation.id AS operation_id,operation.project_id,
                        operation.provider_id,operation.operation_alias
                   FROM provider_secret_operations operation
                   JOIN provider_configurations provider
                     ON provider.project_id=operation.project_id
                    AND provider.id=operation.provider_id
                  WHERE operation.state='prepared' AND operation.material_id IS NULL
                    AND provider.status='provisioning' AND provider.secret_ref IS NULL
                    AND provider.secret_material_id IS NULL
                  ORDER BY operation.created_at,operation.id"
                    .to_owned(),
            ))
            .await
            .map_err(persistence)?;
        for row in rows {
            let operation_id = row.try_get("", "operation_id").map_err(persistence)?;
            let project_id = row.try_get("", "project_id").map_err(persistence)?;
            let provider_id = row.try_get("", "provider_id").map_err(persistence)?;
            let operation_alias = row
                .try_get::<String>("", "operation_alias")
                .map_err(persistence)?;
            let legacy_reference = provider_secret_alias(project_id, &operation_alias);
            if self
                .secret_store
                .read_optional_for_custody_import(&legacy_reference)
                .await?
                .is_none()
            {
                self.abandon_unmaterialized_provider_operation(
                    operation_id,
                    project_id,
                    provider_id,
                    &operation_alias,
                )
                .await?;
            }
        }
        Ok(())
    }

    async fn abandon_unmaterialized_provider_operation(
        &self,
        operation_id: Uuid,
        project_id: Uuid,
        provider_id: Uuid,
        operation_alias: &str,
    ) -> Result<(), ApplicationError> {
        let transaction = self.database.begin().await.map_err(persistence)?;
        let operation = transaction
            .query_one_raw(statement(
                "SELECT state,material_id,operation_alias
                   FROM provider_secret_operations
                  WHERE id=$1 AND project_id=$2 AND provider_id=$3 FOR UPDATE",
                vec![operation_id.into(), project_id.into(), provider_id.into()],
            ))
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::RevisionConflict)?;
        if operation
            .try_get::<String>("", "state")
            .map_err(persistence)?
            != "prepared"
            || operation
                .try_get::<Option<Uuid>>("", "material_id")
                .map_err(persistence)?
                .is_some()
            || operation
                .try_get::<String>("", "operation_alias")
                .map_err(persistence)?
                != operation_alias
        {
            return Err(ApplicationError::RevisionConflict);
        }
        let provider = transaction
            .query_one_raw(statement(
                "SELECT status,secret_ref,secret_material_id
                   FROM provider_configurations
                  WHERE id=$1 AND project_id=$2 FOR UPDATE",
                vec![provider_id.into(), project_id.into()],
            ))
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::RevisionConflict)?;
        if provider
            .try_get::<String>("", "status")
            .map_err(persistence)?
            != "provisioning"
            || provider
                .try_get::<Option<String>>("", "secret_ref")
                .map_err(persistence)?
                .is_some()
            || provider
                .try_get::<Option<Uuid>>("", "secret_material_id")
                .map_err(persistence)?
                .is_some()
        {
            return Err(ApplicationError::RevisionConflict);
        }
        transaction
            .execute_raw(statement(
                "INSERT INTO audit_events
                 (id,project_id,actor_kind,action,target_kind,target_id,outcome,correlation_id,
                  safe_context)
                 VALUES ($1,$2,'deployment_operator','custody.legacy_provider_abandoned',
                         'provider',$3,'success',$4,$5)",
                vec![
                    Uuid::new_v4().into(),
                    project_id.into(),
                    provider_id.into(),
                    Uuid::new_v4().into(),
                    serde_json::json!({"reason":"prepared_without_legacy_effect"}).into(),
                ],
            ))
            .await
            .map_err(persistence)?;
        let deleted = transaction
            .execute_raw(statement(
                "DELETE FROM provider_configurations WHERE id=$1 AND project_id=$2",
                vec![provider_id.into(), project_id.into()],
            ))
            .await
            .map_err(persistence)?;
        if deleted.rows_affected() != 1 {
            return Err(ApplicationError::RevisionConflict);
        }
        transaction.commit().await.map_err(persistence)
    }

    async fn prepare(
        &self,
        candidate: LegacyCandidate,
    ) -> Result<PreparedImport, ApplicationError> {
        let transaction = self.database.begin().await.map_err(persistence)?;
        let existing = transaction
            .query_one_raw(statement(
                "SELECT id,material_id,legacy_reference,cutover_revision
                   FROM custody_import_operations
                  WHERE owner_kind=$1 AND owner_id=$2 AND generation=$3
                  FOR UPDATE",
                vec![
                    candidate.kind.owner_kind().as_str().into(),
                    candidate.owner_id.into(),
                    candidate.generation.into(),
                ],
            ))
            .await
            .map_err(persistence)?;
        let (operation_id, material_id) = if let Some(existing) = &existing {
            if existing
                .try_get::<String>("", "legacy_reference")
                .map_err(persistence)?
                != candidate.legacy_reference
            {
                return Err(ApplicationError::Integrity);
            }
            (
                existing.try_get("", "id").map_err(persistence)?,
                existing.try_get("", "material_id").map_err(persistence)?,
            )
        } else {
            (Uuid::new_v4(), Uuid::new_v4())
        };
        let reservation = self
            .materials
            .reserve_import_in_transaction(
                &transaction,
                candidate.project_id,
                material_id,
                candidate.kind.owner_kind(),
                candidate.owner_id,
                candidate.generation,
                candidate.kind.material_kind(),
                candidate.kind.purpose(),
                self.provider_id.clone(),
                self.provider_format_version,
            )
            .await?;
        if existing.is_none() {
            transaction
                .execute_raw(statement(
                    "INSERT INTO custody_import_operations
                     (id,material_id,owner_kind,owner_id,generation,legacy_reference,
                      cutover_revision,state,attempt_count)
                     VALUES ($1,$2,$3,$4,$5,$6,$7,'reserved',0)",
                    vec![
                        operation_id.into(),
                        material_id.into(),
                        candidate.kind.owner_kind().as_str().into(),
                        candidate.owner_id.into(),
                        candidate.generation.into(),
                        candidate.legacy_reference.clone().into(),
                        reservation.authority.revision.into(),
                    ],
                ))
                .await
                .map_err(persistence)?;
        }
        let updated = transaction
            .execute_raw(statement(
                "UPDATE custody_import_operations
                    SET state='importing',attempt_count=attempt_count+1,
                        failure_class=NULL,verified_at=NULL,updated_at=transaction_timestamp()
                  WHERE id=$1 AND cutover_revision=$2",
                vec![operation_id.into(), reservation.authority.revision.into()],
            ))
            .await
            .map_err(persistence)?;
        if updated.rows_affected() != 1 {
            return Err(ApplicationError::RevisionConflict);
        }
        transaction.commit().await.map_err(persistence)?;
        Ok(PreparedImport {
            candidate,
            operation_id,
            reservation,
        })
    }

    async fn effect_and_finalize(&self, prepared: &PreparedImport) -> Result<(), ApplicationError> {
        let plaintext = match prepared.candidate.kind {
            LegacyMaterialKind::SigningKey => {
                self.signing_store
                    .read_for_custody_import(&prepared.candidate.legacy_reference)
                    .await?
            }
            _ => {
                self.secret_store
                    .read_for_custody_import(&prepared.candidate.legacy_reference)
                    .await?
            }
        };
        let (opaque_value, safe_fingerprint) =
            if prepared.candidate.kind == LegacyMaterialKind::SigningKey {
                let imported = self
                    .provider
                    .import_signing_seed(&prepared.reservation.context, plaintext.as_slice())
                    .map_err(|_| ApplicationError::ExternalStore)?;
                verify_public_jwk(
                    prepared.candidate.public_jwk.as_ref(),
                    imported.public_key.as_bytes(),
                )?;
                (imported.handle.into_zeroizing().to_vec(), None)
            } else {
                self.verify_legacy_fingerprint(&prepared.candidate, plaintext.as_slice())?;
                let sealed = self
                    .provider
                    .seal(SealSecretRequest {
                        context: prepared.reservation.context.clone(),
                        plaintext: SecretPlaintext::from_zeroizing(plaintext)
                            .map_err(|_| ApplicationError::Integrity)?,
                    })
                    .await
                    .map_err(|_| ApplicationError::ExternalStore)?;
                (
                    sealed.envelope.into_zeroizing().to_vec(),
                    Some(sealed.request_fingerprint.into_bytes()),
                )
            };
        self.finalize(prepared, opaque_value, safe_fingerprint)
            .await
    }

    fn verify_legacy_fingerprint(
        &self,
        candidate: &LegacyCandidate,
        plaintext: &[u8],
    ) -> Result<(), ApplicationError> {
        let Some(expected) = candidate.legacy_fingerprint.as_deref() else {
            return Ok(());
        };
        let actual = self.secret_store.request_fingerprint(plaintext);
        if actual.as_slice() == expected {
            Ok(())
        } else {
            Err(ApplicationError::Integrity)
        }
    }

    async fn finalize(
        &self,
        prepared: &PreparedImport,
        opaque_value: Vec<u8>,
        safe_fingerprint: Option<Vec<u8>>,
    ) -> Result<(), ApplicationError> {
        let transaction = self.database.begin().await.map_err(persistence)?;
        let operation = transaction
            .query_one_raw(statement(
                "SELECT state,cutover_revision FROM custody_import_operations WHERE id=$1 FOR UPDATE",
                vec![prepared.operation_id.into()],
            ))
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        if operation
            .try_get::<i64>("", "cutover_revision")
            .map_err(persistence)?
            != prepared.reservation.authority.revision
        {
            return Err(ApplicationError::RevisionConflict);
        }
        let now = OffsetDateTime::now_utc();
        finalize_pending_material(
            &transaction,
            prepared.reservation.id,
            prepared.candidate.project_id,
            opaque_value,
            safe_fingerprint.clone(),
            now,
        )
        .await?;
        // Material becomes live before legacy owner snapshots switch authority. The enclosing
        // transaction and deferred owner-integrity constraints still make this one atomic cutover,
        // while update guards can require every attached snapshot to reference live material.
        attach_owner_and_snapshots(
            &transaction,
            &prepared.candidate,
            prepared.reservation.id,
            safe_fingerprint.as_deref(),
        )
        .await?;
        let updated = transaction
            .execute_raw(statement(
                "UPDATE custody_import_operations
                    SET state='verified',failure_class=NULL,verified_at=$2,updated_at=$2
                  WHERE id=$1 AND state IN ('reserved','importing','failed')",
                vec![prepared.operation_id.into(), now.into()],
            ))
            .await
            .map_err(persistence)?;
        if updated.rows_affected() != 1 {
            return Err(ApplicationError::RevisionConflict);
        }
        transaction.commit().await.map_err(persistence)
    }

    async fn record_failed(
        &self,
        prepared: &PreparedImport,
        failure_class: &'static str,
        now: OffsetDateTime,
    ) -> Result<(), ApplicationError> {
        self.database
            .execute_raw(statement(
                "UPDATE custody_import_operations
                    SET state='failed',failure_class=$2,verified_at=NULL,updated_at=$3
                  WHERE id=$1 AND state<>'verified'",
                vec![
                    prepared.operation_id.into(),
                    failure_class.into(),
                    now.into(),
                ],
            ))
            .await
            .map_err(persistence)
            .map(|_| ())
    }

    pub(super) async fn complete_cutover(
        &self,
        expected: CustodyAuthority,
    ) -> Result<CustodyAuthority, ApplicationError> {
        let transaction = self.database.begin().await.map_err(persistence)?;
        let authority = transaction
            .query_one_raw(Statement::from_string(
                DbBackend::Postgres,
                "SELECT mode,revision FROM custody_cutover_authority
                  WHERE singleton FOR UPDATE"
                    .to_owned(),
            ))
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::Integrity)?;
        if authority
            .try_get::<String>("", "mode")
            .map_err(persistence)?
            != "importing"
            || authority
                .try_get::<i64>("", "revision")
                .map_err(persistence)?
                != expected.revision
        {
            return Err(ApplicationError::RevisionConflict);
        }
        let inventory = transaction
            .query_one_raw(statement(
                CUTOVER_INCOMPLETE_SQL,
                vec![expected.revision.into()],
            ))
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::Persistence)?;
        if inventory
            .try_get::<bool>("", "incomplete")
            .map_err(persistence)?
        {
            return Err(ApplicationError::InvalidTransition);
        }
        let completed_at = OffsetDateTime::now_utc();
        let updated = transaction
            .execute_raw(statement(
                "UPDATE custody_cutover_authority
                    SET mode='protected',revision=revision+1,
                        legacy_inventory_completed_at=$2,protected_at=$2,updated_at=$2
                  WHERE singleton AND mode='importing' AND revision=$1",
                vec![expected.revision.into(), completed_at.into()],
            ))
            .await
            .map_err(persistence)?;
        if updated.rows_affected() != 1 {
            return Err(ApplicationError::RevisionConflict);
        }
        transaction.commit().await.map_err(persistence)?;
        Ok(CustodyAuthority {
            mode: CustodyMode::Protected,
            revision: expected.revision + 1,
        })
    }

    async fn assert_complete_inventory(&self) -> Result<(), ApplicationError> {
        if !self.inventory().await?.is_empty() {
            return Err(ApplicationError::InvalidTransition);
        }
        let row = self
            .database
            .query_one_raw(Statement::from_string(
                DbBackend::Postgres,
                "SELECT COUNT(*)::BIGINT AS count
                   FROM custody_import_operations
                  WHERE state <> 'verified'"
                    .to_owned(),
            ))
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::Persistence)?;
        if row.try_get::<i64>("", "count").map_err(persistence)? != 0 {
            return Err(ApplicationError::InvalidTransition);
        }
        Ok(())
    }
}

const CUTOVER_INCOMPLETE_SQL: &str = r"
SELECT
    EXISTS (
        SELECT 1 FROM custody_import_operations operation
        LEFT JOIN protected_materials material
          ON material.id=operation.material_id
         AND material.owner_kind=operation.owner_kind
         AND material.owner_id=operation.owner_id
         AND material.generation=operation.generation
        WHERE operation.cutover_revision=$1
          AND (operation.state<>'verified' OR material.id IS NULL OR material.state<>'live'
               OR material.custody_mode<>'importing' OR material.custody_revision<>$1)
    )
    OR EXISTS (
        SELECT 1 FROM project_signing_keys
         WHERE signer_material_id IS NULL AND state <> 'abandoned'
    )
    OR EXISTS (
        SELECT 1 FROM provider_configurations
         WHERE status<>'provisioning' AND (secret_ref IS NOT NULL OR secret_material_id IS NULL)
    )
    OR EXISTS (
        SELECT 1 FROM project_smtp_configurations owner
        LEFT JOIN smtp_credential_reference_reservations reservation
          ON reservation.credential_ref=owner.credential_ref
        WHERE owner.credential_material_id IS NULL
          AND reservation.state IS DISTINCT FROM 'erased'
    )
    OR EXISTS (
        SELECT 1 FROM deployment_smtp_generations owner
        LEFT JOIN smtp_credential_reference_reservations reservation
          ON reservation.credential_ref=owner.credential_ref
        WHERE owner.credential_material_id IS NULL
          AND reservation.state IS DISTINCT FROM 'erased'
    )
    OR EXISTS (
        SELECT 1 FROM project_smtp_test_operations
         WHERE recipient_erased_at IS NULL AND recipient_material_id IS NULL
    )
    OR EXISTS (
        SELECT 1 FROM webhook_secret_generations owner
        LEFT JOIN webhook_secret_reference_reservations reservation
          ON reservation.secret_ref=owner.secret_ref
        WHERE owner.material_id IS NULL
          AND reservation.state IS DISTINCT FROM 'erased'
    )
    OR EXISTS (
        SELECT 1 FROM key_provisioning_operations operation
        JOIN project_signing_keys owner
          ON owner.project_id=operation.project_id AND owner.id=operation.key_id
        WHERE operation.material_id IS DISTINCT FROM owner.signer_material_id
    )
    OR EXISTS (
        SELECT 1 FROM provider_secret_operations operation
        JOIN provider_configurations owner
          ON owner.project_id=operation.project_id AND owner.id=operation.provider_id
        WHERE operation.material_id IS DISTINCT FROM owner.secret_material_id
    )
    OR EXISTS (
        SELECT 1 FROM identity_mutation_proof_slots slot
        JOIN provider_configurations provider
          ON provider.project_id=slot.project_id AND provider.id=slot.provider_configuration_id
        WHERE slot.method_kind='provider'
          AND slot.provider_secret_material_id IS DISTINCT FROM provider.secret_material_id
    )
    OR EXISTS (
        SELECT 1 FROM managed_provider_reauthorization_interactions
         WHERE secret_ref IS NOT NULL OR secret_material_id IS NULL
    )
    OR EXISTS (
        SELECT 1 FROM project_smtp_secret_operations operation
        JOIN project_smtp_configurations owner
          ON owner.project_id=operation.project_id AND owner.id=operation.configuration_id
        WHERE operation.material_id IS DISTINCT FROM owner.credential_material_id
    )
    OR EXISTS (
        SELECT 1 FROM project_smtp_test_operations test
        JOIN project_smtp_configurations owner
          ON owner.project_id=test.project_id AND owner.id=test.configuration_id
         AND owner.generation=test.configuration_generation
        WHERE test.credential_material_id IS DISTINCT FROM owner.credential_material_id
    )
    OR EXISTS (
        SELECT 1 FROM smtp_credential_cleanup_operations
         WHERE state IN ('pending','leased') AND material_id IS NULL
    )
    OR EXISTS (
        SELECT 1 FROM smtp_credential_reference_reservations
         WHERE state IN ('live','reserved') AND material_id IS NULL
    )
    OR EXISTS (
        SELECT 1 FROM smtp_test_recipient_reference_reservations
         WHERE state IN ('live','reserved') AND material_id IS NULL
    )
    OR EXISTS (
        SELECT 1 FROM webhook_secret_cleanup_operations
         WHERE state IN ('pending','leased') AND material_id IS NULL
    )
    OR EXISTS (
        SELECT 1 FROM webhook_secret_reference_reservations
         WHERE state IN ('live','reserved') AND material_id IS NULL
    )
    OR EXISTS (
        SELECT 1 FROM webhook_deliveries
         WHERE state='leased'
           AND (claimed_secret_material_id IS NULL
                OR (claimed_overlap_generation IS NOT NULL
                    AND claimed_overlap_material_id IS NULL))
    ) AS incomplete
";

const INVENTORY_SQL: &str = r"
SELECT * FROM (
    SELECT 'signing_key'::TEXT AS owner_kind,
           key.project_id,
           key.id AS owner_id,
           key.signer_material_generation AS generation,
           key.signer_ref AS legacy_reference,
           NULL::TEXT AS operation_alias,
           key.public_jwk AS public_jwk,
           NULL::BYTEA AS legacy_fingerprint
      FROM project_signing_keys AS key
     WHERE key.signer_material_id IS NULL AND key.state <> 'abandoned'
    UNION ALL
    SELECT 'provider_secret', provider.project_id, provider.id, provider.secret_generation,
           provider.secret_ref, operation.operation_alias, NULL::JSONB, NULL::BYTEA
      FROM provider_configurations AS provider
      LEFT JOIN provider_secret_operations AS operation
        ON operation.project_id=provider.project_id AND operation.provider_id=provider.id
     WHERE provider.secret_material_id IS NULL
       AND (provider.secret_ref IS NOT NULL
            OR (provider.status='provisioning' AND operation.state='prepared'
                AND operation.material_id IS NULL))
    UNION ALL
    SELECT 'project_smtp', smtp.project_id, smtp.id, smtp.generation::BIGINT,
           smtp.credential_ref, NULL::TEXT, NULL::JSONB, smtp.safe_fingerprint
      FROM project_smtp_configurations AS smtp
      LEFT JOIN smtp_credential_reference_reservations AS reservation
        ON reservation.credential_ref=smtp.credential_ref
     WHERE smtp.credential_material_id IS NULL
       AND reservation.state IS DISTINCT FROM 'erased'
    UNION ALL
    SELECT 'deployment_smtp', NULL::UUID, smtp.material_owner_id, smtp.generation::BIGINT,
           smtp.credential_ref, NULL::TEXT, NULL::JSONB, smtp.safe_fingerprint
      FROM deployment_smtp_generations AS smtp
      LEFT JOIN smtp_credential_reference_reservations AS reservation
        ON reservation.credential_ref=smtp.credential_ref
     WHERE smtp.credential_material_id IS NULL
       AND reservation.state IS DISTINCT FROM 'erased'
    UNION ALL
    SELECT 'smtp_test_recipient', test.project_id, test.id, 1::BIGINT,
           test.recipient_ref, NULL::TEXT, NULL::JSONB, NULL::BYTEA
      FROM project_smtp_test_operations AS test
     WHERE test.recipient_material_id IS NULL AND test.recipient_erased_at IS NULL
    UNION ALL
    SELECT 'webhook_secret', endpoint.project_id, secret.endpoint_id,
           secret.generation::BIGINT, secret.secret_ref, NULL::TEXT, NULL::JSONB,
           secret.request_fingerprint
      FROM webhook_secret_generations AS secret
      JOIN webhook_endpoints AS endpoint ON endpoint.id=secret.endpoint_id
      LEFT JOIN webhook_secret_reference_reservations AS reservation
        ON reservation.secret_ref=secret.secret_ref
     WHERE secret.material_id IS NULL
       AND reservation.state IS DISTINCT FROM 'erased'
) AS inventory
ORDER BY owner_kind, project_id NULLS FIRST, owner_id, generation
LIMIT 1
";

#[allow(
    clippy::too_many_lines,
    reason = "each typed legacy owner and its durable snapshots are attached in one transaction"
)]
async fn attach_owner_and_snapshots(
    transaction: &DatabaseTransaction,
    candidate: &LegacyCandidate,
    material_id: Uuid,
    safe_fingerprint: Option<&[u8]>,
) -> Result<(), ApplicationError> {
    let affected = match candidate.kind {
        LegacyMaterialKind::SigningKey => {
            transaction
                .execute_raw(statement(
                    "UPDATE key_provisioning_operations SET material_id=$2
                      WHERE key_id=$1 AND project_id=$3
                        AND (material_id IS NULL OR material_id=$2)",
                    vec![
                        candidate.owner_id.into(),
                        material_id.into(),
                        candidate.project_id.into(),
                    ],
                ))
                .await
                .map_err(persistence)?;
            transaction
                .execute_raw(statement(
                    "UPDATE project_signing_keys
                        SET signer_material_id=$2,updated_at=transaction_timestamp()
                      WHERE id=$1 AND project_id=$3 AND signer_ref=$4
                        AND signer_material_generation=$5
                        AND signer_material_id IS NULL",
                    vec![
                        candidate.owner_id.into(),
                        material_id.into(),
                        candidate.project_id.into(),
                        candidate.legacy_reference.clone().into(),
                        candidate.generation.into(),
                    ],
                ))
                .await
                .map_err(persistence)?
        }
        LegacyMaterialKind::ProviderSecret => {
            transaction
                .execute_raw(statement(
                    "UPDATE provider_secret_operations SET material_id=$2
                  WHERE provider_id=$1 AND project_id=$3
                    AND (material_id IS NULL OR material_id=$2)",
                    vec![
                        candidate.owner_id.into(),
                        material_id.into(),
                        candidate.project_id.into(),
                    ],
                ))
                .await
                .map_err(persistence)?;
            transaction
                .execute_raw(statement(
                    "UPDATE identity_mutation_proof_slots SET provider_secret_material_id=$2
                  WHERE provider_configuration_id=$1 AND project_id=$3 AND method_kind='provider'
                    AND (provider_secret_material_id IS NULL OR provider_secret_material_id=$2)",
                    vec![
                        candidate.owner_id.into(),
                        material_id.into(),
                        candidate.project_id.into(),
                    ],
                ))
                .await
                .map_err(persistence)?;
            transaction
                .execute_raw(statement(
                    "UPDATE managed_provider_reauthorization_interactions
                    SET secret_material_id=$2,secret_ref=NULL
                  WHERE provider_configuration_id=$1 AND project_id=$3 AND secret_ref=$4
                    AND secret_material_id IS NULL",
                    vec![
                        candidate.owner_id.into(),
                        material_id.into(),
                        candidate.project_id.into(),
                        candidate.legacy_reference.clone().into(),
                    ],
                ))
                .await
                .map_err(persistence)?;
            let result = transaction
                .execute_raw(statement(
                    "UPDATE provider_configurations
                        SET secret_material_id=$2,secret_ref=NULL,
                            status=CASE WHEN status='provisioning' THEN 'active' ELSE status END,
                            revision=CASE WHEN status='provisioning' THEN revision+1 ELSE revision END,
                            updated_at=transaction_timestamp()
                      WHERE id=$1 AND project_id=$3 AND secret_generation=$5
                        AND secret_material_id IS NULL
                        AND (secret_ref=$4 OR (status='provisioning' AND secret_ref IS NULL))",
                    vec![
                        candidate.owner_id.into(),
                        material_id.into(),
                        candidate.project_id.into(),
                        candidate.legacy_reference.clone().into(),
                        candidate.generation.into(),
                    ],
                ))
                .await
                .map_err(persistence)?;
            transaction
                .execute_raw(statement(
                    "UPDATE provider_secret_operations
                        SET state='completed',completed_at=COALESCE(completed_at,transaction_timestamp()),
                            updated_at=transaction_timestamp()
                      WHERE provider_id=$1 AND project_id=$2 AND material_id=$3
                        AND state IN ('prepared','stored')",
                    vec![
                        candidate.owner_id.into(),
                        candidate.project_id.into(),
                        material_id.into(),
                    ],
                ))
                .await
                .map_err(persistence)?;
            result
        }
        LegacyMaterialKind::ProjectSmtp => {
            let fingerprint = safe_fingerprint.ok_or(ApplicationError::Integrity)?;
            transaction
                .execute_raw(statement(
                    "UPDATE project_smtp_secret_operations SET material_id=$2
                  WHERE configuration_id=$1 AND project_id=$3 AND credential_ref=$4
                    AND (material_id IS NULL OR material_id=$2)",
                    vec![
                        candidate.owner_id.into(),
                        material_id.into(),
                        candidate.project_id.into(),
                        candidate.legacy_reference.clone().into(),
                    ],
                ))
                .await
                .map_err(persistence)?;
            transaction
                .execute_raw(statement(
                    "UPDATE project_smtp_test_operations SET credential_material_id=$2
                  WHERE configuration_id=$1 AND project_id=$3 AND configuration_generation=$5
                    AND credential_ref=$4
                    AND (credential_material_id IS NULL OR credential_material_id=$2)",
                    vec![
                        candidate.owner_id.into(),
                        material_id.into(),
                        candidate.project_id.into(),
                        candidate.legacy_reference.clone().into(),
                        candidate.generation.into(),
                    ],
                ))
                .await
                .map_err(persistence)?;
            transaction
                .execute_raw(statement(
                    "UPDATE smtp_credential_cleanup_operations SET material_id=$1
                  WHERE scope='project' AND project_id=$2 AND generation=$3
                    AND credential_ref=$4 AND (material_id IS NULL OR material_id=$1)",
                    vec![
                        material_id.into(),
                        candidate.project_id.into(),
                        candidate.generation.into(),
                        candidate.legacy_reference.clone().into(),
                    ],
                ))
                .await
                .map_err(persistence)?;
            transaction
                .execute_raw(statement(
                    "UPDATE smtp_credential_reference_reservations
                    SET material_id=$2,updated_at=transaction_timestamp()
                  WHERE credential_ref=$1 AND state IN ('live','reserved')
                    AND (material_id IS NULL OR material_id=$2)",
                    vec![
                        candidate.legacy_reference.clone().into(),
                        material_id.into(),
                    ],
                ))
                .await
                .map_err(persistence)?;
            transaction
                .execute_raw(statement(
                    "UPDATE project_smtp_configurations
                    SET credential_material_id=$2,safe_fingerprint=$6,
                        updated_at=transaction_timestamp()
                  WHERE id=$1 AND project_id=$3 AND generation=$5 AND credential_ref=$4
                    AND credential_material_id IS NULL",
                    vec![
                        candidate.owner_id.into(),
                        material_id.into(),
                        candidate.project_id.into(),
                        candidate.legacy_reference.clone().into(),
                        candidate.generation.into(),
                        fingerprint.to_vec().into(),
                    ],
                ))
                .await
                .map_err(persistence)?
        }
        LegacyMaterialKind::DeploymentSmtp => {
            let fingerprint = safe_fingerprint.ok_or(ApplicationError::Integrity)?;
            transaction
                .execute_raw(statement(
                    "UPDATE smtp_credential_cleanup_operations SET material_id=$1
                  WHERE scope='deployment_default' AND project_id IS NULL AND generation=$2
                    AND credential_ref=$3 AND (material_id IS NULL OR material_id=$1)",
                    vec![
                        material_id.into(),
                        candidate.generation.into(),
                        candidate.legacy_reference.clone().into(),
                    ],
                ))
                .await
                .map_err(persistence)?;
            transaction
                .execute_raw(statement(
                    "UPDATE smtp_credential_reference_reservations
                    SET material_id=$2,updated_at=transaction_timestamp()
                  WHERE credential_ref=$1 AND state IN ('live','reserved')
                    AND (material_id IS NULL OR material_id=$2)",
                    vec![
                        candidate.legacy_reference.clone().into(),
                        material_id.into(),
                    ],
                ))
                .await
                .map_err(persistence)?;
            transaction
                .execute_raw(statement(
                    "UPDATE deployment_smtp_generations
                    SET credential_material_id=$2,safe_fingerprint=$5,
                        updated_at=transaction_timestamp()
                  WHERE material_owner_id=$1 AND generation=$3 AND credential_ref=$4
                    AND credential_material_id IS NULL",
                    vec![
                        candidate.owner_id.into(),
                        material_id.into(),
                        candidate.generation.into(),
                        candidate.legacy_reference.clone().into(),
                        fingerprint.to_vec().into(),
                    ],
                ))
                .await
                .map_err(persistence)?
        }
        LegacyMaterialKind::SmtpTestRecipient => {
            transaction
                .execute_raw(statement(
                    "UPDATE smtp_test_recipient_reference_reservations
                    SET material_id=$2,updated_at=transaction_timestamp()
                  WHERE recipient_ref=$1 AND operation_id=$3 AND state IN ('live','reserved')
                    AND (material_id IS NULL OR material_id=$2)",
                    vec![
                        candidate.legacy_reference.clone().into(),
                        material_id.into(),
                        candidate.owner_id.into(),
                    ],
                ))
                .await
                .map_err(persistence)?;
            transaction
                .execute_raw(statement(
                    "UPDATE project_smtp_test_operations SET recipient_material_id=$2
                  WHERE id=$1 AND project_id=$3 AND recipient_ref=$4
                    AND recipient_erased_at IS NULL AND recipient_material_id IS NULL",
                    vec![
                        candidate.owner_id.into(),
                        material_id.into(),
                        candidate.project_id.into(),
                        candidate.legacy_reference.clone().into(),
                    ],
                ))
                .await
                .map_err(persistence)?
        }
        LegacyMaterialKind::WebhookSecret => {
            let fingerprint = safe_fingerprint.ok_or(ApplicationError::Integrity)?;
            let encoded_fingerprint =
                URL_SAFE_NO_PAD.encode(&fingerprint[..fingerprint.len().min(16)]);
            let result = transaction
                .execute_raw(statement(
                    "UPDATE webhook_secret_generations
                    SET material_id=$3,safe_fingerprint=$4
                  WHERE endpoint_id=$1 AND generation=$2 AND secret_ref=$5
                    AND material_id IS NULL",
                    vec![
                        candidate.owner_id.into(),
                        candidate.generation.into(),
                        material_id.into(),
                        encoded_fingerprint.into(),
                        candidate.legacy_reference.clone().into(),
                    ],
                ))
                .await
                .map_err(persistence)?;
            transaction
                .execute_raw(statement(
                    "UPDATE webhook_deliveries SET claimed_secret_material_id=$3
                  WHERE endpoint_id=$1 AND state='leased' AND claimed_secret_generation=$2
                    AND (claimed_secret_material_id IS NULL OR claimed_secret_material_id=$3)",
                    vec![
                        candidate.owner_id.into(),
                        candidate.generation.into(),
                        material_id.into(),
                    ],
                ))
                .await
                .map_err(persistence)?;
            transaction
                .execute_raw(statement(
                    "UPDATE webhook_deliveries SET claimed_overlap_material_id=$3
                  WHERE endpoint_id=$1 AND state='leased' AND claimed_overlap_generation=$2
                    AND (claimed_overlap_material_id IS NULL OR claimed_overlap_material_id=$3)",
                    vec![
                        candidate.owner_id.into(),
                        candidate.generation.into(),
                        material_id.into(),
                    ],
                ))
                .await
                .map_err(persistence)?;
            transaction
                .execute_raw(statement(
                    "UPDATE webhook_secret_cleanup_operations
                    SET material_id=$3,updated_at=transaction_timestamp()
                  WHERE endpoint_id=$1 AND generation=$2 AND secret_ref=$4
                    AND (material_id IS NULL OR material_id=$3)",
                    vec![
                        candidate.owner_id.into(),
                        candidate.generation.into(),
                        material_id.into(),
                        candidate.legacy_reference.clone().into(),
                    ],
                ))
                .await
                .map_err(persistence)?;
            transaction
                .execute_raw(statement(
                    "UPDATE webhook_secret_reference_reservations
                    SET material_id=$2,updated_at=transaction_timestamp()
                  WHERE secret_ref=$1 AND state IN ('live','reserved')
                    AND (material_id IS NULL OR material_id=$2)",
                    vec![
                        candidate.legacy_reference.clone().into(),
                        material_id.into(),
                    ],
                ))
                .await
                .map_err(persistence)?;
            result
        }
    };
    if affected.rows_affected() != 1 {
        return Err(ApplicationError::RevisionConflict);
    }
    Ok(())
}

fn legacy_reference(
    reference: Option<String>,
    operation_alias: Option<String>,
    project_id: Option<Uuid>,
) -> Result<String, ApplicationError> {
    match (reference, operation_alias, project_id) {
        (Some(reference), _, _) => Ok(reference),
        (None, Some(operation_alias), Some(project_id)) => {
            Ok(provider_secret_alias(project_id, &operation_alias))
        }
        _ => Err(ApplicationError::Integrity),
    }
}

fn provider_secret_alias(project_id: Uuid, operation_alias: &str) -> String {
    let digest = Sha256::digest(operation_alias.as_bytes());
    format!(
        "secret_{}_{}",
        project_id.simple(),
        URL_SAFE_NO_PAD.encode(&digest[..16])
    )
}

fn verify_public_jwk(
    public_jwk: Option<&serde_json::Value>,
    normalized_public_key: &[u8],
) -> Result<(), ApplicationError> {
    let public_jwk = public_jwk.ok_or(ApplicationError::Integrity)?;
    let x = public_jwk
        .get("x")
        .and_then(serde_json::Value::as_str)
        .ok_or(ApplicationError::Integrity)?;
    let decoded = URL_SAFE_NO_PAD
        .decode(x)
        .map_err(|_| ApplicationError::Integrity)?;
    if public_jwk.get("kty").and_then(serde_json::Value::as_str) != Some("OKP")
        || public_jwk.get("crv").and_then(serde_json::Value::as_str) != Some("Ed25519")
        || decoded.as_slice() != normalized_public_key
    {
        return Err(ApplicationError::Integrity);
    }
    Ok(())
}

const fn failure_class(error: ApplicationError) -> &'static str {
    match error {
        ApplicationError::NotFound => "missing",
        ApplicationError::Integrity | ApplicationError::IdempotencyConflict => "mismatch",
        ApplicationError::ExternalStore => "unavailable",
        _ => "unreadable",
    }
}

fn statement(sql: &str, values: Vec<sea_orm::Value>) -> Statement {
    Statement::from_sql_and_values(DbBackend::Postgres, sql, values)
}

fn persistence(_: sea_orm::DbErr) -> ApplicationError {
    ApplicationError::Persistence
}
