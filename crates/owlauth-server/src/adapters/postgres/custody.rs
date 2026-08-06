use std::collections::BTreeMap;

use sea_orm::{
    ActiveModelTrait, ActiveValue::Set, ColumnTrait, DatabaseConnection, DatabaseTransaction,
    EntityTrait, IntoActiveModel, QueryFilter, QueryOrder, QuerySelect, TransactionTrait,
};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use uuid::Uuid;

use super::entity::{custody_cutover_authority, project_signing_key, protected_material};
use crate::application::ApplicationError;
use owlauth_key_provider::{
    ContextVersion, DeploymentId, FieldPurpose, MaterialId, MaterialKind, OwnerId, OwnerKind,
    ProjectId, ProtectionContext, ProtectionContextParts, ProviderFormatVersion, ProviderId, Scope,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MaterialOwnerKind {
    SigningKey,
    ProviderSecret,
    ProjectSmtp,
    DeploymentSmtp,
    SmtpTestRecipient,
    WebhookSecret,
}

impl MaterialOwnerKind {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::SigningKey => "signing_key",
            Self::ProviderSecret => "provider_secret",
            Self::ProjectSmtp => "project_smtp",
            Self::DeploymentSmtp => "deployment_smtp",
            Self::SmtpTestRecipient => "smtp_test_recipient",
            Self::WebhookSecret => "webhook_secret",
        }
    }

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
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MaterialPurpose {
    SigningSeed,
    ProviderClientSecret,
    SmtpCredential,
    SmtpTestRecipient,
    WebhookSigningSecret,
}

impl MaterialPurpose {
    const fn as_str(self) -> &'static str {
        match self {
            Self::SigningSeed => "signing-seed",
            Self::ProviderClientSecret => "provider-client-secret",
            Self::SmtpCredential => "smtp-credential",
            Self::SmtpTestRecipient => "smtp-test-recipient",
            Self::WebhookSigningSecret => "webhook-signing-secret",
        }
    }

    fn for_owner(owner_kind: MaterialOwnerKind) -> Self {
        match owner_kind {
            MaterialOwnerKind::SigningKey => Self::SigningSeed,
            MaterialOwnerKind::ProviderSecret => Self::ProviderClientSecret,
            MaterialOwnerKind::ProjectSmtp | MaterialOwnerKind::DeploymentSmtp => {
                Self::SmtpCredential
            }
            MaterialOwnerKind::SmtpTestRecipient => Self::SmtpTestRecipient,
            MaterialOwnerKind::WebhookSecret => Self::WebhookSigningSecret,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ProtectedMaterialReservation {
    pub id: Uuid,
    pub project_id: Option<Uuid>,
    pub owner_kind: MaterialOwnerKind,
    pub owner_id: Uuid,
    pub generation: i64,
    pub material_kind: MaterialKind,
    pub provider_id: ProviderId,
    pub provider_format_version: ProviderFormatVersion,
    pub context: ProtectionContext,
    pub authority: CustodyAuthority,
    pub state: ProtectedMaterialState,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProtectedMaterialState {
    Pending,
    Live,
    Erased,
}

impl ProtectedMaterialState {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Live => "live",
            Self::Erased => "erased",
        }
    }

    fn parse(value: &str) -> Result<Self, ApplicationError> {
        match value {
            "pending" => Ok(Self::Pending),
            "live" => Ok(Self::Live),
            "erased" => Ok(Self::Erased),
            _ => Err(ApplicationError::Integrity),
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct LiveProtectedMaterial {
    pub reservation: ProtectedMaterialReservation,
    pub opaque_value: Vec<u8>,
    pub safe_fingerprint: Option<Vec<u8>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RequiredRuntimeCapability {
    pub provider_id: ProviderId,
    pub provider_format_version: ProviderFormatVersion,
    pub material_kind: MaterialKind,
}

#[derive(Debug, PartialEq)]
pub(crate) struct RuntimeReadinessCandidate {
    pub material: LiveProtectedMaterial,
    pub signing_public_jwk: Option<serde_json::Value>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CustodyMode {
    Legacy,
    Importing,
    Protected,
}

impl CustodyMode {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Legacy => "legacy",
            Self::Importing => "importing",
            Self::Protected => "protected",
        }
    }

    fn parse(value: &str) -> Result<Self, ApplicationError> {
        match value {
            "legacy" => Ok(Self::Legacy),
            "importing" => Ok(Self::Importing),
            "protected" => Ok(Self::Protected),
            _ => Err(ApplicationError::Integrity),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CustodyAuthority {
    pub mode: CustodyMode,
    pub revision: i64,
}

#[derive(Clone, Debug)]
pub(crate) struct ProtectedMaterialRepository {
    database: DatabaseConnection,
    deployment_id: DeploymentId,
}

impl ProtectedMaterialRepository {
    pub(crate) fn new(
        database: DatabaseConnection,
        deployment_id: &str,
    ) -> Result<Self, ApplicationError> {
        Ok(Self {
            database,
            deployment_id: DeploymentId::new(deployment_id)
                .map_err(|_| ApplicationError::Integrity)?,
        })
    }

    #[allow(clippy::too_many_arguments)]
    #[cfg(test)]
    pub(crate) async fn reserve_project(
        &self,
        project_id: Uuid,
        material_id: Uuid,
        owner_kind: MaterialOwnerKind,
        owner_id: Uuid,
        generation: i64,
        material_kind: MaterialKind,
        purpose: MaterialPurpose,
        provider_id: ProviderId,
        provider_format_version: ProviderFormatVersion,
    ) -> Result<ProtectedMaterialReservation, ApplicationError> {
        self.reserve(
            Some(project_id),
            material_id,
            owner_kind,
            owner_id,
            generation,
            material_kind,
            purpose,
            provider_id,
            provider_format_version,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn reserve_deployment_in_transaction(
        &self,
        transaction: &DatabaseTransaction,
        material_id: Uuid,
        owner_kind: MaterialOwnerKind,
        owner_id: Uuid,
        generation: i64,
        material_kind: MaterialKind,
        purpose: MaterialPurpose,
        provider_id: ProviderId,
        provider_format_version: ProviderFormatVersion,
    ) -> Result<ProtectedMaterialReservation, ApplicationError> {
        self.reserve_in_transaction(
            transaction,
            CustodyMode::Protected,
            None,
            material_id,
            owner_kind,
            owner_id,
            generation,
            material_kind,
            purpose,
            provider_id,
            provider_format_version,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn reserve_project_in_transaction(
        &self,
        transaction: &DatabaseTransaction,
        project_id: Uuid,
        material_id: Uuid,
        owner_kind: MaterialOwnerKind,
        owner_id: Uuid,
        generation: i64,
        material_kind: MaterialKind,
        purpose: MaterialPurpose,
        provider_id: ProviderId,
        provider_format_version: ProviderFormatVersion,
    ) -> Result<ProtectedMaterialReservation, ApplicationError> {
        self.reserve_in_transaction(
            transaction,
            CustodyMode::Protected,
            Some(project_id),
            material_id,
            owner_kind,
            owner_id,
            generation,
            material_kind,
            purpose,
            provider_id,
            provider_format_version,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn reserve_import_in_transaction(
        &self,
        transaction: &DatabaseTransaction,
        project_id: Option<Uuid>,
        material_id: Uuid,
        owner_kind: MaterialOwnerKind,
        owner_id: Uuid,
        generation: i64,
        material_kind: MaterialKind,
        purpose: MaterialPurpose,
        provider_id: ProviderId,
        provider_format_version: ProviderFormatVersion,
    ) -> Result<ProtectedMaterialReservation, ApplicationError> {
        self.reserve_in_transaction(
            transaction,
            CustodyMode::Importing,
            project_id,
            material_id,
            owner_kind,
            owner_id,
            generation,
            material_kind,
            purpose,
            provider_id,
            provider_format_version,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    #[cfg(test)]
    async fn reserve(
        &self,
        project_id: Option<Uuid>,
        material_id: Uuid,
        owner_kind: MaterialOwnerKind,
        owner_id: Uuid,
        generation: i64,
        material_kind: MaterialKind,
        purpose: MaterialPurpose,
        provider_id: ProviderId,
        provider_format_version: ProviderFormatVersion,
    ) -> Result<ProtectedMaterialReservation, ApplicationError> {
        let transaction = self.database.begin().await.map_err(persistence)?;
        let reservation = self
            .reserve_in_transaction(
                &transaction,
                CustodyMode::Protected,
                project_id,
                material_id,
                owner_kind,
                owner_id,
                generation,
                material_kind,
                purpose,
                provider_id,
                provider_format_version,
            )
            .await?;
        transaction.commit().await.map_err(persistence)?;
        Ok(reservation)
    }

    #[allow(clippy::too_many_arguments)]
    async fn reserve_in_transaction(
        &self,
        transaction: &DatabaseTransaction,
        required_mode: CustodyMode,
        project_id: Option<Uuid>,
        material_id: Uuid,
        owner_kind: MaterialOwnerKind,
        owner_id: Uuid,
        generation: i64,
        material_kind: MaterialKind,
        purpose: MaterialPurpose,
        provider_id: ProviderId,
        provider_format_version: ProviderFormatVersion,
    ) -> Result<ProtectedMaterialReservation, ApplicationError> {
        let authority = lock_authority(transaction, required_mode).await?;
        let context = self.context(
            project_id,
            material_id,
            owner_kind,
            owner_id,
            generation,
            material_kind,
            purpose,
            provider_id.clone(),
            provider_format_version,
        )?;
        let context_digest = Sha256::digest(context.canonical_bytes()).to_vec();
        let existing = protected_material::Entity::find()
            .filter(
                protected_material::Column::ScopeKind.eq(if project_id.is_some() {
                    "project"
                } else {
                    "deployment"
                }),
            )
            .filter(match project_id {
                Some(project_id) => protected_material::Column::ProjectId.eq(project_id),
                None => protected_material::Column::ProjectId.is_null(),
            })
            .filter(protected_material::Column::OwnerKind.eq(owner_kind.as_str()))
            .filter(protected_material::Column::OwnerId.eq(owner_id))
            .filter(protected_material::Column::Generation.eq(generation))
            .lock_exclusive()
            .one(transaction)
            .await
            .map_err(persistence)?;
        if let Some(existing) = existing {
            let reservation = map_reservation(existing, &self.deployment_id, purpose)?;
            if reservation.id != material_id
                || reservation.material_kind != material_kind
                || reservation.provider_id != provider_id
                || reservation.provider_format_version != provider_format_version
                || reservation.context != context
                || reservation.authority != authority
            {
                return Err(ApplicationError::IdempotencyConflict);
            }
            return Ok(reservation);
        }
        if generation <= 0 {
            return Err(ApplicationError::InvalidInput);
        }
        let inserted = protected_material::ActiveModel {
            id: Set(material_id),
            scope_kind: Set(if project_id.is_some() {
                "project".to_owned()
            } else {
                "deployment".to_owned()
            }),
            project_id: Set(project_id),
            owner_kind: Set(owner_kind.as_str().to_owned()),
            owner_id: Set(owner_id),
            generation: Set(generation),
            material_kind: Set(material_kind_name(material_kind).to_owned()),
            provider_id: Set(provider_id.as_str().to_owned()),
            provider_format_version: Set(i32::from(provider_format_version.get())),
            context_version: Set(i32::from(ContextVersion::V1.get())),
            context_digest: Set(context_digest),
            custody_mode: Set(authority.mode.as_str().to_owned()),
            custody_revision: Set(authority.revision),
            opaque_value: Set(None),
            safe_fingerprint: Set(None),
            state: Set(ProtectedMaterialState::Pending.as_str().to_owned()),
            erased_at: Set(None),
            ..Default::default()
        }
        .insert(transaction)
        .await
        .map_err(persistence)?;
        map_reservation(inserted, &self.deployment_id, purpose)
    }

    pub(crate) async fn load_project_reservation(
        &self,
        project_id: Uuid,
        material_id: Uuid,
        purpose: MaterialPurpose,
    ) -> Result<ProtectedMaterialReservation, ApplicationError> {
        let model = protected_material::Entity::find_by_id(material_id)
            .filter(protected_material::Column::ProjectId.eq(project_id))
            .one(&self.database)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        map_reservation(model, &self.deployment_id, purpose)
    }

    pub(crate) async fn load_project_reservation_in_transaction(
        &self,
        transaction: &DatabaseTransaction,
        project_id: Uuid,
        material_id: Uuid,
        purpose: MaterialPurpose,
    ) -> Result<ProtectedMaterialReservation, ApplicationError> {
        let model = protected_material::Entity::find_by_id(material_id)
            .filter(protected_material::Column::ProjectId.eq(project_id))
            .one(transaction)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        map_reservation(model, &self.deployment_id, purpose)
    }

    pub(crate) async fn load_reservation_by_id(
        &self,
        material_id: Uuid,
    ) -> Result<ProtectedMaterialReservation, ApplicationError> {
        let model = protected_material::Entity::find_by_id(material_id)
            .one(&self.database)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        let owner_kind = MaterialOwnerKind::parse(&model.owner_kind)?;
        map_reservation(
            model,
            &self.deployment_id,
            MaterialPurpose::for_owner(owner_kind),
        )
    }

    pub(crate) async fn load_live_by_id(
        &self,
        material_id: Uuid,
    ) -> Result<LiveProtectedMaterial, ApplicationError> {
        let model = protected_material::Entity::find_by_id(material_id)
            .one(&self.database)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        let owner_kind = MaterialOwnerKind::parse(&model.owner_kind)?;
        map_live(
            model,
            &self.deployment_id,
            MaterialPurpose::for_owner(owner_kind),
        )
    }

    pub(crate) async fn required_runtime_capabilities(
        &self,
    ) -> Result<Vec<RequiredRuntimeCapability>, ApplicationError> {
        let rows = protected_material::Entity::find()
            .select_only()
            .column(protected_material::Column::ProviderId)
            .column(protected_material::Column::ProviderFormatVersion)
            .column(protected_material::Column::MaterialKind)
            .filter(protected_material::Column::State.eq(ProtectedMaterialState::Live.as_str()))
            .distinct()
            .into_tuple::<(String, i32, String)>()
            .all(&self.database)
            .await
            .map_err(persistence)?;
        rows.into_iter()
            .map(|(provider_id, format_version, material_kind)| {
                Ok(RequiredRuntimeCapability {
                    provider_id: ProviderId::new(provider_id)
                        .map_err(|_| ApplicationError::Integrity)?,
                    provider_format_version: ProviderFormatVersion::new(
                        u16::try_from(format_version).map_err(|_| ApplicationError::Integrity)?,
                    )
                    .map_err(|_| ApplicationError::Integrity)?,
                    material_kind: parse_material_kind(&material_kind)?,
                })
            })
            .collect()
    }

    pub(crate) async fn runtime_readiness_page(
        &self,
        after: Option<Uuid>,
        limit: u64,
    ) -> Result<Vec<RuntimeReadinessCandidate>, ApplicationError> {
        if limit == 0 || limit > 256 {
            return Err(ApplicationError::InvalidInput);
        }
        let mut query = protected_material::Entity::find()
            .filter(protected_material::Column::State.eq(ProtectedMaterialState::Live.as_str()));
        if let Some(after) = after {
            query = query.filter(protected_material::Column::Id.gt(after));
        }
        let rows = query
            .order_by_asc(protected_material::Column::Id)
            .limit(limit)
            .all(&self.database)
            .await
            .map_err(persistence)?;
        let signing_material_ids = rows
            .iter()
            .filter(|row| row.material_kind == material_kind_name(MaterialKind::SigningKey))
            .map(|row| row.id)
            .collect::<Vec<_>>();
        let mut signing_owners = BTreeMap::<Uuid, Vec<project_signing_key::Model>>::new();
        if !signing_material_ids.is_empty() {
            for owner in project_signing_key::Entity::find()
                .filter(
                    project_signing_key::Column::SignerMaterialId
                        .is_in(signing_material_ids.iter().copied()),
                )
                .all(&self.database)
                .await
                .map_err(persistence)?
            {
                let material_id = owner
                    .signer_material_id
                    .ok_or(ApplicationError::Integrity)?;
                signing_owners.entry(material_id).or_default().push(owner);
            }
        }
        let mut candidates = Vec::with_capacity(rows.len());
        for row in rows {
            let owner_kind = MaterialOwnerKind::parse(&row.owner_kind)?;
            let material_id = row.id;
            let material = map_live(
                row,
                &self.deployment_id,
                MaterialPurpose::for_owner(owner_kind),
            )?;
            let signing_public_jwk =
                if material.reservation.material_kind == MaterialKind::SigningKey {
                    if owner_kind != MaterialOwnerKind::SigningKey {
                        return Err(ApplicationError::Integrity);
                    }
                    let owners = signing_owners
                        .remove(&material_id)
                        .ok_or(ApplicationError::Integrity)?;
                    let [owner] = owners.as_slice() else {
                        return Err(ApplicationError::Integrity);
                    };
                    if Some(owner.project_id) != material.reservation.project_id
                        || owner.id != material.reservation.owner_id
                        || owner.signer_material_generation != material.reservation.generation
                    {
                        return Err(ApplicationError::Integrity);
                    }
                    Some(owner.public_jwk.clone())
                } else {
                    if owner_kind == MaterialOwnerKind::SigningKey {
                        return Err(ApplicationError::Integrity);
                    }
                    None
                };
            candidates.push(RuntimeReadinessCandidate {
                material,
                signing_public_jwk,
            });
        }
        if !signing_owners.is_empty() {
            return Err(ApplicationError::Integrity);
        }
        Ok(candidates)
    }

    pub(crate) async fn load_deployment_reservation(
        &self,
        material_id: Uuid,
        purpose: MaterialPurpose,
    ) -> Result<ProtectedMaterialReservation, ApplicationError> {
        let model = protected_material::Entity::find_by_id(material_id)
            .filter(protected_material::Column::ProjectId.is_null())
            .one(&self.database)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        map_reservation(model, &self.deployment_id, purpose)
    }

    pub(crate) async fn load_deployment_reservation_in_transaction(
        &self,
        transaction: &DatabaseTransaction,
        material_id: Uuid,
        purpose: MaterialPurpose,
    ) -> Result<ProtectedMaterialReservation, ApplicationError> {
        let model = protected_material::Entity::find_by_id(material_id)
            .filter(protected_material::Column::ProjectId.is_null())
            .one(transaction)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        map_reservation(model, &self.deployment_id, purpose)
    }

    #[cfg(test)]
    pub(crate) async fn erase_project(
        &self,
        project_id: Uuid,
        material_id: Uuid,
        erased_at: OffsetDateTime,
    ) -> Result<(), ApplicationError> {
        let transaction = self.database.begin().await.map_err(persistence)?;
        lock_material_inventory(&transaction).await?;
        let model = protected_material::Entity::find_by_id(material_id)
            .filter(protected_material::Column::ProjectId.eq(project_id))
            .lock_exclusive()
            .one(&transaction)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        match ProtectedMaterialState::parse(&model.state)? {
            ProtectedMaterialState::Erased => {
                transaction.commit().await.map_err(persistence)?;
                return Ok(());
            }
            ProtectedMaterialState::Pending | ProtectedMaterialState::Live => {}
        }
        let mut active = model.into_active_model();
        active.opaque_value = Set(None);
        active.state = Set(ProtectedMaterialState::Erased.as_str().to_owned());
        active.erased_at = Set(Some(erased_at));
        active.updated_at = Set(erased_at);
        active.update(&transaction).await.map_err(persistence)?;
        transaction.commit().await.map_err(persistence)
    }

    pub(crate) async fn erase_by_id(
        &self,
        material_id: Uuid,
        erased_at: OffsetDateTime,
    ) -> Result<(), ApplicationError> {
        let transaction = self.database.begin().await.map_err(persistence)?;
        self.erase_by_id_in_transaction(&transaction, material_id, erased_at)
            .await?;
        transaction.commit().await.map_err(persistence)
    }

    pub(crate) async fn erase_by_id_in_transaction(
        &self,
        transaction: &DatabaseTransaction,
        material_id: Uuid,
        erased_at: OffsetDateTime,
    ) -> Result<(), ApplicationError> {
        lock_material_inventory(transaction).await?;
        let model = protected_material::Entity::find_by_id(material_id)
            .lock_exclusive()
            .one(transaction)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        match ProtectedMaterialState::parse(&model.state)? {
            ProtectedMaterialState::Erased => return Ok(()),
            ProtectedMaterialState::Pending | ProtectedMaterialState::Live => {}
        }
        let mut active = model.into_active_model();
        active.opaque_value = Set(None);
        active.state = Set(ProtectedMaterialState::Erased.as_str().to_owned());
        active.erased_at = Set(Some(erased_at));
        active.updated_at = Set(erased_at);
        active.update(transaction).await.map_err(persistence)?;
        Ok(())
    }

    pub(crate) async fn authority(&self) -> Result<CustodyAuthority, ApplicationError> {
        let model = custody_cutover_authority::Entity::find_by_id(true)
            .one(&self.database)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::Integrity)?;
        Ok(CustodyAuthority {
            mode: CustodyMode::parse(&model.mode)?,
            revision: model.revision,
        })
    }

    pub(crate) async fn material_inventory_revision(&self) -> Result<i64, ApplicationError> {
        let revision = custody_cutover_authority::Entity::find_by_id(true)
            .select_only()
            .column(custody_cutover_authority::Column::MaterialInventoryRevision)
            .into_tuple::<i64>()
            .one(&self.database)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::Integrity)?;
        if revision <= 0 {
            return Err(ApplicationError::Integrity);
        }
        Ok(revision)
    }

    pub(crate) async fn compare_and_set_authority(
        &self,
        expected: CustodyAuthority,
        target: CustodyMode,
        inventory_completed_at: Option<OffsetDateTime>,
        changed_at: OffsetDateTime,
    ) -> Result<CustodyAuthority, ApplicationError> {
        let valid_transition = matches!(
            (expected.mode, target),
            (CustodyMode::Legacy, CustodyMode::Importing)
                | (
                    CustodyMode::Importing,
                    CustodyMode::Legacy | CustodyMode::Protected,
                )
        );
        if !valid_transition
            || (target == CustodyMode::Protected && inventory_completed_at.is_none())
        {
            return Err(ApplicationError::InvalidTransition);
        }
        let transaction = self.database.begin().await.map_err(persistence)?;
        let model = custody_cutover_authority::Entity::find_by_id(true)
            .lock_exclusive()
            .one(&transaction)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::Integrity)?;
        if model.revision != expected.revision || CustodyMode::parse(&model.mode)? != expected.mode
        {
            return Err(ApplicationError::RevisionConflict);
        }
        let mut active = model.into_active_model();
        active.mode = Set(target.as_str().to_owned());
        active.revision = Set(expected.revision + 1);
        active.legacy_inventory_completed_at = Set(if target == CustodyMode::Legacy {
            None
        } else {
            inventory_completed_at
        });
        active.protected_at = Set((target == CustodyMode::Protected).then_some(changed_at));
        active.updated_at = Set(changed_at);
        let updated = active.update(&transaction).await.map_err(persistence)?;
        transaction.commit().await.map_err(persistence)?;
        Ok(CustodyAuthority {
            mode: CustodyMode::parse(&updated.mode)?,
            revision: updated.revision,
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn context(
        &self,
        project_id: Option<Uuid>,
        material_id: Uuid,
        owner_kind: MaterialOwnerKind,
        owner_id: Uuid,
        generation: i64,
        material_kind: MaterialKind,
        purpose: MaterialPurpose,
        provider_id: ProviderId,
        provider_format_version: ProviderFormatVersion,
    ) -> Result<ProtectionContext, ApplicationError> {
        let generation = u64::try_from(generation).map_err(|_| ApplicationError::InvalidInput)?;
        ProtectionContext::new(ProtectionContextParts {
            version: ContextVersion::V1,
            deployment_id: self.deployment_id.clone(),
            scope: match project_id {
                Some(project_id) => Scope::Project(
                    ProjectId::new(project_id.to_string())
                        .map_err(|_| ApplicationError::Integrity)?,
                ),
                None => Scope::Deployment,
            },
            material_id: MaterialId::new(material_id.to_string())
                .map_err(|_| ApplicationError::Integrity)?,
            material_kind,
            owner_kind: OwnerKind::new(owner_kind.as_str())
                .map_err(|_| ApplicationError::Integrity)?,
            owner_id: OwnerId::new(owner_id.to_string())
                .map_err(|_| ApplicationError::Integrity)?,
            generation,
            field_purpose: FieldPurpose::new(purpose.as_str())
                .map_err(|_| ApplicationError::Integrity)?,
            provider_id,
            provider_format_version,
        })
        .map_err(|_| ApplicationError::Integrity)
    }
}

pub(crate) async fn lock_material_inventory(
    transaction: &DatabaseTransaction,
) -> Result<(), ApplicationError> {
    lock_current_authority(transaction).await.map(|_| ())
}

async fn lock_current_authority(
    transaction: &DatabaseTransaction,
) -> Result<CustodyAuthority, ApplicationError> {
    let model = custody_cutover_authority::Entity::find_by_id(true)
        .lock_exclusive()
        .one(transaction)
        .await
        .map_err(persistence)?
        .ok_or(ApplicationError::Integrity)?;
    Ok(CustodyAuthority {
        mode: CustodyMode::parse(&model.mode)?,
        revision: model.revision,
    })
}

async fn lock_authority(
    transaction: &DatabaseTransaction,
    required_mode: CustodyMode,
) -> Result<CustodyAuthority, ApplicationError> {
    let authority = lock_current_authority(transaction).await?;
    if authority.mode != required_mode {
        return Err(ApplicationError::Disabled);
    }
    Ok(authority)
}

pub(crate) async fn finalize_pending_material(
    transaction: &DatabaseTransaction,
    material_id: Uuid,
    project_id: Option<Uuid>,
    opaque_value: Vec<u8>,
    safe_fingerprint: Option<Vec<u8>>,
    finalized_at: OffsetDateTime,
) -> Result<(), ApplicationError> {
    let authority = lock_current_authority(transaction).await?;
    let model = protected_material::Entity::find_by_id(material_id)
        .filter(match project_id {
            Some(project_id) => protected_material::Column::ProjectId.eq(project_id),
            None => protected_material::Column::ProjectId.is_null(),
        })
        .lock_exclusive()
        .one(transaction)
        .await
        .map_err(persistence)?
        .ok_or(ApplicationError::NotFound)?;
    if CustodyMode::parse(&model.custody_mode)? != authority.mode
        || model.custody_revision != authority.revision
    {
        return Err(ApplicationError::RevisionConflict);
    }
    match ProtectedMaterialState::parse(&model.state)? {
        ProtectedMaterialState::Pending => {
            let mut active = model.into_active_model();
            active.opaque_value = Set(Some(opaque_value));
            active.safe_fingerprint = Set(safe_fingerprint);
            active.state = Set(ProtectedMaterialState::Live.as_str().to_owned());
            active.updated_at = Set(finalized_at);
            active.update(transaction).await.map_err(persistence)?;
            Ok(())
        }
        ProtectedMaterialState::Live
            if model.safe_fingerprint == safe_fingerprint
                && (safe_fingerprint.is_some()
                    || model.opaque_value.as_deref() == Some(opaque_value.as_slice())) =>
        {
            // Configuration-secret retries may produce a different randomized envelope. The first
            // committed envelope remains authoritative when the independently keyed fingerprint is
            // identical. Signing handles have no fingerprint and therefore require exact bytes.
            Ok(())
        }
        ProtectedMaterialState::Live => Err(ApplicationError::IdempotencyConflict),
        ProtectedMaterialState::Erased
            if safe_fingerprint.is_some() && model.safe_fingerprint == safe_fingerprint =>
        {
            // Erasure removes the live envelope but retains the keyed request fingerprint as
            // bounded tombstone authority for exact historical idempotency replay.
            Ok(())
        }
        ProtectedMaterialState::Erased if safe_fingerprint.is_some() => {
            Err(ApplicationError::IdempotencyConflict)
        }
        ProtectedMaterialState::Erased => Err(ApplicationError::InvalidTransition),
    }
}

fn map_live(
    model: protected_material::Model,
    deployment_id: &DeploymentId,
    purpose: MaterialPurpose,
) -> Result<LiveProtectedMaterial, ApplicationError> {
    let opaque_value = model
        .opaque_value
        .clone()
        .ok_or(ApplicationError::Integrity)?;
    let safe_fingerprint = model.safe_fingerprint.clone();
    let reservation = map_reservation(model, deployment_id, purpose)?;
    if reservation.state != ProtectedMaterialState::Live {
        return Err(ApplicationError::InvalidTransition);
    }
    Ok(LiveProtectedMaterial {
        reservation,
        opaque_value,
        safe_fingerprint,
    })
}

fn map_reservation(
    model: protected_material::Model,
    deployment_id: &DeploymentId,
    purpose: MaterialPurpose,
) -> Result<ProtectedMaterialReservation, ApplicationError> {
    let owner_kind = MaterialOwnerKind::parse(&model.owner_kind)?;
    let material_kind = parse_material_kind(&model.material_kind)?;
    let provider_id =
        ProviderId::new(model.provider_id).map_err(|_| ApplicationError::Integrity)?;
    let provider_format_version = ProviderFormatVersion::new(
        u16::try_from(model.provider_format_version).map_err(|_| ApplicationError::Integrity)?,
    )
    .map_err(|_| ApplicationError::Integrity)?;
    let context_version = ContextVersion::try_from(
        u16::try_from(model.context_version).map_err(|_| ApplicationError::Integrity)?,
    )
    .map_err(|_| ApplicationError::Integrity)?;
    let generation = u64::try_from(model.generation).map_err(|_| ApplicationError::Integrity)?;
    let context = ProtectionContext::new(ProtectionContextParts {
        version: context_version,
        deployment_id: deployment_id.clone(),
        scope: match model.project_id {
            Some(project_id) => Scope::Project(
                ProjectId::new(project_id.to_string()).map_err(|_| ApplicationError::Integrity)?,
            ),
            None => Scope::Deployment,
        },
        material_id: MaterialId::new(model.id.to_string())
            .map_err(|_| ApplicationError::Integrity)?,
        material_kind,
        owner_kind: OwnerKind::new(owner_kind.as_str()).map_err(|_| ApplicationError::Integrity)?,
        owner_id: OwnerId::new(model.owner_id.to_string())
            .map_err(|_| ApplicationError::Integrity)?,
        generation,
        field_purpose: FieldPurpose::new(purpose.as_str())
            .map_err(|_| ApplicationError::Integrity)?,
        provider_id: provider_id.clone(),
        provider_format_version,
    })
    .map_err(|_| ApplicationError::Integrity)?;
    let expected_digest = Sha256::digest(context.canonical_bytes());
    if &expected_digest[..] != model.context_digest.as_slice()
        || (model.scope_kind == "project") != model.project_id.is_some()
    {
        return Err(ApplicationError::Integrity);
    }
    Ok(ProtectedMaterialReservation {
        id: model.id,
        project_id: model.project_id,
        owner_kind,
        owner_id: model.owner_id,
        generation: model.generation,
        material_kind,
        provider_id,
        provider_format_version,
        context,
        authority: CustodyAuthority {
            mode: CustodyMode::parse(&model.custody_mode)?,
            revision: model.custody_revision,
        },
        state: ProtectedMaterialState::parse(&model.state)?,
    })
}

const fn material_kind_name(kind: MaterialKind) -> &'static str {
    match kind {
        MaterialKind::SigningKey => "signing_key",
        MaterialKind::ConfigurationSecret => "configuration_secret",
    }
}

fn parse_material_kind(value: &str) -> Result<MaterialKind, ApplicationError> {
    match value {
        "signing_key" => Ok(MaterialKind::SigningKey),
        "configuration_secret" => Ok(MaterialKind::ConfigurationSecret),
        _ => Err(ApplicationError::Integrity),
    }
}

fn persistence(_: sea_orm::DbErr) -> ApplicationError {
    ApplicationError::Persistence
}
