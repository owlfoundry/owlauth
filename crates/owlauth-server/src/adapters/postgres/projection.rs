use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, DbBackend, EntityTrait, IntoActiveModel,
    QueryFilter, QueryOrder, QuerySelect, Set, Statement,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use async_trait::async_trait;
use std::sync::Arc;

use crate::{
    application::{
        ApplicationError, DurableEmailAddressReader, ProjectionVerifiedEmailProtector,
        ProtectedValue,
    },
    domain::{
        ProfileDisplayName, ProfileLocale, ProfilePictureUrl, ProjectUserStatus,
        ProjectionRevision, PublicId, UserProjection, UserProjectionSource, UserRevision,
    },
};

use super::{
    authentication::persistence,
    entity::{
        application, application_user_binding, application_user_projection, project, project_user,
    },
};

pub(super) const MAX_APPLICATION_BINDINGS_PER_USER: usize = 64;

pub(crate) trait ProjectionCryptography: Send + Sync {
    fn projection_write_version(&self) -> i32;
    fn projection_readable_versions(&self) -> std::collections::BTreeSet<i32>;
    fn read_durable_email(
        &self,
        project_id: uuid::Uuid,
        identity_id: uuid::Uuid,
        value: &ProtectedValue,
    ) -> Result<zeroize::Zeroizing<String>, ApplicationError>;
    fn protect_projection_email(
        &self,
        project_id: uuid::Uuid,
        application_id: uuid::Uuid,
        user_id: uuid::Uuid,
        projection_revision: i64,
        email: &[u8],
    ) -> Result<ProtectedValue, ApplicationError>;
    fn unprotect_projection_email(
        &self,
        project_id: uuid::Uuid,
        application_id: uuid::Uuid,
        user_id: uuid::Uuid,
        projection_revision: i64,
        value: &ProtectedValue,
    ) -> Result<zeroize::Zeroizing<String>, ApplicationError>;
}

struct NarrowProjectionCryptography {
    source_reader: Arc<dyn DurableEmailAddressReader>,
    projection_protector: Arc<dyn ProjectionVerifiedEmailProtector>,
}

impl ProjectionCryptography for NarrowProjectionCryptography {
    fn projection_write_version(&self) -> i32 {
        self.projection_protector.write_version()
    }

    fn projection_readable_versions(&self) -> std::collections::BTreeSet<i32> {
        self.projection_protector.readable_versions()
    }

    fn read_durable_email(
        &self,
        project_id: uuid::Uuid,
        identity_id: uuid::Uuid,
        value: &ProtectedValue,
    ) -> Result<zeroize::Zeroizing<String>, ApplicationError> {
        self.source_reader
            .read_durable_address(project_id, identity_id, value)
    }

    fn protect_projection_email(
        &self,
        project_id: uuid::Uuid,
        application_id: uuid::Uuid,
        user_id: uuid::Uuid,
        projection_revision: i64,
        email: &[u8],
    ) -> Result<ProtectedValue, ApplicationError> {
        self.projection_protector.protect_verified_email(
            project_id,
            application_id,
            user_id,
            projection_revision,
            email,
        )
    }

    fn unprotect_projection_email(
        &self,
        project_id: uuid::Uuid,
        application_id: uuid::Uuid,
        user_id: uuid::Uuid,
        projection_revision: i64,
        value: &ProtectedValue,
    ) -> Result<zeroize::Zeroizing<String>, ApplicationError> {
        self.projection_protector.unprotect_verified_email(
            project_id,
            application_id,
            user_id,
            projection_revision,
            value,
        )
    }
}

#[async_trait]
pub(crate) trait IdentityProjectionMaterializer:
    ProjectionCryptography + Send + Sync
{
    async fn fan_out_user(
        &self,
        transaction: &sea_orm::DatabaseTransaction,
        user: &project_user::Model,
        now: OffsetDateTime,
    ) -> Result<(), ApplicationError>;
}

pub(crate) struct PostgresIdentityProjectionMaterializer {
    cryptography: NarrowProjectionCryptography,
}

impl PostgresIdentityProjectionMaterializer {
    pub(crate) fn new(
        source_reader: Arc<dyn DurableEmailAddressReader>,
        projection_protector: Arc<dyn ProjectionVerifiedEmailProtector>,
    ) -> Self {
        Self {
            cryptography: NarrowProjectionCryptography {
                source_reader,
                projection_protector,
            },
        }
    }
}

impl ProjectionCryptography for PostgresIdentityProjectionMaterializer {
    fn projection_write_version(&self) -> i32 {
        self.cryptography.projection_write_version()
    }

    fn projection_readable_versions(&self) -> std::collections::BTreeSet<i32> {
        self.cryptography.projection_readable_versions()
    }

    fn read_durable_email(
        &self,
        project_id: uuid::Uuid,
        identity_id: uuid::Uuid,
        value: &ProtectedValue,
    ) -> Result<zeroize::Zeroizing<String>, ApplicationError> {
        self.cryptography
            .read_durable_email(project_id, identity_id, value)
    }

    fn protect_projection_email(
        &self,
        project_id: uuid::Uuid,
        application_id: uuid::Uuid,
        user_id: uuid::Uuid,
        projection_revision: i64,
        email: &[u8],
    ) -> Result<ProtectedValue, ApplicationError> {
        self.cryptography.protect_projection_email(
            project_id,
            application_id,
            user_id,
            projection_revision,
            email,
        )
    }

    fn unprotect_projection_email(
        &self,
        project_id: uuid::Uuid,
        application_id: uuid::Uuid,
        user_id: uuid::Uuid,
        projection_revision: i64,
        value: &ProtectedValue,
    ) -> Result<zeroize::Zeroizing<String>, ApplicationError> {
        self.cryptography.unprotect_projection_email(
            project_id,
            application_id,
            user_id,
            projection_revision,
            value,
        )
    }
}

#[async_trait]
impl IdentityProjectionMaterializer for PostgresIdentityProjectionMaterializer {
    async fn fan_out_user(
        &self,
        transaction: &sea_orm::DatabaseTransaction,
        user: &project_user::Model,
        now: OffsetDateTime,
    ) -> Result<(), ApplicationError> {
        assert_projection_write_authority(self.cryptography.projection_protector.as_ref())?;
        fan_out_projected_user(transaction, user, &self.cryptography, now).await
    }
}

pub(super) struct ProjectionMaterial {
    pub(super) revision: i64,
    /// Full Runtime wire document. Never persist this value when it contains verified email.
    pub(super) document: Value,
    pub(super) storage_document: Value,
    pub(super) digest: Vec<u8>,
    pub(super) verified_email_source_identity_id: Option<uuid::Uuid>,
    pub(super) verified_email_ciphertext: Option<Vec<u8>>,
    pub(super) verified_email_key_version: Option<i32>,
    /// A public projection field or its governing policy changed. Storage-only repair must not
    /// advance the public revision or emit an Application event.
    pub(super) semantic_change: bool,
    pub(super) storage_repair_required: bool,
}

pub(super) fn base_profile_digest(
    display_name: Option<&str>,
    picture_url: Option<&str>,
    locale: Option<&str>,
    _verified_email: Option<&str>,
) -> Result<Vec<u8>, ApplicationError> {
    let mut profile = serde_json::Map::new();
    profile.insert("display_name".to_owned(), json!(display_name));
    profile.insert("picture_url".to_owned(), json!(picture_url));
    if locale.is_some() {
        profile.insert("locale".to_owned(), json!(locale));
    }
    let canonical = serde_json::to_vec(&profile).map_err(|_| ApplicationError::Integrity)?;
    Ok(Sha256::digest(canonical).to_vec())
}

#[cfg(test)]
pub(super) fn projection_material(
    user: &project_user::Model,
    projection_revision: i64,
) -> Result<(Value, Vec<u8>), ApplicationError> {
    let (wire_document, digest) =
        projection_material_with_verified_email(user, projection_revision, None)?;
    Ok((safe_projection_document(&wire_document)?, digest))
}

pub(super) fn projection_material_with_verified_email(
    user: &project_user::Model,
    projection_revision: i64,
    verified_email: Option<String>,
) -> Result<(Value, Vec<u8>), ApplicationError> {
    if projection_revision <= 0 {
        return Err(ApplicationError::Integrity);
    }
    let source = UserProjectionSource {
        user_id: PublicId::parse(user.public_id.clone())
            .map_err(|_| ApplicationError::Integrity)?,
        status: match user.status.as_str() {
            "active" => ProjectUserStatus::Active,
            "disabled" => ProjectUserStatus::Disabled,
            _ => return Err(ApplicationError::Integrity),
        },
        display_name: user
            .display_name
            .clone()
            .map(ProfileDisplayName::parse)
            .transpose()
            .map_err(|_| ApplicationError::Integrity)?,
        picture_url: user
            .picture_url
            .clone()
            .map(ProfilePictureUrl::parse)
            .transpose()
            .map_err(|_| ApplicationError::Integrity)?,
        locale: user
            .locale
            .clone()
            .map(ProfileLocale::parse)
            .transpose()
            .map_err(|_| ApplicationError::Integrity)?,
        verified_email,
        created_at: user.created_at,
        updated_at: user.updated_at,
        user_revision: UserRevision::parse(user.user_revision)
            .map_err(|_| ApplicationError::Integrity)?,
    };
    let projection = UserProjection::materialize(
        source,
        ProjectionRevision::parse(projection_revision).map_err(|_| ApplicationError::Integrity)?,
    )
    .map_err(|_| ApplicationError::Integrity)?;
    let document = json!({
        "display_name": projection.display_name,
        "picture_url": projection.picture_url,
        "locale": projection.locale,
        "verified_email": projection.verified_email,
        "projection_revision": projection.projection_revision,
        "projection_schema": projection.schema,
        "status": projection.status.as_str(),
        "user_id": projection.user_id,
        "user_revision": projection.user_revision,
        "created_at": projection.created_at.format(&Rfc3339).map_err(|_| ApplicationError::Integrity)?,
        "updated_at": projection.updated_at.format(&Rfc3339).map_err(|_| ApplicationError::Integrity)?,
    });
    let canonical = serde_json::to_vec(&document).map_err(|_| ApplicationError::Integrity)?;
    Ok((document, Sha256::digest(canonical).to_vec()))
}

pub(super) fn safe_projection_document(wire_document: &Value) -> Result<Value, ApplicationError> {
    let mut document = wire_document.clone();
    let object = document
        .as_object_mut()
        .ok_or(ApplicationError::Integrity)?;
    object.insert("verified_email".to_owned(), Value::Null);
    Ok(document)
}

#[cfg(test)]
pub(super) fn protect_projection_verified_email(
    protector: &dyn ProjectionVerifiedEmailProtector,
    project_id: uuid::Uuid,
    application_id: uuid::Uuid,
    user_id: uuid::Uuid,
    projection_revision: i64,
    email: &str,
) -> Result<ProtectedValue, ApplicationError> {
    protector.protect_verified_email(
        project_id,
        application_id,
        user_id,
        projection_revision,
        email.as_bytes(),
    )
}

fn decrypted_projection_verified_email<P: ProjectionCryptography + ?Sized>(
    projection: &application_user_projection::Model,
    protector: &P,
) -> Result<Option<String>, ApplicationError> {
    match (
        projection.verified_email_source_identity_id,
        projection.verified_email_ciphertext.as_ref(),
        projection.verified_email_key_version,
    ) {
        (None, None, None) => Ok(None),
        (Some(_), Some(ciphertext), Some(key_version)) if key_version > 0 => {
            let protected = ProtectedValue {
                ciphertext: ciphertext.clone(),
                key_version,
            };
            let plaintext = protector.unprotect_projection_email(
                projection.project_id,
                projection.application_id,
                projection.user_id,
                projection.projection_revision,
                &protected,
            )?;
            Ok(Some((*plaintext).clone()))
        }
        _ => Err(ApplicationError::Integrity),
    }
}

pub(super) fn wire_projection_document<P: ProjectionCryptography + ?Sized>(
    projection: &application_user_projection::Model,
    protector: &P,
) -> Result<Value, ApplicationError> {
    let mut document = projection.document.clone();
    let email = decrypted_projection_verified_email(projection, protector)?;
    document
        .as_object_mut()
        .ok_or(ApplicationError::Integrity)?
        .insert("verified_email".to_owned(), json!(email));
    let canonical = serde_json::to_vec(&document).map_err(|_| ApplicationError::Integrity)?;
    let digest = Sha256::digest(canonical);
    if !bool::from(projection.canonical_digest.as_slice().ct_eq(&digest[..])) {
        return Err(ApplicationError::Integrity);
    }
    Ok(document)
}

pub(super) async fn primary_verified_email<P: ProjectionCryptography + ?Sized>(
    transaction: &sea_orm::DatabaseTransaction,
    user: &project_user::Model,
    protector: &P,
) -> Result<Option<(uuid::Uuid, String)>, ApplicationError> {
    match user.status.as_str() {
        // Disabled projections are terminal public views and must never retain or reload PII.
        // Merge deliberately clears the loser's immediate primary-identity references before it
        // publishes this view and moves identity ownership in the same transaction.
        "disabled" => return Ok(None),
        "active" => {}
        _ => return Err(ApplicationError::Integrity),
    }
    if user.primary_source_kind != "email" {
        return Ok(None);
    }
    let Some(identity_id) = user.primary_email_identity_id else {
        return Err(ApplicationError::Integrity);
    };
    let row = transaction
        .query_one_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "SELECT user_id,status,address_ciphertext,address_key_version,verified_at
               FROM email_identities WHERE project_id=$1 AND id=$2 FOR SHARE",
            [user.project_id.into(), identity_id.into()],
        ))
        .await
        .map_err(persistence)?
        .ok_or(ApplicationError::Integrity)?;
    let owner: uuid::Uuid = row.try_get("", "user_id").map_err(persistence)?;
    let status: String = row.try_get("", "status").map_err(persistence)?;
    let verified_at: Option<OffsetDateTime> =
        row.try_get("", "verified_at").map_err(persistence)?;
    if owner != user.id {
        return Err(ApplicationError::Integrity);
    }
    match (status.as_str(), verified_at) {
        ("disabled", Some(_)) => return Ok(None),
        ("active", Some(_)) => {}
        _ => return Err(ApplicationError::Integrity),
    }
    let protected = ProtectedValue {
        ciphertext: row.try_get("", "address_ciphertext").map_err(persistence)?,
        key_version: row
            .try_get("", "address_key_version")
            .map_err(persistence)?,
    };
    let plaintext = protector.read_durable_email(user.project_id, identity_id, &protected)?;
    Ok(Some((identity_id, (*plaintext).clone())))
}

#[allow(
    clippy::too_many_lines,
    reason = "Runtime projection materialization keeps authority version and encryption decisions visible"
)]
pub(super) async fn authoritative_runtime_projection_material<
    P: ProjectionCryptography + ?Sized,
>(
    transaction: &sea_orm::DatabaseTransaction,
    projection: Option<&application_user_projection::Model>,
    application_id: uuid::Uuid,
    user: &project_user::Model,
    protector: &P,
) -> Result<ProjectionMaterial, ApplicationError> {
    let source_email = primary_verified_email(transaction, user, protector).await?;
    let projection_write_version = if source_email.is_some()
        || projection.is_some_and(|existing| existing.verified_email_ciphertext.is_some())
    {
        Some(projection_authority_write_version(protector)?)
    } else {
        None
    };
    let source_identity_id = source_email.as_ref().map(|(identity_id, _)| *identity_id);
    let semantic_change = projection.is_none_or(|existing| {
        existing.user_id != user.id
            || existing.source_user_revision != user.user_revision
            || existing.verified_email_source_identity_id != source_identity_id
            || existing.verified_email_ciphertext.is_some() != source_email.is_some()
            || existing.verified_email_key_version.is_some() != source_email.is_some()
    });
    let revision = match projection {
        None => 1,
        Some(existing) if semantic_change => existing
            .projection_revision
            .checked_add(1)
            .ok_or(ApplicationError::Integrity)?,
        Some(existing) => existing.projection_revision,
    };
    let can_reuse_protected = projection.is_some_and(|existing| {
        !semantic_change
            && existing.verified_email_source_identity_id == source_identity_id
            && existing.verified_email_ciphertext.is_some() == source_email.is_some()
            && existing.verified_email_key_version.is_some() == source_email.is_some()
            && existing.verified_email_key_version == projection_write_version
    });

    let (ciphertext, key_version) = match source_email.as_ref() {
        None => (None, None),
        Some((_, _)) if can_reuse_protected => {
            let existing = projection.ok_or(ApplicationError::Integrity)?;
            (
                existing.verified_email_ciphertext.clone(),
                existing.verified_email_key_version,
            )
        }
        Some((_, email)) => {
            let protected = protector.protect_projection_email(
                user.project_id,
                application_id,
                user.id,
                revision,
                email.as_bytes(),
            )?;
            (Some(protected.ciphertext), Some(protected.key_version))
        }
    };
    let email = source_email.map(|(_, email)| email);
    let (document, digest) =
        projection_material_with_verified_email(user, revision, email.clone())?;
    if can_reuse_protected {
        let existing = projection.ok_or(ApplicationError::Integrity)?;
        if decrypted_projection_verified_email(existing, protector)? != email {
            return Err(ApplicationError::Integrity);
        }
    }
    let storage_document = safe_projection_document(&document)?;
    let storage_repair_required = projection.is_none_or(|existing| {
        semantic_change
            || existing.document != storage_document
            || existing.verified_email_source_identity_id != source_identity_id
            || existing.verified_email_ciphertext != ciphertext
            || existing.verified_email_key_version != key_version
            || !bool::from(
                existing
                    .canonical_digest
                    .as_slice()
                    .ct_eq(digest.as_slice()),
            )
            || !bool::from(
                existing
                    .source_base_profile_digest
                    .as_slice()
                    .ct_eq(user.base_profile_digest.as_slice()),
            )
    });
    Ok(ProjectionMaterial {
        revision,
        document,
        storage_document,
        digest,
        verified_email_source_identity_id: source_identity_id,
        verified_email_ciphertext: ciphertext,
        verified_email_key_version: key_version,
        semantic_change,
        storage_repair_required,
    })
}

pub(super) async fn repair_runtime_projection<P: ProjectionCryptography + ?Sized>(
    transaction: &sea_orm::DatabaseTransaction,
    projection: application_user_projection::Model,
    application_id: uuid::Uuid,
    user: &project_user::Model,
    protector: &P,
    now: OffsetDateTime,
) -> Result<(application_user_projection::Model, ProjectionMaterial), ApplicationError> {
    let material = authoritative_runtime_projection_material(
        transaction,
        Some(&projection),
        application_id,
        user,
        protector,
    )
    .await?;
    let projection = if material.storage_repair_required {
        let mut active = projection.into_active_model();
        active.user_id = Set(user.id);
        active.projection_revision = Set(material.revision);
        active.source_user_revision = Set(user.user_revision);
        active.canonical_digest = Set(material.digest.clone());
        active.source_base_profile_digest = Set(user.base_profile_digest.clone());
        active.verified_email_source_identity_id = Set(material.verified_email_source_identity_id);
        active.verified_email_ciphertext = Set(material.verified_email_ciphertext.clone());
        active.verified_email_key_version = Set(material.verified_email_key_version);
        active.document = Set(material.storage_document.clone());
        active.updated_at = Set(now);
        active.update(transaction).await.map_err(persistence)?
    } else {
        projection
    };
    Ok((projection, material))
}

/// Runtime-only eager materializer used by identity lifecycle transitions. Unlike Control's
/// PII-blind fan-out, it derives verified email from the exact primary identity and persists only
/// purpose-bound ciphertext plus a wire digest; the JSON document always remains ring-safe.
async fn fan_out_projected_user<P: ProjectionCryptography + ?Sized>(
    transaction: &sea_orm::DatabaseTransaction,
    user: &project_user::Model,
    protector: &P,
    now: OffsetDateTime,
) -> Result<(), ApplicationError> {
    let project = project::Entity::find_by_id(user.project_id)
        .lock_shared()
        .one(transaction)
        .await
        .map_err(persistence)?
        .ok_or(ApplicationError::Integrity)?;
    if project.status != "active" {
        return Ok(());
    }
    let bindings = application_user_binding::Entity::find()
        .filter(application_user_binding::Column::ProjectId.eq(user.project_id))
        .filter(application_user_binding::Column::UserId.eq(user.id))
        .filter(application_user_binding::Column::Status.eq("active"))
        .order_by_asc(application_user_binding::Column::ApplicationId)
        .limit((MAX_APPLICATION_BINDINGS_PER_USER + 1) as u64)
        .lock_exclusive()
        .all(transaction)
        .await
        .map_err(persistence)?;
    if bindings.len() > MAX_APPLICATION_BINDINGS_PER_USER {
        return Err(ApplicationError::Integrity);
    }
    for binding in bindings {
        let application = application::Entity::find_by_id(binding.application_id)
            .filter(application::Column::ProjectId.eq(user.project_id))
            .lock_shared()
            .one(transaction)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::Integrity)?;
        if application.status != "active" {
            continue;
        }
        let projection = application_user_projection::Entity::find()
            .filter(application_user_projection::Column::ProjectId.eq(user.project_id))
            .filter(application_user_projection::Column::BindingId.eq(binding.id))
            .lock_exclusive()
            .one(transaction)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::Integrity)?;
        let binding_id = projection.binding_id;
        let (projection, material) = repair_runtime_projection(
            transaction,
            projection,
            application.id,
            user,
            protector,
            now,
        )
        .await?;
        if material.semantic_change {
            let event_type = if user.status == "disabled" {
                crate::domain::ApplicationUserEventType::Disabled
            } else {
                crate::domain::ApplicationUserEventType::Updated
            };
            super::webhook::append_projection_event(
                transaction,
                &project.public_id,
                &application.public_id,
                binding_id,
                &projection,
                &material.document,
                event_type,
            )
            .await?;
        }
    }
    Ok(())
}

pub(super) fn assert_projection_write_authority(
    protector: &dyn ProjectionVerifiedEmailProtector,
) -> Result<(), ApplicationError> {
    validate_local_projection_ring(protector.write_version(), &protector.readable_versions())
        .map(|_| ())
}

pub(super) fn assert_projection_crypto_authority<P: ProjectionCryptography + ?Sized>(
    protector: &P,
) -> Result<(), ApplicationError> {
    projection_authority_write_version(protector).map(|_| ())
}

fn projection_authority_write_version<P: ProjectionCryptography + ?Sized>(
    protector: &P,
) -> Result<i32, ApplicationError> {
    validate_local_projection_ring(
        protector.projection_write_version(),
        &protector.projection_readable_versions(),
    )
}

fn validate_local_projection_ring(
    write_version: i32,
    readable: &std::collections::BTreeSet<i32>,
) -> Result<i32, ApplicationError> {
    if write_version <= 0 || !readable.contains(&write_version) {
        return Err(ApplicationError::Disabled);
    }
    Ok(write_version)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use uuid::Uuid;

    use crate::{
        adapters::runtime_security::SoftwareProjectionVerifiedEmailProtector,
        application::{ApplicationError, ProjectionVerifiedEmailProtector},
    };

    #[test]
    fn verified_email_ciphertext_is_bound_to_the_exact_projection_context() {
        let protector = SoftwareProjectionVerifiedEmailProtector::new(
            "projection-context-test".to_owned(),
            1,
            [42; 32],
            BTreeMap::new(),
        )
        .expect("projection protector");
        let project_id = Uuid::new_v4();
        let application_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();
        let protected = protector
            .protect_verified_email(project_id, application_id, user_id, 7, b"ada@example.test")
            .expect("protect verified email");
        assert_eq!(
            protector
                .unprotect_verified_email(project_id, application_id, user_id, 7, &protected,)
                .expect("exact context decrypts")
                .as_str(),
            "ada@example.test"
        );

        let substitutions = [
            (Uuid::new_v4(), application_id, user_id, 7),
            (project_id, Uuid::new_v4(), user_id, 7),
            (project_id, application_id, Uuid::new_v4(), 7),
            (project_id, application_id, user_id, 8),
        ];
        for (
            substituted_project,
            substituted_application,
            substituted_user,
            substituted_revision,
        ) in substitutions
        {
            assert_eq!(
                protector.unprotect_verified_email(
                    substituted_project,
                    substituted_application,
                    substituted_user,
                    substituted_revision,
                    &protected,
                ),
                Err(ApplicationError::Integrity)
            );
        }
    }
}
