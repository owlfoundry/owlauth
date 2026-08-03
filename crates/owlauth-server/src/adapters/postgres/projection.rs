use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, DbBackend, EntityTrait, IntoActiveModel,
    QueryFilter, QueryOrder, QuerySelect, Set, Statement, TransactionTrait,
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
        ProtectedPurpose, ProtectedValue, RuntimeProtector,
    },
    domain::{
        ProfileDisplayName, ProfileLocale, ProfilePictureUrl, ProjectUserStatus,
        ProjectionRevision, PublicId, UserProjection, UserProjectionSource, UserRevision,
    },
};

use super::{
    authentication::persistence,
    entity::{
        application, application_user_binding, application_user_projection, project_policy,
        project_user,
    },
};

pub(super) const MAX_APPLICATION_BINDINGS_PER_USER: usize = 64;

pub(super) trait ProjectionCryptography: Send + Sync {
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

impl<T: RuntimeProtector + ?Sized> ProjectionCryptography for T {
    fn projection_write_version(&self) -> i32 {
        self.projection_email_write_version()
    }

    fn projection_readable_versions(&self) -> std::collections::BTreeSet<i32> {
        self.projection_email_readable_versions()
    }

    fn read_durable_email(
        &self,
        project_id: uuid::Uuid,
        identity_id: uuid::Uuid,
        value: &ProtectedValue,
    ) -> Result<zeroize::Zeroizing<String>, ApplicationError> {
        let plaintext = self.unprotect(
            ProtectedPurpose::EmailIdentityAddress,
            &email_identity_context(project_id, identity_id),
            value,
        )?;
        let text =
            std::str::from_utf8(plaintext.as_slice()).map_err(|_| ApplicationError::Integrity)?;
        let canonical = crate::domain::CanonicalEmail::parse_v1(text)
            .map_err(|_| ApplicationError::Integrity)?;
        Ok(zeroize::Zeroizing::new(canonical.expose().to_owned()))
    }

    fn protect_projection_email(
        &self,
        project_id: uuid::Uuid,
        application_id: uuid::Uuid,
        user_id: uuid::Uuid,
        projection_revision: i64,
        email: &[u8],
    ) -> Result<ProtectedValue, ApplicationError> {
        self.protect(
            ProtectedPurpose::ApplicationProjectionVerifiedEmail,
            &projection_verified_email_context(
                project_id,
                application_id,
                user_id,
                projection_revision,
            )?,
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
        self.unprotect(
            ProtectedPurpose::ApplicationProjectionVerifiedEmail,
            &projection_verified_email_context(
                project_id,
                application_id,
                user_id,
                projection_revision,
            )?,
            value,
        )
        .and_then(|plaintext| {
            let text = std::str::from_utf8(plaintext.as_slice())
                .map_err(|_| ApplicationError::Integrity)?;
            let canonical = crate::domain::CanonicalEmail::parse_v1(text)
                .map_err(|_| ApplicationError::Integrity)?;
            Ok(zeroize::Zeroizing::new(canonical.expose().to_owned()))
        })
    }
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
pub(crate) trait IdentityProjectionMaterializer: Send + Sync {
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

#[cfg(test)]
pub(crate) struct LegacyRuntimeProjectionMaterializer {
    protector: Arc<dyn RuntimeProtector>,
}

#[cfg(test)]
impl LegacyRuntimeProjectionMaterializer {
    pub(crate) fn new(protector: Arc<dyn RuntimeProtector>) -> Self {
        Self { protector }
    }
}

#[cfg(test)]
#[async_trait]
impl IdentityProjectionMaterializer for LegacyRuntimeProjectionMaterializer {
    async fn fan_out_user(
        &self,
        transaction: &sea_orm::DatabaseTransaction,
        user: &project_user::Model,
        now: OffsetDateTime,
    ) -> Result<(), ApplicationError> {
        fan_out_projected_user(transaction, user, self.protector.as_ref(), now).await
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
        assert_projection_write_authority(
            transaction,
            self.cryptography.projection_protector.as_ref(),
        )
        .await?;
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

pub(super) fn projection_material(
    user: &project_user::Model,
    projection_revision: i64,
    project_projection_revision: i64,
    application_projection_revision: i64,
) -> Result<(Value, Vec<u8>), ApplicationError> {
    let (wire_document, digest) = projection_material_with_verified_email(
        user,
        projection_revision,
        project_projection_revision,
        application_projection_revision,
        None,
    )?;
    Ok((safe_projection_document(&wire_document)?, digest))
}

pub(super) fn projection_material_with_verified_email(
    user: &project_user::Model,
    projection_revision: i64,
    project_projection_revision: i64,
    application_projection_revision: i64,
    verified_email: Option<String>,
) -> Result<(Value, Vec<u8>), ApplicationError> {
    if projection_revision <= 0
        || project_projection_revision <= 0
        || application_projection_revision <= 0
    {
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

pub(super) fn projection_verified_email_context(
    project_id: uuid::Uuid,
    application_id: uuid::Uuid,
    user_id: uuid::Uuid,
    projection_revision: i64,
) -> Result<Vec<u8>, ApplicationError> {
    if projection_revision <= 0 {
        return Err(ApplicationError::Integrity);
    }
    let mut context = Vec::with_capacity(80);
    context.extend_from_slice(b"owlauth-application-projection-email-v1\0");
    context.extend_from_slice(project_id.as_bytes());
    context.extend_from_slice(application_id.as_bytes());
    context.extend_from_slice(user_id.as_bytes());
    context.extend_from_slice(&projection_revision.to_be_bytes());
    context.extend_from_slice(crate::domain::USER_PROJECTION_SCHEMA_V1.as_bytes());
    Ok(context)
}

#[cfg(test)]
pub(super) fn protect_projection_verified_email(
    protector: &dyn RuntimeProtector,
    project_id: uuid::Uuid,
    application_id: uuid::Uuid,
    user_id: uuid::Uuid,
    projection_revision: i64,
    email: &str,
) -> Result<ProtectedValue, ApplicationError> {
    protector.protect(
        ProtectedPurpose::ApplicationProjectionVerifiedEmail,
        &projection_verified_email_context(
            project_id,
            application_id,
            user_id,
            projection_revision,
        )?,
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

fn email_identity_context(project_id: uuid::Uuid, identity_id: uuid::Uuid) -> Vec<u8> {
    let mut context = Vec::with_capacity(58);
    context.extend_from_slice(b"owlauth-email-identity-v1\0");
    context.extend_from_slice(project_id.as_bytes());
    context.extend_from_slice(identity_id.as_bytes());
    context
}

pub(super) fn authoritative_projection_material(
    projection: Option<&application_user_projection::Model>,
    user: &project_user::Model,
    project_projection_revision: i64,
    application_projection_revision: i64,
) -> Result<ProjectionMaterial, ApplicationError> {
    let Some(existing) = projection else {
        let (document, digest) = projection_material(
            user,
            1,
            project_projection_revision,
            application_projection_revision,
        )?;
        return Ok(ProjectionMaterial {
            revision: 1,
            storage_document: document.clone(),
            document,
            digest,
            verified_email_source_identity_id: None,
            verified_email_ciphertext: None,
            verified_email_key_version: None,
            storage_repair_required: true,
        });
    };

    let semantic_change = existing.source_user_revision != user.user_revision
        || existing.project_policy_revision != project_projection_revision
        || existing.application_policy_revision != application_projection_revision;
    let revision = if semantic_change {
        existing
            .projection_revision
            .checked_add(1)
            .ok_or(ApplicationError::Integrity)?
    } else {
        existing.projection_revision
    };
    let (document, digest) = projection_material(
        user,
        revision,
        project_projection_revision,
        application_projection_revision,
    )?;
    let storage_repair_required = semantic_change
        || existing.document != document
        || !bool::from(existing.canonical_digest.as_slice().ct_eq(&digest[..]))
        || existing
            .source_base_profile_digest
            .as_deref()
            .is_none_or(|digest| !bool::from(digest.ct_eq(user.base_profile_digest.as_slice())));
    Ok(ProjectionMaterial {
        revision,
        storage_document: document.clone(),
        document,
        digest,
        verified_email_source_identity_id: None,
        verified_email_ciphertext: None,
        verified_email_key_version: None,
        storage_repair_required,
    })
}

#[allow(
    clippy::too_many_arguments,
    reason = "Runtime projection materialization keeps exact policy and encryption authority visible"
)]
pub(super) async fn authoritative_runtime_projection_material<
    P: ProjectionCryptography + ?Sized,
>(
    transaction: &sea_orm::DatabaseTransaction,
    projection: Option<&application_user_projection::Model>,
    application_id: uuid::Uuid,
    user: &project_user::Model,
    project_projection_revision: i64,
    application_projection_revision: i64,
    project_email_admitted: bool,
    application_email_admitted: bool,
    protector: &P,
) -> Result<ProjectionMaterial, ApplicationError> {
    let admitted = project_email_admitted && application_email_admitted;
    let source_email = if admitted {
        primary_verified_email(transaction, user, protector).await?
    } else {
        None
    };
    if source_email.is_some()
        || projection.is_some_and(|existing| existing.verified_email_ciphertext.is_some())
    {
        assert_projection_crypto_authority(transaction, protector).await?;
    }
    let source_identity_id = source_email.as_ref().map(|(identity_id, _)| *identity_id);
    let semantic_change = projection.is_none_or(|existing| {
        existing.source_user_revision != user.user_revision
            || existing.project_policy_revision != project_projection_revision
            || existing.application_policy_revision != application_projection_revision
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
    let (document, digest) = projection_material_with_verified_email(
        user,
        revision,
        project_projection_revision,
        application_projection_revision,
        email.clone(),
    )?;
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
            || existing
                .source_base_profile_digest
                .as_deref()
                .is_none_or(|stored| !bool::from(stored.ct_eq(user.base_profile_digest.as_slice())))
    });
    Ok(ProjectionMaterial {
        revision,
        document,
        storage_document,
        digest,
        verified_email_source_identity_id: source_identity_id,
        verified_email_ciphertext: ciphertext,
        verified_email_key_version: key_version,
        storage_repair_required,
    })
}

#[allow(
    clippy::too_many_arguments,
    reason = "Runtime projection repair keeps exact policy and encryption authority visible"
)]
pub(super) async fn repair_runtime_projection<P: ProjectionCryptography + ?Sized>(
    transaction: &sea_orm::DatabaseTransaction,
    projection: application_user_projection::Model,
    application_id: uuid::Uuid,
    user: &project_user::Model,
    project_projection_revision: i64,
    application_projection_revision: i64,
    project_email_admitted: bool,
    application_email_admitted: bool,
    protector: &P,
    now: OffsetDateTime,
) -> Result<(application_user_projection::Model, ProjectionMaterial), ApplicationError> {
    let material = authoritative_runtime_projection_material(
        transaction,
        Some(&projection),
        application_id,
        user,
        project_projection_revision,
        application_projection_revision,
        project_email_admitted,
        application_email_admitted,
        protector,
    )
    .await?;
    let projection = if material.storage_repair_required {
        let mut active = projection.into_active_model();
        active.projection_revision = Set(material.revision);
        active.source_user_revision = Set(user.user_revision);
        active.project_policy_revision = Set(project_projection_revision);
        active.application_policy_revision = Set(application_projection_revision);
        active.canonical_digest = Set(material.digest.clone());
        active.source_base_profile_digest = Set(Some(user.base_profile_digest.clone()));
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

pub(super) async fn repair_projection(
    transaction: &sea_orm::DatabaseTransaction,
    projection: application_user_projection::Model,
    user: &project_user::Model,
    project_projection_revision: i64,
    application_projection_revision: i64,
    now: OffsetDateTime,
) -> Result<(application_user_projection::Model, ProjectionMaterial), ApplicationError> {
    if projection.verified_email_source_identity_id.is_some()
        || projection.verified_email_ciphertext.is_some()
        || projection.verified_email_key_version.is_some()
    {
        return Err(ApplicationError::Integrity);
    }
    let material = authoritative_projection_material(
        Some(&projection),
        user,
        project_projection_revision,
        application_projection_revision,
    )?;
    let projection = if material.storage_repair_required {
        let mut active = projection.into_active_model();
        active.projection_revision = Set(material.revision);
        active.source_user_revision = Set(user.user_revision);
        active.project_policy_revision = Set(project_projection_revision);
        active.application_policy_revision = Set(application_projection_revision);
        active.canonical_digest = Set(material.digest.clone());
        active.source_base_profile_digest = Set(Some(user.base_profile_digest.clone()));
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
    let policy = project_policy::Entity::find_by_id(user.project_id)
        .lock_shared()
        .one(transaction)
        .await
        .map_err(persistence)?
        .ok_or(ApplicationError::Integrity)?;
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
            .one(transaction)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::Integrity)?;
        let projection = application_user_projection::Entity::find()
            .filter(application_user_projection::Column::ProjectId.eq(user.project_id))
            .filter(application_user_projection::Column::BindingId.eq(binding.id))
            .lock_exclusive()
            .one(transaction)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::Integrity)?;
        repair_runtime_projection(
            transaction,
            projection,
            application.id,
            user,
            policy.projection_revision,
            application.projection_revision,
            policy.projection_verified_email_enabled,
            application.projection_verified_email_enabled,
            protector,
            now,
        )
        .await?;
    }
    Ok(())
}

pub(super) async fn assert_projection_write_authority(
    transaction: &sea_orm::DatabaseTransaction,
    protector: &dyn ProjectionVerifiedEmailProtector,
) -> Result<(), ApplicationError> {
    assert_projection_versions(
        transaction,
        protector.write_version(),
        &protector.readable_versions(),
    )
    .await
}

pub(super) async fn assert_projection_crypto_authority<P: ProjectionCryptography + ?Sized>(
    transaction: &sea_orm::DatabaseTransaction,
    protector: &P,
) -> Result<(), ApplicationError> {
    assert_projection_versions(
        transaction,
        protector.projection_write_version(),
        &protector.projection_readable_versions(),
    )
    .await
}

async fn assert_projection_versions(
    transaction: &sea_orm::DatabaseTransaction,
    local_write_version: i32,
    readable: &std::collections::BTreeSet<i32>,
) -> Result<(), ApplicationError> {
    let row = transaction
        .query_one_raw(Statement::from_string(
            DbBackend::Postgres,
            "SELECT write_version,accepted_versions FROM projection_email_key_authority \
             WHERE singleton=TRUE FOR SHARE"
                .to_owned(),
        ))
        .await
        .map_err(persistence)?
        .ok_or(ApplicationError::Integrity)?;
    let write_version: i32 = row.try_get("", "write_version").map_err(persistence)?;
    let accepted: Vec<i32> = row.try_get("", "accepted_versions").map_err(persistence)?;
    if write_version != local_write_version
        || !accepted.contains(&write_version)
        || !accepted.iter().all(|version| readable.contains(version))
    {
        return Err(ApplicationError::Disabled);
    }
    Ok(())
}

const MAX_PROJECTION_AUTHORITY_DURATION_MILLIS: i64 = 86_400_000;

fn bounded_projection_authority_duration(
    duration: time::Duration,
) -> Result<i64, ApplicationError> {
    let milliseconds = duration.whole_milliseconds();
    if !(1..=i128::from(MAX_PROJECTION_AUTHORITY_DURATION_MILLIS)).contains(&milliseconds) {
        return Err(ApplicationError::InvalidInput);
    }
    let milliseconds = i64::try_from(milliseconds).map_err(|_| ApplicationError::InvalidInput)?;
    if duration != time::Duration::milliseconds(milliseconds) {
        return Err(ApplicationError::InvalidInput);
    }
    Ok(milliseconds)
}

#[derive(Clone)]
pub(crate) struct PostgresProjectionEmailKeyAuthority {
    database: sea_orm::DatabaseConnection,
}

impl PostgresProjectionEmailKeyAuthority {
    pub(crate) fn new(database: sea_orm::DatabaseConnection) -> Self {
        Self { database }
    }

    pub(crate) async fn observe_runtime(
        &self,
        process_id: &str,
        process_incarnation: uuid::Uuid,
        protector: &dyn ProjectionVerifiedEmailProtector,
        lease_duration: time::Duration,
    ) -> Result<(), ApplicationError> {
        if process_id.is_empty() {
            return Err(ApplicationError::InvalidInput);
        }
        let lease_milliseconds = bounded_projection_authority_duration(lease_duration)?;
        let transaction = self.database.begin().await.map_err(persistence)?;
        let incarnation = transaction
            .query_one_raw(Statement::from_sql_and_values(
                DbBackend::Postgres,
                "SELECT process_incarnation FROM runtime_process_incarnations \
                 WHERE process_id=$1 FOR SHARE",
                [process_id.into()],
            ))
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::Disabled)?;
        let current: uuid::Uuid = incarnation
            .try_get("", "process_incarnation")
            .map_err(persistence)?;
        if current != process_incarnation {
            return Err(ApplicationError::Disabled);
        }
        let authority = transaction
            .query_one_raw(Statement::from_string(
                DbBackend::Postgres,
                "SELECT authority_revision FROM projection_email_key_authority \
                 WHERE singleton=TRUE FOR SHARE"
                    .to_owned(),
            ))
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::Integrity)?;
        let revision: i64 = authority
            .try_get("", "authority_revision")
            .map_err(persistence)?;
        let readable = protector
            .readable_versions()
            .into_iter()
            .collect::<Vec<_>>();
        transaction
            .execute_raw(Statement::from_sql_and_values(
                DbBackend::Postgres,
                "WITH db_clock AS (SELECT clock_timestamp() AS observed_at) \
                 INSERT INTO projection_email_runtime_observations \
                 (process_id,process_incarnation,authority_revision,readable_versions,observed_at,lease_expires_at) \
                 SELECT $1,$2,$3,$4,db_clock.observed_at, \
                        db_clock.observed_at + $5 * INTERVAL '1 millisecond' FROM db_clock \
                 ON CONFLICT (process_id,process_incarnation) DO UPDATE SET \
                 authority_revision=EXCLUDED.authority_revision, \
                 readable_versions=EXCLUDED.readable_versions,observed_at=EXCLUDED.observed_at, \
                 lease_expires_at=EXCLUDED.lease_expires_at",
                [
                    process_id.into(),
                    process_incarnation.into(),
                    revision.into(),
                    readable.into(),
                    lease_milliseconds.into(),
                ],
            ))
            .await
            .map_err(persistence)?;
        transaction.commit().await.map_err(persistence)
    }

    #[allow(
        clippy::too_many_arguments,
        clippy::too_many_lines,
        reason = "one revision-CAS lifecycle keeps staging, observation, cutover, reference, and retirement authority explicit"
    )]
    pub(crate) async fn reconcile(
        &self,
        required_process_ids: &[String],
        protector: &dyn ProjectionVerifiedEmailProtector,
        requested_cutover: Option<i32>,
        requested_retirement: Option<i32>,
        retirement_retention: time::Duration,
    ) -> Result<(), ApplicationError> {
        if required_process_ids.is_empty()
            || requested_cutover.is_some() && requested_retirement.is_some()
        {
            return Err(ApplicationError::InvalidInput);
        }
        let retention_milliseconds = bounded_projection_authority_duration(retirement_retention)?;
        let transaction = self.database.begin().await.map_err(persistence)?;
        let row = transaction
            .query_one_raw(Statement::from_sql_and_values(
                DbBackend::Postgres,
                "SELECT authority_revision,write_version,accepted_versions,target_version, \
                 target_staged_at,retirement_version,retirement_authorized_at, \
                 retirement_authorized_at IS NOT NULL AND clock_timestamp() >= \
                   retirement_authorized_at + $1 * INTERVAL '1 millisecond' AS retirement_elapsed \
                 FROM projection_email_key_authority WHERE singleton=TRUE FOR UPDATE",
                [retention_milliseconds.into()],
            ))
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::Integrity)?;
        let revision: i64 = row.try_get("", "authority_revision").map_err(persistence)?;
        let write_version: i32 = row.try_get("", "write_version").map_err(persistence)?;
        let mut accepted: Vec<i32> = row.try_get("", "accepted_versions").map_err(persistence)?;
        let target: Option<i32> = row.try_get("", "target_version").map_err(persistence)?;
        let retirement: Option<i32> = row.try_get("", "retirement_version").map_err(persistence)?;
        let retirement_elapsed: bool =
            row.try_get("", "retirement_elapsed").map_err(persistence)?;
        let local_write = protector.write_version();
        let readable = protector.readable_versions();
        if !readable.contains(&local_write) || accepted.iter().any(|v| !readable.contains(v)) {
            return Err(ApplicationError::Disabled);
        }

        if local_write != write_version && target.is_none() {
            if requested_cutover != Some(local_write) {
                return Err(ApplicationError::Disabled);
            }
            accepted.push(local_write);
            accepted.sort_unstable();
            accepted.dedup();
            transaction
                .execute_raw(Statement::from_sql_and_values(
                    DbBackend::Postgres,
                    "UPDATE projection_email_key_authority SET authority_revision=authority_revision+1, \
                     accepted_versions=$1,target_version=$2,target_staged_at=db_clock.now, \
                     updated_at=db_clock.now FROM (SELECT clock_timestamp() AS now) db_clock \
                     WHERE singleton=TRUE AND authority_revision=$3",
                    [accepted.into(), local_write.into(), revision.into()],
                ))
                .await
                .map_err(persistence)?;
            transaction.commit().await.map_err(persistence)?;
            return Err(ApplicationError::Disabled);
        }

        if target == Some(local_write) && requested_cutover == Some(local_write) {
            assert_required_projection_observations(
                &transaction,
                required_process_ids,
                revision,
                local_write,
            )
            .await?;
            transaction
                .execute_raw(Statement::from_sql_and_values(
                    DbBackend::Postgres,
                    "UPDATE projection_email_key_authority SET authority_revision=authority_revision+1, \
                     write_version=$1,target_version=NULL,target_staged_at=NULL, \
                     updated_at=db_clock.now FROM (SELECT clock_timestamp() AS now) db_clock \
                     WHERE singleton=TRUE AND authority_revision=$2",
                    [local_write.into(), revision.into()],
                ))
                .await
                .map_err(persistence)?;
            transaction.commit().await.map_err(persistence)?;
            return Ok(());
        }

        if let Some(version) = requested_retirement {
            if version == write_version || !accepted.contains(&version) {
                return Err(ApplicationError::InvalidInput);
            }
            let observation_revision = if retirement == Some(version) {
                revision.checked_sub(1).ok_or(ApplicationError::Integrity)?
            } else {
                revision
            };
            assert_required_projection_observations(
                &transaction,
                required_process_ids,
                observation_revision,
                write_version,
            )
            .await?;
            let references: i64 = transaction
                .query_one_raw(Statement::from_sql_and_values(
                    DbBackend::Postgres,
                    "SELECT count(*)::BIGINT AS count FROM application_user_projections \
                     WHERE verified_email_key_version=$1",
                    [version.into()],
                ))
                .await
                .map_err(persistence)?
                .ok_or(ApplicationError::Integrity)?
                .try_get("", "count")
                .map_err(persistence)?;
            if references != 0 {
                return Err(ApplicationError::Disabled);
            }
            if retirement != Some(version) {
                transaction
                    .execute_raw(Statement::from_sql_and_values(
                        DbBackend::Postgres,
                        "UPDATE projection_email_key_authority SET authority_revision=authority_revision+1, \
                         retirement_version=$1,retirement_authorized_at=db_clock.now, \
                         updated_at=db_clock.now FROM (SELECT clock_timestamp() AS now) db_clock \
                         WHERE singleton=TRUE AND authority_revision=$2",
                        [version.into(), revision.into()],
                    ))
                    .await
                    .map_err(persistence)?;
                transaction.commit().await.map_err(persistence)?;
                return Err(ApplicationError::Disabled);
            }
            if !retirement_elapsed {
                return Err(ApplicationError::Disabled);
            }
            accepted.retain(|accepted_version| *accepted_version != version);
            transaction
                .execute_raw(Statement::from_sql_and_values(
                    DbBackend::Postgres,
                    "UPDATE projection_email_key_authority SET authority_revision=authority_revision+1, \
                     accepted_versions=$1,retirement_version=NULL,retirement_authorized_at=NULL, \
                     updated_at=db_clock.now FROM (SELECT clock_timestamp() AS now) db_clock \
                     WHERE singleton=TRUE AND authority_revision=$2",
                    [accepted.into(), revision.into()],
                ))
                .await
                .map_err(persistence)?;
        }
        transaction.commit().await.map_err(persistence)
    }
}

async fn assert_required_projection_observations(
    transaction: &sea_orm::DatabaseTransaction,
    required_process_ids: &[String],
    authority_revision: i64,
    required_version: i32,
) -> Result<(), ApplicationError> {
    for process_id in required_process_ids {
        let row = transaction
            .query_one_raw(Statement::from_sql_and_values(
                DbBackend::Postgres,
                "SELECT observation.authority_revision,observation.readable_versions, \
                 observation.lease_expires_at > clock_timestamp() AS lease_is_live \
                 FROM runtime_process_incarnations incarnation \
                 JOIN projection_email_runtime_observations observation \
                   ON observation.process_id=incarnation.process_id \
                  AND observation.process_incarnation=incarnation.process_incarnation \
                 WHERE incarnation.process_id=$1 FOR SHARE OF incarnation,observation",
                [process_id.clone().into()],
            ))
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::Disabled)?;
        let observed_revision: i64 = row.try_get("", "authority_revision").map_err(persistence)?;
        let versions: Vec<i32> = row.try_get("", "readable_versions").map_err(persistence)?;
        let lease_is_live: bool = row.try_get("", "lease_is_live").map_err(persistence)?;
        if observed_revision < authority_revision
            || !versions.contains(&required_version)
            || !lease_is_live
        {
            return Err(ApplicationError::Disabled);
        }
    }
    Ok(())
}

pub(super) async fn fan_out_user_projections(
    transaction: &sea_orm::DatabaseTransaction,
    user: &project_user::Model,
    now: OffsetDateTime,
) -> Result<(), ApplicationError> {
    let policy = project_policy::Entity::find_by_id(user.project_id)
        .lock_shared()
        .one(transaction)
        .await
        .map_err(persistence)?
        .ok_or(ApplicationError::Integrity)?;
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
        // The caller already holds the Project user exclusively, which serializes binding
        // creation and user mutations. Do not lock the Application after binding rows: Runtime
        // reads lock Application before user/binding, and the inverse order could deadlock.
        // A concurrent projection-policy revision is repaired lazily on the next Runtime read.
        let application = application::Entity::find_by_id(binding.application_id)
            .filter(application::Column::ProjectId.eq(user.project_id))
            .one(transaction)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::Integrity)?;
        let projection = application_user_projection::Entity::find()
            .filter(application_user_projection::Column::ProjectId.eq(user.project_id))
            .filter(application_user_projection::Column::BindingId.eq(binding.id))
            .lock_exclusive()
            .one(transaction)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::Integrity)?;
        repair_projection(
            transaction,
            projection,
            user,
            policy.projection_revision,
            application.projection_revision,
            now,
        )
        .await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use uuid::Uuid;

    use super::{projection_verified_email_context, protect_projection_verified_email};
    use crate::{
        adapters::runtime_security::{RuntimeKeyMaterial, SoftwareRuntimeProtector},
        application::{ApplicationError, ProtectedPurpose, RuntimeProtector},
    };

    #[test]
    fn verified_email_ciphertext_is_bound_to_the_exact_projection_context() {
        let protector = SoftwareRuntimeProtector::new(
            "projection-context-test".to_owned(),
            1,
            RuntimeKeyMaterial::new([41; 32], [42; 32]),
            BTreeMap::new(),
        )
        .expect("projection protector");
        let project_id = Uuid::new_v4();
        let application_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();
        let protected = protect_projection_verified_email(
            &protector,
            project_id,
            application_id,
            user_id,
            7,
            "ada@example.test",
        )
        .expect("protect verified email");
        let exact = projection_verified_email_context(project_id, application_id, user_id, 7)
            .expect("exact context");
        assert_eq!(
            protector
                .unprotect(
                    ProtectedPurpose::ApplicationProjectionVerifiedEmail,
                    &exact,
                    &protected,
                )
                .expect("exact context decrypts")
                .as_slice(),
            b"ada@example.test"
        );

        let substitutions = [
            projection_verified_email_context(Uuid::new_v4(), application_id, user_id, 7)
                .expect("different Project context"),
            projection_verified_email_context(project_id, Uuid::new_v4(), user_id, 7)
                .expect("different Application context"),
            projection_verified_email_context(project_id, application_id, Uuid::new_v4(), 7)
                .expect("different user context"),
            projection_verified_email_context(project_id, application_id, user_id, 8)
                .expect("different revision context"),
        ];
        for substituted in substitutions {
            assert_eq!(
                protector.unprotect(
                    ProtectedPurpose::ApplicationProjectionVerifiedEmail,
                    &substituted,
                    &protected,
                ),
                Err(ApplicationError::Integrity)
            );
        }

        let mut substituted_schema = exact;
        *substituted_schema.last_mut().expect("schema context byte") ^= 1;
        assert_eq!(
            protector.unprotect(
                ProtectedPurpose::ApplicationProjectionVerifiedEmail,
                &substituted_schema,
                &protected,
            ),
            Err(ApplicationError::Integrity)
        );
    }
}
