use sea_orm::{
    ActiveModelTrait, ColumnTrait, EntityTrait, IntoActiveModel, QueryFilter, QueryOrder,
    QuerySelect, Set,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use crate::{
    application::ApplicationError,
    domain::{
        ProfileDisplayName, ProfilePictureUrl, ProjectUserStatus, ProjectionRevision, PublicId,
        UserProjection, UserProjectionSource, UserRevision,
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

pub(super) struct ProjectionMaterial {
    pub(super) revision: i64,
    pub(super) document: Value,
    pub(super) digest: Vec<u8>,
    pub(super) storage_repair_required: bool,
}

pub(super) fn base_profile_digest(
    display_name: Option<&str>,
    picture_url: Option<&str>,
    locale: Option<&str>,
    verified_email: Option<&str>,
) -> Result<Vec<u8>, ApplicationError> {
    let mut profile = serde_json::Map::new();
    profile.insert("display_name".to_owned(), json!(display_name));
    profile.insert("picture_url".to_owned(), json!(picture_url));
    if locale.is_some() {
        profile.insert("locale".to_owned(), json!(locale));
    }
    if verified_email.is_some() {
        profile.insert("verified_email".to_owned(), json!(verified_email));
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
            document,
            digest,
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
        || !bool::from(
            existing
                .canonical_digest
                .as_slice()
                .ct_eq(digest.as_slice()),
        )
        || existing
            .source_base_profile_digest
            .as_deref()
            .is_none_or(|digest| !bool::from(digest.ct_eq(user.base_profile_digest.as_slice())));
    Ok(ProjectionMaterial {
        revision,
        document,
        digest,
        storage_repair_required,
    })
}

pub(super) async fn repair_projection(
    transaction: &sea_orm::DatabaseTransaction,
    projection: application_user_projection::Model,
    user: &project_user::Model,
    project_projection_revision: i64,
    application_projection_revision: i64,
    now: OffsetDateTime,
) -> Result<(application_user_projection::Model, ProjectionMaterial), ApplicationError> {
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
        active.document = Set(material.document.clone());
        active.updated_at = Set(now);
        active.update(transaction).await.map_err(persistence)?
    } else {
        projection
    };
    Ok((projection, material))
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
