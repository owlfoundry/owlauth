use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

use async_trait::async_trait;
use sea_orm::{
    ColumnTrait, Condition, ConnectionTrait, DatabaseConnection, DatabaseTransaction, DbBackend,
    EntityTrait, QueryFilter, QueryOrder, QuerySelect, Statement, TransactionTrait,
};
#[cfg(test)]
use subtle::ConstantTimeEq;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::application::{
    ActiveClientToken, ApplicationError, ClientApiRepository, ClientApplicationProjection,
    ClientEmailLookupDigester, ClientKeyAuthority, ClientTokenSessionLookup,
    ClientTokenSignatureVerifier, ClientUser, ClientUserCursor, ClientUserStatus,
    ClientVerificationKey, DurableEmailAddressReader, OpaquePurpose,
    ProjectionVerifiedEmailProtector, ProtectedValue, RuntimeProtector, VersionedDigest,
};

use super::{
    authentication::persistence,
    entity::{
        application, application_user_binding, application_user_projection, project,
        project_key_ring, project_signing_key, project_user,
    },
    projection::ProjectionCryptography,
};

#[derive(Clone)]
pub(crate) struct RuntimeClientEmailLookupDigester {
    protector: Arc<dyn RuntimeProtector>,
    readable_versions: BTreeSet<i32>,
}

impl RuntimeClientEmailLookupDigester {
    pub(crate) fn new(
        protector: Arc<dyn RuntimeProtector>,
        readable_versions: BTreeSet<i32>,
    ) -> Result<Self, ApplicationError> {
        if readable_versions.is_empty()
            || readable_versions.len() > 32
            || readable_versions.iter().any(|version| *version <= 0)
            || !readable_versions.contains(&protector.email_identity_active_version())
        {
            return Err(ApplicationError::InvalidInput);
        }
        Ok(Self {
            protector,
            readable_versions,
        })
    }
}

impl ClientEmailLookupDigester for RuntimeClientEmailLookupDigester {
    fn digest_candidates(
        &self,
        project_id: Uuid,
        canonical_email: &str,
    ) -> Result<Vec<VersionedDigest>, ApplicationError> {
        self.readable_versions
            .iter()
            .copied()
            .map(|version| {
                self.protector.digest_at(
                    OpaquePurpose::EmailIdentityLookup,
                    project_id.as_bytes(),
                    canonical_email.as_bytes(),
                    version,
                )
            })
            .collect()
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Ed25519ClientTokenVerifier;

impl ClientTokenSignatureVerifier for Ed25519ClientTokenVerifier {
    fn verify(
        &self,
        public_jwk: &serde_json::Value,
        signing_input: &[u8],
        signature: &[u8],
    ) -> Result<(), ApplicationError> {
        crate::adapters::runtime_security::verify_ed25519(public_jwk, signing_input, signature)
    }
}

struct ClientProjectionReader {
    source_reader: Arc<dyn DurableEmailAddressReader>,
    projection_protector: Arc<dyn ProjectionVerifiedEmailProtector>,
}

impl ProjectionCryptography for ClientProjectionReader {
    fn projection_write_version(&self) -> i32 {
        self.projection_protector.write_version()
    }

    fn projection_readable_versions(&self) -> BTreeSet<i32> {
        self.projection_protector.readable_versions()
    }

    fn read_durable_email(
        &self,
        project_id: Uuid,
        identity_id: Uuid,
        value: &ProtectedValue,
    ) -> Result<zeroize::Zeroizing<String>, ApplicationError> {
        self.source_reader
            .read_durable_address(project_id, identity_id, value)
    }

    fn protect_projection_email(
        &self,
        _project_id: Uuid,
        _application_id: Uuid,
        _user_id: Uuid,
        _projection_revision: i64,
        _email: &[u8],
    ) -> Result<ProtectedValue, ApplicationError> {
        Err(ApplicationError::Disabled)
    }

    fn unprotect_projection_email(
        &self,
        project_id: Uuid,
        application_id: Uuid,
        user_id: Uuid,
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

#[derive(Clone)]
pub(crate) struct PostgresClientApiRepository {
    database: DatabaseConnection,
    client_process_id: String,
    client_process_incarnation: Uuid,
    source_reader: Arc<dyn DurableEmailAddressReader>,
    projection_protector: Arc<dyn ProjectionVerifiedEmailProtector>,
}

impl PostgresClientApiRepository {
    pub(crate) fn new(
        database: DatabaseConnection,
        client_process_id: String,
        client_process_incarnation: Uuid,
        source_reader: Arc<dyn DurableEmailAddressReader>,
        projection_protector: Arc<dyn ProjectionVerifiedEmailProtector>,
    ) -> Result<Self, ApplicationError> {
        if client_process_incarnation.is_nil()
            || client_process_id.is_empty()
            || client_process_id.len() > 128
            || !client_process_id.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-')
            })
        {
            return Err(ApplicationError::InvalidInput);
        }
        Ok(Self {
            database,
            client_process_id,
            client_process_incarnation,
            source_reader,
            projection_protector,
        })
    }

    async fn fenced_transaction(
        &self,
        read_only: bool,
    ) -> Result<DatabaseTransaction, ApplicationError> {
        let transaction = self.database.begin().await.map_err(persistence)?;
        if read_only {
            // The incarnation fence below requires a row-level `FOR SHARE` lock. PostgreSQL
            // rejects that lock in a transaction declared READ ONLY, so read paths use a
            // repeatable-read transaction and enforce no-write authority in this repository's
            // narrow methods rather than weakening the replacement fence.
            transaction
                .execute_raw(Statement::from_string(
                    DbBackend::Postgres,
                    "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ".to_owned(),
                ))
                .await
                .map_err(persistence)?;
        }
        let observed = transaction
            .query_one_raw(Statement::from_sql_and_values(
                DbBackend::Postgres,
                "SELECT process_incarnation FROM client_process_incarnations
                  WHERE process_id=$1 AND process_incarnation=$2 FOR SHARE",
                [
                    self.client_process_id.clone().into(),
                    self.client_process_incarnation.into(),
                ],
            ))
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::Disabled)?;
        let incarnation: Uuid = observed
            .try_get("", "process_incarnation")
            .map_err(persistence)?;
        if incarnation != self.client_process_incarnation {
            return Err(ApplicationError::Integrity);
        }
        Ok(transaction)
    }

    fn projection_reader(&self) -> ClientProjectionReader {
        ClientProjectionReader {
            source_reader: Arc::clone(&self.source_reader),
            projection_protector: Arc::clone(&self.projection_protector),
        }
    }

    async fn active_project<C: ConnectionTrait>(
        &self,
        database: &C,
        project_id: Uuid,
        project_public_id: &str,
    ) -> Result<(), ApplicationError> {
        let owner = project::Entity::find_by_id(project_id)
            .filter(project::Column::PublicId.eq(project_public_id))
            .filter(project::Column::Status.eq("active"))
            .one(database)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        if owner.id != project_id {
            return Err(ApplicationError::Integrity);
        }
        Ok(())
    }

    #[allow(
        clippy::too_many_lines,
        reason = "mapping users must reconcile one snapshot of policy, identities, ownership, and protected email data"
    )]
    async fn map_users<C: ConnectionTrait>(
        &self,
        database: &C,
        project_public_id: &str,
        users: Vec<project_user::Model>,
    ) -> Result<Vec<ClientUser>, ApplicationError> {
        let statuses = users
            .iter()
            .map(user_status)
            .collect::<Result<Vec<_>, _>>()?;
        let needs_verified_email = users.iter().zip(&statuses).any(|(user, status)| {
            *status == ClientUserStatus::Active && user.primary_source_kind == "email"
        });
        let email_projection_enabled = if needs_verified_email {
            database
                .query_one_raw(Statement::from_sql_and_values(
                    DbBackend::Postgres,
                    "SELECT projection_verified_email_enabled
                       FROM project_policies WHERE project_id=$1",
                    [users
                        .first()
                        .ok_or(ApplicationError::Integrity)?
                        .project_id
                        .into()],
                ))
                .await
                .map_err(persistence)?
                .ok_or(ApplicationError::Integrity)?
                .try_get::<bool>("", "projection_verified_email_enabled")
                .map_err(persistence)?
        } else {
            false
        };

        let mut identity_ids = Vec::new();
        if email_projection_enabled {
            for (user, status) in users.iter().zip(&statuses) {
                if *status == ClientUserStatus::Active && user.primary_source_kind == "email" {
                    identity_ids.push(
                        user.primary_email_identity_id
                            .ok_or(ApplicationError::Integrity)?,
                    );
                }
            }
        }
        identity_ids.sort_unstable();
        identity_ids.dedup();

        let mut email_sources = BTreeMap::new();
        if !identity_ids.is_empty() {
            let project_id = users.first().ok_or(ApplicationError::Integrity)?.project_id;
            let rows = database
                .query_all_raw(Statement::from_sql_and_values(
                    DbBackend::Postgres,
                    "SELECT id,user_id,status,address_ciphertext,address_key_version,verified_at
                       FROM email_identities
                      WHERE project_id=$1
                        AND id IN (
                            SELECT value::UUID
                              FROM jsonb_array_elements_text($2::jsonb) requested(value))",
                    [project_id.into(), serde_json::json!(identity_ids).into()],
                ))
                .await
                .map_err(persistence)?;
            for row in rows {
                let identity_id: Uuid = row.try_get("", "id").map_err(persistence)?;
                let previous = email_sources.insert(
                    identity_id,
                    (
                        row.try_get::<Uuid>("", "user_id").map_err(persistence)?,
                        row.try_get::<String>("", "status").map_err(persistence)?,
                        row.try_get::<Vec<u8>>("", "address_ciphertext")
                            .map_err(persistence)?,
                        row.try_get::<i32>("", "address_key_version")
                            .map_err(persistence)?,
                        row.try_get::<Option<OffsetDateTime>>("", "verified_at")
                            .map_err(persistence)?,
                    ),
                );
                if previous.is_some() {
                    return Err(ApplicationError::Integrity);
                }
            }
        }

        users
            .into_iter()
            .zip(statuses)
            .map(|(user, status)| {
                let primary_verified_email = if email_projection_enabled
                    && status == ClientUserStatus::Active
                    && user.primary_source_kind == "email"
                {
                    let identity_id = user
                        .primary_email_identity_id
                        .ok_or(ApplicationError::Integrity)?;
                    let (owner, identity_status, ciphertext, key_version, verified_at) =
                        email_sources
                            .get(&identity_id)
                            .ok_or(ApplicationError::Integrity)?;
                    if *owner != user.id {
                        return Err(ApplicationError::Integrity);
                    }
                    if identity_status == "disabled" && verified_at.is_some() {
                        None
                    } else if identity_status == "active" && verified_at.is_some() {
                        Some(
                            self.source_reader
                                .read_durable_address(
                                    user.project_id,
                                    identity_id,
                                    &ProtectedValue {
                                        ciphertext: ciphertext.clone(),
                                        key_version: *key_version,
                                    },
                                )?
                                .to_string(),
                        )
                    } else {
                        return Err(ApplicationError::Integrity);
                    }
                } else {
                    None
                };
                Ok(ClientUser {
                    project_public_id: project_public_id.to_owned(),
                    user_public_id: user.public_id,
                    status,
                    display_name: user.display_name,
                    picture_url: user.picture_url,
                    primary_verified_email,
                    user_revision: user.user_revision,
                    created_at: user.created_at,
                    updated_at: user.updated_at,
                })
            })
            .collect()
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "the async-trait expansion includes fenced email-authority resolution that must remain in one snapshot"
)]
#[async_trait]
impl ClientApiRepository for PostgresClientApiRepository {
    async fn client_key_authority(
        &self,
        public_key_id: &str,
    ) -> Result<ClientKeyAuthority, ApplicationError> {
        let transaction = self.fenced_transaction(true).await?;
        let row = transaction
            .query_one_raw(Statement::from_sql_and_values(
                DbBackend::Postgres,
                "SELECT key.id AS key_id,key.project_id,owner.public_id AS project_public_id,
                        key.public_key_id,key.digest_key_version,key.credential_digest
                   FROM project_client_keys key
                   JOIN projects owner ON owner.id=key.project_id
                  WHERE key.public_key_id=$1 AND key.status='active'
                    AND key.revoked_at IS NULL AND owner.status='active'",
                [public_key_id.to_owned().into()],
            ))
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        let digest = row
            .try_get::<Vec<u8>>("", "credential_digest")
            .map_err(persistence)?;
        let digest: [u8; 32] = digest.try_into().map_err(|_| ApplicationError::Integrity)?;
        let version = row
            .try_get::<i32>("", "digest_key_version")
            .map_err(persistence)?;
        if version <= 0 {
            return Err(ApplicationError::Integrity);
        }
        let authority = ClientKeyAuthority {
            key_id: row.try_get("", "key_id").map_err(persistence)?,
            project_id: row.try_get("", "project_id").map_err(persistence)?,
            project_public_id: row.try_get("", "project_public_id").map_err(persistence)?,
            public_key_id: row.try_get("", "public_key_id").map_err(persistence)?,
            digest_key_version: version,
            credential_digest: digest,
        };
        transaction.commit().await.map_err(persistence)?;
        Ok(authority)
    }

    async fn confirm_active(&self, project_id: Uuid, key_id: Uuid) -> Result<(), ApplicationError> {
        let transaction = self.fenced_transaction(true).await?;
        let row = transaction
            .query_one_raw(Statement::from_sql_and_values(
                DbBackend::Postgres,
                "SELECT key.id
                   FROM project_client_keys key
                   JOIN projects owner ON owner.id=key.project_id
                  WHERE key.project_id=$1 AND key.id=$2 AND key.status='active'
                    AND key.revoked_at IS NULL AND owner.status='active'",
                [project_id.into(), key_id.into()],
            ))
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::Disabled)?;
        let returned: Uuid = row.try_get("", "id").map_err(persistence)?;
        if returned != key_id {
            return Err(ApplicationError::Integrity);
        }
        transaction.commit().await.map_err(persistence)
    }

    async fn record_usage_if_older(
        &self,
        project_id: Uuid,
        key_id: Uuid,
        usage_bucket: OffsetDateTime,
    ) -> Result<(), ApplicationError> {
        // This is deliberately outside the authoritative request transaction. A no-op can mean
        // either that this bucket was already observed or that revocation won; both are valid for
        // best-effort, lifecycle-neutral telemetry.
        self.database
            .execute_raw(Statement::from_sql_and_values(
                DbBackend::Postgres,
                "UPDATE project_client_keys key
                    SET last_used_at=GREATEST($3::timestamptz,key.created_at)
                  WHERE key.project_id=$1 AND key.id=$2 AND key.status='active'
                    AND key.revoked_at IS NULL
                    AND (key.last_used_at IS NULL OR
                         key.last_used_at < GREATEST($3::timestamptz,key.created_at))
                    AND EXISTS (SELECT 1 FROM projects owner
                                 WHERE owner.id=key.project_id AND owner.status='active')",
                [project_id.into(), key_id.into(), usage_bucket.into()],
            ))
            .await
            .map_err(persistence)?;
        Ok(())
    }

    async fn list_users(
        &self,
        project_id: Uuid,
        project_public_id: &str,
        after: Option<ClientUserCursor>,
        limit_plus_one: usize,
    ) -> Result<Vec<(ClientUserCursor, ClientUser)>, ApplicationError> {
        if !(2..=101).contains(&limit_plus_one) {
            return Err(ApplicationError::InvalidInput);
        }
        let transaction = self.fenced_transaction(true).await?;
        self.active_project(&transaction, project_id, project_public_id)
            .await?;
        let mut query =
            project_user::Entity::find().filter(project_user::Column::ProjectId.eq(project_id));
        if let Some(after) = after {
            query = query.filter(
                Condition::any()
                    .add(project_user::Column::CreatedAt.gt(after.created_at))
                    .add(
                        Condition::all()
                            .add(project_user::Column::CreatedAt.eq(after.created_at))
                            .add(project_user::Column::Id.gt(after.user_id)),
                    ),
            );
        }
        let users = query
            .order_by_asc(project_user::Column::CreatedAt)
            .order_by_asc(project_user::Column::Id)
            .limit(u64::try_from(limit_plus_one).map_err(|_| ApplicationError::InvalidInput)?)
            .all(&transaction)
            .await
            .map_err(persistence)?;
        let cursors = users
            .iter()
            .map(|user| ClientUserCursor {
                created_at: user.created_at,
                user_id: user.id,
            })
            .collect::<Vec<_>>();
        let mapped = self
            .map_users(&transaction, project_public_id, users)
            .await?;
        let result = cursors.into_iter().zip(mapped).collect();
        transaction.commit().await.map_err(persistence)?;
        Ok(result)
    }

    async fn user_by_public_id(
        &self,
        project_id: Uuid,
        project_public_id: &str,
        user_public_id: &str,
    ) -> Result<ClientUser, ApplicationError> {
        let transaction = self.fenced_transaction(true).await?;
        self.active_project(&transaction, project_id, project_public_id)
            .await?;
        let user = project_user::Entity::find()
            .filter(project_user::Column::ProjectId.eq(project_id))
            .filter(project_user::Column::PublicId.eq(user_public_id))
            .one(&transaction)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        let user = self
            .map_users(&transaction, project_public_id, vec![user])
            .await?
            .pop()
            .ok_or(ApplicationError::Integrity)?;
        transaction.commit().await.map_err(persistence)?;
        Ok(user)
    }

    #[allow(
        clippy::too_many_lines,
        reason = "email lookup must validate alias-version authority and resolve every digest in one fenced snapshot"
    )]
    async fn user_by_email_digests(
        &self,
        project_id: Uuid,
        project_public_id: &str,
        candidates: &[VersionedDigest],
    ) -> Result<Option<ClientUser>, ApplicationError> {
        if candidates.is_empty() || candidates.len() > 32 {
            return Err(ApplicationError::InvalidInput);
        }
        let transaction = self.fenced_transaction(true).await?;
        self.active_project(&transaction, project_id, project_public_id)
            .await?;
        // Alias acceptance is a durable rollout authority, not the process key-ring inventory.
        // Filter the precomputed readable candidates by the accepted versions observed in this
        // same repeatable-read snapshot so a retained-but-retired alias cannot authenticate a
        // lookup and a newly accepted version missing locally fails closed.
        let authority = transaction
            .query_one_raw(Statement::from_string(
                DbBackend::Postgres,
                "SELECT accepted_versions FROM email_identity_alias_authority WHERE singleton=TRUE"
                    .to_owned(),
            ))
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::Integrity)?;
        let accepted: serde_json::Value = authority
            .try_get("", "accepted_versions")
            .map_err(persistence)?;
        let accepted = serde_json::from_value::<Vec<i32>>(accepted)
            .map_err(|_| ApplicationError::Integrity)?;
        let accepted_set = accepted.iter().copied().collect::<BTreeSet<_>>();
        if accepted.is_empty()
            || accepted.len() > 16
            || accepted_set.len() != accepted.len()
            || accepted_set.iter().any(|version| *version <= 0)
            || accepted_set.iter().any(|version| {
                !candidates
                    .iter()
                    .any(|candidate| candidate.key_version == *version)
            })
        {
            return Err(ApplicationError::Integrity);
        }
        let mut user_ids = BTreeSet::new();
        for candidate in candidates
            .iter()
            .filter(|candidate| accepted_set.contains(&candidate.key_version))
        {
            if candidate.key_version <= 0 {
                return Err(ApplicationError::InvalidInput);
            }
            let row = transaction
                .query_one_raw(Statement::from_sql_and_values(
                    DbBackend::Postgres,
                    "SELECT identity.user_id
                       FROM email_identity_aliases alias
                       JOIN email_identities identity
                         ON identity.project_id=alias.project_id
                        AND identity.id=alias.identity_id
                      WHERE alias.project_id=$1 AND alias.canonicalization_version=1
                        AND alias.digest_key_version=$2 AND alias.lookup_digest=$3
                        AND identity.status='active'",
                    [
                        project_id.into(),
                        candidate.key_version.into(),
                        candidate.value.to_vec().into(),
                    ],
                ))
                .await
                .map_err(persistence)?;
            if let Some(row) = row {
                user_ids.insert(row.try_get::<Uuid>("", "user_id").map_err(persistence)?);
            }
        }
        if user_ids.len() > 1 {
            return Err(ApplicationError::Integrity);
        }
        let Some(user_id) = user_ids.into_iter().next() else {
            transaction.commit().await.map_err(persistence)?;
            return Ok(None);
        };
        let user = project_user::Entity::find_by_id(user_id)
            .filter(project_user::Column::ProjectId.eq(project_id))
            .one(&transaction)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::Integrity)?;
        let user = self
            .map_users(&transaction, project_public_id, vec![user])
            .await?
            .pop()
            .ok_or(ApplicationError::Integrity)?;
        transaction.commit().await.map_err(persistence)?;
        Ok(Some(user))
    }

    async fn application_projection(
        &self,
        project_id: Uuid,
        project_public_id: &str,
        application_public_id: &str,
        user_public_id: &str,
    ) -> Result<ClientApplicationProjection, ApplicationError> {
        let transaction = self.fenced_transaction(true).await?;
        self.active_project(&transaction, project_id, project_public_id)
            .await?;
        let application = application::Entity::find()
            .filter(application::Column::ProjectId.eq(project_id))
            .filter(application::Column::PublicId.eq(application_public_id))
            .filter(application::Column::Status.eq("active"))
            .one(&transaction)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        let user = project_user::Entity::find()
            .filter(project_user::Column::ProjectId.eq(project_id))
            .filter(project_user::Column::PublicId.eq(user_public_id))
            .one(&transaction)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        let binding = application_user_binding::Entity::find()
            .filter(application_user_binding::Column::ProjectId.eq(project_id))
            .filter(application_user_binding::Column::ApplicationId.eq(application.id))
            .filter(application_user_binding::Column::UserId.eq(user.id))
            .filter(application_user_binding::Column::Status.eq("active"))
            .one(&transaction)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        let projection = application_user_projection::Entity::find()
            .filter(application_user_projection::Column::ProjectId.eq(project_id))
            .filter(application_user_projection::Column::BindingId.eq(binding.id))
            .filter(application_user_projection::Column::ApplicationId.eq(application.id))
            .filter(application_user_projection::Column::UserId.eq(user.id))
            .one(&transaction)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        let document =
            super::projection::wire_projection_document(&projection, &self.projection_reader())?;
        let result = ClientApplicationProjection {
            project_public_id: project_public_id.to_owned(),
            application_public_id: application.public_id,
            user_public_id: user.public_id,
            projection_revision: projection.projection_revision,
            document,
        };
        transaction.commit().await.map_err(persistence)?;
        Ok(result)
    }

    async fn verification_key(
        &self,
        project_id: Uuid,
        kid: &str,
        now: OffsetDateTime,
    ) -> Result<ClientVerificationKey, ApplicationError> {
        let transaction = self.fenced_transaction(true).await?;
        let owner = project::Entity::find_by_id(project_id)
            .filter(project::Column::Status.eq("active"))
            .one(&transaction)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        let ring = project_key_ring::Entity::find()
            .filter(project_key_ring::Column::ProjectId.eq(project_id))
            .filter(project_key_ring::Column::Purpose.eq("application_tokens"))
            .filter(project_key_ring::Column::Algorithm.eq("EdDSA"))
            .one(&transaction)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        let key = project_signing_key::Entity::find()
            .filter(project_signing_key::Column::ProjectId.eq(project_id))
            .filter(project_signing_key::Column::RingId.eq(ring.id))
            .filter(project_signing_key::Column::Kid.eq(kid))
            .one(&transaction)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::NotFound)?;
        if key.state != "active"
            && !(key.state == "retiring" && key.verify_not_after.is_some_and(|cutoff| cutoff > now))
        {
            return Err(ApplicationError::Disabled);
        }
        let result = ClientVerificationKey {
            project_id,
            project_public_id: owner.public_id,
            issuer: ring.issuer,
            public_jwk: key.public_jwk,
        };
        transaction.commit().await.map_err(persistence)?;
        Ok(result)
    }

    async fn introspect_session(
        &self,
        lookup: ClientTokenSessionLookup,
    ) -> Result<ActiveClientToken, ApplicationError> {
        let transaction = self.fenced_transaction(true).await?;
        let row = transaction
            .query_one_raw(Statement::from_sql_and_values(
                DbBackend::Postgres,
                "SELECT owner.public_id AS project_public_id,
                        app.id AS application_id,app.public_id AS application_public_id,
                        app.revision AS application_revision,
                        usr.id AS user_id,usr.public_id AS user_public_id,usr.user_revision,
                        session.id AS application_session_id,session.session_revision,
                        session.authenticated_at,session.absolute_expires_at,
                        projection.id AS projection_id,projection.projection_revision
                   FROM projects owner
                   JOIN project_policies policy ON policy.project_id=owner.id
                   JOIN applications app ON app.project_id=owner.id AND app.public_id=$2
                   JOIN project_users usr ON usr.project_id=owner.id AND usr.public_id=$3
                   JOIN application_sessions session
                     ON session.project_id=owner.id AND session.application_id=app.id
                    AND session.user_id=usr.id AND session.id=$4
                   JOIN project_browser_sessions browser
                     ON browser.project_id=owner.id AND browser.user_id=usr.id
                    AND browser.id=session.browser_session_id
                   JOIN refresh_families family
                     ON family.project_id=owner.id AND family.application_id=app.id
                    AND family.user_id=usr.id AND family.application_session_id=session.id
                   JOIN application_user_bindings binding
                     ON binding.project_id=owner.id AND binding.application_id=app.id
                    AND binding.user_id=usr.id AND binding.id=session.binding_id
                   JOIN application_user_projections projection
                     ON projection.project_id=owner.id AND projection.application_id=app.id
                    AND projection.user_id=usr.id AND projection.binding_id=binding.id
                  WHERE owner.id=$1 AND owner.status='active'
                    AND app.status='active' AND usr.status='active'
                    AND session.status='active' AND session.absolute_expires_at>$6
                    AND $7::timestamptz<=session.absolute_expires_at
                    AND $8::timestamptz>=session.authenticated_at
                    AND browser.status='active' AND browser.idle_expires_at>$6
                    AND browser.absolute_expires_at>$6
                    AND family.status='active' AND family.absolute_expires_at>$6
                    AND binding.status='active'
                    AND session.project_security_revision=owner.security_revision
                    AND session.application_security_revision=app.security_revision
                    AND session.user_security_revision=usr.security_revision
                    AND session.claims_revision=$5 AND policy.claims_revision=$5
                    AND session.policy_session_revision=policy.session_revision
                    AND browser.project_security_revision=owner.security_revision
                    AND browser.user_security_revision=usr.security_revision
                    AND browser.policy_session_revision=policy.session_revision",
                [
                    lookup.project_id.into(),
                    lookup.application_public_id.clone().into(),
                    lookup.user_public_id.clone().into(),
                    lookup.application_session_id.into(),
                    lookup.claims_revision.into(),
                    lookup.now.into(),
                    lookup.expires_at.into(),
                    lookup.issued_at.into(),
                ],
            ))
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::Disabled)?;
        let projection_id: Uuid = row.try_get("", "projection_id").map_err(persistence)?;
        let projection = application_user_projection::Entity::find_by_id(projection_id)
            .one(&transaction)
            .await
            .map_err(persistence)?
            .ok_or(ApplicationError::Integrity)?;
        let project_public_id: String =
            row.try_get("", "project_public_id").map_err(persistence)?;
        let application_public_id: String = row
            .try_get("", "application_public_id")
            .map_err(persistence)?;
        let user_public_id: String = row.try_get("", "user_public_id").map_err(persistence)?;
        if project_public_id.is_empty()
            || application_public_id != lookup.application_public_id
            || user_public_id != lookup.user_public_id
            || projection.projection_revision
                != row
                    .try_get::<i64>("", "projection_revision")
                    .map_err(persistence)?
        {
            return Err(ApplicationError::Integrity);
        }
        let document =
            super::projection::wire_projection_document(&projection, &self.projection_reader())?;
        let active = ActiveClientToken {
            project_public_id,
            application_public_id,
            user_public_id,
            application_session_id: lookup.application_session_id,
            token_type: "Bearer".to_owned(),
            issued_at: lookup.issued_at,
            expires_at: lookup.expires_at,
            user_revision: row.try_get("", "user_revision").map_err(persistence)?,
            application_revision: row
                .try_get("", "application_revision")
                .map_err(persistence)?,
            session_revision: row.try_get("", "session_revision").map_err(persistence)?,
            claims_revision: lookup.claims_revision,
            projection_revision: projection.projection_revision,
            projection_document: document,
        };
        transaction.commit().await.map_err(persistence)?;
        Ok(active)
    }
}

fn user_status(user: &project_user::Model) -> Result<ClientUserStatus, ApplicationError> {
    if user.user_revision <= 0 {
        return Err(ApplicationError::Integrity);
    }
    match user.status.as_str() {
        "active" if user.merged_into_user_id.is_none() => Ok(ClientUserStatus::Active),
        "disabled" if user.merged_into_user_id.is_none() => Ok(ClientUserStatus::Disabled),
        "merged" if user.merged_into_user_id.is_some() => Ok(ClientUserStatus::Merged),
        _ => Err(ApplicationError::Integrity),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_status_rejects_incoherent_merge_state() {
        let mut user = project_user::Model {
            id: Uuid::new_v4(),
            project_id: Uuid::new_v4(),
            public_id: "usr_test".to_owned(),
            status: "active".to_owned(),
            merged_into_user_id: None,
            user_revision: 1,
            security_revision: 1,
            primary_profile_identity_id: None,
            primary_email_identity_id: None,
            primary_source_kind: "none".to_owned(),
            base_profile_digest: vec![0; 32],
            local_display_name_set: false,
            local_display_name: None,
            local_picture_url_set: false,
            local_picture_url: None,
            local_locale_set: false,
            local_locale: None,
            display_name: None,
            picture_url: None,
            locale: None,
            created_at: OffsetDateTime::UNIX_EPOCH,
            updated_at: OffsetDateTime::UNIX_EPOCH,
        };
        assert_eq!(user_status(&user), Ok(ClientUserStatus::Active));
        user.status = "merged".to_owned();
        assert_eq!(user_status(&user), Err(ApplicationError::Integrity));
        user.merged_into_user_id = Some(Uuid::new_v4());
        assert_eq!(user_status(&user), Ok(ClientUserStatus::Merged));
    }

    #[test]
    fn credential_digest_length_is_constant_time_comparable() {
        assert_eq!([1_u8; 32].ct_eq(&[1_u8; 32]).unwrap_u8(), 1);
        assert_eq!([1_u8; 32].ct_eq(&[2_u8; 32]).unwrap_u8(), 0);
    }
}
