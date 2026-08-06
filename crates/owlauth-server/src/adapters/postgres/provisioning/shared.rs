use super::*;

pub(in crate::adapters::postgres) async fn authenticate_committed_signing_provider_replay(
    transaction: &DatabaseTransaction,
    project_id: Uuid,
    prepared: &PreparedSigningKey,
    material: &ProvisionedProtectedSigningMaterial,
    public_jwk: &Value,
) -> Result<(), ApplicationError> {
    // This performs no finalization. It authenticates a late idempotent provider response against
    // the complete committed result after another lease owner finalized.
    let key = project_signing_key::Entity::find_by_id(prepared.key_id)
        .filter(project_signing_key::Column::ProjectId.eq(project_id))
        .one(transaction)
        .await
        .map_err(persistence)?
        .ok_or(ApplicationError::NotFound)?;
    let committed = protected_material::Entity::find_by_id(material.material_id)
        .filter(protected_material::Column::ProjectId.eq(project_id))
        .one(transaction)
        .await
        .map_err(persistence)?
        .ok_or(ApplicationError::Integrity)?;
    let committed_handle = committed
        .opaque_value
        .as_deref()
        .ok_or(ApplicationError::Integrity)?;
    let handle_matches = material
        .handle
        .expose(|returned| returned == committed_handle);
    validate_protected_signing_jwk(&prepared.kid, &material.public_key, public_jwk)?;
    if key.signer_material_id != material.material_id
        || key.public_jwk != *public_jwk
        || committed.state != "live"
        || !handle_matches
    {
        return Err(ApplicationError::Integrity);
    }
    Ok(())
}

pub(in crate::adapters::postgres) fn signing_public_key_from_jwk(
    jwk: &Value,
) -> Result<SigningPublicKey, ApplicationError> {
    let encoded = jwk
        .get("x")
        .and_then(Value::as_str)
        .ok_or(ApplicationError::Integrity)?;
    let bytes = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| ApplicationError::Integrity)?;
    SigningPublicKey::new(SigningAlgorithm::Ed25519, bytes).map_err(|_| ApplicationError::Integrity)
}

pub(in crate::adapters::postgres) fn validate_protected_signing_jwk(
    kid: &str,
    public_key: &SigningPublicKey,
    jwk: &Value,
) -> Result<(), ApplicationError> {
    let object = jwk.as_object().ok_or(ApplicationError::Integrity)?;
    if public_key.algorithm() != SigningAlgorithm::Ed25519
        || public_key.as_bytes().len() != 32
        || object.get("kty").and_then(Value::as_str) != Some("OKP")
        || object.get("crv").and_then(Value::as_str) != Some("Ed25519")
        || object.get("alg").and_then(Value::as_str) != Some(SIGNING_ALGORITHM)
        || object.get("use").and_then(Value::as_str) != Some("sig")
        || object.get("kid").and_then(Value::as_str) != Some(kid)
        || object.get("x").and_then(Value::as_str)
            != Some(URL_SAFE_NO_PAD.encode(public_key.as_bytes()).as_str())
    {
        return Err(ApplicationError::Integrity);
    }
    Ok(())
}

pub(in crate::adapters::postgres) fn provisioning_operation_state(
    value: &str,
) -> Result<ProvisioningOperationState, ApplicationError> {
    match value {
        "prepared" => Ok(ProvisioningOperationState::Prepared),
        "submitted" => Ok(ProvisioningOperationState::Submitted),
        "stored" => Ok(ProvisioningOperationState::Stored),
        "completed" => Ok(ProvisioningOperationState::Completed),
        "cleanup_pending" => Ok(ProvisioningOperationState::CleanupPending),
        "cleanup_leased" => Ok(ProvisioningOperationState::CleanupLeased),
        "cleanup_blocked" => Ok(ProvisioningOperationState::CleanupBlocked),
        "failed" => Ok(ProvisioningOperationState::Failed),
        "abandoned" => Ok(ProvisioningOperationState::Abandoned),
        _ => Err(ApplicationError::Integrity),
    }
}

pub(in crate::adapters::postgres) fn validate_signing_operation(
    prepared: &PreparedSigningKey,
    operation: &key_provisioning_operation::Model,
) -> Result<(), ApplicationError> {
    if operation.key_id != prepared.key_id
        || operation.ring_id != prepared.ring_id
        || operation.request_digest != prepared.request_digest
    {
        return Err(ApplicationError::Integrity);
    }
    Ok(())
}

pub(in crate::adapters::postgres) async fn ensure_signing_provider_lease(
    transaction: &DatabaseTransaction,
    operation: &key_provisioning_operation::Model,
    lease: SigningProviderLease,
) -> Result<(), ApplicationError> {
    let now = database_now(transaction).await?;
    if operation.provider_lease_token != Some(lease.token)
        || operation
            .provider_lease_expires_at
            .is_none_or(|expires_at| expires_at <= now)
    {
        return Err(ApplicationError::OperationInProgress);
    }
    Ok(())
}

pub(in crate::adapters::postgres) fn provider_error_class_name(
    value: ProviderErrorClass,
) -> &'static str {
    match value {
        ProviderErrorClass::InvalidRequest => "invalid_request",
        ProviderErrorClass::UnsupportedAlgorithm => "unsupported_algorithm",
        ProviderErrorClass::NotFound => "not_found",
        ProviderErrorClass::Conflict => "conflict",
        ProviderErrorClass::PermissionDenied => "permission_denied",
        ProviderErrorClass::Unavailable => "unavailable",
        _ => "integrity",
    }
}

pub(in crate::adapters::postgres) fn retry_classification_name(
    value: RetryClassification,
) -> &'static str {
    match value {
        RetryClassification::Never => "never",
        RetryClassification::ExactInputSafe => "exact_input_safe",
        _ => "reconcile",
    }
}

pub(in crate::adapters::postgres) fn prepared_signing_key(
    key: project_signing_key::Model,
    operation: key_provisioning_operation::Model,
) -> Result<PreparedSigningKey, ApplicationError> {
    if operation.key_id != key.id || operation.ring_id != key.ring_id {
        return Err(ApplicationError::Integrity);
    }
    Ok(PreparedSigningKey {
        operation_id: operation.id,
        ring_id: operation.ring_id,
        key_id: operation.key_id,
        kid: key.kid,
        signer_material_id: operation.material_id,
        request_digest: operation.request_digest,
        state: provisioning_operation_state(&operation.state)?,
    })
}

pub(in crate::adapters::postgres) fn prepared_provider(
    operation: provider_secret_operation::Model,
) -> Result<PreparedProvider, ApplicationError> {
    Ok(PreparedProvider {
        operation_id: operation.id,
        provider_id: operation.provider_id,
        request_digest: operation.request_digest,
        state: provisioning_operation_state(&operation.state)?,
    })
}

pub(in crate::adapters::postgres) fn project_policy_record(
    model: &project_policy::Model,
) -> Result<ProjectPolicyRecord, ApplicationError> {
    let access_token_lifetime_seconds = model
        .claims_policy
        .get("access_token_lifetime_seconds")
        .and_then(Value::as_i64)
        .and_then(|value| i32::try_from(value).ok())
        .filter(|value| (60..=3600).contains(value))
        .ok_or(ApplicationError::InvalidTransition)?;
    let browser_session_reuse = model
        .session_policy
        .get("browser_session_reuse")
        .and_then(Value::as_bool)
        .ok_or(ApplicationError::InvalidTransition)?;
    Ok(ProjectPolicyRecord {
        project_id: model.project_id,
        access_token_lifetime_seconds,
        browser_session_reuse,
        claims_revision: model.claims_revision,
        session_revision: model.session_revision,
    })
}

pub(in crate::adapters::postgres) fn project_record(model: project::Model) -> ProjectRecord {
    ProjectRecord {
        id: model.id,
        public_id: model.public_id,
        display_name: model.display_name,
        belongs_to: model.belongs_to,
        status: model.status,
        metadata_revision: model.metadata_revision,
        security_revision: model.security_revision,
    }
}

pub(in crate::adapters::postgres) async fn locked_project<C>(
    connection: &C,
    project_id: Uuid,
) -> Result<project::Model, ApplicationError>
where
    C: ConnectionTrait,
{
    project::Entity::find_by_id(project_id)
        .lock_exclusive()
        .one(connection)
        .await
        .map_err(persistence)?
        .ok_or(ApplicationError::NotFound)
}

pub(in crate::adapters::postgres) async fn active_project<C>(
    connection: &C,
    project_id: Uuid,
) -> Result<project::Model, ApplicationError>
where
    C: ConnectionTrait,
{
    let project = locked_project(connection, project_id).await?;
    if project.status != "active" {
        return Err(ApplicationError::Disabled);
    }
    Ok(project)
}

pub(in crate::adapters::postgres) async fn enforce_provider_egress_fence<C: ConnectionTrait>(
    database: &C,
    project_id: Uuid,
    expected_revision: Option<i64>,
) -> Result<(), ApplicationError> {
    let Some(expected_revision) = expected_revision else {
        return Ok(());
    };
    let current = project_provider_egress_policy::Entity::find_by_id(project_id)
        .lock_shared()
        .one(database)
        .await
        .map_err(persistence)?
        .ok_or(ApplicationError::Integrity)?;
    if current.revision != expected_revision {
        return Err(ApplicationError::RevisionConflict);
    }
    Ok(())
}

pub(in crate::adapters::postgres) fn enforce_project_fence(
    project: &project::Model,
    expected_revision: i64,
) -> Result<(), ApplicationError> {
    if project.status != "active" {
        return Err(ApplicationError::Disabled);
    }
    if project.metadata_revision != expected_revision {
        return Err(ApplicationError::RevisionConflict);
    }
    Ok(())
}

pub(in crate::adapters::postgres) fn requires_project_reauthorization(
    project: &project::Model,
    operation_state: &str,
    captured_revision: i64,
    expected_revision: i64,
) -> Result<bool, ApplicationError> {
    if matches!(
        operation_state,
        "completed"
            | "cleanup_pending"
            | "cleanup_leased"
            | "cleanup_blocked"
            | "abandoned"
            | "failed"
    ) {
        return Ok(false);
    }
    if operation_state == "submitted" && project.status != "active" {
        return Ok(false);
    }
    enforce_project_fence(project, expected_revision)?;
    Ok(captured_revision != expected_revision)
}

pub(in crate::adapters::postgres) async fn ensure_project<C>(
    connection: &C,
    project_id: Uuid,
) -> Result<(), ApplicationError>
where
    C: ConnectionTrait,
{
    project::Entity::find_by_id(project_id)
        .one(connection)
        .await
        .map_err(persistence)?
        .ok_or(ApplicationError::NotFound)?;
    Ok(())
}

pub(in crate::adapters::postgres) async fn find_application<C>(
    connection: &C,
    project_id: Uuid,
    application_id: Uuid,
) -> Result<application::Model, ApplicationError>
where
    C: ConnectionTrait,
{
    application::Entity::find_by_id(application_id)
        .filter(application::Column::ProjectId.eq(project_id))
        .one(connection)
        .await
        .map_err(persistence)?
        .ok_or(ApplicationError::NotFound)
}

pub(in crate::adapters::postgres) async fn active_application<C>(
    connection: &C,
    project_id: Uuid,
    application_id: Uuid,
) -> Result<application::Model, ApplicationError>
where
    C: ConnectionTrait,
{
    let application = application::Entity::find_by_id(application_id)
        .filter(application::Column::ProjectId.eq(project_id))
        .lock_exclusive()
        .one(connection)
        .await
        .map_err(persistence)?
        .ok_or(ApplicationError::NotFound)?;
    if application.status != "active" {
        return Err(ApplicationError::Disabled);
    }
    Ok(application)
}

pub(in crate::adapters::postgres) async fn find_signing_key<C>(
    connection: &C,
    project_id: Uuid,
    key_id: Uuid,
) -> Result<project_signing_key::Model, ApplicationError>
where
    C: ConnectionTrait,
{
    project_signing_key::Entity::find_by_id(key_id)
        .filter(project_signing_key::Column::ProjectId.eq(project_id))
        .one(connection)
        .await
        .map_err(persistence)?
        .ok_or(ApplicationError::NotFound)
}

pub(in crate::adapters::postgres) async fn signing_key_record<C>(
    connection: &C,
    key: project_signing_key::Model,
) -> Result<SigningKeyRecord, ApplicationError>
where
    C: ConnectionTrait,
{
    let ring = project_key_ring::Entity::find_by_id(key.ring_id)
        .filter(project_key_ring::Column::ProjectId.eq(key.project_id))
        .one(connection)
        .await
        .map_err(persistence)?
        .ok_or(ApplicationError::NotFound)?;
    Ok(SigningKeyRecord {
        id: key.id,
        project_id: key.project_id,
        kid: key.kid,
        algorithm: ring.algorithm,
        state: key.state,
        ring_revision: ring.revision,
        signing_epoch: ring.signing_epoch,
        sign_not_before: key.sign_not_before,
        verify_not_after: key.verify_not_after,
        public_jwk: key.public_jwk,
    })
}

pub(in crate::adapters::postgres) async fn find_provider<C>(
    connection: &C,
    project_id: Uuid,
    provider_id: Uuid,
) -> Result<provider_configuration::Model, ApplicationError>
where
    C: ConnectionTrait,
{
    provider_configuration::Entity::find_by_id(provider_id)
        .filter(provider_configuration::Column::ProjectId.eq(project_id))
        .one(connection)
        .await
        .map_err(persistence)?
        .ok_or(ApplicationError::NotFound)
}

pub(in crate::adapters::postgres) async fn active_provider<C>(
    connection: &C,
    project_id: Uuid,
    provider_id: Uuid,
) -> Result<provider_configuration::Model, ApplicationError>
where
    C: ConnectionTrait,
{
    let provider = find_provider(connection, project_id, provider_id).await?;
    if provider.status != "active" {
        return Err(ApplicationError::Disabled);
    }
    Ok(provider)
}

pub(in crate::adapters::postgres) async fn bump_application_security(
    transaction: &DatabaseTransaction,
    application: application::Model,
    next_revision: i64,
) -> Result<(), ApplicationError> {
    let aggregate_revision = application.revision + 1;
    let mut active = application.into_active_model();
    active.security_revision = Set(next_revision);
    active.revision = Set(aggregate_revision);
    active.updated_at = Set(OffsetDateTime::now_utc());
    active.update(transaction).await.map_err(persistence)?;
    Ok(())
}

pub(in crate::adapters::postgres) async fn bump_provider_revision(
    transaction: &DatabaseTransaction,
    provider: provider_configuration::Model,
) -> Result<provider_configuration::Model, ApplicationError> {
    let next_revision = provider.revision + 1;
    let mut active = provider.into_active_model();
    active.revision = Set(next_revision);
    active.update(transaction).await.map_err(persistence)
}

#[allow(
    clippy::too_many_arguments,
    reason = "the arguments are the complete immutable key transition event"
)]
pub(in crate::adapters::postgres) async fn insert_key_state_event(
    transaction: &DatabaseTransaction,
    project_id: Uuid,
    ring_id: Uuid,
    signing_key_id: Uuid,
    ring_revision: i64,
    from_state: SigningKeyState,
    to_state: SigningKeyState,
    occurred_at: OffsetDateTime,
) -> Result<(), ApplicationError> {
    key_state_event::ActiveModel {
        id: Set(Uuid::new_v4()),
        project_id: Set(project_id),
        ring_id: Set(ring_id),
        signing_key_id: Set(signing_key_id),
        ring_revision: Set(ring_revision),
        from_state: Set(from_state.as_str().to_owned()),
        to_state: Set(to_state.as_str().to_owned()),
        actor_kind: Set("deployment_operator".to_owned()),
        occurred_at: Set(occurred_at),
    }
    .insert(transaction)
    .await
    .map_err(persistence)?;
    Ok(())
}

pub(in crate::adapters::postgres) async fn insert_audit(
    transaction: &DatabaseTransaction,
    project_id: Option<Uuid>,
    action: &str,
    target_kind: &str,
    target_id: Option<Uuid>,
    correlation_id: Uuid,
) -> Result<(), ApplicationError> {
    audit_event::ActiveModel {
        id: Set(Uuid::new_v4()),
        project_id: Set(project_id),
        actor_kind: Set("deployment_operator".to_owned()),
        action: Set(action.to_owned()),
        target_kind: Set(target_kind.to_owned()),
        target_id: Set(target_id),
        outcome: Set("succeeded".to_owned()),
        correlation_id: Set(correlation_id),
        safe_context: Set(Value::Object(Map::new())),
    }
    .insert(transaction)
    .await
    .map_err(persistence)?;
    Ok(())
}

pub(in crate::adapters::postgres) async fn lock_idempotency_key(
    transaction: &DatabaseTransaction,
    idempotency_key: &str,
) -> Result<(), ApplicationError> {
    lock_advisory(transaction, idempotency_key).await
}

pub(in crate::adapters::postgres) async fn lock_project_capacity(
    transaction: &DatabaseTransaction,
) -> Result<(), ApplicationError> {
    lock_advisory(transaction, PROJECT_CAPACITY_LOCK).await
}

pub(in crate::adapters::postgres) async fn ensure_application_capacity(
    transaction: &DatabaseTransaction,
    project_id: Uuid,
    capacity_error: ApplicationError,
) -> Result<(), ApplicationError> {
    let applications = application::Entity::find()
        .filter(application::Column::ProjectId.eq(project_id))
        .limit(LIST_LIMIT + 1)
        .all(transaction)
        .await
        .map_err(persistence)?;
    ensure_capacity(applications.len(), LIST_LIMIT, capacity_error)
}

pub(in crate::adapters::postgres) async fn ensure_publishable_signing_key_capacity(
    transaction: &DatabaseTransaction,
    project_id: Uuid,
) -> Result<(), ApplicationError> {
    let keys = project_signing_key::Entity::find()
        .filter(project_signing_key::Column::ProjectId.eq(project_id))
        .filter(project_signing_key::Column::State.is_in([
            SigningKeyState::Published.as_str(),
            SigningKeyState::Active.as_str(),
            SigningKeyState::Retiring.as_str(),
        ]))
        .limit(LIST_LIMIT + 1)
        .all(transaction)
        .await
        .map_err(persistence)?;
    ensure_capacity(keys.len(), LIST_LIMIT, ApplicationError::InvalidTransition)
}

pub(in crate::adapters::postgres) async fn abandon_signing_key_operation(
    transaction: &DatabaseTransaction,
    project_id: Uuid,
    key_id: Uuid,
    abandoned_at: OffsetDateTime,
) -> Result<Option<Uuid>, ApplicationError> {
    let operation = key_provisioning_operation::Entity::find()
        .filter(key_provisioning_operation::Column::ProjectId.eq(project_id))
        .filter(key_provisioning_operation::Column::KeyId.eq(key_id))
        .lock_exclusive()
        .one(transaction)
        .await
        .map_err(persistence)?
        .ok_or(ApplicationError::Integrity)?;
    if !matches!(
        operation.state.as_str(),
        "prepared" | "submitted" | "stored" | "cleanup_pending" | "failed"
    ) {
        return Err(ApplicationError::InvalidTransition);
    }
    let cleanup_required = matches!(
        operation.state.as_str(),
        "submitted" | "stored" | "cleanup_pending"
    );
    let material_id = operation.material_id;
    let mut operation = operation.into_active_model();
    operation.state = Set(if cleanup_required {
        "cleanup_pending".to_owned()
    } else {
        "abandoned".to_owned()
    });
    operation.provider_lease_token = Set(None);
    operation.provider_lease_expires_at = Set(None);
    operation.next_attempt_at = Set(cleanup_required.then_some(abandoned_at));
    operation.abandoned_at = Set((!cleanup_required).then_some(abandoned_at));
    operation.update(transaction).await.map_err(persistence)?;
    Ok((!cleanup_required).then_some(material_id))
}

pub(in crate::adapters::postgres) async fn lock_advisory(
    transaction: &DatabaseTransaction,
    namespace: &str,
) -> Result<(), ApplicationError> {
    transaction
        .execute_raw(Statement::from_sql_and_values(
            transaction.get_database_backend(),
            "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))",
            [namespace.to_owned().into()],
        ))
        .await
        .map_err(persistence)?;
    Ok(())
}

pub(in crate::adapters::postgres) async fn replay<T>(
    transaction: &DatabaseTransaction,
    idempotency_key: &str,
    operation_kind: &str,
    scope: &str,
    digest: &[u8],
) -> Result<Option<T>, ApplicationError>
where
    T: for<'de> Deserialize<'de>,
{
    let Some(existing) = control_idempotency_record::Entity::find_by_id(idempotency_key)
        .one(transaction)
        .await
        .map_err(persistence)?
    else {
        return Ok(None);
    };
    if existing.operation_kind != operation_kind
        || existing.request_scope != scope
        || existing.request_digest != digest
    {
        return Err(ApplicationError::IdempotencyConflict);
    }
    if existing.state != "completed" {
        return Err(ApplicationError::OperationInProgress);
    }
    let response = existing.response.ok_or(ApplicationError::Persistence)?;
    serde_json::from_value(response)
        .map(Some)
        .map_err(|_| ApplicationError::Persistence)
}

#[allow(
    clippy::too_many_arguments,
    reason = "the arguments are the durable idempotency record and its response"
)]
pub(in crate::adapters::postgres) async fn complete_idempotency<T>(
    transaction: &DatabaseTransaction,
    idempotency_key: String,
    owner_project_id: Option<Uuid>,
    result_resource_id: Option<Uuid>,
    operation_kind: &str,
    scope: &str,
    digest: Vec<u8>,
    result: &T,
) -> Result<(), ApplicationError>
where
    T: Serialize,
{
    control_idempotency_record::ActiveModel {
        idempotency_key: Set(idempotency_key),
        project_id: Set(owner_project_id),
        request_digest: Set(digest),
        state: Set("completed".to_owned()),
        result_resource_id: Set(result_resource_id),
        response: Set(Some(
            serde_json::to_value(result).map_err(|_| ApplicationError::Persistence)?,
        )),
        operation_kind: Set(operation_kind.to_owned()),
        request_scope: Set(scope.to_owned()),
        expires_at: Set(None),
        completed_at: Set(Some(OffsetDateTime::now_utc())),
    }
    .insert(transaction)
    .await
    .map_err(persistence)?;
    Ok(())
}

pub(in crate::adapters::postgres) fn generated_id(prefix: &str) -> String {
    format!("{prefix}_{}", Uuid::new_v4().simple())
}

pub(in crate::adapters::postgres) fn ensure_capacity(
    item_count: usize,
    limit: u64,
    capacity_error: ApplicationError,
) -> Result<(), ApplicationError> {
    let item_count = u64::try_from(item_count).map_err(|_| ApplicationError::Integrity)?;
    if item_count > limit {
        return Err(ApplicationError::Integrity);
    }
    if item_count == limit {
        return Err(capacity_error);
    }
    Ok(())
}

pub(in crate::adapters::postgres) fn bounded_items<T>(
    items: Vec<T>,
    limit: usize,
) -> Result<Vec<T>, ApplicationError> {
    if items.len() > limit {
        return Err(ApplicationError::Integrity);
    }
    Ok(items)
}

pub(in crate::adapters::postgres) fn bounded_list<T>(
    items: Vec<T>,
) -> Result<Vec<T>, ApplicationError> {
    bounded_items(
        items,
        usize::try_from(LIST_LIMIT).expect("the list limit fits usize"),
    )
}

pub(in crate::adapters::postgres) fn reject_duplicates(
    values: impl Iterator<Item = String>,
) -> Result<(), ApplicationError> {
    let mut unique = BTreeSet::new();
    for value in values {
        if !unique.insert(value) {
            return Err(ApplicationError::InvalidInput);
        }
    }
    Ok(())
}

pub(in crate::adapters::postgres) fn parse_application_type(
    value: &str,
) -> Result<ApplicationType, ApplicationError> {
    match value {
        "web" => Ok(ApplicationType::Web),
        "native" => Ok(ApplicationType::Native),
        _ => Err(ApplicationError::Persistence),
    }
}

pub(in crate::adapters::postgres) fn parse_signing_state(
    value: &str,
) -> Result<SigningKeyState, ApplicationError> {
    match value {
        "provisioning" => Ok(SigningKeyState::Provisioning),
        "published" => Ok(SigningKeyState::Published),
        "active" => Ok(SigningKeyState::Active),
        "retiring" => Ok(SigningKeyState::Retiring),
        "retired" => Ok(SigningKeyState::Retired),
        "revoked" => Ok(SigningKeyState::Revoked),
        "abandoned" => Ok(SigningKeyState::Abandoned),
        _ => Err(ApplicationError::Persistence),
    }
}

#[derive(FromQueryResult)]
struct DatabaseTime {
    database_now: OffsetDateTime,
}

pub(in crate::adapters::postgres) async fn database_now<C>(
    connection: &C,
) -> Result<OffsetDateTime, ApplicationError>
where
    C: ConnectionTrait,
{
    DatabaseTime::find_by_statement(Statement::from_string(
        connection.get_database_backend(),
        "SELECT transaction_timestamp() AS database_now",
    ))
    .one(connection)
    .await
    .map_err(persistence)?
    .map(|row| row.database_now)
    .ok_or(ApplicationError::Persistence)
}

pub(in crate::adapters::postgres) fn persistence(error: DbErr) -> ApplicationError {
    match error {
        DbErr::Exec(RuntimeErr::SqlxError(error)) | DbErr::Query(RuntimeErr::SqlxError(error)) => {
            match error.as_ref() {
                sqlx::Error::Database(error) => match error.code().as_deref() {
                    Some("23505" | "40001" | "40P01") => ApplicationError::RevisionConflict,
                    Some("55P03") => ApplicationError::Persistence,
                    Some("23503" | "23514" | "23P01") => ApplicationError::InvalidInput,
                    _ => ApplicationError::Integrity,
                },
                _ => ApplicationError::Integrity,
            }
        }
        DbErr::Conn(_) | DbErr::ConnectionAcquire(_) => ApplicationError::Persistence,
        _ => ApplicationError::Integrity,
    }
}
