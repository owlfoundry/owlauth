use std::{fmt, sync::Arc};

use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use serde_json::json;
use time::OffsetDateTime;
use uuid::Uuid;
use zeroize::Zeroizing;

use super::{ApplicationError, Clock, RequestDigester};

pub(crate) const SERVER_KEY_CREDENTIAL_PREFIX: &str = "owl_server_v1";
pub(crate) const SERVER_KEY_PUBLIC_ID_BYTES: usize = 16;
pub(crate) const SERVER_KEY_PUBLIC_ID_LENGTH: usize = 22;
pub(crate) const SERVER_KEY_SECRET_BYTES: usize = 32;
pub(crate) const SERVER_KEY_SECRET_LENGTH: usize = 43;
pub(crate) const SERVER_KEY_DISPLAY_PREFIX_LENGTH: usize =
    SERVER_KEY_CREDENTIAL_PREFIX.len() + 1 + SERVER_KEY_PUBLIC_ID_LENGTH;
pub(crate) const SERVER_KEY_CREDENTIAL_LENGTH: usize =
    SERVER_KEY_DISPLAY_PREFIX_LENGTH + 1 + SERVER_KEY_SECRET_LENGTH;
pub(crate) const MAX_ACTIVE_SERVER_KEYS_PER_PROJECT: usize = 10;
pub(crate) const MAX_SERVER_KEY_LABEL_LENGTH: usize = 64;
const MAX_SERVER_KEY_CREATE_ATTEMPTS: usize = 4;
pub(crate) const DEFAULT_SERVER_KEY_LIST_RESULTS: usize = 50;
pub(crate) const MAX_SERVER_KEY_LIST_RESULTS: usize = 100;
const SERVER_KEY_CURSOR_VERSION: u8 = 1;
const SERVER_KEY_CURSOR_BYTES: usize = 33;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ProjectServerKeyStatus {
    Active,
    Revoked,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ProjectServerKeyCursor {
    pub created_at: OffsetDateTime,
    pub key_id: Uuid,
}

impl ProjectServerKeyCursor {
    pub(crate) fn encode(self) -> String {
        let mut bytes = [0_u8; SERVER_KEY_CURSOR_BYTES];
        bytes[0] = SERVER_KEY_CURSOR_VERSION;
        bytes[1..17].copy_from_slice(&self.created_at.unix_timestamp_nanos().to_be_bytes());
        bytes[17..].copy_from_slice(self.key_id.as_bytes());
        URL_SAFE_NO_PAD.encode(bytes)
    }

    pub(crate) fn parse(value: &str) -> Result<Self, ApplicationError> {
        if value.len() > 64 || !value.is_ascii() {
            return Err(ApplicationError::InvalidInput);
        }
        let decoded = URL_SAFE_NO_PAD
            .decode(value)
            .map_err(|_| ApplicationError::InvalidInput)?;
        if decoded.len() != SERVER_KEY_CURSOR_BYTES || URL_SAFE_NO_PAD.encode(&decoded) != value {
            return Err(ApplicationError::InvalidInput);
        }
        let bytes: [u8; SERVER_KEY_CURSOR_BYTES] = decoded
            .try_into()
            .map_err(|_| ApplicationError::InvalidInput)?;
        if bytes[0] != SERVER_KEY_CURSOR_VERSION {
            return Err(ApplicationError::InvalidInput);
        }
        let timestamp = i128::from_be_bytes(
            bytes[1..17]
                .try_into()
                .map_err(|_| ApplicationError::InvalidInput)?,
        );
        Ok(Self {
            created_at: OffsetDateTime::from_unix_timestamp_nanos(timestamp)
                .map_err(|_| ApplicationError::InvalidInput)?,
            key_id: Uuid::from_slice(&bytes[17..]).map_err(|_| ApplicationError::InvalidInput)?,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct ProjectServerKeyRecord {
    pub id: Uuid,
    pub project_id: Uuid,
    pub public_key_id: String,
    pub label: String,
    pub status: ProjectServerKeyStatus,
    pub digest_key_version: i32,
    pub display_prefix: String,
    pub revision: i64,
    pub created_at: OffsetDateTime,
    pub credential_acknowledged_at: Option<OffsetDateTime>,
    pub last_used_at: Option<OffsetDateTime>,
    pub revoked_at: Option<OffsetDateTime>,
}

pub(crate) struct OneTimeServerCredential(Zeroizing<String>);

impl OneTimeServerCredential {
    pub(crate) fn new(value: Zeroizing<String>) -> Result<Self, ApplicationError> {
        ParsedServerCredential::parse(value.as_str())?;
        Ok(Self(value))
    }

    pub(crate) fn expose(&self) -> &str {
        self.0.as_str()
    }
}

impl fmt::Debug for OneTimeServerCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("OneTimeServerCredential([REDACTED])")
    }
}

pub(crate) struct ParsedServerCredential {
    public_key_id: String,
    secret: Zeroizing<[u8; SERVER_KEY_SECRET_BYTES]>,
}

impl ParsedServerCredential {
    pub(crate) fn parse(value: &str) -> Result<Self, ApplicationError> {
        if value.len() != SERVER_KEY_CREDENTIAL_LENGTH || !value.is_ascii() {
            return Err(ApplicationError::InvalidInput);
        }
        let mut parts = value.split('.');
        let version = parts.next().ok_or(ApplicationError::InvalidInput)?;
        let public_key_id = parts.next().ok_or(ApplicationError::InvalidInput)?;
        let encoded_secret = parts.next().ok_or(ApplicationError::InvalidInput)?;
        if parts.next().is_some()
            || version != SERVER_KEY_CREDENTIAL_PREFIX
            || !is_canonical_base64url(public_key_id, SERVER_KEY_PUBLIC_ID_BYTES)
            || !is_canonical_base64url(encoded_secret, SERVER_KEY_SECRET_BYTES)
        {
            return Err(ApplicationError::InvalidInput);
        }
        let decoded = URL_SAFE_NO_PAD
            .decode(encoded_secret)
            .map_err(|_| ApplicationError::InvalidInput)?;
        let secret: [u8; SERVER_KEY_SECRET_BYTES] = decoded
            .try_into()
            .map_err(|_| ApplicationError::InvalidInput)?;
        Ok(Self {
            public_key_id: public_key_id.to_owned(),
            secret: Zeroizing::new(secret),
        })
    }

    pub(crate) fn public_key_id(&self) -> &str {
        &self.public_key_id
    }

    pub(crate) fn secret(&self) -> &[u8; SERVER_KEY_SECRET_BYTES] {
        &self.secret
    }
}

impl fmt::Debug for ParsedServerCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ParsedServerCredential")
            .field("public_key_id", &self.public_key_id)
            .field("secret", &"[REDACTED]")
            .finish()
    }
}

pub(crate) struct IssuedServerCredential {
    pub public_key_id: String,
    pub display_prefix: String,
    pub digest_key_version: i32,
    pub digest: [u8; 32],
    pub credential: OneTimeServerCredential,
}

impl fmt::Debug for IssuedServerCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IssuedServerCredential")
            .field("public_key_id", &self.public_key_id)
            .field("display_prefix", &self.display_prefix)
            .field("digest_key_version", &self.digest_key_version)
            .field("digest", &"[REDACTED]")
            .field("credential", &"[REDACTED]")
            .finish()
    }
}

pub(crate) trait ServerKeyIssuer: Send + Sync {
    fn active_version(&self) -> i32;

    fn issue(
        &self,
        project_id: Uuid,
        key_id: Uuid,
    ) -> Result<IssuedServerCredential, ApplicationError>;
}

pub(crate) trait ServerKeyVerifier: Send + Sync {
    fn digest_candidate(
        &self,
        project_id: Uuid,
        key_id: Uuid,
        public_key_id: &str,
        secret: &[u8; SERVER_KEY_SECRET_BYTES],
        digest_key_version: i32,
    ) -> Result<[u8; 32], ApplicationError>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CreateProjectServerKey {
    pub project_id: Uuid,
    pub label: String,
    pub idempotency_key: String,
    pub correlation_id: Uuid,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AcknowledgeProjectServerKeyDelivery {
    pub project_id: Uuid,
    pub key_id: Uuid,
    pub expected_revision: i64,
    pub idempotency_key: String,
    pub correlation_id: Uuid,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RevokeProjectServerKey {
    pub project_id: Uuid,
    pub key_id: Uuid,
    pub expected_revision: i64,
    pub idempotency_key: String,
    pub correlation_id: Uuid,
}

pub(crate) struct PreparedProjectServerKey {
    pub id: Uuid,
    pub project_id: Uuid,
    pub public_key_id: String,
    pub label: String,
    pub digest_key_version: i32,
    pub credential_digest: [u8; 32],
    pub display_prefix: String,
    pub idempotency_key: String,
    pub request_digest: Vec<u8>,
    pub correlation_id: Uuid,
    pub created_at: OffsetDateTime,
}

impl fmt::Debug for PreparedProjectServerKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedProjectServerKey")
            .field("id", &self.id)
            .field("project_id", &self.project_id)
            .field("public_key_id", &self.public_key_id)
            .field("label", &self.label)
            .field("digest_key_version", &self.digest_key_version)
            .field("credential_digest", &"[REDACTED]")
            .field("display_prefix", &self.display_prefix)
            .field("idempotency_key", &self.idempotency_key)
            .field("request_digest", &"[REDACTED]")
            .field("correlation_id", &self.correlation_id)
            .field("created_at", &self.created_at)
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum StoredProjectServerKeyCreate {
    Created(ProjectServerKeyRecord),
    ReplayWithoutSecret(ProjectServerKeyRecord),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ServerKeyCreateAttemptError {
    PublicIdCollision,
    Application(ApplicationError),
}

impl From<ApplicationError> for ServerKeyCreateAttemptError {
    fn from(error: ApplicationError) -> Self {
        Self::Application(error)
    }
}

pub(crate) enum CreateProjectServerKeyResult {
    Created {
        metadata: ProjectServerKeyRecord,
        credential: OneTimeServerCredential,
    },
    ReplayWithoutSecret {
        metadata: ProjectServerKeyRecord,
    },
}

impl fmt::Debug for CreateProjectServerKeyResult {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Created { metadata, .. } => formatter
                .debug_struct("Created")
                .field("metadata", metadata)
                .field("credential", &"[REDACTED]")
                .finish(),
            Self::ReplayWithoutSecret { metadata } => formatter
                .debug_struct("ReplayWithoutSecret")
                .field("metadata", metadata)
                .finish(),
        }
    }
}

#[async_trait]
pub(crate) trait ServerKeyLifecyclePort: Send + Sync {
    async fn list_project_server_keys(
        &self,
        project_id: Uuid,
        after: Option<ProjectServerKeyCursor>,
        limit_plus_one: usize,
    ) -> Result<Vec<ProjectServerKeyRecord>, ApplicationError>;

    async fn active_unacknowledged_project_server_key(
        &self,
        project_id: Uuid,
    ) -> Result<Option<ProjectServerKeyRecord>, ApplicationError>;

    async fn get_project_server_key(
        &self,
        project_id: Uuid,
        key_id: Uuid,
    ) -> Result<ProjectServerKeyRecord, ApplicationError>;

    async fn replay_project_server_key_create(
        &self,
        project_id: Uuid,
        idempotency_key: &str,
        request_digest: &[u8],
    ) -> Result<Option<ProjectServerKeyRecord>, ApplicationError>;

    async fn create_project_server_key_attempt(
        &self,
        prepared: PreparedProjectServerKey,
    ) -> Result<StoredProjectServerKeyCreate, ServerKeyCreateAttemptError>;

    async fn acknowledge_project_server_key_delivery(
        &self,
        command: AcknowledgeProjectServerKeyDelivery,
        request_digest: Vec<u8>,
        acknowledged_at: OffsetDateTime,
    ) -> Result<ProjectServerKeyRecord, ApplicationError>;

    async fn revoke_project_server_key(
        &self,
        command: RevokeProjectServerKey,
        request_digest: Vec<u8>,
        revoked_at: OffsetDateTime,
    ) -> Result<ProjectServerKeyRecord, ApplicationError>;
}

#[derive(Clone)]
pub(crate) struct ServerKeyLifecycleService {
    port: Arc<dyn ServerKeyLifecyclePort>,
    issuer: Arc<dyn ServerKeyIssuer>,
    digester: Arc<dyn RequestDigester>,
    clock: Arc<dyn Clock>,
}

impl ServerKeyLifecycleService {
    pub(crate) fn new(
        port: Arc<dyn ServerKeyLifecyclePort>,
        issuer: Arc<dyn ServerKeyIssuer>,
        digester: Arc<dyn RequestDigester>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            port,
            issuer,
            digester,
            clock,
        }
    }

    pub(crate) async fn list_project_server_keys(
        &self,
        project_id: Uuid,
        cursor: Option<&str>,
        limit: Option<usize>,
    ) -> Result<
        (
            Vec<ProjectServerKeyRecord>,
            Option<String>,
            Option<ProjectServerKeyRecord>,
        ),
        ApplicationError,
    > {
        let limit = limit.unwrap_or(DEFAULT_SERVER_KEY_LIST_RESULTS);
        if limit == 0 || limit > MAX_SERVER_KEY_LIST_RESULTS {
            return Err(ApplicationError::InvalidInput);
        }
        let after = cursor.map(ProjectServerKeyCursor::parse).transpose()?;
        let (mut records, active_unacknowledged_key) = tokio::try_join!(
            self.port
                .list_project_server_keys(project_id, after, limit + 1),
            self.port
                .active_unacknowledged_project_server_key(project_id),
        )?;
        let next_cursor = if records.len() > limit {
            records.truncate(limit);
            let last = records.last().ok_or(ApplicationError::Integrity)?;
            Some(
                ProjectServerKeyCursor {
                    created_at: last.created_at,
                    key_id: last.id,
                }
                .encode(),
            )
        } else {
            None
        };
        Ok((records, next_cursor, active_unacknowledged_key))
    }

    pub(crate) async fn get_project_server_key(
        &self,
        project_id: Uuid,
        key_id: Uuid,
    ) -> Result<ProjectServerKeyRecord, ApplicationError> {
        self.port.get_project_server_key(project_id, key_id).await
    }

    pub(crate) async fn create_project_server_key(
        &self,
        command: CreateProjectServerKey,
    ) -> Result<CreateProjectServerKeyResult, ApplicationError> {
        validate_server_key_label(&command.label)?;
        validate_server_key_idempotency_key(&command.idempotency_key)?;
        let request_digest = self.digester.digest_json(&json!({
            "project_id": command.project_id,
            "label": command.label.as_str(),
        }))?;
        if let Some(metadata) = self
            .port
            .replay_project_server_key_create(
                command.project_id,
                &command.idempotency_key,
                &request_digest,
            )
            .await?
        {
            return Ok(CreateProjectServerKeyResult::ReplayWithoutSecret { metadata });
        }

        for _ in 0..MAX_SERVER_KEY_CREATE_ATTEMPTS {
            let key_id = Uuid::new_v4();
            let issued = self.issuer.issue(command.project_id, key_id)?;
            let credential = issued.credential;
            let expected_public_key_id = issued.public_key_id.clone();
            let expected_display_prefix = issued.display_prefix.clone();
            let expected_version = issued.digest_key_version;
            if expected_version != self.issuer.active_version() {
                return Err(ApplicationError::Integrity);
            }
            let prepared = PreparedProjectServerKey {
                id: key_id,
                project_id: command.project_id,
                public_key_id: issued.public_key_id,
                label: command.label.clone(),
                digest_key_version: issued.digest_key_version,
                credential_digest: issued.digest,
                display_prefix: issued.display_prefix,
                idempotency_key: command.idempotency_key.clone(),
                request_digest: request_digest.clone(),
                correlation_id: command.correlation_id,
                created_at: self.clock.now(),
            };
            match self.port.create_project_server_key_attempt(prepared).await {
                Ok(StoredProjectServerKeyCreate::Created(metadata)) => {
                    if metadata.id != key_id
                        || metadata.project_id != command.project_id
                        || metadata.public_key_id != expected_public_key_id
                        || metadata.display_prefix != expected_display_prefix
                        || metadata.digest_key_version != expected_version
                    {
                        return Err(ApplicationError::Integrity);
                    }
                    return Ok(CreateProjectServerKeyResult::Created {
                        metadata,
                        credential,
                    });
                }
                Ok(StoredProjectServerKeyCreate::ReplayWithoutSecret(metadata)) => {
                    return Ok(CreateProjectServerKeyResult::ReplayWithoutSecret { metadata });
                }
                Err(ServerKeyCreateAttemptError::PublicIdCollision) => {}
                Err(ServerKeyCreateAttemptError::Application(error)) => return Err(error),
            }
        }
        Err(ApplicationError::Persistence)
    }

    pub(crate) async fn acknowledge_project_server_key_delivery(
        &self,
        command: AcknowledgeProjectServerKeyDelivery,
    ) -> Result<ProjectServerKeyRecord, ApplicationError> {
        if command.expected_revision <= 0 {
            return Err(ApplicationError::InvalidInput);
        }
        validate_server_key_idempotency_key(&command.idempotency_key)?;
        let request_digest = self.digester.digest_json(&json!({
            "project_id": command.project_id,
            "key_id": command.key_id,
            "expected_revision": command.expected_revision,
        }))?;
        self.port
            .acknowledge_project_server_key_delivery(command, request_digest, self.clock.now())
            .await
    }

    pub(crate) async fn revoke_project_server_key(
        &self,
        command: RevokeProjectServerKey,
    ) -> Result<ProjectServerKeyRecord, ApplicationError> {
        if command.expected_revision <= 0 {
            return Err(ApplicationError::InvalidInput);
        }
        validate_server_key_idempotency_key(&command.idempotency_key)?;
        let request_digest = self.digester.digest_json(&json!({
            "project_id": command.project_id,
            "key_id": command.key_id,
            "expected_revision": command.expected_revision,
        }))?;
        self.port
            .revoke_project_server_key(command, request_digest, self.clock.now())
            .await
    }
}

pub(crate) fn validate_server_key_label(value: &str) -> Result<(), ApplicationError> {
    if value.is_empty()
        || value.chars().count() > MAX_SERVER_KEY_LABEL_LENGTH
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return Err(ApplicationError::InvalidInput);
    }
    Ok(())
}

fn validate_server_key_idempotency_key(value: &str) -> Result<(), ApplicationError> {
    if !(8..=128).contains(&value.len())
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(ApplicationError::InvalidInput);
    }
    Ok(())
}

pub(crate) fn server_key_display_prefix(public_key_id: &str) -> Result<String, ApplicationError> {
    if !is_canonical_base64url(public_key_id, SERVER_KEY_PUBLIC_ID_BYTES) {
        return Err(ApplicationError::InvalidInput);
    }
    Ok(format!("{SERVER_KEY_CREDENTIAL_PREFIX}.{public_key_id}"))
}

fn is_canonical_base64url(value: &str, decoded_length: usize) -> bool {
    let expected_encoded_length = match decoded_length {
        SERVER_KEY_PUBLIC_ID_BYTES => SERVER_KEY_PUBLIC_ID_LENGTH,
        SERVER_KEY_SECRET_BYTES => SERVER_KEY_SECRET_LENGTH,
        _ => return false,
    };
    value.len() == expected_encoded_length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
        && URL_SAFE_NO_PAD.decode(value).is_ok_and(|decoded| {
            decoded.len() == decoded_length && URL_SAFE_NO_PAD.encode(decoded) == value
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn credential() -> String {
        format!(
            "{SERVER_KEY_CREDENTIAL_PREFIX}.{}.{}",
            URL_SAFE_NO_PAD.encode([7_u8; SERVER_KEY_PUBLIC_ID_BYTES]),
            URL_SAFE_NO_PAD.encode([9_u8; SERVER_KEY_SECRET_BYTES])
        )
    }

    #[test]
    fn parses_only_the_canonical_credential_grammar() {
        let value = credential();
        let parsed = ParsedServerCredential::parse(&value).expect("canonical credential");
        assert_eq!(
            parsed.public_key_id(),
            URL_SAFE_NO_PAD.encode([7_u8; SERVER_KEY_PUBLIC_ID_BYTES])
        );
        assert_eq!(parsed.secret(), &[9_u8; SERVER_KEY_SECRET_BYTES]);

        for invalid in [
            format!(" {value}"),
            format!("{value} "),
            value.replace("owl_server_v1", "owl_server_v2"),
            value.replace('.', "_"),
            format!("{value}.extra"),
            value.replacen('.', "..", 1),
            format!("{value}="),
        ] {
            assert_eq!(
                ParsedServerCredential::parse(&invalid).err(),
                Some(ApplicationError::InvalidInput),
                "accepted {invalid:?}"
            );
        }
    }

    #[test]
    fn redacts_secret_bearing_debug_output() {
        let parsed = ParsedServerCredential::parse(&credential()).expect("canonical credential");
        let debug = format!("{parsed:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains(&URL_SAFE_NO_PAD.encode([9_u8; SERVER_KEY_SECRET_BYTES])));
    }

    #[test]
    fn labels_are_trimmed_bounded_and_control_free() {
        assert!(validate_server_key_label("production backend").is_ok());
        for invalid in ["", " leading", "trailing ", "line\nbreak"] {
            assert_eq!(
                validate_server_key_label(invalid),
                Err(ApplicationError::InvalidInput)
            );
        }
        assert_eq!(
            validate_server_key_label(&"a".repeat(MAX_SERVER_KEY_LABEL_LENGTH + 1)),
            Err(ApplicationError::InvalidInput)
        );
    }

    use std::sync::{
        Mutex,
        atomic::{AtomicUsize, Ordering},
    };

    struct FixedClock;

    impl Clock for FixedClock {
        fn now(&self) -> OffsetDateTime {
            OffsetDateTime::UNIX_EPOCH + time::Duration::days(1)
        }
    }

    struct FixedDigester;

    impl RequestDigester for FixedDigester {
        fn digest_json(&self, _: &serde_json::Value) -> Result<Vec<u8>, ApplicationError> {
            Ok(vec![5_u8; 32])
        }
    }

    struct CountingIssuer {
        calls: AtomicUsize,
    }

    impl ServerKeyIssuer for CountingIssuer {
        fn active_version(&self) -> i32 {
            7
        }

        fn issue(
            &self,
            project_id: Uuid,
            key_id: Uuid,
        ) -> Result<IssuedServerCredential, ApplicationError> {
            let call = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
            let byte = u8::try_from(call).map_err(|_| ApplicationError::Integrity)?;
            let public_key_id = URL_SAFE_NO_PAD.encode([byte; SERVER_KEY_PUBLIC_ID_BYTES]);
            let display_prefix = server_key_display_prefix(&public_key_id)?;
            let secret = URL_SAFE_NO_PAD.encode([9_u8; SERVER_KEY_SECRET_BYTES]);
            let credential =
                OneTimeServerCredential::new(Zeroizing::new(format!("{display_prefix}.{secret}")))?;
            let mut digest = [0_u8; 32];
            digest[..16].copy_from_slice(project_id.as_bytes());
            digest[16..].copy_from_slice(key_id.as_bytes());
            Ok(IssuedServerCredential {
                public_key_id,
                display_prefix,
                digest_key_version: 7,
                digest,
                credential,
            })
        }
    }

    struct MockLifecyclePort {
        replay: Mutex<Option<ProjectServerKeyRecord>>,
        collisions: usize,
        attempts: AtomicUsize,
    }

    #[async_trait]
    impl ServerKeyLifecyclePort for MockLifecyclePort {
        async fn list_project_server_keys(
            &self,
            _: Uuid,
            _: Option<ProjectServerKeyCursor>,
            _: usize,
        ) -> Result<Vec<ProjectServerKeyRecord>, ApplicationError> {
            Ok(Vec::new())
        }

        async fn active_unacknowledged_project_server_key(
            &self,
            _: Uuid,
        ) -> Result<Option<ProjectServerKeyRecord>, ApplicationError> {
            Ok(None)
        }

        async fn get_project_server_key(
            &self,
            _: Uuid,
            _: Uuid,
        ) -> Result<ProjectServerKeyRecord, ApplicationError> {
            Err(ApplicationError::NotFound)
        }

        async fn replay_project_server_key_create(
            &self,
            _: Uuid,
            _: &str,
            _: &[u8],
        ) -> Result<Option<ProjectServerKeyRecord>, ApplicationError> {
            Ok(self.replay.lock().expect("replay lock").clone())
        }

        async fn create_project_server_key_attempt(
            &self,
            prepared: PreparedProjectServerKey,
        ) -> Result<StoredProjectServerKeyCreate, ServerKeyCreateAttemptError> {
            let attempt = self.attempts.fetch_add(1, Ordering::SeqCst);
            if attempt < self.collisions {
                return Err(ServerKeyCreateAttemptError::PublicIdCollision);
            }
            Ok(StoredProjectServerKeyCreate::Created(
                ProjectServerKeyRecord {
                    id: prepared.id,
                    project_id: prepared.project_id,
                    public_key_id: prepared.public_key_id,
                    label: prepared.label,
                    status: ProjectServerKeyStatus::Active,
                    digest_key_version: prepared.digest_key_version,
                    display_prefix: prepared.display_prefix,
                    revision: 1,
                    created_at: prepared.created_at,
                    credential_acknowledged_at: None,
                    last_used_at: None,
                    revoked_at: None,
                },
            ))
        }

        async fn acknowledge_project_server_key_delivery(
            &self,
            _: AcknowledgeProjectServerKeyDelivery,
            _: Vec<u8>,
            _: OffsetDateTime,
        ) -> Result<ProjectServerKeyRecord, ApplicationError> {
            Err(ApplicationError::NotFound)
        }

        async fn revoke_project_server_key(
            &self,
            _: RevokeProjectServerKey,
            _: Vec<u8>,
            _: OffsetDateTime,
        ) -> Result<ProjectServerKeyRecord, ApplicationError> {
            Err(ApplicationError::NotFound)
        }
    }

    fn service(
        port: Arc<MockLifecyclePort>,
        issuer: Arc<CountingIssuer>,
    ) -> ServerKeyLifecycleService {
        ServerKeyLifecycleService::new(port, issuer, Arc::new(FixedDigester), Arc::new(FixedClock))
    }

    fn replay_record(project_id: Uuid) -> ProjectServerKeyRecord {
        let public_key_id = URL_SAFE_NO_PAD.encode([3_u8; SERVER_KEY_PUBLIC_ID_BYTES]);
        ProjectServerKeyRecord {
            id: Uuid::new_v4(),
            project_id,
            display_prefix: server_key_display_prefix(&public_key_id).expect("display prefix"),
            public_key_id,
            label: "backend".to_owned(),
            status: ProjectServerKeyStatus::Active,
            digest_key_version: 7,
            revision: 1,
            created_at: OffsetDateTime::UNIX_EPOCH,
            credential_acknowledged_at: None,
            last_used_at: None,
            revoked_at: None,
        }
    }

    #[tokio::test]
    async fn replay_returns_safe_metadata_without_generating_or_revealing_a_secret() {
        let project_id = Uuid::new_v4();
        let replay = replay_record(project_id);
        let port = Arc::new(MockLifecyclePort {
            replay: Mutex::new(Some(replay.clone())),
            collisions: 0,
            attempts: AtomicUsize::new(0),
        });
        let issuer = Arc::new(CountingIssuer {
            calls: AtomicUsize::new(0),
        });
        let result = service(Arc::clone(&port), Arc::clone(&issuer))
            .create_project_server_key(CreateProjectServerKey {
                project_id,
                label: "backend".to_owned(),
                idempotency_key: "server-key-create-1".to_owned(),
                correlation_id: Uuid::new_v4(),
            })
            .await
            .expect("safe replay");
        assert!(matches!(
            result,
            CreateProjectServerKeyResult::ReplayWithoutSecret { metadata } if metadata == replay
        ));
        assert_eq!(issuer.calls.load(Ordering::SeqCst), 0);
        assert_eq!(port.attempts.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn inventory_cursor_is_canonical_bounded_and_round_trips() {
        let cursor = ProjectServerKeyCursor {
            created_at: OffsetDateTime::from_unix_timestamp_nanos(1_800_000_000_123_456_789)
                .expect("test timestamp"),
            key_id: Uuid::new_v4(),
        };
        let encoded = cursor.encode();
        assert!(encoded.len() <= 64);
        assert_eq!(ProjectServerKeyCursor::parse(&encoded), Ok(cursor));
        for invalid in [
            String::new(),
            format!("{encoded}="),
            "!".repeat(encoded.len()),
            "A".repeat(65),
        ] {
            assert_eq!(
                ProjectServerKeyCursor::parse(&invalid),
                Err(ApplicationError::InvalidInput)
            );
        }
    }

    #[tokio::test]
    async fn create_retries_bounded_public_id_collisions_and_reveals_only_the_winner() {
        let project_id = Uuid::new_v4();
        let port = Arc::new(MockLifecyclePort {
            replay: Mutex::new(None),
            collisions: 2,
            attempts: AtomicUsize::new(0),
        });
        let issuer = Arc::new(CountingIssuer {
            calls: AtomicUsize::new(0),
        });
        let result = service(Arc::clone(&port), Arc::clone(&issuer))
            .create_project_server_key(CreateProjectServerKey {
                project_id,
                label: "production backend".to_owned(),
                idempotency_key: "server-key-create-2".to_owned(),
                correlation_id: Uuid::new_v4(),
            })
            .await
            .expect("eventual create");
        let CreateProjectServerKeyResult::Created {
            metadata,
            credential,
        } = result
        else {
            panic!("expected original create")
        };
        assert_eq!(metadata.project_id, project_id);
        assert_eq!(metadata.public_key_id, URL_SAFE_NO_PAD.encode([3_u8; 16]));
        assert_eq!(
            ParsedServerCredential::parse(credential.expose())
                .expect("winning credential")
                .public_key_id(),
            metadata.public_key_id
        );
        assert_eq!(issuer.calls.load(Ordering::SeqCst), 3);
        assert_eq!(port.attempts.load(Ordering::SeqCst), 3);
    }
}
