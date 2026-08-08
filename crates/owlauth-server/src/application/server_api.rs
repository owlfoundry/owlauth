use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use subtle::ConstantTimeEq;
use time::{Duration, OffsetDateTime};
use tokio::sync::Semaphore;
use uuid::Uuid;

use super::{
    ApplicationError, Clock, EmailIdentityLookupDigester, ParsedServerCredential,
    ServerKeyVerifier, VersionedDigest,
};

pub(crate) const DEFAULT_SERVER_USER_PAGE_LIMIT: usize = 50;
pub(crate) const MAX_SERVER_USER_PAGE_LIMIT: usize = 100;
pub(crate) const MAX_SERVER_ACCESS_TOKEN_BYTES: usize = 16_384;
const SERVER_CURSOR_BYTES: usize = 33;
const SERVER_CURSOR_VERSION: u8 = 1;
const SERVER_KEY_USAGE_BUCKET: Duration = Duration::minutes(15);
const SERVER_TOKEN_CLOCK_SKEW_SECONDS: i64 = 60;
const SERVER_USAGE_TELEMETRY_CAPACITY: usize = 8_192;
const SERVER_USAGE_TELEMETRY_CONCURRENCY: usize = 1;
const SERVER_USAGE_TELEMETRY_DEADLINE_MILLIS: u64 = 1_000;
const SERVER_ACCESS_TOKEN_TYP: &str = "at+jwt";

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ServerKeyAuthority {
    pub key_id: Uuid,
    pub project_id: Uuid,
    pub project_public_id: String,
    pub public_key_id: String,
    pub digest_key_version: i32,
    pub credential_digest: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(
    clippy::struct_field_names,
    reason = "explicit project/key and public/internal identifier names prevent authority confusion"
)]
pub(crate) struct ServerPrincipal {
    pub project_id: Uuid,
    pub project_public_id: String,
    pub key_id: Uuid,
    pub public_key_id: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ServerUserStatus {
    Active,
    Disabled,
    Merged,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct ServerUser {
    pub project_public_id: String,
    pub user_public_id: String,
    pub status: ServerUserStatus,
    pub display_name: Option<String>,
    pub picture_url: Option<String>,
    pub primary_verified_email: Option<String>,
    pub user_revision: i64,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ServerUserCursor {
    pub created_at: OffsetDateTime,
    pub user_id: Uuid,
}

impl ServerUserCursor {
    pub(crate) fn encode(self) -> String {
        let mut bytes = [0_u8; SERVER_CURSOR_BYTES];
        bytes[0] = SERVER_CURSOR_VERSION;
        bytes[1..17].copy_from_slice(&self.created_at.unix_timestamp_nanos().to_be_bytes());
        bytes[17..].copy_from_slice(self.user_id.as_bytes());
        URL_SAFE_NO_PAD.encode(bytes)
    }

    pub(crate) fn parse(value: &str) -> Result<Self, ApplicationError> {
        if value.len() > 64 || !value.is_ascii() {
            return Err(ApplicationError::InvalidInput);
        }
        let decoded = URL_SAFE_NO_PAD
            .decode(value)
            .map_err(|_| ApplicationError::InvalidInput)?;
        if decoded.len() != SERVER_CURSOR_BYTES || URL_SAFE_NO_PAD.encode(&decoded) != value {
            return Err(ApplicationError::InvalidInput);
        }
        let bytes: [u8; SERVER_CURSOR_BYTES] = decoded
            .try_into()
            .map_err(|_| ApplicationError::InvalidInput)?;
        if bytes[0] != SERVER_CURSOR_VERSION {
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
            user_id: Uuid::from_bytes(
                bytes[17..]
                    .try_into()
                    .map_err(|_| ApplicationError::InvalidInput)?,
            ),
        })
    }
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct ServerUserPage {
    pub users: Vec<ServerUser>,
    pub next_cursor: Option<String>,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct ServerApplicationProjection {
    pub project_public_id: String,
    pub application_public_id: String,
    pub user_public_id: String,
    pub projection_revision: i64,
    pub document: Value,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct ActiveServerToken {
    pub project_public_id: String,
    pub application_public_id: String,
    pub user_public_id: String,
    pub application_session_id: Uuid,
    pub token_type: String,
    pub issued_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
    pub user_revision: i64,
    pub application_revision: i64,
    pub session_revision: i64,
    pub claims_revision: i64,
    pub projection_revision: i64,
    pub projection_document: Value,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) enum ServerTokenIntrospection {
    Inactive,
    Active(Box<ActiveServerToken>),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ServerVerificationKey {
    pub project_id: Uuid,
    pub project_public_id: String,
    pub issuer: String,
    pub public_jwk: Value,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ServerTokenSessionLookup {
    pub project_id: Uuid,
    pub application_public_id: String,
    pub user_public_id: String,
    pub application_session_id: Uuid,
    pub claims_revision: i64,
    pub issued_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
    pub now: OffsetDateTime,
}

pub(crate) trait ServerTokenSignatureVerifier: Send + Sync {
    fn verify(
        &self,
        public_jwk: &Value,
        signing_input: &[u8],
        signature: &[u8],
    ) -> Result<(), ApplicationError>;
}

#[async_trait]
pub(crate) trait ServerApiRepository: Send + Sync {
    async fn server_key_authority(
        &self,
        public_key_id: &str,
    ) -> Result<ServerKeyAuthority, ApplicationError>;

    async fn confirm_active(&self, project_id: Uuid, key_id: Uuid) -> Result<(), ApplicationError>;

    async fn record_usage_if_older(
        &self,
        project_id: Uuid,
        key_id: Uuid,
        usage_bucket: OffsetDateTime,
    ) -> Result<(), ApplicationError>;

    async fn list_users(
        &self,
        project_id: Uuid,
        project_public_id: &str,
        after: Option<ServerUserCursor>,
        limit_plus_one: usize,
    ) -> Result<Vec<(ServerUserCursor, ServerUser)>, ApplicationError>;

    async fn user_by_public_id(
        &self,
        project_id: Uuid,
        project_public_id: &str,
        user_public_id: &str,
    ) -> Result<ServerUser, ApplicationError>;

    async fn user_by_email_digests(
        &self,
        project_id: Uuid,
        project_public_id: &str,
        candidates: &[VersionedDigest],
    ) -> Result<Option<ServerUser>, ApplicationError>;

    async fn application_projection(
        &self,
        project_id: Uuid,
        project_public_id: &str,
        application_public_id: &str,
        user_public_id: &str,
    ) -> Result<ServerApplicationProjection, ApplicationError>;

    async fn verification_key(
        &self,
        project_id: Uuid,
        kid: &str,
        now: OffsetDateTime,
    ) -> Result<ServerVerificationKey, ApplicationError>;

    async fn introspect_session(
        &self,
        lookup: ServerTokenSessionLookup,
    ) -> Result<ActiveServerToken, ApplicationError>;
}

struct ServerUsageTelemetry {
    observed_buckets: Mutex<HashMap<(Uuid, Uuid), i64>>,
    permits: Arc<Semaphore>,
}

impl ServerUsageTelemetry {
    fn new() -> Self {
        Self {
            observed_buckets: Mutex::new(HashMap::new()),
            permits: Arc::new(Semaphore::new(SERVER_USAGE_TELEMETRY_CONCURRENCY)),
        }
    }
}

#[derive(Clone)]
pub(crate) struct ServerApiService {
    repository: Arc<dyn ServerApiRepository>,
    key_verifier: Arc<dyn ServerKeyVerifier>,
    email_digester: Arc<dyn EmailIdentityLookupDigester>,
    token_verifier: Arc<dyn ServerTokenSignatureVerifier>,
    clock: Arc<dyn Clock>,
    usage_telemetry: Arc<ServerUsageTelemetry>,
}

impl ServerApiService {
    pub(crate) fn new(
        repository: Arc<dyn ServerApiRepository>,
        key_verifier: Arc<dyn ServerKeyVerifier>,
        email_digester: Arc<dyn EmailIdentityLookupDigester>,
        token_verifier: Arc<dyn ServerTokenSignatureVerifier>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            repository,
            key_verifier,
            email_digester,
            token_verifier,
            clock,
            usage_telemetry: Arc::new(ServerUsageTelemetry::new()),
        }
    }

    pub(crate) async fn authenticate(
        &self,
        route_project_public_id: &str,
        credential: &str,
    ) -> Result<ServerPrincipal, ApplicationError> {
        let parsed =
            ParsedServerCredential::parse(credential).map_err(|_| ApplicationError::Disabled)?;
        let authority = self
            .repository
            .server_key_authority(parsed.public_key_id())
            .await
            .map_err(generic_auth_error)?;
        if authority.project_public_id != route_project_public_id
            || authority.public_key_id != parsed.public_key_id()
        {
            return Err(ApplicationError::Disabled);
        }
        let candidate = self
            .key_verifier
            .digest_candidate(
                authority.project_id,
                authority.key_id,
                &authority.public_key_id,
                parsed.secret(),
                authority.digest_key_version,
            )
            .map_err(|_| ApplicationError::Disabled)?;
        if candidate.ct_eq(&authority.credential_digest).unwrap_u8() != 1 {
            return Err(ApplicationError::Disabled);
        }
        self.repository
            .confirm_active(authority.project_id, authority.key_id)
            .await
            .map_err(generic_auth_error)?;
        Ok(ServerPrincipal {
            project_id: authority.project_id,
            project_public_id: authority.project_public_id,
            key_id: authority.key_id,
            public_key_id: authority.public_key_id,
        })
    }

    /// Schedules lifecycle-neutral usage telemetry only after authentication succeeds. Work is
    /// coalesced per key/bucket, bounded to one detached
    /// database operation, and dropped on saturation or timeout.
    pub(crate) fn observe_server_key_usage(&self, principal: &ServerPrincipal) {
        let bucket_seconds = SERVER_KEY_USAGE_BUCKET.whole_seconds();
        let bucket_unix =
            self.clock.now().unix_timestamp().div_euclid(bucket_seconds) * bucket_seconds;
        let Ok(permit) = Arc::clone(&self.usage_telemetry.permits).try_acquire_owned() else {
            return;
        };
        let Ok(mut observed) = self.usage_telemetry.observed_buckets.lock() else {
            return;
        };
        observed.retain(|_, seen_bucket| *seen_bucket >= bucket_unix);
        let identity = (principal.project_id, principal.key_id);
        if observed
            .get(&identity)
            .is_some_and(|seen| *seen >= bucket_unix)
            || (observed.len() >= SERVER_USAGE_TELEMETRY_CAPACITY
                && !observed.contains_key(&identity))
        {
            return;
        }
        observed.insert(identity, bucket_unix);
        drop(observed);

        let Ok(bucket) = OffsetDateTime::from_unix_timestamp(bucket_unix) else {
            return;
        };
        let repository = Arc::clone(&self.repository);
        tokio::spawn(async move {
            let _permit = permit;
            let _ = tokio::time::timeout(
                std::time::Duration::from_millis(SERVER_USAGE_TELEMETRY_DEADLINE_MILLIS),
                repository.record_usage_if_older(identity.0, identity.1, bucket),
            )
            .await;
        });
    }

    pub(crate) async fn list_users(
        &self,
        principal: &ServerPrincipal,
        cursor: Option<&str>,
        limit: Option<usize>,
    ) -> Result<ServerUserPage, ApplicationError> {
        let limit = limit.unwrap_or(DEFAULT_SERVER_USER_PAGE_LIMIT);
        if limit == 0 || limit > MAX_SERVER_USER_PAGE_LIMIT {
            return Err(ApplicationError::InvalidInput);
        }
        let after = cursor.map(ServerUserCursor::parse).transpose()?;
        let mut rows = self
            .repository
            .list_users(
                principal.project_id,
                &principal.project_public_id,
                after,
                limit + 1,
            )
            .await?;
        let has_more = rows.len() > limit;
        if has_more {
            rows.truncate(limit);
        }
        let next_cursor = has_more
            .then(|| rows.last().map(|(cursor, _)| cursor.encode()))
            .flatten();
        Ok(ServerUserPage {
            users: rows.into_iter().map(|(_, user)| user).collect(),
            next_cursor,
        })
    }

    pub(crate) async fn user(
        &self,
        principal: &ServerPrincipal,
        user_public_id: &str,
    ) -> Result<ServerUser, ApplicationError> {
        self.repository
            .user_by_public_id(
                principal.project_id,
                &principal.project_public_id,
                user_public_id,
            )
            .await
    }

    pub(crate) async fn lookup_user_by_email(
        &self,
        principal: &ServerPrincipal,
        email: &str,
    ) -> Result<Option<ServerUser>, ApplicationError> {
        if email.len() > 320 {
            return Err(ApplicationError::InvalidInput);
        }
        let canonical = crate::domain::CanonicalEmail::parse_v1(email)
            .map_err(|_| ApplicationError::InvalidInput)?;
        let candidates = self
            .email_digester
            .digest_candidates(principal.project_id, canonical.expose())?;
        if candidates.is_empty() || candidates.len() > 32 {
            return Err(ApplicationError::Integrity);
        }
        self.repository
            .user_by_email_digests(
                principal.project_id,
                &principal.project_public_id,
                &candidates,
            )
            .await
    }

    pub(crate) async fn application_projection(
        &self,
        principal: &ServerPrincipal,
        application_public_id: &str,
        user_public_id: &str,
    ) -> Result<ServerApplicationProjection, ApplicationError> {
        self.repository
            .application_projection(
                principal.project_id,
                &principal.project_public_id,
                application_public_id,
                user_public_id,
            )
            .await
    }

    pub(crate) async fn introspect(
        &self,
        principal: &ServerPrincipal,
        token: &str,
        expected_application_public_id: Option<&str>,
    ) -> Result<ServerTokenIntrospection, ApplicationError> {
        match self
            .introspect_active(principal, token, expected_application_public_id)
            .await
        {
            Ok(active) => Ok(ServerTokenIntrospection::Active(Box::new(active))),
            Err(
                ApplicationError::InvalidInput
                | ApplicationError::NotFound
                | ApplicationError::Disabled
                | ApplicationError::InvalidTransition,
            ) => Ok(ServerTokenIntrospection::Inactive),
            Err(error) => Err(error),
        }
    }

    async fn introspect_active(
        &self,
        principal: &ServerPrincipal,
        token: &str,
        expected_application_public_id: Option<&str>,
    ) -> Result<ActiveServerToken, ApplicationError> {
        let parsed = ParsedAccessToken::parse(token)?;
        if expected_application_public_id
            .is_some_and(|expected| expected != parsed.claims.application_id)
        {
            return Err(ApplicationError::Disabled);
        }
        let now = self.clock.now();
        let key = self
            .repository
            .verification_key(principal.project_id, &parsed.header.kid, now)
            .await?;
        let claims = &parsed.claims;
        if key.project_id != principal.project_id
            || key.project_public_id != principal.project_public_id
            || claims.issuer != key.issuer
            || claims.audience != key.project_public_id
            || claims.claims_revision <= 0
            || claims.jwt_id.is_empty()
            || claims.issued_at > claims.not_before
            || claims.not_before > claims.expires_at
            || claims.authenticated_at > claims.issued_at
        {
            return Err(ApplicationError::Disabled);
        }
        let now_seconds = now.unix_timestamp();
        if claims.expires_at <= now_seconds - SERVER_TOKEN_CLOCK_SKEW_SECONDS
            || claims.not_before > now_seconds + SERVER_TOKEN_CLOCK_SKEW_SECONDS
            || claims.issued_at > now_seconds + SERVER_TOKEN_CLOCK_SKEW_SECONDS
        {
            return Err(ApplicationError::InvalidTransition);
        }
        self.token_verifier.verify(
            &key.public_jwk,
            parsed.signing_input.as_bytes(),
            &parsed.signature,
        )?;
        self.repository
            .introspect_session(ServerTokenSessionLookup {
                project_id: principal.project_id,
                application_public_id: claims.application_id.clone(),
                user_public_id: claims.subject.clone(),
                application_session_id: claims.session_id,
                claims_revision: claims.claims_revision,
                issued_at: OffsetDateTime::from_unix_timestamp(claims.issued_at)
                    .map_err(|_| ApplicationError::InvalidInput)?,
                expires_at: OffsetDateTime::from_unix_timestamp(claims.expires_at)
                    .map_err(|_| ApplicationError::InvalidInput)?,
                now,
            })
            .await
    }
}

fn generic_auth_error(error: ApplicationError) -> ApplicationError {
    match error {
        ApplicationError::Persistence | ApplicationError::Integrity => error,
        _ => ApplicationError::Disabled,
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AccessTokenHeader {
    alg: String,
    typ: String,
    kid: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AccessTokenClaims {
    #[serde(rename = "iss")]
    issuer: String,
    #[serde(rename = "aud")]
    audience: String,
    #[serde(rename = "sub")]
    subject: String,
    #[serde(rename = "app_id")]
    application_id: String,
    #[serde(rename = "sid")]
    session_id: Uuid,
    #[serde(rename = "iat")]
    issued_at: i64,
    #[serde(rename = "nbf")]
    not_before: i64,
    #[serde(rename = "exp")]
    expires_at: i64,
    #[serde(rename = "jti")]
    jwt_id: String,
    #[serde(rename = "auth_time")]
    authenticated_at: i64,
    #[serde(rename = "claims_rev")]
    claims_revision: i64,
}

struct ParsedAccessToken {
    header: AccessTokenHeader,
    claims: AccessTokenClaims,
    signing_input: String,
    signature: Vec<u8>,
}

impl ParsedAccessToken {
    fn parse(token: &str) -> Result<Self, ApplicationError> {
        if token.is_empty() || token.len() > MAX_SERVER_ACCESS_TOKEN_BYTES || !token.is_ascii() {
            return Err(ApplicationError::InvalidInput);
        }
        let mut parts = token.split('.');
        let (Some(encoded_header), Some(encoded_claims), Some(encoded_signature), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(ApplicationError::InvalidInput);
        };
        let decode = |encoded: &str| {
            URL_SAFE_NO_PAD
                .decode(encoded)
                .map_err(|_| ApplicationError::InvalidInput)
        };
        let header: AccessTokenHeader = serde_json::from_slice(&decode(encoded_header)?)
            .map_err(|_| ApplicationError::InvalidInput)?;
        let claims: AccessTokenClaims = serde_json::from_slice(&decode(encoded_claims)?)
            .map_err(|_| ApplicationError::InvalidInput)?;
        if header.alg != "EdDSA"
            || header.typ != SERVER_ACCESS_TOKEN_TYP
            || header.kid.is_empty()
            || header.kid.len() > 128
        {
            return Err(ApplicationError::InvalidInput);
        }
        let signature = decode(encoded_signature)?;
        if signature.len() != 64 {
            return Err(ApplicationError::InvalidInput);
        }
        Ok(Self {
            header,
            claims,
            signing_input: format!("{encoded_header}.{encoded_claims}"),
            signature,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicI64, AtomicUsize, Ordering};

    use super::*;

    struct TelemetryRepository {
        calls: AtomicUsize,
        active: AtomicUsize,
        maximum_active: AtomicUsize,
        delay_millis: u64,
    }

    struct ActiveTelemetryCall<'a>(&'a AtomicUsize);

    impl Drop for ActiveTelemetryCall<'_> {
        fn drop(&mut self) {
            self.0.fetch_sub(1, Ordering::SeqCst);
        }
    }

    #[async_trait]
    impl ServerApiRepository for TelemetryRepository {
        async fn server_key_authority(
            &self,
            _public_key_id: &str,
        ) -> Result<ServerKeyAuthority, ApplicationError> {
            Err(ApplicationError::NotFound)
        }

        async fn confirm_active(
            &self,
            _project_id: Uuid,
            _key_id: Uuid,
        ) -> Result<(), ApplicationError> {
            Ok(())
        }

        async fn record_usage_if_older(
            &self,
            _project_id: Uuid,
            _key_id: Uuid,
            _usage_bucket: OffsetDateTime,
        ) -> Result<(), ApplicationError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let active = self.active.fetch_add(1, Ordering::SeqCst) + 1;
            self.maximum_active.fetch_max(active, Ordering::SeqCst);
            let _active = ActiveTelemetryCall(&self.active);
            tokio::time::sleep(std::time::Duration::from_millis(self.delay_millis)).await;
            Ok(())
        }

        async fn list_users(
            &self,
            _project_id: Uuid,
            _project_public_id: &str,
            _after: Option<ServerUserCursor>,
            _limit_plus_one: usize,
        ) -> Result<Vec<(ServerUserCursor, ServerUser)>, ApplicationError> {
            Ok(Vec::new())
        }

        async fn user_by_public_id(
            &self,
            _project_id: Uuid,
            _project_public_id: &str,
            _user_public_id: &str,
        ) -> Result<ServerUser, ApplicationError> {
            Err(ApplicationError::NotFound)
        }

        async fn user_by_email_digests(
            &self,
            _project_id: Uuid,
            _project_public_id: &str,
            _candidates: &[VersionedDigest],
        ) -> Result<Option<ServerUser>, ApplicationError> {
            Ok(None)
        }

        async fn application_projection(
            &self,
            _project_id: Uuid,
            _project_public_id: &str,
            _application_public_id: &str,
            _user_public_id: &str,
        ) -> Result<ServerApplicationProjection, ApplicationError> {
            Err(ApplicationError::NotFound)
        }

        async fn verification_key(
            &self,
            _project_id: Uuid,
            _kid: &str,
            _now: OffsetDateTime,
        ) -> Result<ServerVerificationKey, ApplicationError> {
            Err(ApplicationError::NotFound)
        }

        async fn introspect_session(
            &self,
            _lookup: ServerTokenSessionLookup,
        ) -> Result<ActiveServerToken, ApplicationError> {
            Err(ApplicationError::Disabled)
        }
    }

    struct UnusedKeyVerifier;

    impl ServerKeyVerifier for UnusedKeyVerifier {
        fn digest_candidate(
            &self,
            _project_id: Uuid,
            _key_id: Uuid,
            _public_key_id: &str,
            _secret: &[u8; crate::application::SERVER_KEY_SECRET_BYTES],
            _digest_key_version: i32,
        ) -> Result<[u8; 32], ApplicationError> {
            Ok([0; 32])
        }
    }

    struct UnusedEmailDigester;

    impl EmailIdentityLookupDigester for UnusedEmailDigester {
        fn digest_candidates(
            &self,
            _project_id: Uuid,
            _canonical_email: &str,
        ) -> Result<Vec<VersionedDigest>, ApplicationError> {
            Ok(Vec::new())
        }
    }

    struct UnusedTokenVerifier;

    impl ServerTokenSignatureVerifier for UnusedTokenVerifier {
        fn verify(
            &self,
            _public_jwk: &Value,
            _signing_input: &[u8],
            _signature: &[u8],
        ) -> Result<(), ApplicationError> {
            Ok(())
        }
    }

    struct AdjustableClock(AtomicI64);

    impl Clock for AdjustableClock {
        fn now(&self) -> OffsetDateTime {
            OffsetDateTime::from_unix_timestamp(self.0.load(Ordering::SeqCst))
                .expect("test timestamp")
        }
    }

    fn telemetry_service(
        repository: Arc<TelemetryRepository>,
        clock: Arc<AdjustableClock>,
    ) -> ServerApiService {
        ServerApiService::new(
            repository,
            Arc::new(UnusedKeyVerifier),
            Arc::new(UnusedEmailDigester),
            Arc::new(UnusedTokenVerifier),
            clock,
        )
    }

    fn telemetry_principal(key: u128) -> ServerPrincipal {
        ServerPrincipal {
            project_id: Uuid::from_u128(1),
            project_public_id: "project".to_owned(),
            key_id: Uuid::from_u128(key),
            public_key_id: format!("key-{key}"),
        }
    }

    async fn wait_for_calls(repository: &TelemetryRepository, expected: usize) {
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while repository.calls.load(Ordering::SeqCst) < expected {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("telemetry call should start");
    }

    #[tokio::test]
    async fn usage_telemetry_coalesces_each_key_bucket_and_is_single_flight() {
        let repository = Arc::new(TelemetryRepository {
            calls: AtomicUsize::new(0),
            active: AtomicUsize::new(0),
            maximum_active: AtomicUsize::new(0),
            delay_millis: 20,
        });
        let clock = Arc::new(AdjustableClock(AtomicI64::new(1_800_000_000)));
        let service = telemetry_service(repository.clone(), clock.clone());
        let principal = telemetry_principal(2);

        for _ in 0..32 {
            service.observe_server_key_usage(&principal);
        }
        wait_for_calls(&repository, 1).await;
        tokio::time::sleep(std::time::Duration::from_millis(40)).await;
        service.observe_server_key_usage(&principal);
        tokio::time::sleep(std::time::Duration::from_millis(30)).await;
        assert_eq!(repository.calls.load(Ordering::SeqCst), 1);

        clock.0.fetch_add(15 * 60, Ordering::SeqCst);
        service.observe_server_key_usage(&principal);
        wait_for_calls(&repository, 2).await;
        assert_eq!(repository.maximum_active.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn usage_telemetry_drops_on_saturation_and_releases_permit_after_deadline() {
        let repository = Arc::new(TelemetryRepository {
            calls: AtomicUsize::new(0),
            active: AtomicUsize::new(0),
            maximum_active: AtomicUsize::new(0),
            delay_millis: 500,
        });
        let clock = Arc::new(AdjustableClock(AtomicI64::new(1_800_000_000)));
        let service = telemetry_service(repository.clone(), clock);

        service.observe_server_key_usage(&telemetry_principal(2));
        wait_for_calls(&repository, 1).await;
        service.observe_server_key_usage(&telemetry_principal(3));
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        assert_eq!(repository.calls.load(Ordering::SeqCst), 1);

        tokio::time::sleep(std::time::Duration::from_millis(
            SERVER_USAGE_TELEMETRY_DEADLINE_MILLIS + 30,
        ))
        .await;
        service.observe_server_key_usage(&telemetry_principal(3));
        wait_for_calls(&repository, 2).await;
        assert_eq!(repository.maximum_active.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn cursor_round_trip_is_fixed_canonical_and_rejects_malleability() {
        let cursor = ServerUserCursor {
            created_at: OffsetDateTime::from_unix_timestamp_nanos(1_234_567_890_123)
                .expect("timestamp"),
            user_id: Uuid::new_v4(),
        };
        let encoded = cursor.encode();
        assert_eq!(ServerUserCursor::parse(&encoded), Ok(cursor));
        assert_eq!(
            ServerUserCursor::parse(&format!("{encoded}=")),
            Err(ApplicationError::InvalidInput)
        );
        let mut bytes = URL_SAFE_NO_PAD.decode(encoded).expect("cursor bytes");
        bytes[0] = 2;
        assert_eq!(
            ServerUserCursor::parse(&URL_SAFE_NO_PAD.encode(bytes)),
            Err(ApplicationError::InvalidInput)
        );
    }

    #[test]
    fn access_token_parser_is_strict_and_bounded() {
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"EdDSA","typ":"at+jwt","kid":"k1"}"#);
        let claims = URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&serde_json::json!({
                "iss":"https://issuer.example/","aud":"project","sub":"user",
                "app_id":"app","sid":Uuid::nil(),"iat":1,"nbf":1,"exp":2,
                "jti":"j","auth_time":1,"claims_rev":1
            }))
            .expect("claims"),
        );
        let signature = URL_SAFE_NO_PAD.encode([0_u8; 64]);
        assert!(ParsedAccessToken::parse(&format!("{header}.{claims}.{signature}")).is_ok());
        assert!(ParsedAccessToken::parse(&format!("{header}.{claims}.{signature}.extra")).is_err());
    }
}
