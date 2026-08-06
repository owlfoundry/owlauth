use std::{
    sync::{
        Arc,
        atomic::{AtomicU8, Ordering},
    },
    time::Duration,
};

use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use owlauth_key_provider::{SealSecretRequest, SecretPlaintext};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use uuid::Uuid;
use zeroize::Zeroizing;

use super::{
    ApplicationError, Clock, ConfigurationSecretSealers, PreparedSecretMaterial,
    SealedProtectedMaterial,
};
use crate::domain::{
    ApplicationUserEventType, MAX_WEBHOOK_DELIVERY_ATTEMPTS, WebhookDeliveryOutcome,
    WebhookEndpointStatus, WebhookEndpointUrl, WebhookSubscriptions,
};

const MIN_WEBHOOK_SECRET_BYTES: usize = 32;
const MAX_WEBHOOK_SECRET_BYTES: usize = 128;
const MIN_SECRET_OVERLAP_SECONDS: i64 = 300;
const MAX_SECRET_OVERLAP_SECONDS: i64 = 86_400;
const MAX_CONTROL_RESULTS: usize = 100;
const DEFAULT_CONTROL_RESULTS: usize = 50;
const WEBHOOK_MAINTENANCE_ROWS: u32 = 25;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct WebhookEndpointRecord {
    pub id: Uuid,
    pub public_id: String,
    pub project_id: Uuid,
    pub application_id: Uuid,
    pub url: String,
    pub subscribed_event_types: Vec<String>,
    pub status: String,
    pub revision: i64,
    pub current_secret_generation: Option<i32>,
    pub overlap_secret_generation: Option<i32>,
    pub overlap_expires_at: Option<OffsetDateTime>,
    pub consecutive_failure_count: i32,
    pub last_delivery_at: Option<OffsetDateTime>,
    pub last_success_at: Option<OffsetDateTime>,
    pub last_failure_class: Option<String>,
    pub last_tested_at: Option<OffsetDateTime>,
    pub last_test_succeeded_at: Option<OffsetDateTime>,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ApplicationUserEventRecord {
    pub id: Uuid,
    pub event_id: String,
    pub project_id: Uuid,
    pub application_id: Uuid,
    pub user_id: Uuid,
    pub event_type: String,
    pub user_revision: i64,
    pub projection_revision: i64,
    pub projection_schema: String,
    pub safe_body: serde_json::Value,
    pub occurred_at: OffsetDateTime,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct WebhookDeliveryRecord {
    pub id: Uuid,
    pub endpoint_id: Uuid,
    pub event_id: String,
    pub replay_sequence: i32,
    pub replay_of_delivery_id: Option<Uuid>,
    pub state: String,
    pub attempt_count: i32,
    pub next_attempt_at: OffsetDateTime,
    pub last_outcome_class: Option<String>,
    pub last_http_status: Option<i32>,
    pub delivered_at: Option<OffsetDateTime>,
    pub terminal_at: Option<OffsetDateTime>,
    pub created_at: OffsetDateTime,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct HistoryCursor {
    pub timestamp: OffsetDateTime,
    pub id: Uuid,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct HistoryPage<T> {
    pub items: Vec<T>,
    pub next_cursor: Option<String>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct EncodedHistoryCursor {
    v: u8,
    t: String,
    id: Uuid,
}

pub(crate) struct CreateWebhookEndpoint {
    pub url: String,
    pub subscribed_event_types: Vec<String>,
    pub secret: Zeroizing<Vec<u8>>,
    pub idempotency_key: String,
}

#[derive(Clone, Debug)]
pub(crate) struct UpdateWebhookEndpoint {
    pub subscribed_event_types: Vec<String>,
    pub expected_revision: i64,
}

pub(crate) struct PrepareWebhookSecretRotation {
    pub secret: Zeroizing<Vec<u8>>,
    pub idempotency_key: String,
    pub expected_revision: i64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WebhookSecretPreparationState {
    Pending,
    Provisioned,
    Terminal,
}

#[derive(Clone, Debug)]
pub(crate) struct PreparedWebhookSecret {
    pub endpoint: WebhookEndpointRecord,
    pub generation: i32,
    pub material: PreparedSecretMaterial,
    pub preparation_state: WebhookSecretPreparationState,
    pub already_active: bool,
}

#[derive(Clone, Debug)]
pub(crate) struct PreparedWebhookEndpoint {
    pub endpoint: WebhookEndpointRecord,
    pub material: PreparedSecretMaterial,
    pub preparation_state: WebhookSecretPreparationState,
}

#[derive(Clone, Debug)]
pub(crate) struct PrepareWebhookEndpoint {
    pub url: String,
    pub subscribed_event_types: Vec<String>,
    pub idempotency_key: String,
    pub request_fingerprint: Vec<u8>,
}

#[derive(Clone, Debug)]
pub(crate) struct PrepareWebhookRotation {
    pub idempotency_key: String,
    pub request_fingerprint: Vec<u8>,
    pub expected_revision: i64,
}

#[async_trait]
#[allow(
    clippy::too_many_arguments,
    reason = "repository commands preserve explicit Project/Application/revision custody"
)]
pub(crate) trait WebhookControlPort: Send + Sync {
    async fn prepare_endpoint(
        &self,
        project_id: Uuid,
        application_id: Uuid,
        command: PrepareWebhookEndpoint,
        now: OffsetDateTime,
        correlation_id: Uuid,
    ) -> Result<PreparedWebhookEndpoint, ApplicationError>;

    async fn finalize_protected_secret(
        &self,
        project_id: Uuid,
        application_id: Uuid,
        endpoint_id: Uuid,
        generation: i32,
        expected_endpoint_revision: i64,
        request_fingerprint: &[u8],
        material: SealedProtectedMaterial,
        now: OffsetDateTime,
        correlation_id: Uuid,
    ) -> Result<(), ApplicationError>;

    async fn get_endpoint(
        &self,
        project_id: Uuid,
        application_id: Uuid,
        endpoint_id: Uuid,
    ) -> Result<WebhookEndpointRecord, ApplicationError>;

    async fn record_endpoint_test_success(
        &self,
        project_id: Uuid,
        application_id: Uuid,
        endpoint_id: Uuid,
        expected_revision: i64,
        now: OffsetDateTime,
        correlation_id: Uuid,
    ) -> Result<WebhookEndpointRecord, ApplicationError>;

    async fn activate_prepared_endpoint(
        &self,
        project_id: Uuid,
        application_id: Uuid,
        endpoint_id: Uuid,
        expected_revision: i64,
        now: OffsetDateTime,
        correlation_id: Uuid,
    ) -> Result<WebhookEndpointRecord, ApplicationError>;

    async fn list_endpoints(
        &self,
        project_id: Uuid,
        application_id: Uuid,
    ) -> Result<Vec<WebhookEndpointRecord>, ApplicationError>;

    async fn update_endpoint(
        &self,
        project_id: Uuid,
        application_id: Uuid,
        endpoint_id: Uuid,
        command: UpdateWebhookEndpoint,
        now: OffsetDateTime,
        correlation_id: Uuid,
    ) -> Result<WebhookEndpointRecord, ApplicationError>;

    async fn disable_endpoint(
        &self,
        project_id: Uuid,
        application_id: Uuid,
        endpoint_id: Uuid,
        expected_revision: i64,
        now: OffsetDateTime,
        correlation_id: Uuid,
    ) -> Result<WebhookEndpointRecord, ApplicationError>;

    async fn prepare_secret_rotation(
        &self,
        project_id: Uuid,
        application_id: Uuid,
        endpoint_id: Uuid,
        command: PrepareWebhookRotation,
        now: OffsetDateTime,
        correlation_id: Uuid,
    ) -> Result<PreparedWebhookSecret, ApplicationError>;

    async fn activate_secret_rotation(
        &self,
        project_id: Uuid,
        application_id: Uuid,
        endpoint_id: Uuid,
        generation: i32,
        expected_revision: i64,
        overlap_seconds: i64,
        correlation_id: Uuid,
    ) -> Result<WebhookEndpointRecord, ApplicationError>;

    async fn list_events(
        &self,
        project_id: Uuid,
        application_id: Uuid,
        cursor: Option<HistoryCursor>,
        limit: usize,
    ) -> Result<Vec<ApplicationUserEventRecord>, ApplicationError>;

    async fn list_deliveries(
        &self,
        project_id: Uuid,
        application_id: Uuid,
        endpoint_id: Option<Uuid>,
        cursor: Option<HistoryCursor>,
        limit: usize,
    ) -> Result<Vec<WebhookDeliveryRecord>, ApplicationError>;

    async fn replay_delivery(
        &self,
        project_id: Uuid,
        application_id: Uuid,
        delivery_id: Uuid,
        now: OffsetDateTime,
        correlation_id: Uuid,
    ) -> Result<WebhookDeliveryRecord, ApplicationError>;
}

#[async_trait]
pub(crate) trait WebhookEndpointValidator: Send + Sync {
    async fn validate(&self, endpoint_url: &str) -> Result<(), ApplicationError>;
}

#[derive(Clone)]
pub(crate) struct WebhookControlService {
    port: Arc<dyn WebhookControlPort>,
    secret_sealers: ConfigurationSecretSealers,
    validator: Arc<dyn WebhookEndpointValidator>,
    clock: Arc<dyn Clock>,
}

impl WebhookControlService {
    pub(crate) fn new_protected(
        port: Arc<dyn WebhookControlPort>,
        secret_sealers: ConfigurationSecretSealers,
        validator: Arc<dyn WebhookEndpointValidator>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            port,
            secret_sealers,
            validator,
            clock,
        }
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the durable protected webhook prepare, seal, and finalize sequence remains explicit"
    )]
    pub(crate) async fn create_endpoint(
        &self,
        project_id: Uuid,
        application_id: Uuid,
        command: CreateWebhookEndpoint,
        correlation_id: Uuid,
    ) -> Result<WebhookEndpointRecord, ApplicationError> {
        validate_idempotency_key(&command.idempotency_key)?;
        validate_secret(&command.secret)?;
        let url = WebhookEndpointUrl::parse(command.url)?.into_inner();
        self.validator.validate(&url).await?;
        let subscriptions =
            WebhookSubscriptions::parse(&command.subscribed_event_types)?.into_strings();
        let protected_fingerprint = || {
            protected_webhook_request_digest(&[
                b"endpoint-v1",
                url.as_bytes(),
                command.idempotency_key.as_bytes(),
                subscriptions.join("\0").as_bytes(),
            ])
        };
        let fingerprint = protected_fingerprint();
        let prepared = self
            .port
            .prepare_endpoint(
                project_id,
                application_id,
                PrepareWebhookEndpoint {
                    url,
                    subscribed_event_types: subscriptions,
                    idempotency_key: command.idempotency_key,
                    request_fingerprint: fingerprint.clone(),
                },
                self.clock.now(),
                correlation_id,
            )
            .await?;
        if prepared.preparation_state != WebhookSecretPreparationState::Terminal {
            let material = prepared.material.clone();
            let sealer = self.secret_sealers.resolve(&material)?;
            let protected_secret = sealer
                .seal(SealSecretRequest {
                    context: material.context,
                    plaintext: SecretPlaintext::from_zeroizing(command.secret)
                        .map_err(|_| ApplicationError::InvalidInput)?,
                })
                .await
                .map_err(super::provisioning::map_provider_error)?;
            self.port
                .finalize_protected_secret(
                    project_id,
                    application_id,
                    prepared.endpoint.id,
                    1,
                    prepared.endpoint.revision,
                    &fingerprint,
                    SealedProtectedMaterial {
                        material_id: material.material_id,
                        provider_id: material.provider_id,
                        provider_format_version: material.provider_format_version,
                        envelope: protected_secret.envelope,
                        request_fingerprint: protected_secret.request_fingerprint,
                    },
                    self.clock.now(),
                    correlation_id,
                )
                .await?;
        }
        Ok(prepared.endpoint)
    }

    pub(crate) async fn get_endpoint(
        &self,
        project_id: Uuid,
        application_id: Uuid,
        endpoint_id: Uuid,
    ) -> Result<WebhookEndpointRecord, ApplicationError> {
        self.port
            .get_endpoint(project_id, application_id, endpoint_id)
            .await
    }

    pub(crate) async fn test_endpoint(
        &self,
        project_id: Uuid,
        application_id: Uuid,
        endpoint_id: Uuid,
        expected_revision: i64,
        correlation_id: Uuid,
    ) -> Result<WebhookEndpointRecord, ApplicationError> {
        positive_revision(expected_revision)?;
        let endpoint = self
            .port
            .get_endpoint(project_id, application_id, endpoint_id)
            .await?;
        if endpoint.revision != expected_revision {
            return Err(ApplicationError::RevisionConflict);
        }
        self.validator.validate(&endpoint.url).await?;
        self.port
            .record_endpoint_test_success(
                project_id,
                application_id,
                endpoint_id,
                expected_revision,
                self.clock.now(),
                correlation_id,
            )
            .await
    }

    pub(crate) async fn activate_endpoint(
        &self,
        project_id: Uuid,
        application_id: Uuid,
        endpoint_id: Uuid,
        expected_revision: i64,
        correlation_id: Uuid,
    ) -> Result<WebhookEndpointRecord, ApplicationError> {
        positive_revision(expected_revision)?;
        let endpoint = self
            .port
            .get_endpoint(project_id, application_id, endpoint_id)
            .await?;
        if endpoint.status == "active" && endpoint.revision == expected_revision.saturating_add(1) {
            return Ok(endpoint);
        }
        if endpoint.revision != expected_revision {
            return Err(ApplicationError::RevisionConflict);
        }
        self.validator.validate(&endpoint.url).await?;
        self.port
            .activate_prepared_endpoint(
                project_id,
                application_id,
                endpoint_id,
                expected_revision,
                self.clock.now(),
                correlation_id,
            )
            .await
    }

    pub(crate) async fn list_endpoints(
        &self,
        project_id: Uuid,
        application_id: Uuid,
    ) -> Result<Vec<WebhookEndpointRecord>, ApplicationError> {
        let records = self.port.list_endpoints(project_id, application_id).await?;
        if records.len() > MAX_CONTROL_RESULTS {
            return Err(ApplicationError::Integrity);
        }
        Ok(records)
    }

    pub(crate) async fn update_endpoint(
        &self,
        project_id: Uuid,
        application_id: Uuid,
        endpoint_id: Uuid,
        mut command: UpdateWebhookEndpoint,
        correlation_id: Uuid,
    ) -> Result<WebhookEndpointRecord, ApplicationError> {
        command.subscribed_event_types =
            WebhookSubscriptions::parse(&command.subscribed_event_types)?.into_strings();
        positive_revision(command.expected_revision)?;
        self.port
            .update_endpoint(
                project_id,
                application_id,
                endpoint_id,
                command,
                self.clock.now(),
                correlation_id,
            )
            .await
    }

    pub(crate) async fn disable_endpoint(
        &self,
        project_id: Uuid,
        application_id: Uuid,
        endpoint_id: Uuid,
        expected_revision: i64,
        correlation_id: Uuid,
    ) -> Result<WebhookEndpointRecord, ApplicationError> {
        positive_revision(expected_revision)?;
        self.port
            .disable_endpoint(
                project_id,
                application_id,
                endpoint_id,
                expected_revision,
                self.clock.now(),
                correlation_id,
            )
            .await
    }

    pub(crate) async fn prepare_secret_rotation(
        &self,
        project_id: Uuid,
        application_id: Uuid,
        endpoint_id: Uuid,
        command: PrepareWebhookSecretRotation,
        correlation_id: Uuid,
    ) -> Result<PreparedWebhookSecret, ApplicationError> {
        validate_idempotency_key(&command.idempotency_key)?;
        validate_secret(&command.secret)?;
        positive_revision(command.expected_revision)?;
        let protected_fingerprint = || {
            protected_webhook_request_digest(&[
                b"rotation-v1",
                endpoint_id.as_bytes(),
                command.idempotency_key.as_bytes(),
            ])
        };
        let fingerprint = protected_fingerprint();
        let prepared = self
            .port
            .prepare_secret_rotation(
                project_id,
                application_id,
                endpoint_id,
                PrepareWebhookRotation {
                    idempotency_key: command.idempotency_key,
                    request_fingerprint: fingerprint.clone(),
                    expected_revision: command.expected_revision,
                },
                self.clock.now(),
                correlation_id,
            )
            .await?;
        if prepared.preparation_state != WebhookSecretPreparationState::Terminal {
            let material = prepared.material.clone();
            let sealer = self.secret_sealers.resolve(&material)?;
            let protected_secret = sealer
                .seal(SealSecretRequest {
                    context: material.context,
                    plaintext: SecretPlaintext::from_zeroizing(command.secret)
                        .map_err(|_| ApplicationError::InvalidInput)?,
                })
                .await
                .map_err(super::provisioning::map_provider_error)?;
            self.port
                .finalize_protected_secret(
                    project_id,
                    application_id,
                    endpoint_id,
                    prepared.generation,
                    prepared.endpoint.revision,
                    &fingerprint,
                    SealedProtectedMaterial {
                        material_id: material.material_id,
                        provider_id: material.provider_id,
                        provider_format_version: material.provider_format_version,
                        envelope: protected_secret.envelope,
                        request_fingerprint: protected_secret.request_fingerprint,
                    },
                    self.clock.now(),
                    correlation_id,
                )
                .await?;
        }
        Ok(prepared)
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn activate_secret_rotation(
        &self,
        project_id: Uuid,
        application_id: Uuid,
        endpoint_id: Uuid,
        generation: i32,
        expected_revision: i64,
        overlap_seconds: i64,
        correlation_id: Uuid,
    ) -> Result<WebhookEndpointRecord, ApplicationError> {
        if generation < 1
            || !(MIN_SECRET_OVERLAP_SECONDS..=MAX_SECRET_OVERLAP_SECONDS).contains(&overlap_seconds)
        {
            return Err(ApplicationError::InvalidInput);
        }
        positive_revision(expected_revision)?;
        self.port
            .activate_secret_rotation(
                project_id,
                application_id,
                endpoint_id,
                generation,
                expected_revision,
                overlap_seconds,
                correlation_id,
            )
            .await
    }

    pub(crate) async fn list_events(
        &self,
        project_id: Uuid,
        application_id: Uuid,
        cursor: Option<&str>,
        limit: Option<usize>,
    ) -> Result<HistoryPage<ApplicationUserEventRecord>, ApplicationError> {
        let limit = history_limit(limit)?;
        let records = self
            .port
            .list_events(
                project_id,
                application_id,
                decode_cursor(cursor)?,
                limit + 1,
            )
            .await?;
        history_page(records, limit, |record| HistoryCursor {
            timestamp: record.occurred_at,
            id: record.id,
        })
    }

    pub(crate) async fn list_deliveries(
        &self,
        project_id: Uuid,
        application_id: Uuid,
        endpoint_id: Option<Uuid>,
        cursor: Option<&str>,
        limit: Option<usize>,
    ) -> Result<HistoryPage<WebhookDeliveryRecord>, ApplicationError> {
        let limit = history_limit(limit)?;
        let records = self
            .port
            .list_deliveries(
                project_id,
                application_id,
                endpoint_id,
                decode_cursor(cursor)?,
                limit + 1,
            )
            .await?;
        history_page(records, limit, |record| HistoryCursor {
            timestamp: record.created_at,
            id: record.id,
        })
    }

    pub(crate) async fn replay_delivery(
        &self,
        project_id: Uuid,
        application_id: Uuid,
        delivery_id: Uuid,
        correlation_id: Uuid,
    ) -> Result<WebhookDeliveryRecord, ApplicationError> {
        self.port
            .replay_delivery(
                project_id,
                application_id,
                delivery_id,
                self.clock.now(),
                correlation_id,
            )
            .await
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ClaimedWebhookSecretCleanup {
    pub id: Uuid,
    pub material_id: Uuid,
    pub lease_owner: String,
    pub lease_incarnation: Uuid,
    pub lease_generation: i64,
}

#[derive(Clone, Debug)]
pub(crate) struct ClaimedWebhookDelivery {
    pub delivery_id: Uuid,
    pub lease_owner: String,
    pub lease_incarnation: Uuid,
    pub lease_generation: i64,
    pub event_id: String,
    pub endpoint_url: String,
    pub raw_body: Vec<u8>,
    pub primary_secret_material_id: Uuid,
    pub overlap_secret_material_id: Option<Uuid>,
    pub attempt_number: i32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct WebhookTransportOutcome {
    pub outcome: WebhookDeliveryOutcome,
    pub http_status: Option<u16>,
    pub duration_millis: u32,
}

#[async_trait]
pub(crate) trait WebhookDeliveryRepository: Send + Sync {
    async fn maintain(&self, now: OffsetDateTime, row_budget: u32)
    -> Result<u32, ApplicationError>;

    async fn claim_secret_cleanup(
        &self,
        worker_id: &str,
        worker_incarnation: Uuid,
        now: OffsetDateTime,
        lease_duration: Duration,
    ) -> Result<Option<ClaimedWebhookSecretCleanup>, ApplicationError>;

    async fn finish_secret_cleanup(
        &self,
        cleanup: &ClaimedWebhookSecretCleanup,
        now: OffsetDateTime,
    ) -> Result<(), ApplicationError>;

    async fn claim_one(
        &self,
        worker_id: &str,
        worker_incarnation: Uuid,
        now: OffsetDateTime,
        lease_duration: Duration,
    ) -> Result<Option<ClaimedWebhookDelivery>, ApplicationError>;

    async fn finish(
        &self,
        claim: &ClaimedWebhookDelivery,
        attempt_timestamp: i64,
        outcome: WebhookTransportOutcome,
        next_attempt_at: Option<OffsetDateTime>,
        now: OffsetDateTime,
        correlation_id: Uuid,
    ) -> Result<(), ApplicationError>;
}

#[async_trait]
pub(crate) trait WebhookSecretResolver: Send + Sync {
    async fn resolve(&self, material_id: Uuid) -> Result<Zeroizing<Vec<u8>>, ApplicationError>;
}

#[async_trait]
pub(crate) trait WebhookTransport: Send + Sync {
    async fn post(
        &self,
        endpoint_url: &str,
        event_id: &str,
        attempt_timestamp: i64,
        signature: &str,
        raw_body: &[u8],
    ) -> WebhookTransportOutcome;
}

pub(crate) struct WebhookWorker {
    repository: Arc<dyn WebhookDeliveryRepository>,
    secrets: Arc<dyn WebhookSecretResolver>,
    transport: Arc<dyn WebhookTransport>,
    clock: Arc<dyn Clock>,
    worker_id: String,
    worker_incarnation: Uuid,
    lease_duration: Duration,
    schedule_cursor: AtomicU8,
}

impl WebhookWorker {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        repository: Arc<dyn WebhookDeliveryRepository>,
        secrets: Arc<dyn WebhookSecretResolver>,
        transport: Arc<dyn WebhookTransport>,
        clock: Arc<dyn Clock>,
        worker_id: String,
        worker_incarnation: Uuid,
        lease_duration: Duration,
    ) -> Result<Self, ApplicationError> {
        if worker_id.is_empty() || worker_id.len() > 128 || lease_duration.is_zero() {
            return Err(ApplicationError::InvalidInput);
        }
        Ok(Self {
            repository,
            secrets,
            transport,
            clock,
            worker_id,
            worker_incarnation,
            lease_duration,
            schedule_cursor: AtomicU8::new(0),
        })
    }

    pub(crate) async fn run_once(&self) -> Result<bool, ApplicationError> {
        let now = self.clock.now();
        let lane = self.schedule_cursor.fetch_add(1, Ordering::Relaxed) % 3;
        if lane == 0 {
            match self
                .repository
                .maintain(now, WEBHOOK_MAINTENANCE_ROWS)
                .await
            {
                Ok(affected) if affected > 0 => return Ok(true),
                Ok(_) => {}
                Err(error) => tracing::warn!(
                    event = "webhook_maintenance_failed",
                    error = ?error,
                    "bounded webhook maintenance will retry without blocking delivery"
                ),
            }
        }
        if lane == 1 && self.run_secret_cleanup_once(now).await? {
            return Ok(true);
        }
        self.run_delivery_once(now).await
    }

    async fn run_delivery_once(&self, now: OffsetDateTime) -> Result<bool, ApplicationError> {
        let Some(claim) = self
            .repository
            .claim_one(
                &self.worker_id,
                self.worker_incarnation,
                now,
                self.lease_duration,
            )
            .await?
        else {
            return Ok(false);
        };
        let attempt_timestamp = now.unix_timestamp();
        let Ok(primary) = self.secrets.resolve(claim.primary_secret_material_id).await else {
            return self
                .finish_claim(
                    &claim,
                    attempt_timestamp,
                    WebhookDeliveryOutcome::Transient,
                    now,
                )
                .await;
        };
        let Ok(primary_signature) = webhook_signature(
            &primary,
            attempt_timestamp,
            &claim.event_id,
            &claim.raw_body,
        ) else {
            return self
                .finish_claim(
                    &claim,
                    attempt_timestamp,
                    WebhookDeliveryOutcome::Permanent,
                    now,
                )
                .await;
        };
        let mut signatures = vec![primary_signature];
        if let Some(overlap_material_id) = claim.overlap_secret_material_id {
            let Ok(overlap) = self.secrets.resolve(overlap_material_id).await else {
                return self
                    .finish_claim(
                        &claim,
                        attempt_timestamp,
                        WebhookDeliveryOutcome::Transient,
                        now,
                    )
                    .await;
            };
            let Ok(overlap_signature) = webhook_signature(
                &overlap,
                attempt_timestamp,
                &claim.event_id,
                &claim.raw_body,
            ) else {
                return self
                    .finish_claim(
                        &claim,
                        attempt_timestamp,
                        WebhookDeliveryOutcome::Permanent,
                        now,
                    )
                    .await;
            };
            signatures.push(overlap_signature);
        }
        let signature = signatures.join(",");
        let outcome = self
            .transport
            .post(
                &claim.endpoint_url,
                &claim.event_id,
                attempt_timestamp,
                &signature,
                &claim.raw_body,
            )
            .await;
        self.finish_transport_claim(&claim, attempt_timestamp, outcome, now)
            .await
    }

    async fn run_secret_cleanup_once(&self, now: OffsetDateTime) -> Result<bool, ApplicationError> {
        let Some(cleanup) = self
            .repository
            .claim_secret_cleanup(
                &self.worker_id,
                self.worker_incarnation,
                now,
                self.lease_duration,
            )
            .await?
        else {
            return Ok(false);
        };
        self.repository
            .finish_secret_cleanup(&cleanup, self.clock.now())
            .await?;
        Ok(true)
    }

    async fn finish_claim(
        &self,
        claim: &ClaimedWebhookDelivery,
        attempt_timestamp: i64,
        outcome: WebhookDeliveryOutcome,
        now: OffsetDateTime,
    ) -> Result<bool, ApplicationError> {
        self.finish_transport_claim(
            claim,
            attempt_timestamp,
            WebhookTransportOutcome {
                outcome,
                http_status: None,
                duration_millis: 0,
            },
            now,
        )
        .await
    }

    async fn finish_transport_claim(
        &self,
        claim: &ClaimedWebhookDelivery,
        attempt_timestamp: i64,
        outcome: WebhookTransportOutcome,
        now: OffsetDateTime,
    ) -> Result<bool, ApplicationError> {
        let next_attempt_at = if outcome.outcome.retryable()
            && claim.attempt_number < MAX_WEBHOOK_DELIVERY_ATTEMPTS
        {
            Some(retry_at(now, claim.delivery_id, claim.attempt_number)?)
        } else {
            None
        };
        self.repository
            .finish(
                claim,
                attempt_timestamp,
                outcome,
                next_attempt_at,
                self.clock.now(),
                Uuid::new_v4(),
            )
            .await?;
        Ok(true)
    }
}

pub(crate) fn webhook_signature(
    secret: &[u8],
    timestamp: i64,
    event_id: &str,
    raw_body: &[u8],
) -> Result<String, ApplicationError> {
    validate_secret(secret)?;
    if timestamp <= 0 || event_id.is_empty() || event_id.len() > 128 {
        return Err(ApplicationError::InvalidInput);
    }
    let mut mac =
        Hmac::<Sha256>::new_from_slice(secret).map_err(|_| ApplicationError::Integrity)?;
    mac.update(timestamp.to_string().as_bytes());
    mac.update(b".");
    mac.update(event_id.as_bytes());
    mac.update(b".");
    mac.update(raw_body);
    Ok(format!(
        "v1={}",
        URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
    ))
}

fn retry_at(
    now: OffsetDateTime,
    delivery_id: Uuid,
    attempt_number: i32,
) -> Result<OffsetDateTime, ApplicationError> {
    let exponent =
        u32::try_from(attempt_number.clamp(1, 10) - 1).map_err(|_| ApplicationError::Integrity)?;
    let base = 5_i64
        .checked_mul(1_i64.checked_shl(exponent).unwrap_or(i64::MAX))
        .unwrap_or(3600)
        .min(3600);
    let jitter = i64::from(delivery_id.as_bytes()[0] % 11);
    now.checked_add(time::Duration::seconds(base + jitter))
        .ok_or(ApplicationError::Integrity)
}

fn protected_webhook_request_digest(parts: &[&[u8]]) -> Vec<u8> {
    let mut digest = Sha256::new();
    digest.update(b"owlauth-webhook-protected-request-v1\0");
    for part in parts {
        digest.update(u64::try_from(part.len()).unwrap_or(u64::MAX).to_be_bytes());
        digest.update(part);
    }
    digest.finalize().to_vec()
}

fn validate_secret(secret: &[u8]) -> Result<(), ApplicationError> {
    if !(MIN_WEBHOOK_SECRET_BYTES..=MAX_WEBHOOK_SECRET_BYTES).contains(&secret.len()) {
        return Err(ApplicationError::InvalidInput);
    }
    Ok(())
}

fn validate_idempotency_key(value: &str) -> Result<(), ApplicationError> {
    if value.is_empty() || value.len() > 128 || value.chars().any(char::is_control) {
        return Err(ApplicationError::InvalidInput);
    }
    Ok(())
}

fn positive_revision(value: i64) -> Result<(), ApplicationError> {
    if value < 1 {
        return Err(ApplicationError::InvalidInput);
    }
    Ok(())
}

fn history_limit(limit: Option<usize>) -> Result<usize, ApplicationError> {
    let limit = limit.unwrap_or(DEFAULT_CONTROL_RESULTS);
    if !(1..=MAX_CONTROL_RESULTS).contains(&limit) {
        return Err(ApplicationError::InvalidInput);
    }
    Ok(limit)
}

fn history_page<T>(
    mut records: Vec<T>,
    limit: usize,
    cursor: impl Fn(&T) -> HistoryCursor,
) -> Result<HistoryPage<T>, ApplicationError> {
    if records.len() > limit + 1 {
        return Err(ApplicationError::Integrity);
    }
    let has_more = records.len() > limit;
    records.truncate(limit);
    let next_cursor = has_more
        .then(|| records.last().map(&cursor))
        .flatten()
        .map(encode_cursor)
        .transpose()?;
    Ok(HistoryPage {
        items: records,
        next_cursor,
    })
}

fn encode_cursor(cursor: HistoryCursor) -> Result<String, ApplicationError> {
    let value = EncodedHistoryCursor {
        v: 1,
        t: cursor
            .timestamp
            .format(&Rfc3339)
            .map_err(|_| ApplicationError::Integrity)?,
        id: cursor.id,
    };
    let bytes = serde_json::to_vec(&value).map_err(|_| ApplicationError::Integrity)?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

fn decode_cursor(value: Option<&str>) -> Result<Option<HistoryCursor>, ApplicationError> {
    let Some(value) = value else { return Ok(None) };
    if value.is_empty() || value.len() > 512 {
        return Err(ApplicationError::InvalidInput);
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| ApplicationError::InvalidInput)?;
    let cursor: EncodedHistoryCursor =
        serde_json::from_slice(&bytes).map_err(|_| ApplicationError::InvalidInput)?;
    if cursor.v != 1 {
        return Err(ApplicationError::InvalidInput);
    }
    Ok(Some(HistoryCursor {
        timestamp: OffsetDateTime::parse(&cursor.t, &Rfc3339)
            .map_err(|_| ApplicationError::InvalidInput)?,
        id: cursor.id,
    }))
}

pub(crate) fn endpoint_status(value: &str) -> Result<WebhookEndpointStatus, ApplicationError> {
    WebhookEndpointStatus::parse(value).map_err(Into::into)
}

pub(crate) fn event_type(value: &str) -> Result<ApplicationUserEventType, ApplicationError> {
    ApplicationUserEventType::parse(value).map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    struct FixedClock(OffsetDateTime);

    impl Clock for FixedClock {
        fn now(&self) -> OffsetDateTime {
            self.0
        }
    }

    struct OneClaimRepository {
        claim: Mutex<Option<ClaimedWebhookDelivery>>,
        finished: Mutex<Option<(WebhookTransportOutcome, Option<OffsetDateTime>)>>,
    }

    #[async_trait]
    impl WebhookDeliveryRepository for OneClaimRepository {
        async fn maintain(
            &self,
            _now: OffsetDateTime,
            _row_budget: u32,
        ) -> Result<u32, ApplicationError> {
            Ok(0)
        }

        async fn claim_secret_cleanup(
            &self,
            _worker_id: &str,
            _worker_incarnation: Uuid,
            _now: OffsetDateTime,
            _lease_duration: Duration,
        ) -> Result<Option<ClaimedWebhookSecretCleanup>, ApplicationError> {
            Ok(None)
        }

        async fn finish_secret_cleanup(
            &self,
            _cleanup: &ClaimedWebhookSecretCleanup,
            _now: OffsetDateTime,
        ) -> Result<(), ApplicationError> {
            unreachable!("no cleanup is returned")
        }

        async fn claim_one(
            &self,
            _worker_id: &str,
            _worker_incarnation: Uuid,
            _now: OffsetDateTime,
            _lease_duration: Duration,
        ) -> Result<Option<ClaimedWebhookDelivery>, ApplicationError> {
            Ok(self.claim.lock().expect("claim lock").take())
        }

        async fn finish(
            &self,
            _claim: &ClaimedWebhookDelivery,
            _attempt_timestamp: i64,
            outcome: WebhookTransportOutcome,
            next_attempt_at: Option<OffsetDateTime>,
            _now: OffsetDateTime,
            _correlation_id: Uuid,
        ) -> Result<(), ApplicationError> {
            self.finished
                .lock()
                .expect("finish lock")
                .replace((outcome, next_attempt_at));
            Ok(())
        }
    }

    struct UnavailableSecretResolver;

    #[async_trait]
    impl WebhookSecretResolver for UnavailableSecretResolver {
        async fn resolve(
            &self,
            _material_id: Uuid,
        ) -> Result<Zeroizing<Vec<u8>>, ApplicationError> {
            Err(ApplicationError::ExternalStore)
        }
    }

    struct UnexpectedTransport;

    #[async_trait]
    impl WebhookTransport for UnexpectedTransport {
        async fn post(
            &self,
            _endpoint_url: &str,
            _event_id: &str,
            _attempt_timestamp: i64,
            _signature: &str,
            _raw_body: &[u8],
        ) -> WebhookTransportOutcome {
            panic!("pre-dispatch secret failure must not call the transport")
        }
    }

    #[tokio::test]
    async fn pre_dispatch_secret_failure_finishes_the_claim_with_bounded_retry() {
        let now = OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();
        let repository = Arc::new(OneClaimRepository {
            claim: Mutex::new(Some(ClaimedWebhookDelivery {
                delivery_id: Uuid::from_u128(1),
                lease_owner: "runtime-a".to_owned(),
                lease_incarnation: Uuid::from_u128(2),
                lease_generation: 1,
                event_id: "evt_12345678".to_owned(),
                endpoint_url: "https://hooks.example/events".to_owned(),
                raw_body: b"{}".to_vec(),
                primary_secret_material_id: Uuid::from_u128(3),
                overlap_secret_material_id: None,
                attempt_number: 1,
            })),
            finished: Mutex::new(None),
        });
        let worker = WebhookWorker::new(
            repository.clone(),
            Arc::new(UnavailableSecretResolver),
            Arc::new(UnexpectedTransport),
            Arc::new(FixedClock(now)),
            "runtime-a".to_owned(),
            Uuid::from_u128(2),
            Duration::from_secs(30),
        )
        .unwrap();

        assert!(worker.run_once().await.unwrap());
        let finished = repository
            .finished
            .lock()
            .expect("finish lock")
            .expect("claim was finished");
        assert_eq!(finished.0.outcome, WebhookDeliveryOutcome::Transient);
        assert_eq!(finished.0.http_status, None);
        assert!(finished.1.is_some());
    }

    #[test]
    fn signature_uses_exact_timestamp_event_and_raw_body_grammar() {
        let signature = webhook_signature(
            &[7; 32],
            1_700_000_000,
            "evt_12345678",
            br#"{"event_id":"evt_12345678"}"#,
        )
        .unwrap();
        assert_eq!(signature, "v1=L5P362UpAgKIirQGE34KCfr6Bi4piY-C25B9rJ8Mpxw");
        assert_ne!(
            signature,
            webhook_signature(
                &[7; 32],
                1_700_000_000,
                "evt_12345678",
                br#"{ "event_id":"evt_12345678"}"#,
            )
            .unwrap()
        );
    }

    #[test]
    fn retry_schedule_is_bounded_and_deterministic() {
        let now = OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();
        let id = Uuid::nil();
        assert_eq!(
            retry_at(now, id, 1).unwrap(),
            now + time::Duration::seconds(5)
        );
        assert!(retry_at(now, id, 12).unwrap() <= now + time::Duration::hours(1));
    }
}
