use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::atomic::{AtomicU8, Ordering},
    time::Duration as StdDuration,
};

use async_trait::async_trait;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;
use zeroize::Zeroizing;

use super::ApplicationError;

pub(crate) const MAX_DNS_ANSWERS: usize = 16;
pub(crate) const MAX_CNAME_DEPTH: usize = 8;
pub(crate) const MAX_MAIL_BODY_BYTES: usize = 64 * 1024;
pub(crate) const MAX_MAIL_ATTEMPTS: i16 = 8;
pub(crate) const SHORT_TERM_DATA_RETENTION: Duration = Duration::minutes(10);
pub(crate) const MAX_MAINTENANCE_ROWS_PER_TICK: u32 = 100;
const MAIL_CLAIM_LEASE: StdDuration = StdDuration::from_secs(30);
const MAIL_COMPLETION_RESERVE: StdDuration = StdDuration::from_secs(5);
const _: () = assert!(MAIL_COMPLETION_RESERVE.as_secs() < MAIL_CLAIM_LEASE.as_secs());

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SmtpTlsMode {
    ImplicitTls,
    StartTlsRequired,
    DevelopmentLoopbackPlaintext,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SmtpEndpoint {
    pub hostname: String,
    pub port: u16,
    pub tls_mode: SmtpTlsMode,
    pub explicitly_allowed_private_ips: Vec<IpAddr>,
    pub development_plaintext_enabled: bool,
}

impl SmtpEndpoint {
    pub(crate) fn validate(&self) -> Result<(), ApplicationError> {
        if self.hostname.is_empty()
            || self.hostname.len() > 253
            || self.hostname.parse::<IpAddr>().is_ok()
            || self.port == 0
            || self.explicitly_allowed_private_ips.len() > 16
        {
            return Err(ApplicationError::InvalidInput);
        }
        if self.tls_mode == SmtpTlsMode::DevelopmentLoopbackPlaintext
            && (!self.development_plaintext_enabled || self.hostname != "localhost")
        {
            return Err(ApplicationError::InvalidInput);
        }
        Ok(())
    }

    pub(crate) fn validate_resolution(
        &self,
        cname_depth: usize,
        addresses: &[IpAddr],
    ) -> Result<(), ApplicationError> {
        self.validate()?;
        if cname_depth > MAX_CNAME_DEPTH
            || addresses.is_empty()
            || addresses.len() > MAX_DNS_ANSWERS
        {
            return Err(ApplicationError::InvalidInput);
        }
        for address in addresses {
            let explicitly_allowed_tls_loopback = self.tls_mode
                != SmtpTlsMode::DevelopmentLoopbackPlaintext
                && address.is_loopback()
                && self.explicitly_allowed_private_ips.contains(address);
            if unconditionally_denied(*address)
                && !(self.tls_mode == SmtpTlsMode::DevelopmentLoopbackPlaintext
                    && address.is_loopback())
                && !explicitly_allowed_tls_loopback
            {
                return Err(ApplicationError::Disabled);
            }
            if private_requires_explicit_allow(*address)
                && !self.explicitly_allowed_private_ips.contains(address)
            {
                return Err(ApplicationError::Disabled);
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MailTransportOutcome {
    Delivered,
    Transient,
    Permanent,
    Ambiguous,
    PolicyDenied,
}

pub(crate) struct MailSubmission {
    pub endpoint: SmtpEndpoint,
    pub message_id: String,
    pub envelope_from: String,
    pub sender_name: Option<String>,
    pub reply_to: Option<String>,
    pub envelope_to: String,
    pub credential: Zeroizing<Vec<u8>>,
    pub body: Zeroizing<Vec<u8>>,
}

impl MailSubmission {
    pub(crate) fn validate(&self) -> Result<(), ApplicationError> {
        self.endpoint.validate()?;
        if self.message_id.len() < 16
            || self.message_id.len() > 255
            || invalid_mailbox(&self.envelope_from)
            || invalid_mailbox(&self.envelope_to)
            || self.reply_to.as_deref().is_some_and(invalid_mailbox)
            || self.sender_name.as_deref().is_some_and(|name| {
                name.is_empty() || name.len() > 128 || name.chars().any(char::is_control)
            })
            || self.credential.len() > 4096
            || self.body.is_empty()
            || self.body.len() > MAX_MAIL_BODY_BYTES
        {
            return Err(ApplicationError::InvalidInput);
        }
        Ok(())
    }
}

fn invalid_mailbox(value: &str) -> bool {
    value.is_empty()
        || value.len() > 254
        || value
            .chars()
            .any(|character| character.is_control() || matches!(character, '<' | '>'))
        || crate::domain::CanonicalEmail::parse_v1(value).is_err()
}

#[async_trait]
pub(crate) trait MailTransport: Send + Sync {
    /// The implementation must stop all physical submission work by `deadline`. It owns the
    /// pre-DATA versus post-DATA timeout classification because only the protocol adapter knows
    /// whether relay acceptance has become uncertain.
    async fn submit(
        &self,
        submission: MailSubmission,
        deadline: tokio::time::Instant,
    ) -> Result<MailTransportOutcome, ApplicationError>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct MailRetryState {
    pub attempts: i16,
    pub max_attempts: i16,
    pub useful_until: OffsetDateTime,
}

impl MailRetryState {
    pub(crate) fn next_attempt(
        self,
        outcome: MailTransportOutcome,
        now: OffsetDateTime,
        jitter_millis: i64,
    ) -> Result<Option<OffsetDateTime>, ApplicationError> {
        if self.attempts < 0
            || self.max_attempts < 1
            || self.max_attempts > MAX_MAIL_ATTEMPTS
            || self.attempts >= self.max_attempts
            || !(0..=1_000).contains(&jitter_millis)
        {
            return Ok(None);
        }
        if !matches!(
            outcome,
            MailTransportOutcome::Transient | MailTransportOutcome::Ambiguous
        ) {
            return Ok(None);
        }
        let exponent =
            u32::try_from(self.attempts.min(6)).map_err(|_| ApplicationError::Integrity)?;
        let seconds = 2_i64.pow(exponent).min(60);
        let retry = now + Duration::seconds(seconds) + Duration::milliseconds(jitter_millis);
        Ok((retry < self.useful_until).then_some(retry))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ClaimedSmtpSecretCleanup {
    pub project_id: uuid::Uuid,
    pub idempotency_key: String,
    pub recipient_material_id: uuid::Uuid,
    pub lease_owner: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ClaimedSmtpCredentialCleanup {
    pub id: uuid::Uuid,
    pub credential_material_id: uuid::Uuid,
    pub lease_owner: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ClaimedSmtpTestJob {
    pub project_id: uuid::Uuid,
    pub configuration_id: uuid::Uuid,
    pub configuration_generation: i32,
    pub configuration_revision: i64,
    pub configuration_security_eligibility_revision: i64,
    pub idempotency_key: String,
    pub message_id: String,
    pub recipient_material_id: uuid::Uuid,
    pub endpoint: SmtpEndpoint,
    pub envelope_from: String,
    pub credential_material_id: uuid::Uuid,
    pub safe_fingerprint: [u8; 32],
    pub lease_owner: String,
    pub lease_expires_at: OffsetDateTime,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MailChallengeOwner {
    Login {
        transaction_id: uuid::Uuid,
    },
    IdentityMutation {
        intent_id: uuid::Uuid,
        proof_slot_id: uuid::Uuid,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ClaimedMailJob {
    pub id: uuid::Uuid,
    pub project_id: uuid::Uuid,
    pub owner: MailChallengeOwner,
    pub challenge_id: uuid::Uuid,
    pub challenge_generation: i16,
    pub message_id: String,
    pub envelope: super::ProtectedValue,
    pub body: super::ProtectedValue,
    pub endpoint: SmtpEndpoint,
    pub envelope_from: String,
    pub sender_name: Option<String>,
    pub reply_to: Option<String>,
    pub credential_material_id: uuid::Uuid,
    pub safe_fingerprint: [u8; 32],
    pub lease_owner: String,
    pub lease_expires_at: OffsetDateTime,
    pub attempts: i16,
    pub max_attempts: i16,
    pub useful_until: OffsetDateTime,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DeploymentSmtpDesiredStatus {
    Reconciled,
    Active,
    Disabled,
    Compromised,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DeploymentSmtpGeneration {
    pub generation: i32,
    pub desired_status: DeploymentSmtpDesiredStatus,
    pub host: String,
    pub port: u16,
    pub tls_mode: SmtpTlsMode,
    pub sender_address: String,
    pub credential_material_id: uuid::Uuid,
    pub safe_fingerprint: [u8; 32],
    pub explicitly_allowed_private_ips: Vec<IpAddr>,
}

impl DeploymentSmtpGeneration {
    pub(crate) fn endpoint(&self) -> SmtpEndpoint {
        SmtpEndpoint {
            hostname: self.host.clone(),
            port: self.port,
            tls_mode: self.tls_mode,
            explicitly_allowed_private_ips: self.explicitly_allowed_private_ips.clone(),
            development_plaintext_enabled: false,
        }
    }
}

#[async_trait]
pub(crate) trait DeploymentSmtpRegistry: Send + Sync {
    async fn reconcile_deployment_smtp(
        &self,
        generation: &DeploymentSmtpGeneration,
        now: OffsetDateTime,
    ) -> Result<(), ApplicationError>;

    async fn assert_no_active_deployment_smtp(&self) -> Result<(), ApplicationError>;
}

#[async_trait]
pub(crate) trait MailOutboxRepository: Send + Sync {
    /// Performs bounded terminalization and irreversible short-term payload redaction before a
    /// worker claim. Implementations must honor the total row budget across every cleanup class.
    async fn maintain_short_term_data(
        &self,
        now: OffsetDateTime,
        row_budget: u32,
    ) -> Result<u32, ApplicationError>;

    async fn claim_due_mail(
        &self,
        worker: &str,
        now: OffsetDateTime,
        lease_until: OffsetDateTime,
    ) -> Result<Option<ClaimedMailJob>, ApplicationError>;

    async fn finish_mail_attempt(
        &self,
        job: &ClaimedMailJob,
        outcome: MailTransportOutcome,
        next_attempt_at: Option<OffsetDateTime>,
        now: OffsetDateTime,
    ) -> Result<(), ApplicationError>;

    async fn claim_smtp_test(
        &self,
        worker: &str,
        now: OffsetDateTime,
        lease_until: OffsetDateTime,
    ) -> Result<Option<ClaimedSmtpTestJob>, ApplicationError>;

    async fn finish_smtp_test(
        &self,
        job: &ClaimedSmtpTestJob,
        outcome: MailTransportOutcome,
        now: OffsetDateTime,
    ) -> Result<(), ApplicationError>;

    async fn claim_smtp_secret_cleanup(
        &self,
        worker: &str,
        now: OffsetDateTime,
        lease_until: OffsetDateTime,
    ) -> Result<Option<ClaimedSmtpSecretCleanup>, ApplicationError>;

    async fn finish_smtp_secret_cleanup(
        &self,
        cleanup: &ClaimedSmtpSecretCleanup,
        now: OffsetDateTime,
    ) -> Result<(), ApplicationError>;

    async fn claim_smtp_credential_cleanup(
        &self,
        worker: &str,
        now: OffsetDateTime,
        lease_until: OffsetDateTime,
    ) -> Result<Option<ClaimedSmtpCredentialCleanup>, ApplicationError>;

    async fn finish_smtp_credential_cleanup(
        &self,
        cleanup: &ClaimedSmtpCredentialCleanup,
        now: OffsetDateTime,
    ) -> Result<(), ApplicationError>;
}

#[async_trait]
pub(crate) trait SmtpCredentialResolver: Send + Sync {
    async fn resolve(&self, material_id: Uuid) -> Result<Zeroizing<Vec<u8>>, ApplicationError>;

    async fn resolve_checked(
        &self,
        material_id: Uuid,
        _expected_fingerprint: &[u8; 32],
    ) -> Result<Zeroizing<Vec<u8>>, ApplicationError> {
        self.resolve(material_id).await
    }
}

pub(crate) struct MailWorker {
    repository: std::sync::Arc<dyn MailOutboxRepository>,
    transport: std::sync::Arc<dyn MailTransport>,
    credentials: std::sync::Arc<dyn SmtpCredentialResolver>,
    protector: std::sync::Arc<dyn super::RuntimeProtector>,
    worker_id: String,
    schedule_cursor: AtomicU8,
}

impl MailWorker {
    pub(crate) fn new(
        repository: std::sync::Arc<dyn MailOutboxRepository>,
        transport: std::sync::Arc<dyn MailTransport>,
        credentials: std::sync::Arc<dyn SmtpCredentialResolver>,
        protector: std::sync::Arc<dyn super::RuntimeProtector>,
        worker_id: String,
    ) -> Result<Self, ApplicationError> {
        if worker_id.is_empty() || worker_id.len() > 128 {
            return Err(ApplicationError::InvalidInput);
        }
        Ok(Self {
            repository,
            transport,
            credentials,
            protector,
            worker_id,
            schedule_cursor: AtomicU8::new(0),
        })
    }

    pub(crate) async fn run_once(
        &self,
        clock: &dyn super::Clock,
    ) -> Result<bool, ApplicationError> {
        self.run_once_with_limits(clock, MAIL_CLAIM_LEASE, MAIL_COMPLETION_RESERVE)
            .await
    }

    async fn run_once_with_limits(
        &self,
        clock: &dyn super::Clock,
        claim_lease: StdDuration,
        completion_reserve: StdDuration,
    ) -> Result<bool, ApplicationError> {
        if completion_reserve >= claim_lease {
            return Err(ApplicationError::InvalidInput);
        }
        let now = clock.now();
        let maintained = match self
            .repository
            .maintain_short_term_data(now, MAX_MAINTENANCE_ROWS_PER_TICK)
            .await
        {
            Ok(affected) => affected,
            Err(error) => {
                // Cleanup is bounded best-effort work. Its timeout/error domain must never block
                // due-mail, SMTP-test, or credential-retirement claim progress in this tick.
                tracing::warn!(
                    event = "mail_short_term_maintenance_failed",
                    error = ?error,
                    "bounded short-term maintenance will retry without blocking mail claims"
                );
                0
            }
        };
        let lane = self.schedule_cursor.fetch_add(1, Ordering::Relaxed) % 4;
        if lane == 1
            && self
                .run_smtp_test_once(clock, claim_lease, completion_reserve)
                .await?
        {
            return Ok(true);
        }
        if lane == 2 && self.run_smtp_secret_cleanup_once(clock.now()).await? {
            return Ok(true);
        }
        if lane == 3 && self.run_smtp_credential_cleanup_once(clock.now()).await? {
            return Ok(true);
        }

        // The local deadline starts before repository acquisition. PostgreSQL creates the
        // authoritative lease from its own clock at the final claim update, so this monotonic
        // deadline is conservative even when acquisition or row locking is slow.
        let claim_started = tokio::time::Instant::now();
        let lease_deadline = claim_started
            .checked_add(claim_lease)
            .ok_or(ApplicationError::Integrity)?;
        let dispatch_deadline = lease_deadline
            .checked_sub(completion_reserve)
            .ok_or(ApplicationError::Integrity)?;
        let claim_now = clock.now();
        let claim_lease_duration =
            Duration::try_from(claim_lease).map_err(|_| ApplicationError::Integrity)?;
        let claimed = tokio::time::timeout_at(
            dispatch_deadline,
            self.repository.claim_due_mail(
                &self.worker_id,
                claim_now,
                claim_now + claim_lease_duration,
            ),
        )
        .await
        .map_err(|_| ApplicationError::Persistence)??;
        let Some(job) = claimed else {
            if lane != 1
                && self
                    .run_smtp_test_once(clock, claim_lease, completion_reserve)
                    .await?
            {
                return Ok(true);
            }
            if lane != 2 && self.run_smtp_secret_cleanup_once(clock.now()).await? {
                return Ok(true);
            }
            if lane != 3 && self.run_smtp_credential_cleanup_once(clock.now()).await? {
                return Ok(true);
            }
            return Ok(maintained > 0);
        };

        let outcome = if tokio::time::Instant::now() >= dispatch_deadline {
            MailTransportOutcome::Transient
        } else if clock.now() >= job.useful_until {
            MailTransportOutcome::PolicyDenied
        } else {
            self.dispatch_claimed(&job, dispatch_deadline).await
        };
        tracing::info!(event = "mail_dispatch_completed", mail_id = %job.id, outcome = ?outcome, "Runtime mail dispatch completed");
        let completed_at = clock.now();
        let retry = MailRetryState {
            // The PostgreSQL claim advances the recorded attempt before dispatch so a crash
            // cannot reuse an unrecorded predecessor attempt.
            attempts: job.attempts,
            max_attempts: job.max_attempts,
            useful_until: job.useful_until,
        }
        .next_attempt(
            outcome,
            completed_at,
            stable_retry_jitter_ms(job.id, job.attempts),
        )?;
        tokio::time::timeout_at(
            lease_deadline,
            self.repository
                .finish_mail_attempt(&job, outcome, retry, completed_at),
        )
        .await
        .map_err(|_| ApplicationError::Persistence)??;
        Ok(true)
    }

    async fn run_smtp_secret_cleanup_once(
        &self,
        now: OffsetDateTime,
    ) -> Result<bool, ApplicationError> {
        let Some(cleanup) = self
            .repository
            .claim_smtp_secret_cleanup(&self.worker_id, now, now + Duration::seconds(30))
            .await?
        else {
            return Ok(false);
        };
        self.repository
            .finish_smtp_secret_cleanup(&cleanup, now)
            .await?;
        Ok(true)
    }

    async fn run_smtp_credential_cleanup_once(
        &self,
        now: OffsetDateTime,
    ) -> Result<bool, ApplicationError> {
        let Some(cleanup) = self
            .repository
            .claim_smtp_credential_cleanup(&self.worker_id, now, now + Duration::seconds(30))
            .await?
        else {
            return Ok(false);
        };
        self.repository
            .finish_smtp_credential_cleanup(&cleanup, now)
            .await?;
        Ok(true)
    }

    async fn run_smtp_test_once(
        &self,
        clock: &dyn super::Clock,
        claim_lease: StdDuration,
        completion_reserve: StdDuration,
    ) -> Result<bool, ApplicationError> {
        let claim_started = tokio::time::Instant::now();
        let lease_deadline = claim_started
            .checked_add(claim_lease)
            .ok_or(ApplicationError::Integrity)?;
        let dispatch_deadline = lease_deadline
            .checked_sub(completion_reserve)
            .ok_or(ApplicationError::Integrity)?;
        let now = clock.now();
        let lease = Duration::try_from(claim_lease).map_err(|_| ApplicationError::Integrity)?;
        let claimed = tokio::time::timeout_at(
            dispatch_deadline,
            self.repository
                .claim_smtp_test(&self.worker_id, now, now + lease),
        )
        .await
        .map_err(|_| ApplicationError::Persistence)??;
        let Some(job) = claimed else {
            return Ok(false);
        };
        let outcome = if tokio::time::Instant::now() >= dispatch_deadline {
            MailTransportOutcome::Transient
        } else {
            let prepared = tokio::time::timeout_at(dispatch_deadline, async {
                let recipient = self.credentials.resolve(job.recipient_material_id).await?;
                if tokio::time::Instant::now() >= dispatch_deadline {
                    return Err(ApplicationError::ExternalStore);
                }
                let recipient = String::from_utf8(recipient.to_vec())
                    .map_err(|_| ApplicationError::InvalidInput)?;
                let credential = self
                    .credentials
                    .resolve_checked(job.credential_material_id, &job.safe_fingerprint)
                    .await?;
                let submission = MailSubmission {
                    endpoint: job.endpoint.clone(),
                    message_id: job.message_id.clone(),
                    envelope_from: job.envelope_from.clone(),
                    sender_name: None,
                    reply_to: None,
                    envelope_to: recipient,
                    credential,
                    body: Zeroizing::new(
                        b"This is a bounded OwlAuth SMTP configuration test.\r\n".to_vec(),
                    ),
                };
                submission.validate()?;
                Ok::<_, ApplicationError>(submission)
            })
            .await;
            match prepared {
                Ok(Ok(_)) if tokio::time::Instant::now() >= dispatch_deadline => {
                    MailTransportOutcome::Transient
                }
                Ok(Ok(submission)) => self
                    .transport
                    .submit(submission, dispatch_deadline)
                    .await
                    .unwrap_or(MailTransportOutcome::Ambiguous),
                Ok(Err(ApplicationError::Disabled)) => MailTransportOutcome::PolicyDenied,
                Ok(Err(ApplicationError::InvalidInput)) => MailTransportOutcome::Permanent,
                Ok(Err(_)) | Err(_) => MailTransportOutcome::Transient,
            }
        };
        let completed_at = clock.now();
        tokio::time::timeout_at(
            lease_deadline,
            self.repository
                .finish_smtp_test(&job, outcome, completed_at),
        )
        .await
        .map_err(|_| ApplicationError::Persistence)??;
        Ok(true)
    }

    async fn dispatch_claimed(
        &self,
        job: &ClaimedMailJob,
        dispatch_deadline: tokio::time::Instant,
    ) -> MailTransportOutcome {
        if tokio::time::Instant::now() >= dispatch_deadline {
            return MailTransportOutcome::Transient;
        }
        let prepared = tokio::time::timeout_at(dispatch_deadline, async {
            let context = mail_context(job);
            let envelope = self.protector.unprotect(
                super::ProtectedPurpose::EmailOutboxEnvelope,
                &context,
                &job.envelope,
            )?;
            let body = self.protector.unprotect(
                super::ProtectedPurpose::EmailOutboxBody,
                &context,
                &job.body,
            )?;
            let envelope: serde_json::Value = serde_json::from_slice(envelope.as_slice())
                .map_err(|_| ApplicationError::InvalidInput)?;
            let recipient = envelope
                .get("to")
                .and_then(serde_json::Value::as_str)
                .filter(|value| !value.is_empty() && value.len() <= 254)
                .ok_or(ApplicationError::InvalidInput)?;
            if tokio::time::Instant::now() >= dispatch_deadline {
                return Err(ApplicationError::ExternalStore);
            }
            let credential = self
                .credentials
                .resolve_checked(job.credential_material_id, &job.safe_fingerprint)
                .await?;
            let submission = MailSubmission {
                endpoint: job.endpoint.clone(),
                message_id: job.message_id.clone(),
                envelope_from: job.envelope_from.clone(),
                sender_name: job.sender_name.clone(),
                reply_to: job.reply_to.clone(),
                envelope_to: recipient.to_owned(),
                credential,
                body,
            };
            submission.validate()?;
            Ok::<_, ApplicationError>(submission)
        })
        .await;
        let submission = match prepared {
            Ok(Ok(submission)) => submission,
            Ok(Err(ApplicationError::Disabled)) => {
                tracing::error!(
                    event = "mail_credential_fingerprint_mismatch",
                    "the locally resolved SMTP credential does not match the pinned generation"
                );
                return MailTransportOutcome::PolicyDenied;
            }
            Ok(Err(ApplicationError::InvalidInput | ApplicationError::Integrity)) => {
                return MailTransportOutcome::Permanent;
            }
            Ok(Err(error)) => {
                tracing::warn!(event = "mail_preparation_failed", error = ?error, "Runtime could not prepare the pinned SMTP submission");
                return MailTransportOutcome::Transient;
            }
            Err(_) => {
                tracing::warn!(
                    event = "mail_preparation_timed_out",
                    "Runtime mail preparation exhausted the pre-dispatch deadline"
                );
                return MailTransportOutcome::Transient;
            }
        };
        if tokio::time::Instant::now() >= dispatch_deadline {
            return MailTransportOutcome::Transient;
        }
        match self.transport.submit(submission, dispatch_deadline).await {
            Ok(outcome) => outcome,
            Err(error) => {
                tracing::warn!(event = "mail_transport_failed", error = ?error, "Runtime SMTP transport failed before a classified response");
                MailTransportOutcome::Ambiguous
            }
        }
    }
}

pub(crate) fn mail_context(job: &ClaimedMailJob) -> Vec<u8> {
    let mut context = Vec::with_capacity(112);
    match job.owner {
        MailChallengeOwner::Login { transaction_id } => {
            context.extend_from_slice(b"owlauth-email-challenge-v1\0");
            context.extend_from_slice(job.project_id.as_bytes());
            context.extend_from_slice(transaction_id.as_bytes());
        }
        MailChallengeOwner::IdentityMutation {
            intent_id,
            proof_slot_id,
        } => {
            context.extend_from_slice(b"owlauth-identity-mutation-email-challenge-v1\0");
            context.extend_from_slice(job.project_id.as_bytes());
            context.extend_from_slice(intent_id.as_bytes());
            context.extend_from_slice(proof_slot_id.as_bytes());
        }
    }
    context.extend_from_slice(job.challenge_id.as_bytes());
    context.extend_from_slice(&job.challenge_generation.to_be_bytes());
    context
}

pub(crate) fn classify_smtp_status(code: u16) -> MailTransportOutcome {
    match code {
        200..=299 => MailTransportOutcome::Delivered,
        400..=499 => MailTransportOutcome::Transient,
        500..=599 => MailTransportOutcome::Permanent,
        _ => MailTransportOutcome::Ambiguous,
    }
}

pub(crate) fn validate_private_relay_allowlist(
    addresses: &[IpAddr],
) -> Result<(), ApplicationError> {
    if addresses.len() > 16
        || addresses.iter().any(|address| {
            (!address.is_loopback() && unconditionally_denied(*address))
                || (!address.is_loopback() && !private_requires_explicit_allow(*address))
        })
    {
        return Err(ApplicationError::InvalidInput);
    }
    Ok(())
}

fn unconditionally_denied(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => {
            address.is_loopback()
                || address.is_link_local()
                || address.is_broadcast()
                || address.is_unspecified()
                || address.is_multicast()
                || address.octets()[0] == 0
                || address.octets()[0] >= 224
                || address == Ipv4Addr::new(169, 254, 169, 254)
                || address == Ipv4Addr::new(100, 100, 100, 200)
        }
        IpAddr::V6(address) => {
            address.to_ipv4_mapped().is_some()
                || address.is_loopback()
                || address.is_unspecified()
                || address.is_multicast()
                || is_ipv6_link_local(address)
                || (!is_ipv6_unique_local(address) && !is_globally_routable_ipv6(address))
        }
    }
}

fn private_requires_explicit_allow(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => address.is_private() || is_non_public_ipv4(address),
        IpAddr::V6(address) => is_ipv6_unique_local(address),
    }
}

fn is_non_public_ipv4(value: Ipv4Addr) -> bool {
    let [first, second, third, _] = value.octets();
    first == 0
        || (first == 100 && second & 0xc0 == 64) // RFC 6598 shared/CGNAT space
        || (first == 192 && second == 0 && third == 0) // IETF protocol assignments
        || (first == 192 && second == 0 && third == 2) // documentation
        || (first == 192 && second == 88 && third == 99) // deprecated 6to4 relay
        || (first == 198 && matches!(second, 18 | 19)) // benchmark networks
        || (first == 198 && second == 51 && third == 100) // documentation
        || (first == 203 && second == 0 && third == 113) // documentation
        || first >= 240 // reserved and limited broadcast
}

fn is_ipv6_unique_local(value: Ipv6Addr) -> bool {
    value.octets()[0] & 0xfe == 0xfc
}

fn is_ipv6_link_local(value: Ipv6Addr) -> bool {
    value.octets()[0] == 0xfe && value.octets()[1] & 0xc0 == 0x80
}

/// Conservative stable replacement for the still-unstable standard-library global-address API.
/// Only ordinary `2000::/3` global unicast is admitted. IETF special assignments, documentation,
/// transition/embedded-IPv4 mechanisms, benchmarking, ORCHID, and 6to4 are denied fail-closed.
fn is_globally_routable_ipv6(value: Ipv6Addr) -> bool {
    let octets = value.octets();
    if octets[0] & 0xe0 != 0x20 {
        return false;
    }
    // 2001::/23 is the IETF special-purpose block and contains Teredo and ORCHID assignments.
    if octets[0] == 0x20 && octets[1] == 0x01 && octets[2] <= 0x01 {
        return false;
    }
    // 2001:db8::/32 documentation space.
    if octets[..4] == [0x20, 0x01, 0x0d, 0xb8] {
        return false;
    }
    // 2002::/16 embeds an arbitrary IPv4 destination (6to4).
    if octets[..2] == [0x20, 0x02] {
        return false;
    }
    // 2620:4f:8000::/48 is the special-purpose AS112 direct-delegation service.
    if octets[..6] == [0x26, 0x20, 0x00, 0x4f, 0x80, 0x00] {
        return false;
    }
    // 3fff::/20 is documentation space.
    if octets[0] == 0x3f && octets[1] == 0xff && octets[2] & 0xf0 == 0 {
        return false;
    }
    true
}

fn stable_retry_jitter_ms(mail_id: uuid::Uuid, attempt: i16) -> i64 {
    let bytes = mail_id.as_bytes();
    let seed = u64::from_be_bytes(bytes[..8].try_into().expect("UUID prefix is eight bytes"))
        ^ u64::try_from(attempt.max(0))
            .expect("nonnegative i16 fits u64")
            .wrapping_mul(0x9e37_79b9_7f4a_7c15);
    i64::try_from(seed % 1_000 + 1).expect("bounded jitter fits i64")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::application::Clock as _;

    struct TestClock {
        base: OffsetDateTime,
        started: std::time::Instant,
    }

    impl TestClock {
        fn new(base: OffsetDateTime) -> Self {
            Self {
                base,
                started: std::time::Instant::now(),
            }
        }
    }

    impl crate::application::Clock for TestClock {
        fn now(&self) -> OffsetDateTime {
            self.base
                + Duration::try_from(self.started.elapsed())
                    .expect("test elapsed duration fits the application clock")
        }
    }

    struct MaintenanceFailureRepository(std::sync::atomic::AtomicUsize);

    #[async_trait::async_trait]
    impl MailOutboxRepository for MaintenanceFailureRepository {
        async fn maintain_short_term_data(
            &self,
            _now: OffsetDateTime,
            _row_budget: u32,
        ) -> Result<u32, ApplicationError> {
            Err(ApplicationError::Persistence)
        }

        async fn claim_due_mail(
            &self,
            _worker: &str,
            _now: OffsetDateTime,
            _lease_until: OffsetDateTime,
        ) -> Result<Option<ClaimedMailJob>, ApplicationError> {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(None)
        }

        async fn finish_mail_attempt(
            &self,
            _job: &ClaimedMailJob,
            _outcome: MailTransportOutcome,
            _next_attempt_at: Option<OffsetDateTime>,
            _now: OffsetDateTime,
        ) -> Result<(), ApplicationError> {
            unreachable!("no mail is returned")
        }

        async fn claim_smtp_test(
            &self,
            _worker: &str,
            _now: OffsetDateTime,
            _lease_until: OffsetDateTime,
        ) -> Result<Option<ClaimedSmtpTestJob>, ApplicationError> {
            Ok(None)
        }

        async fn finish_smtp_test(
            &self,
            _job: &ClaimedSmtpTestJob,
            _outcome: MailTransportOutcome,
            _now: OffsetDateTime,
        ) -> Result<(), ApplicationError> {
            unreachable!("no SMTP test is returned")
        }

        async fn claim_smtp_secret_cleanup(
            &self,
            _worker: &str,
            _now: OffsetDateTime,
            _lease_until: OffsetDateTime,
        ) -> Result<Option<ClaimedSmtpSecretCleanup>, ApplicationError> {
            Ok(None)
        }

        async fn finish_smtp_secret_cleanup(
            &self,
            _cleanup: &ClaimedSmtpSecretCleanup,
            _now: OffsetDateTime,
        ) -> Result<(), ApplicationError> {
            unreachable!("no secret cleanup is returned")
        }

        async fn claim_smtp_credential_cleanup(
            &self,
            _worker: &str,
            _now: OffsetDateTime,
            _lease_until: OffsetDateTime,
        ) -> Result<Option<ClaimedSmtpCredentialCleanup>, ApplicationError> {
            Ok(None)
        }

        async fn finish_smtp_credential_cleanup(
            &self,
            _cleanup: &ClaimedSmtpCredentialCleanup,
            _now: OffsetDateTime,
        ) -> Result<(), ApplicationError> {
            unreachable!("no credential cleanup is returned")
        }
    }

    struct LateSmtpTestRepository {
        claim_delay: StdDuration,
        finished_outcome: std::sync::Mutex<Option<MailTransportOutcome>>,
    }

    #[async_trait::async_trait]
    impl MailOutboxRepository for LateSmtpTestRepository {
        async fn maintain_short_term_data(
            &self,
            _now: OffsetDateTime,
            _row_budget: u32,
        ) -> Result<u32, ApplicationError> {
            Ok(0)
        }

        async fn claim_due_mail(
            &self,
            _worker: &str,
            _now: OffsetDateTime,
            _lease_until: OffsetDateTime,
        ) -> Result<Option<ClaimedMailJob>, ApplicationError> {
            Ok(None)
        }

        async fn finish_mail_attempt(
            &self,
            _job: &ClaimedMailJob,
            _outcome: MailTransportOutcome,
            _next_attempt_at: Option<OffsetDateTime>,
            _now: OffsetDateTime,
        ) -> Result<(), ApplicationError> {
            unreachable!("no mail is returned")
        }

        async fn claim_smtp_test(
            &self,
            worker: &str,
            _now: OffsetDateTime,
            lease_until: OffsetDateTime,
        ) -> Result<Option<ClaimedSmtpTestJob>, ApplicationError> {
            // Tokio polls the wrapped future before its timeout. Tests can deliberately overrun
            // the local deadline in this first poll to prove post-claim work has an explicit guard.
            std::thread::sleep(self.claim_delay);
            Ok(Some(ClaimedSmtpTestJob {
                project_id: uuid::Uuid::new_v4(),
                configuration_id: uuid::Uuid::new_v4(),
                configuration_generation: 1,
                configuration_revision: 1,
                configuration_security_eligibility_revision: 1,
                idempotency_key: "late-smtp-test".to_owned(),
                message_id: "<late-smtp-test@mail.owlauth.invalid>".to_owned(),
                recipient_material_id: uuid::Uuid::from_u128(101),
                endpoint: endpoint(),
                envelope_from: "sender@example.com".to_owned(),
                credential_material_id: uuid::Uuid::from_u128(102),
                safe_fingerprint: [7; 32],
                lease_owner: worker.to_owned(),
                lease_expires_at: lease_until,
            }))
        }

        async fn finish_smtp_test(
            &self,
            _job: &ClaimedSmtpTestJob,
            outcome: MailTransportOutcome,
            _now: OffsetDateTime,
        ) -> Result<(), ApplicationError> {
            *self.finished_outcome.lock().unwrap() = Some(outcome);
            Ok(())
        }

        async fn claim_smtp_secret_cleanup(
            &self,
            _worker: &str,
            _now: OffsetDateTime,
            _lease_until: OffsetDateTime,
        ) -> Result<Option<ClaimedSmtpSecretCleanup>, ApplicationError> {
            Ok(None)
        }

        async fn finish_smtp_secret_cleanup(
            &self,
            _cleanup: &ClaimedSmtpSecretCleanup,
            _now: OffsetDateTime,
        ) -> Result<(), ApplicationError> {
            unreachable!("no secret cleanup is returned")
        }

        async fn claim_smtp_credential_cleanup(
            &self,
            _worker: &str,
            _now: OffsetDateTime,
            _lease_until: OffsetDateTime,
        ) -> Result<Option<ClaimedSmtpCredentialCleanup>, ApplicationError> {
            Ok(None)
        }

        async fn finish_smtp_credential_cleanup(
            &self,
            _cleanup: &ClaimedSmtpCredentialCleanup,
            _now: OffsetDateTime,
        ) -> Result<(), ApplicationError> {
            unreachable!("no credential cleanup is returned")
        }
    }

    #[derive(Default)]
    struct TimeoutRepositoryState {
        lease_owner: Option<String>,
        lease_until: Option<OffsetDateTime>,
        observed_lease: Option<Duration>,
        attempts: i16,
        finished: bool,
        completed_at: Option<OffsetDateTime>,
        next_attempt_at: Option<OffsetDateTime>,
        outcomes: Vec<MailTransportOutcome>,
    }

    struct TimeoutRepository {
        clock: std::sync::Arc<TestClock>,
        job: ClaimedMailJob,
        first_claim_delay: StdDuration,
        finish_delay: StdDuration,
        maintenance_calls: std::sync::atomic::AtomicUsize,
        claim_calls: std::sync::atomic::AtomicUsize,
        state: std::sync::Mutex<TimeoutRepositoryState>,
    }

    #[async_trait::async_trait]
    impl MailOutboxRepository for TimeoutRepository {
        async fn maintain_short_term_data(
            &self,
            _now: OffsetDateTime,
            _row_budget: u32,
        ) -> Result<u32, ApplicationError> {
            self.maintenance_calls
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(0)
        }

        async fn claim_due_mail(
            &self,
            worker: &str,
            now: OffsetDateTime,
            lease_until: OffsetDateTime,
        ) -> Result<Option<ClaimedMailJob>, ApplicationError> {
            let claim_index = self
                .claim_calls
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if claim_index == 0 {
                tokio::time::sleep(self.first_claim_delay).await;
            }
            let requested_lease = lease_until - now;
            let authoritative_now = self.clock.now();
            let mut state = self.state.lock().unwrap();
            state.observed_lease = Some(requested_lease);
            if state.finished
                || state
                    .lease_until
                    .is_some_and(|current_lease| current_lease > authoritative_now)
            {
                return Ok(None);
            }
            state.attempts += 1;
            let authoritative_lease = authoritative_now + requested_lease;
            state.lease_owner = Some(worker.to_owned());
            state.lease_until = Some(authoritative_lease);
            let mut job = self.job.clone();
            job.lease_owner = worker.to_owned();
            job.lease_expires_at = authoritative_lease;
            job.attempts = state.attempts;
            Ok(Some(job))
        }

        async fn finish_mail_attempt(
            &self,
            job: &ClaimedMailJob,
            outcome: MailTransportOutcome,
            next_attempt_at: Option<OffsetDateTime>,
            now: OffsetDateTime,
        ) -> Result<(), ApplicationError> {
            tokio::time::sleep(self.finish_delay).await;
            let mut state = self.state.lock().unwrap();
            if state.lease_owner.as_deref() != Some(job.lease_owner.as_str())
                || state.lease_until != Some(job.lease_expires_at)
                || state.attempts != job.attempts
                || self.clock.now() >= job.lease_expires_at
            {
                return Err(ApplicationError::RevisionConflict);
            }
            state.finished = true;
            state.completed_at = Some(now);
            state.next_attempt_at = next_attempt_at;
            state.outcomes.push(outcome);
            Ok(())
        }

        async fn claim_smtp_test(
            &self,
            _worker: &str,
            _now: OffsetDateTime,
            _lease_until: OffsetDateTime,
        ) -> Result<Option<ClaimedSmtpTestJob>, ApplicationError> {
            Ok(None)
        }

        async fn finish_smtp_test(
            &self,
            _job: &ClaimedSmtpTestJob,
            _outcome: MailTransportOutcome,
            _now: OffsetDateTime,
        ) -> Result<(), ApplicationError> {
            unreachable!("no SMTP test is returned")
        }

        async fn claim_smtp_secret_cleanup(
            &self,
            _worker: &str,
            _now: OffsetDateTime,
            _lease_until: OffsetDateTime,
        ) -> Result<Option<ClaimedSmtpSecretCleanup>, ApplicationError> {
            Ok(None)
        }

        async fn finish_smtp_secret_cleanup(
            &self,
            _cleanup: &ClaimedSmtpSecretCleanup,
            _now: OffsetDateTime,
        ) -> Result<(), ApplicationError> {
            unreachable!("no secret cleanup is returned")
        }

        async fn claim_smtp_credential_cleanup(
            &self,
            _worker: &str,
            _now: OffsetDateTime,
            _lease_until: OffsetDateTime,
        ) -> Result<Option<ClaimedSmtpCredentialCleanup>, ApplicationError> {
            Ok(None)
        }

        async fn finish_smtp_credential_cleanup(
            &self,
            _cleanup: &ClaimedSmtpCredentialCleanup,
            _now: OffsetDateTime,
        ) -> Result<(), ApplicationError> {
            unreachable!("no credential cleanup is returned")
        }
    }

    struct ActiveSubmission<'a> {
        active: &'a std::sync::atomic::AtomicUsize,
        clock: &'a TestClock,
        completed_at: &'a std::sync::Mutex<Vec<OffsetDateTime>>,
    }

    impl Drop for ActiveSubmission<'_> {
        fn drop(&mut self) {
            self.active
                .fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
            self.completed_at.lock().unwrap().push(self.clock.now());
        }
    }

    struct HangingTransport {
        calls: std::sync::atomic::AtomicUsize,
        active: std::sync::atomic::AtomicUsize,
        max_active: std::sync::atomic::AtomicUsize,
        started: tokio::sync::Notify,
        clock: std::sync::Arc<TestClock>,
        completed_at: std::sync::Mutex<Vec<OffsetDateTime>>,
    }

    #[async_trait::async_trait]
    impl MailTransport for HangingTransport {
        async fn submit(
            &self,
            _submission: MailSubmission,
            _deadline: tokio::time::Instant,
        ) -> Result<MailTransportOutcome, ApplicationError> {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let active = self
                .active
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
                + 1;
            self.max_active
                .fetch_max(active, std::sync::atomic::Ordering::SeqCst);
            let _active = ActiveSubmission {
                active: &self.active,
                clock: self.clock.as_ref(),
                completed_at: &self.completed_at,
            };
            self.started.notify_one();
            tokio::time::sleep_until(_deadline).await;
            Ok(MailTransportOutcome::Ambiguous)
        }
    }

    struct SuccessfulCredentials;

    #[async_trait::async_trait]
    impl SmtpCredentialResolver for SuccessfulCredentials {
        async fn resolve(
            &self,
            _material_id: Uuid,
        ) -> Result<Zeroizing<Vec<u8>>, ApplicationError> {
            Ok(Zeroizing::new(b"local-secret".to_vec()))
        }
    }

    struct TimeoutFixture {
        clock: std::sync::Arc<TestClock>,
        repository: std::sync::Arc<TimeoutRepository>,
        transport: std::sync::Arc<HangingTransport>,
        first_worker: std::sync::Arc<MailWorker>,
        second_worker: MailWorker,
    }

    fn timeout_fixture(
        now: OffsetDateTime,
        first_claim_delay: StdDuration,
        finish_delay: StdDuration,
    ) -> TimeoutFixture {
        let protected = crate::application::ProtectedValue {
            ciphertext: vec![1],
            key_version: 1,
        };
        let clock = std::sync::Arc::new(TestClock::new(now));
        let repository = std::sync::Arc::new(TimeoutRepository {
            clock: clock.clone(),
            job: ClaimedMailJob {
                id: uuid::Uuid::new_v4(),
                project_id: uuid::Uuid::new_v4(),
                owner: MailChallengeOwner::Login {
                    transaction_id: uuid::Uuid::new_v4(),
                },
                challenge_id: uuid::Uuid::new_v4(),
                challenge_generation: 1,
                message_id: "<timeout@mail.owlauth.invalid>".to_owned(),
                envelope: protected.clone(),
                body: protected,
                endpoint: endpoint(),
                envelope_from: "sender@example.com".to_owned(),
                sender_name: None,
                reply_to: None,
                credential_material_id: uuid::Uuid::from_u128(103),
                safe_fingerprint: [7; 32],
                lease_owner: String::new(),
                lease_expires_at: now,
                attempts: 0,
                max_attempts: 3,
                useful_until: now + Duration::hours(1),
            },
            first_claim_delay,
            finish_delay,
            maintenance_calls: std::sync::atomic::AtomicUsize::new(0),
            claim_calls: std::sync::atomic::AtomicUsize::new(0),
            state: std::sync::Mutex::new(TimeoutRepositoryState::default()),
        });
        let transport = std::sync::Arc::new(HangingTransport {
            calls: std::sync::atomic::AtomicUsize::new(0),
            active: std::sync::atomic::AtomicUsize::new(0),
            max_active: std::sync::atomic::AtomicUsize::new(0),
            started: tokio::sync::Notify::new(),
            clock: clock.clone(),
            completed_at: std::sync::Mutex::new(Vec::new()),
        });
        let make_worker = |worker_id: &str| {
            MailWorker::new(
                repository.clone(),
                transport.clone(),
                std::sync::Arc::new(SuccessfulCredentials),
                std::sync::Arc::new(UnusedProtector),
                worker_id.to_owned(),
            )
            .unwrap()
        };
        let first_worker = std::sync::Arc::new(make_worker("runtime-timeout-a"));
        let second_worker = make_worker("runtime-timeout-b");
        TimeoutFixture {
            clock,
            repository,
            transport,
            first_worker,
            second_worker,
        }
    }

    struct UnusedTransport;

    #[async_trait::async_trait]
    impl MailTransport for UnusedTransport {
        async fn submit(
            &self,
            _submission: MailSubmission,
            _deadline: tokio::time::Instant,
        ) -> Result<MailTransportOutcome, ApplicationError> {
            unreachable!("claim returned no mail")
        }
    }

    struct UnusedCredentials;

    #[async_trait::async_trait]
    impl SmtpCredentialResolver for UnusedCredentials {
        async fn resolve(
            &self,
            _material_id: Uuid,
        ) -> Result<Zeroizing<Vec<u8>>, ApplicationError> {
            unreachable!("claim returned no mail")
        }
    }

    struct SlowCredentials;

    #[async_trait::async_trait]
    impl SmtpCredentialResolver for SlowCredentials {
        async fn resolve(
            &self,
            _material_id: Uuid,
        ) -> Result<Zeroizing<Vec<u8>>, ApplicationError> {
            tokio::time::sleep(StdDuration::from_secs(1)).await;
            Ok(Zeroizing::new(b"local-secret".to_vec()))
        }
    }

    struct CountingCredentials(std::sync::atomic::AtomicUsize);

    #[async_trait::async_trait]
    impl SmtpCredentialResolver for CountingCredentials {
        async fn resolve(&self, material_id: Uuid) -> Result<Zeroizing<Vec<u8>>, ApplicationError> {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if material_id == uuid::Uuid::from_u128(101) {
                Ok(Zeroizing::new(b"recipient@example.com".to_vec()))
            } else {
                Ok(Zeroizing::new(b"local-secret".to_vec()))
            }
        }
    }

    struct BoundaryCredentials(std::sync::atomic::AtomicUsize);

    #[async_trait::async_trait]
    impl SmtpCredentialResolver for BoundaryCredentials {
        async fn resolve(
            &self,
            _material_id: Uuid,
        ) -> Result<Zeroizing<Vec<u8>>, ApplicationError> {
            let call = self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if call == 0 {
                // Complete the recipient stage in the same child-first poll that crosses the
                // deadline. The worker must not start the credential stage afterward.
                std::thread::sleep(StdDuration::from_millis(20));
                Ok(Zeroizing::new(b"recipient@example.com".to_vec()))
            } else {
                Ok(Zeroizing::new(b"local-secret".to_vec()))
            }
        }
    }

    struct MismatchedCredentials;

    #[async_trait::async_trait]
    impl SmtpCredentialResolver for MismatchedCredentials {
        async fn resolve(
            &self,
            _material_id: Uuid,
        ) -> Result<Zeroizing<Vec<u8>>, ApplicationError> {
            Ok(Zeroizing::new(b"local-secret".to_vec()))
        }

        async fn resolve_checked(
            &self,
            _material_id: Uuid,
            _expected_fingerprint: &[u8; 32],
        ) -> Result<Zeroizing<Vec<u8>>, ApplicationError> {
            Err(ApplicationError::Disabled)
        }
    }

    struct CountingTransport(std::sync::atomic::AtomicUsize);

    #[async_trait::async_trait]
    impl MailTransport for CountingTransport {
        async fn submit(
            &self,
            _submission: MailSubmission,
            _deadline: tokio::time::Instant,
        ) -> Result<MailTransportOutcome, ApplicationError> {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(MailTransportOutcome::Delivered)
        }
    }

    struct UnusedProtector;

    impl crate::application::RuntimeProtector for UnusedProtector {
        fn active_version(&self) -> i32 {
            1
        }

        fn readable_key_versions(&self) -> std::collections::BTreeSet<i32> {
            std::collections::BTreeSet::from([1])
        }

        fn random_opaque(&self, _bytes: usize) -> Result<Zeroizing<String>, ApplicationError> {
            unreachable!("claim returned no mail")
        }

        fn digest(
            &self,
            _purpose: crate::application::OpaquePurpose,
            _context: &[u8],
            _value: &[u8],
        ) -> Result<crate::application::VersionedDigest, ApplicationError> {
            unreachable!("claim returned no mail")
        }

        fn digest_at(
            &self,
            _purpose: crate::application::OpaquePurpose,
            _context: &[u8],
            _value: &[u8],
            _key_version: i32,
        ) -> Result<crate::application::VersionedDigest, ApplicationError> {
            unreachable!("claim returned no mail")
        }

        fn derive_opaque(
            &self,
            _purpose: crate::application::OpaquePurpose,
            _context: &[u8],
            _key_version: Option<i32>,
        ) -> Result<Zeroizing<String>, ApplicationError> {
            unreachable!("claim returned no mail")
        }

        fn protect(
            &self,
            _purpose: crate::application::ProtectedPurpose,
            _context: &[u8],
            _value: &[u8],
        ) -> Result<crate::application::ProtectedValue, ApplicationError> {
            unreachable!("claim returned no mail")
        }

        fn unprotect(
            &self,
            purpose: crate::application::ProtectedPurpose,
            _context: &[u8],
            _value: &crate::application::ProtectedValue,
        ) -> Result<Zeroizing<Vec<u8>>, ApplicationError> {
            match purpose {
                crate::application::ProtectedPurpose::EmailOutboxEnvelope => Ok(Zeroizing::new(
                    br#"{"to":"recipient@example.com"}"#.to_vec(),
                )),
                crate::application::ProtectedPurpose::EmailOutboxBody => {
                    Ok(Zeroizing::new(b"body\r\n".to_vec()))
                }
                _ => unreachable!("only outbox payloads are exercised"),
            }
        }
    }

    #[tokio::test]
    async fn late_smtp_test_claim_cannot_start_credential_or_transport_work() {
        let repository = std::sync::Arc::new(LateSmtpTestRepository {
            claim_delay: StdDuration::from_millis(20),
            finished_outcome: std::sync::Mutex::new(None),
        });
        let credentials =
            std::sync::Arc::new(CountingCredentials(std::sync::atomic::AtomicUsize::new(0)));
        let transport =
            std::sync::Arc::new(CountingTransport(std::sync::atomic::AtomicUsize::new(0)));
        let worker = MailWorker::new(
            repository.clone(),
            transport.clone(),
            credentials.clone(),
            std::sync::Arc::new(UnusedProtector),
            "runtime-late-smtp-test".to_owned(),
        )
        .unwrap();
        let clock = TestClock::new(OffsetDateTime::UNIX_EPOCH);

        assert!(
            worker
                .run_smtp_test_once(
                    &clock,
                    StdDuration::from_millis(20),
                    StdDuration::from_millis(5),
                )
                .await
                .unwrap()
        );
        assert_eq!(credentials.0.load(std::sync::atomic::Ordering::SeqCst), 0);
        assert_eq!(transport.0.load(std::sync::atomic::Ordering::SeqCst), 0);
        assert_eq!(
            *repository.finished_outcome.lock().unwrap(),
            Some(MailTransportOutcome::Transient)
        );
    }

    #[tokio::test]
    async fn smtp_test_deadline_stops_between_recipient_and_credential_stages() {
        let repository = std::sync::Arc::new(LateSmtpTestRepository {
            claim_delay: StdDuration::ZERO,
            finished_outcome: std::sync::Mutex::new(None),
        });
        let credentials =
            std::sync::Arc::new(BoundaryCredentials(std::sync::atomic::AtomicUsize::new(0)));
        let transport =
            std::sync::Arc::new(CountingTransport(std::sync::atomic::AtomicUsize::new(0)));
        let worker = MailWorker::new(
            repository.clone(),
            transport.clone(),
            credentials.clone(),
            std::sync::Arc::new(UnusedProtector),
            "runtime-smtp-test-stage-deadline".to_owned(),
        )
        .unwrap();
        let clock = TestClock::new(OffsetDateTime::UNIX_EPOCH);

        assert!(
            worker
                .run_smtp_test_once(
                    &clock,
                    StdDuration::from_millis(20),
                    StdDuration::from_millis(5),
                )
                .await
                .unwrap()
        );
        assert_eq!(credentials.0.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert_eq!(transport.0.load(std::sync::atomic::Ordering::SeqCst), 0);
        assert_eq!(
            *repository.finished_outcome.lock().unwrap(),
            Some(MailTransportOutcome::Transient)
        );
    }

    #[tokio::test]
    async fn mismatched_pinned_smtp_credential_never_reaches_transport() {
        let transport =
            std::sync::Arc::new(CountingTransport(std::sync::atomic::AtomicUsize::new(0)));
        let worker = MailWorker::new(
            std::sync::Arc::new(MaintenanceFailureRepository(
                std::sync::atomic::AtomicUsize::new(0),
            )),
            transport.clone(),
            std::sync::Arc::new(MismatchedCredentials),
            std::sync::Arc::new(UnusedProtector),
            "runtime-fingerprint-regression".to_owned(),
        )
        .unwrap();
        let protected = crate::application::ProtectedValue {
            ciphertext: vec![1],
            key_version: 1,
        };
        let job = ClaimedMailJob {
            id: uuid::Uuid::new_v4(),
            project_id: uuid::Uuid::new_v4(),
            owner: MailChallengeOwner::Login {
                transaction_id: uuid::Uuid::new_v4(),
            },
            challenge_id: uuid::Uuid::new_v4(),
            challenge_generation: 1,
            message_id: "<fingerprint@mail.owlauth.invalid>".to_owned(),
            envelope: protected.clone(),
            body: protected,
            endpoint: endpoint(),
            envelope_from: "sender@example.com".to_owned(),
            sender_name: None,
            reply_to: None,
            credential_material_id: uuid::Uuid::from_u128(103),
            safe_fingerprint: [2; 32],
            lease_owner: "runtime-fingerprint-regression".to_owned(),
            lease_expires_at: OffsetDateTime::UNIX_EPOCH + Duration::minutes(1),
            attempts: 1,
            max_attempts: 3,
            useful_until: OffsetDateTime::UNIX_EPOCH + Duration::hours(1),
        };

        assert_eq!(
            worker
                .dispatch_claimed(
                    &job,
                    tokio::time::Instant::now() + StdDuration::from_secs(1),
                )
                .await,
            MailTransportOutcome::PolicyDenied
        );
        assert_eq!(transport.0.load(std::sync::atomic::Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn pre_dispatch_timeout_is_transient_and_never_reaches_transport() {
        let transport =
            std::sync::Arc::new(CountingTransport(std::sync::atomic::AtomicUsize::new(0)));
        let worker = MailWorker::new(
            std::sync::Arc::new(MaintenanceFailureRepository(
                std::sync::atomic::AtomicUsize::new(0),
            )),
            transport.clone(),
            std::sync::Arc::new(SlowCredentials),
            std::sync::Arc::new(UnusedProtector),
            "runtime-pre-dispatch-timeout".to_owned(),
        )
        .unwrap();
        let protected = crate::application::ProtectedValue {
            ciphertext: vec![1],
            key_version: 1,
        };
        let now = OffsetDateTime::UNIX_EPOCH;
        let job = ClaimedMailJob {
            id: uuid::Uuid::new_v4(),
            project_id: uuid::Uuid::new_v4(),
            owner: MailChallengeOwner::Login {
                transaction_id: uuid::Uuid::new_v4(),
            },
            challenge_id: uuid::Uuid::new_v4(),
            challenge_generation: 1,
            message_id: "<pre-dispatch-timeout@mail.owlauth.invalid>".to_owned(),
            envelope: protected.clone(),
            body: protected,
            endpoint: endpoint(),
            envelope_from: "sender@example.com".to_owned(),
            sender_name: None,
            reply_to: None,
            credential_material_id: uuid::Uuid::from_u128(103),
            safe_fingerprint: [7; 32],
            lease_owner: "runtime-pre-dispatch-timeout".to_owned(),
            lease_expires_at: now + Duration::seconds(1),
            attempts: 1,
            max_attempts: 3,
            useful_until: now + Duration::hours(1),
        };

        assert_eq!(
            worker
                .dispatch_claimed(
                    &job,
                    tokio::time::Instant::now() + StdDuration::from_millis(30),
                )
                .await,
            MailTransportOutcome::Transient
        );
        assert_eq!(transport.0.load(std::sync::atomic::Ordering::SeqCst), 0);
        assert_eq!(
            worker
                .dispatch_claimed(
                    &job,
                    tokio::time::Instant::now() - StdDuration::from_millis(1),
                )
                .await,
            MailTransportOutcome::Transient
        );
        assert_eq!(transport.0.load(std::sync::atomic::Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn claim_timeout_cannot_start_a_late_physical_submission() {
        let TimeoutFixture {
            clock,
            repository,
            transport,
            first_worker,
            ..
        } = timeout_fixture(
            OffsetDateTime::UNIX_EPOCH,
            StdDuration::from_millis(300),
            StdDuration::ZERO,
        );
        let started = tokio::time::Instant::now();
        assert_eq!(
            first_worker
                .run_once_with_limits(
                    clock.as_ref(),
                    StdDuration::from_millis(300),
                    StdDuration::from_millis(80),
                )
                .await,
            Err(ApplicationError::Persistence)
        );
        assert!(started.elapsed() < StdDuration::from_millis(280));
        assert_eq!(transport.calls.load(std::sync::atomic::Ordering::SeqCst), 0);
        assert_eq!(repository.state.lock().unwrap().attempts, 0);
    }

    #[tokio::test]
    async fn claim_delay_and_slow_completion_never_overlap_expired_reclaim() {
        let TimeoutFixture {
            clock,
            repository,
            transport,
            first_worker,
            second_worker,
        } = timeout_fixture(
            OffsetDateTime::UNIX_EPOCH,
            StdDuration::from_millis(80),
            StdDuration::from_millis(200),
        );
        let claim_lease = StdDuration::from_millis(300);
        let completion_reserve = StdDuration::from_millis(80);
        let submission_started = transport.started.notified();
        let first = tokio::spawn({
            let worker = first_worker.clone();
            let clock = clock.clone();
            async move {
                worker
                    .run_once_with_limits(clock.as_ref(), claim_lease, completion_reserve)
                    .await
            }
        });

        tokio::time::timeout(StdDuration::from_secs(1), submission_started)
            .await
            .expect("the first worker should reach physical submission");
        assert_eq!(
            transport.active.load(std::sync::atomic::Ordering::SeqCst),
            1
        );
        assert!(
            !second_worker
                .run_once_with_limits(clock.as_ref(), claim_lease, completion_reserve)
                .await
                .unwrap()
        );
        assert_eq!(
            transport.active.load(std::sync::atomic::Ordering::SeqCst),
            1
        );

        assert_eq!(
            tokio::time::timeout(StdDuration::from_secs(1), first)
                .await
                .expect("the first worker must remain bounded by its claim lease")
                .unwrap(),
            Err(ApplicationError::Persistence)
        );
        assert_eq!(
            transport.active.load(std::sync::atomic::Ordering::SeqCst),
            0
        );
        let first_lease = repository
            .state
            .lock()
            .unwrap()
            .lease_until
            .expect("first authoritative lease");
        let first_submission_completed_at = transport
            .completed_at
            .lock()
            .unwrap()
            .first()
            .copied()
            .expect("the first physical submission should record its terminal boundary");
        assert!(
            first_submission_completed_at < first_lease,
            "physical submission must stop before its authoritative claim lease expires"
        );
        while clock.now() <= first_lease {
            tokio::time::sleep(StdDuration::from_millis(5)).await;
        }

        assert_eq!(
            second_worker
                .run_once_with_limits(clock.as_ref(), claim_lease, completion_reserve)
                .await,
            Err(ApplicationError::Persistence)
        );
        let state = repository.state.lock().unwrap();
        assert_eq!(
            state.observed_lease,
            Some(Duration::try_from(claim_lease).unwrap())
        );
        assert!(!state.finished);
        assert_eq!(state.attempts, 2);
        assert_eq!(transport.calls.load(std::sync::atomic::Ordering::SeqCst), 2);
        assert_eq!(
            transport
                .max_active
                .load(std::sync::atomic::Ordering::SeqCst),
            1
        );
        assert!(
            repository
                .maintenance_calls
                .load(std::sync::atomic::Ordering::SeqCst)
                >= 3
        );
    }

    #[tokio::test]
    async fn retry_backoff_starts_when_the_attempt_completes() {
        let TimeoutFixture {
            clock,
            repository,
            first_worker,
            ..
        } = timeout_fixture(
            OffsetDateTime::UNIX_EPOCH,
            StdDuration::ZERO,
            StdDuration::ZERO,
        );
        assert!(
            first_worker
                .run_once_with_limits(
                    clock.as_ref(),
                    StdDuration::from_millis(300),
                    StdDuration::from_millis(80),
                )
                .await
                .unwrap()
        );
        let state = repository.state.lock().unwrap();
        let completed_at = state.completed_at.expect("completion timestamp");
        let next_attempt_at = state.next_attempt_at.expect("retry timestamp");
        assert!(next_attempt_at > completed_at + Duration::seconds(2));
        assert_eq!(state.outcomes, [MailTransportOutcome::Ambiguous]);
    }

    #[tokio::test]
    async fn maintenance_failure_does_not_block_due_mail_claim_attempt() {
        let repository = std::sync::Arc::new(MaintenanceFailureRepository(
            std::sync::atomic::AtomicUsize::new(0),
        ));
        let worker = MailWorker::new(
            repository.clone(),
            std::sync::Arc::new(UnusedTransport),
            std::sync::Arc::new(UnusedCredentials),
            std::sync::Arc::new(UnusedProtector),
            "runtime-maintenance-regression".to_owned(),
        )
        .unwrap();
        let clock = TestClock::new(OffsetDateTime::UNIX_EPOCH);
        assert!(!worker.run_once(&clock).await.unwrap());
        assert_eq!(repository.0.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    fn endpoint() -> SmtpEndpoint {
        SmtpEndpoint {
            hostname: "smtp.example.test".to_owned(),
            port: 465,
            tls_mode: SmtpTlsMode::ImplicitTls,
            explicitly_allowed_private_ips: vec![],
            development_plaintext_enabled: false,
        }
    }

    #[test]
    fn resolution_denies_mixed_private_metadata_mapped_and_unbounded_answers() {
        let public: IpAddr = "8.8.8.8".parse().unwrap();
        assert!(endpoint().validate_resolution(1, &[public]).is_ok());
        for denied in [
            "127.0.0.1",
            "10.0.0.1",
            "169.254.169.254",
            "100.100.100.200",
            "100.64.0.1",
            "100.127.255.254",
            "198.18.0.1",
            "203.0.113.10",
            "fe80::1",
            "fc00::1",
            "::ffff:127.0.0.1",
        ] {
            assert_eq!(
                endpoint().validate_resolution(0, &[public, denied.parse().unwrap()]),
                Err(ApplicationError::Disabled)
            );
        }
        assert!(endpoint().validate_resolution(9, &[public]).is_err());
        assert!(
            endpoint()
                .validate_resolution(0, &vec![public; 17])
                .is_err()
        );
    }

    #[test]
    fn explicit_private_relay_allowlist_is_exact_and_only_tls_can_opt_into_loopback() {
        let allowed =
            ["10.0.0.8", "100.64.0.8", "fc00::8"].map(|value| value.parse::<IpAddr>().unwrap());
        assert!(validate_private_relay_allowlist(&allowed).is_ok());
        assert!(
            endpoint()
                .validate_resolution(0, &["2606:4700:4700::1111".parse().unwrap()])
                .is_ok()
        );
        let mut value = endpoint();
        value.explicitly_allowed_private_ips = allowed.to_vec();
        for address in allowed {
            assert!(value.validate_resolution(0, &[address]).is_ok());
        }
        assert_eq!(
            value.validate_resolution(0, &["10.0.0.9".parse().unwrap()]),
            Err(ApplicationError::Disabled)
        );
        let loopback = "127.0.0.1".parse().unwrap();
        assert!(validate_private_relay_allowlist(&[loopback]).is_ok());
        value.explicitly_allowed_private_ips = vec![loopback];
        assert!(value.validate_resolution(0, &[loopback]).is_ok());
        for unconditional in [
            "169.254.1.1",
            "169.254.169.254",
            "100.100.100.200",
            "fe80::1",
            "::ffff:10.0.0.8",
            "2001:db8::1",
            "64:ff9b::a00:8",
            "64:ff9b:1::a00:8",
            "2001::1",
            "2001:2::1",
            "2001:10::1",
            "2001:20::1",
            "2002:0a00:0008::1",
            "2620:4f:8000::1",
            "3fff::1",
            "100::1",
        ] {
            let address = unconditional.parse().unwrap();
            assert!(validate_private_relay_allowlist(&[address]).is_err());
            value.explicitly_allowed_private_ips = vec![address];
            assert_eq!(
                value.validate_resolution(0, &[address]),
                Err(ApplicationError::Disabled)
            );
        }
    }

    #[test]
    fn only_explicit_development_loopback_can_use_plaintext() {
        let mut value = endpoint();
        value.tls_mode = SmtpTlsMode::DevelopmentLoopbackPlaintext;
        assert!(value.validate().is_err());
        value.hostname = "localhost".to_owned();
        value.development_plaintext_enabled = true;
        assert!(
            value
                .validate_resolution(0, &["127.0.0.1".parse().unwrap()])
                .is_ok()
        );
    }

    #[test]
    fn production_retry_jitter_is_stable_nonzero_and_bounded() {
        let mail_id = uuid::Uuid::parse_str("018f4f26-5d55-7a11-8e00-112233445566").unwrap();
        let first = stable_retry_jitter_ms(mail_id, 2);
        assert!((1..=1_000).contains(&first));
        assert_eq!(first, stable_retry_jitter_ms(mail_id, 2));
        assert_ne!(first, stable_retry_jitter_ms(mail_id, 3));
        let now = OffsetDateTime::UNIX_EPOCH;
        let retry = MailRetryState {
            attempts: 2,
            max_attempts: 5,
            useful_until: now + Duration::minutes(1),
        }
        .next_attempt(MailTransportOutcome::Transient, now, first)
        .unwrap()
        .expect("production transient outcome remains useful");
        assert!(retry > now + Duration::seconds(4));
        assert!(retry <= now + Duration::seconds(5));
    }

    #[test]
    fn retry_is_bounded_by_attempt_ceiling_and_challenge_usefulness() {
        let now = OffsetDateTime::UNIX_EPOCH;
        let state = MailRetryState {
            attempts: 2,
            max_attempts: 5,
            useful_until: now + Duration::seconds(30),
        };
        assert_eq!(
            state
                .next_attempt(MailTransportOutcome::Transient, now, 250)
                .unwrap(),
            Some(now + Duration::milliseconds(4_250))
        );
        assert_eq!(
            MailRetryState {
                attempts: 5,
                ..state
            }
            .next_attempt(MailTransportOutcome::Transient, now, 0)
            .unwrap(),
            None
        );
        assert_eq!(
            state
                .next_attempt(MailTransportOutcome::Permanent, now, 0)
                .unwrap(),
            None
        );
    }

    #[test]
    fn response_classification_never_persists_vendor_text() {
        assert_eq!(classify_smtp_status(250), MailTransportOutcome::Delivered);
        assert_eq!(classify_smtp_status(421), MailTransportOutcome::Transient);
        assert_eq!(classify_smtp_status(550), MailTransportOutcome::Permanent);
        assert_eq!(classify_smtp_status(0), MailTransportOutcome::Ambiguous);
    }
}
