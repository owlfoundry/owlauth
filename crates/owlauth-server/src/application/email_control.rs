use std::{net::IpAddr, sync::Arc};

use async_trait::async_trait;
use serde_json::json;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

use super::{
    ApplicationError, Clock, ConfigurationSecretSealers, MailTransportOutcome,
    PreparedSecretMaterial, RequestDigester, SealedProtectedMaterial,
};
use crate::domain::CanonicalEmail;
use owlauth_key_provider::{SealSecretRequest, SecretPlaintext};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SmtpControlTlsMode {
    ImplicitTls,
    StarttlsRequired,
}

impl SmtpControlTlsMode {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::ImplicitTls => "implicit_tls",
            Self::StarttlsRequired => "starttls_required",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SmtpControlStatus {
    Reconciled,
    Pending,
    Active,
    Retained,
    Disabled,
    Compromised,
    Retired,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "persisted email policy keeps independent security switches explicit"
)]
pub(crate) struct EmailPolicyRecord {
    pub project_id: Uuid,
    pub enabled: bool,
    pub policy_revision: i64,
    pub security_revision: i64,
    pub otp_enabled: bool,
    pub magic_link_enabled: bool,
    pub otp_digits: i16,
    pub otp_validity_seconds: i32,
    pub otp_max_attempts: i16,
    pub resend_after_seconds: i32,
    pub max_generations: i16,
    pub magic_validity_seconds: i32,
    pub signup_enabled: bool,
    pub transferred_magic_link_enabled: bool,
    pub allow_deployment_default: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct EmailAssignmentRecord {
    pub project_id: Uuid,
    pub application_id: Uuid,
    pub enabled: bool,
    pub security_revision: i64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "email policy mutation keeps independent security switches explicit"
)]
pub(crate) struct UpdateEmailPolicy {
    pub enabled: bool,
    pub otp_enabled: bool,
    pub magic_link_enabled: bool,
    pub otp_digits: i16,
    pub otp_validity_seconds: i32,
    pub otp_max_attempts: i16,
    pub resend_after_seconds: i32,
    pub max_generations: i16,
    pub magic_validity_seconds: i32,
    pub signup_enabled: bool,
    pub transferred_magic_link_enabled: bool,
    pub allow_deployment_default: bool,
    pub expected_policy_revision: i64,
    pub expected_security_revision: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SmtpConfigurationRecord {
    pub id: Uuid,
    pub project_id: Uuid,
    pub generation: i32,
    pub revision: i64,
    pub security_eligibility_revision: i64,
    pub status: SmtpControlStatus,
    pub host: String,
    pub port: u16,
    pub tls_mode: SmtpControlTlsMode,
    pub sender_address: String,
    pub sender_name: Option<String>,
    pub reply_to: Option<String>,
    pub retained_until: Option<OffsetDateTime>,
    pub safe_fingerprint: Option<[u8; 32]>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DeploymentSmtpGenerationRecord {
    pub generation: i32,
    pub revision: i64,
    pub security_eligibility_revision: i64,
    pub status: SmtpControlStatus,
    pub host: String,
    pub port: u16,
    pub tls_mode: SmtpControlTlsMode,
    pub sender_address: String,
    pub retained_until: Option<OffsetDateTime>,
    pub safe_fingerprint: [u8; 32],
    pub explicitly_allowed_private_ips: Vec<IpAddr>,
}

#[derive(Clone, Debug)]
pub(crate) struct ReconcileDeploymentSmtpGeneration {
    pub generation: i32,
    pub host: String,
    pub port: u16,
    pub tls_mode: SmtpControlTlsMode,
    pub sender_address: String,
    pub expected_safe_fingerprint: Option<[u8; 32]>,
    pub explicitly_allowed_private_ips: Vec<IpAddr>,
    pub credential: Zeroizing<String>,
    pub idempotency_key: String,
    pub correlation_id: Uuid,
}

#[derive(Clone, Debug)]
pub(crate) struct PreparedDeploymentSmtpGeneration {
    pub operation_id: Uuid,
    pub idempotency_key: String,
    pub request_digest: Vec<u8>,
    pub material: PreparedSecretMaterial,
    pub correlation_id: Uuid,
}

#[derive(Clone, Debug)]
pub(crate) struct CreateSmtpConfiguration {
    pub host: String,
    pub port: u16,
    pub tls_mode: SmtpControlTlsMode,
    pub sender_address: String,
    pub sender_name: Option<String>,
    pub reply_to: Option<String>,
    pub credential: Zeroizing<String>,
    pub idempotency_key: String,
    pub expected_project_security_revision: i64,
    pub correlation_id: Uuid,
}

#[derive(Clone, Debug)]
pub(crate) struct PrepareSmtpConfiguration {
    pub id: Uuid,
    pub host: String,
    pub port: u16,
    pub tls_mode: SmtpControlTlsMode,
    pub sender_address: String,
    pub sender_name: Option<String>,
    pub reply_to: Option<String>,
    pub operation_alias: String,
    pub credential_material_id: Uuid,
    pub request_digest: Vec<u8>,
    pub expected_project_security_revision: i64,
    pub correlation_id: Uuid,
}

#[derive(Clone, Debug)]
pub(crate) struct PrepareSmtpTest {
    pub id: Uuid,
    pub configuration_id: Uuid,
    pub recipient_material_id: Uuid,
    pub idempotency_key: String,
    pub request_digest: Vec<u8>,
    pub expected_revision: i64,
    pub correlation_id: Uuid,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SmtpTestState {
    Preparing,
    Pending,
    Submitting,
    Delivered,
    Failed,
    Ambiguous,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SmtpTestOperationRecord {
    pub id: Uuid,
    pub project_id: Uuid,
    pub configuration_id: Uuid,
    pub state: SmtpTestState,
    pub outcome: Option<MailTransportOutcome>,
    pub created_at: OffsetDateTime,
    pub completed_at: Option<OffsetDateTime>,
    pub recipient_material_id: Uuid,
}

#[derive(Clone, Debug)]
pub(crate) struct PreparedSmtpTest {
    pub record: SmtpTestOperationRecord,
    pub material: PreparedSecretMaterial,
}

#[derive(Clone, Debug)]
pub(crate) struct PreparedSmtpConfiguration {
    pub record: SmtpConfigurationRecord,
    pub operation_alias: String,
    pub request_digest: Vec<u8>,
    pub correlation_id: Uuid,
    pub material: PreparedSecretMaterial,
}

#[async_trait]
pub(crate) trait EmailControlPort: Send + Sync {
    async fn get_email_policy(
        &self,
        project_id: Uuid,
    ) -> Result<EmailPolicyRecord, ApplicationError>;

    async fn update_email_policy(
        &self,
        project_id: Uuid,
        update: UpdateEmailPolicy,
        correlation_id: Uuid,
        now: OffsetDateTime,
    ) -> Result<EmailPolicyRecord, ApplicationError>;

    async fn list_email_assignments(
        &self,
        project_id: Uuid,
    ) -> Result<Vec<EmailAssignmentRecord>, ApplicationError>;

    async fn assign_email_method(
        &self,
        project_id: Uuid,
        application_id: Uuid,
        enabled: bool,
        expected_application_security_revision: i64,
        correlation_id: Uuid,
        now: OffsetDateTime,
    ) -> Result<(), ApplicationError>;

    async fn prepare_smtp_configuration(
        &self,
        project_id: Uuid,
        prepared: PrepareSmtpConfiguration,
        now: OffsetDateTime,
    ) -> Result<PreparedSmtpConfiguration, ApplicationError>;

    async fn finalize_protected_smtp_configuration(
        &self,
        _project_id: Uuid,
        _prepared: &PreparedSmtpConfiguration,
        _material: SealedProtectedMaterial,
        _now: OffsetDateTime,
    ) -> Result<SmtpConfigurationRecord, ApplicationError> {
        Err(ApplicationError::Integrity)
    }

    async fn list_smtp_configurations(
        &self,
        project_id: Uuid,
    ) -> Result<Vec<SmtpConfigurationRecord>, ApplicationError>;

    async fn prepare_smtp_test(
        &self,
        project_id: Uuid,
        command: PrepareSmtpTest,
        now: OffsetDateTime,
    ) -> Result<PreparedSmtpTest, ApplicationError>;

    async fn finalize_protected_smtp_test_enqueue(
        &self,
        _project_id: Uuid,
        _prepared: &PreparedSmtpTest,
        _request_digest: &[u8],
        _material: SealedProtectedMaterial,
        _now: OffsetDateTime,
    ) -> Result<SmtpTestOperationRecord, ApplicationError> {
        Err(ApplicationError::Integrity)
    }

    async fn get_smtp_test(
        &self,
        project_id: Uuid,
        operation_id: Uuid,
    ) -> Result<SmtpTestOperationRecord, ApplicationError>;

    async fn activate_smtp_configuration(
        &self,
        project_id: Uuid,
        configuration_id: Uuid,
        expected_revision: i64,
        retained_until: OffsetDateTime,
        correlation_id: Uuid,
        now: OffsetDateTime,
    ) -> Result<SmtpConfigurationRecord, ApplicationError>;

    async fn prepare_deployment_smtp_generation(
        &self,
        command: &ReconcileDeploymentSmtpGeneration,
        request_digest: &[u8],
        now: OffsetDateTime,
    ) -> Result<PreparedDeploymentSmtpGeneration, ApplicationError> {
        let _ = (command, request_digest, now);
        Err(ApplicationError::Integrity)
    }

    async fn finalize_protected_deployment_smtp_generation(
        &self,
        _prepared: &PreparedDeploymentSmtpGeneration,
        _material: SealedProtectedMaterial,
        _now: OffsetDateTime,
    ) -> Result<DeploymentSmtpGenerationRecord, ApplicationError> {
        Err(ApplicationError::Integrity)
    }

    async fn list_deployment_smtp_generations(
        &self,
    ) -> Result<Vec<DeploymentSmtpGenerationRecord>, ApplicationError>;

    async fn terminate_deployment_smtp_generation(
        &self,
        generation: i32,
        expected_revision: i64,
        compromised: bool,
        correlation_id: Uuid,
        now: OffsetDateTime,
    ) -> Result<DeploymentSmtpGenerationRecord, ApplicationError>;

    async fn terminate_smtp_configuration(
        &self,
        project_id: Uuid,
        configuration_id: Uuid,
        expected_revision: i64,
        compromised: bool,
        correlation_id: Uuid,
        now: OffsetDateTime,
    ) -> Result<SmtpConfigurationRecord, ApplicationError>;
}

#[derive(Clone)]
pub(crate) struct EmailControlService {
    port: Arc<dyn EmailControlPort>,
    secret_sealers: ConfigurationSecretSealers,
    clock: Arc<dyn Clock>,
    digester: Arc<dyn RequestDigester>,
}

impl EmailControlService {
    pub(crate) fn new_protected(
        port: Arc<dyn EmailControlPort>,
        secret_sealers: ConfigurationSecretSealers,
        clock: Arc<dyn Clock>,
        digester: Arc<dyn RequestDigester>,
    ) -> Self {
        Self {
            port,
            secret_sealers,
            clock,
            digester,
        }
    }

    pub(crate) async fn get_policy(
        &self,
        project_id: Uuid,
    ) -> Result<EmailPolicyRecord, ApplicationError> {
        self.port.get_email_policy(project_id).await
    }

    pub(crate) async fn update_policy(
        &self,
        project_id: Uuid,
        update: UpdateEmailPolicy,
        correlation_id: Uuid,
    ) -> Result<EmailPolicyRecord, ApplicationError> {
        validate_policy(&update)?;
        self.port
            .update_email_policy(project_id, update, correlation_id, self.clock.now())
            .await
    }

    pub(crate) async fn list_assignments(
        &self,
        project_id: Uuid,
    ) -> Result<Vec<EmailAssignmentRecord>, ApplicationError> {
        self.port.list_email_assignments(project_id).await
    }

    pub(crate) async fn assign(
        &self,
        project_id: Uuid,
        application_id: Uuid,
        enabled: bool,
        expected_application_security_revision: i64,
        correlation_id: Uuid,
    ) -> Result<(), ApplicationError> {
        positive_revision(expected_application_security_revision)?;
        self.port
            .assign_email_method(
                project_id,
                application_id,
                enabled,
                expected_application_security_revision,
                correlation_id,
                self.clock.now(),
            )
            .await
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the durable protected SMTP prepare, seal, and finalize sequence remains explicit"
    )]
    pub(crate) async fn create_smtp(
        &self,
        project_id: Uuid,
        mut command: CreateSmtpConfiguration,
    ) -> Result<SmtpConfigurationRecord, ApplicationError> {
        positive_revision(command.expected_project_security_revision)?;
        validate_idempotency_key(&command.idempotency_key)?;
        let host = normalize_hostname(&command.host)?;
        let sender_address = CanonicalEmail::parse_v1(&command.sender_address)
            .map_err(|_| ApplicationError::InvalidInput)?
            .expose()
            .to_owned();
        let reply_to = command
            .reply_to
            .as_deref()
            .map(CanonicalEmail::parse_v1)
            .transpose()
            .map_err(|_| ApplicationError::InvalidInput)?
            .map(|value| value.expose().to_owned());
        let sender_name = normalize_optional_text(command.sender_name.take(), 128)?;
        let credential = normalize_smtp_credential(&mut command.credential)?;
        let request_digest = self.digester.digest_json(&json!({
            "purpose": "smtp_configuration_v2",
            "project_id": project_id,
            "host": host,
            "port": command.port,
            "tls_mode": command.tls_mode.as_str(),
            "sender_address": sender_address,
            "sender_name": sender_name,
            "reply_to": reply_to,
            "expected_project_security_revision": command.expected_project_security_revision,
            "idempotency_key": command.idempotency_key,
        }))?;
        let prepared = self
            .port
            .prepare_smtp_configuration(
                project_id,
                PrepareSmtpConfiguration {
                    id: Uuid::new_v4(),
                    host,
                    port: command.port,
                    tls_mode: command.tls_mode,
                    sender_address,
                    sender_name,
                    reply_to,
                    operation_alias: command.idempotency_key,
                    credential_material_id: Uuid::new_v4(),
                    request_digest,
                    expected_project_security_revision: command.expected_project_security_revision,
                    correlation_id: command.correlation_id,
                },
                self.clock.now(),
            )
            .await?;
        let material = prepared.material.clone();
        let sealer = self.secret_sealers.resolve(&material)?;
        let protected_secret = sealer
            .seal(SealSecretRequest {
                context: material.context,
                plaintext: SecretPlaintext::from_zeroizing(Zeroizing::new(credential))
                    .map_err(|_| ApplicationError::InvalidInput)?,
            })
            .await
            .map_err(super::provisioning::map_provider_error)?;
        self.port
            .finalize_protected_smtp_configuration(
                project_id,
                &prepared,
                SealedProtectedMaterial {
                    material_id: material.material_id,
                    provider_id: material.provider_id,
                    provider_format_version: material.provider_format_version,
                    envelope: protected_secret.envelope,
                    request_fingerprint: protected_secret.request_fingerprint,
                },
                self.clock.now(),
            )
            .await
    }

    pub(crate) async fn list_smtp(
        &self,
        project_id: Uuid,
    ) -> Result<Vec<SmtpConfigurationRecord>, ApplicationError> {
        self.port.list_smtp_configurations(project_id).await
    }

    pub(crate) async fn test_smtp(
        &self,
        project_id: Uuid,
        configuration_id: Uuid,
        recipient: &str,
        expected_revision: i64,
        idempotency_key: String,
        correlation_id: Uuid,
    ) -> Result<SmtpTestOperationRecord, ApplicationError> {
        positive_revision(expected_revision)?;
        validate_idempotency_key(&idempotency_key)?;
        let recipient = CanonicalEmail::parse_v1(recipient)
            .map_err(|_| ApplicationError::InvalidInput)?
            .expose()
            .to_owned();
        let request_digest = self.digester.digest_json(&json!({
            "purpose": "smtp_test_v3",
            "project_id": project_id,
            "configuration_id": configuration_id,
            "expected_revision": expected_revision,
        }))?;
        let operation = self
            .port
            .prepare_smtp_test(
                project_id,
                PrepareSmtpTest {
                    id: Uuid::new_v4(),
                    configuration_id,
                    recipient_material_id: Uuid::new_v4(),
                    idempotency_key,
                    request_digest: request_digest.clone(),
                    expected_revision,
                    correlation_id,
                },
                self.clock.now(),
            )
            .await?;
        let material = operation.material.clone();
        let sealer = self.secret_sealers.resolve(&material)?;
        let protected_secret = sealer
            .seal(SealSecretRequest {
                context: material.context,
                plaintext: SecretPlaintext::new(recipient.as_bytes().to_vec())
                    .map_err(|_| ApplicationError::InvalidInput)?,
            })
            .await
            .map_err(super::provisioning::map_provider_error)?;
        self.port
            .finalize_protected_smtp_test_enqueue(
                project_id,
                &operation,
                &request_digest,
                SealedProtectedMaterial {
                    material_id: material.material_id,
                    provider_id: material.provider_id,
                    provider_format_version: material.provider_format_version,
                    envelope: protected_secret.envelope,
                    request_fingerprint: protected_secret.request_fingerprint,
                },
                self.clock.now(),
            )
            .await
    }

    pub(crate) async fn get_smtp_test(
        &self,
        project_id: Uuid,
        operation_id: Uuid,
    ) -> Result<SmtpTestOperationRecord, ApplicationError> {
        self.port.get_smtp_test(project_id, operation_id).await
    }

    pub(crate) async fn activate_smtp(
        &self,
        project_id: Uuid,
        configuration_id: Uuid,
        expected_revision: i64,
        correlation_id: Uuid,
    ) -> Result<SmtpConfigurationRecord, ApplicationError> {
        positive_revision(expected_revision)?;
        self.port
            .activate_smtp_configuration(
                project_id,
                configuration_id,
                expected_revision,
                self.clock.now() + Duration::minutes(10),
                correlation_id,
                self.clock.now(),
            )
            .await
    }

    pub(crate) async fn reconcile_deployment_smtp(
        &self,
        mut command: ReconcileDeploymentSmtpGeneration,
    ) -> Result<DeploymentSmtpGenerationRecord, ApplicationError> {
        validate_idempotency_key(&command.idempotency_key)?;
        if command.generation <= 0 || command.expected_safe_fingerprint == Some([0; 32]) {
            return Err(ApplicationError::InvalidInput);
        }
        command.host = normalize_hostname(&command.host)?;
        CanonicalEmail::parse_v1(&command.sender_address)
            .map_err(|_| ApplicationError::InvalidInput)?
            .expose()
            .clone_into(&mut command.sender_address);
        let credential = normalize_smtp_credential(&mut command.credential)?;
        let request_digest = self.digester.digest_json(&json!({
            "purpose": "deployment_smtp_generation_v1",
            "generation": command.generation,
            "host": command.host,
            "port": command.port,
            "tls_mode": command.tls_mode.as_str(),
            "sender_address": command.sender_address,
            "expected_safe_fingerprint": command.expected_safe_fingerprint.map(|value| hex(&value)),
            "explicitly_allowed_private_ips": command.explicitly_allowed_private_ips,
            "idempotency_key": command.idempotency_key,
        }))?;
        let prepared = self
            .port
            .prepare_deployment_smtp_generation(&command, &request_digest, self.clock.now())
            .await?;
        let sealer = self.secret_sealers.resolve(&prepared.material)?;
        let protected_secret = sealer
            .seal(SealSecretRequest {
                context: prepared.material.context.clone(),
                plaintext: SecretPlaintext::from_zeroizing(Zeroizing::new(credential))
                    .map_err(|_| ApplicationError::InvalidInput)?,
            })
            .await
            .map_err(super::provisioning::map_provider_error)?;
        if command
            .expected_safe_fingerprint
            .is_some_and(|expected| *protected_secret.request_fingerprint.as_bytes() != expected)
        {
            return Err(ApplicationError::IdempotencyConflict);
        }
        self.port
            .finalize_protected_deployment_smtp_generation(
                &prepared,
                SealedProtectedMaterial {
                    material_id: prepared.material.material_id,
                    provider_id: prepared.material.provider_id.clone(),
                    provider_format_version: prepared.material.provider_format_version,
                    envelope: protected_secret.envelope,
                    request_fingerprint: protected_secret.request_fingerprint,
                },
                self.clock.now(),
            )
            .await
    }

    pub(crate) async fn list_deployment_smtp(
        &self,
    ) -> Result<Vec<DeploymentSmtpGenerationRecord>, ApplicationError> {
        self.port.list_deployment_smtp_generations().await
    }

    pub(crate) async fn terminate_deployment_smtp(
        &self,
        generation: i32,
        expected_revision: i64,
        compromised: bool,
        correlation_id: Uuid,
    ) -> Result<DeploymentSmtpGenerationRecord, ApplicationError> {
        if generation <= 0 {
            return Err(ApplicationError::InvalidInput);
        }
        positive_revision(expected_revision)?;
        self.port
            .terminate_deployment_smtp_generation(
                generation,
                expected_revision,
                compromised,
                correlation_id,
                self.clock.now(),
            )
            .await
    }

    pub(crate) async fn terminate_smtp(
        &self,
        project_id: Uuid,
        configuration_id: Uuid,
        expected_revision: i64,
        compromised: bool,
        correlation_id: Uuid,
    ) -> Result<SmtpConfigurationRecord, ApplicationError> {
        positive_revision(expected_revision)?;
        self.port
            .terminate_smtp_configuration(
                project_id,
                configuration_id,
                expected_revision,
                compromised,
                correlation_id,
                self.clock.now(),
            )
            .await
    }
}

fn validate_policy(update: &UpdateEmailPolicy) -> Result<(), ApplicationError> {
    positive_revision(update.expected_policy_revision)?;
    positive_revision(update.expected_security_revision)?;
    if !update.otp_enabled && !update.magic_link_enabled
        || !(6..=10).contains(&update.otp_digits)
        || !(30..=600).contains(&update.otp_validity_seconds)
        || !(1..=5).contains(&update.otp_max_attempts)
        || !(30..=600).contains(&update.resend_after_seconds)
        || !(1..=5).contains(&update.max_generations)
        || !(30..=600).contains(&update.magic_validity_seconds)
    {
        return Err(ApplicationError::InvalidInput);
    }
    Ok(())
}

fn positive_revision(value: i64) -> Result<(), ApplicationError> {
    if value <= 0 {
        return Err(ApplicationError::InvalidInput);
    }
    Ok(())
}

fn validate_idempotency_key(value: &str) -> Result<(), ApplicationError> {
    if !(8..=128).contains(&value.len())
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(ApplicationError::InvalidInput);
    }
    Ok(())
}

fn normalize_hostname(value: &str) -> Result<String, ApplicationError> {
    let value = value.trim().to_ascii_lowercase();
    if value.is_empty()
        || value.len() > 253
        || value.parse::<std::net::IpAddr>().is_ok()
        || value.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
    {
        return Err(ApplicationError::InvalidInput);
    }
    Ok(value)
}

fn normalize_optional_text(
    value: Option<String>,
    maximum: usize,
) -> Result<Option<String>, ApplicationError> {
    value
        .map(|value| {
            let value = value.trim().to_owned();
            if value.is_empty()
                || value.len() > maximum
                || value.bytes().any(|byte| matches!(byte, b'\r' | b'\n' | 0))
            {
                return Err(ApplicationError::InvalidInput);
            }
            Ok(value)
        })
        .transpose()
}

fn normalize_smtp_credential(value: &mut Zeroizing<String>) -> Result<Vec<u8>, ApplicationError> {
    let parsed: serde_json::Value =
        serde_json::from_str(value).map_err(|_| ApplicationError::InvalidInput)?;
    let username = parsed
        .get("username")
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.is_empty() && value.len() <= 256)
        .ok_or(ApplicationError::InvalidInput)?;
    let password = parsed
        .get("password")
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.is_empty() && value.len() <= 2048)
        .ok_or(ApplicationError::InvalidInput)?;
    if username
        .bytes()
        .any(|byte| matches!(byte, b'\r' | b'\n' | 0))
        || password
            .bytes()
            .any(|byte| matches!(byte, b'\r' | b'\n' | 0))
    {
        return Err(ApplicationError::InvalidInput);
    }
    let result = serde_json::to_vec(&json!({"username": username, "password": password}))
        .map_err(|_| ApplicationError::Integrity)?;
    value.zeroize();
    Ok(result)
}

fn hex(value: &[u8]) -> String {
    const TABLE: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(value.len() * 2);
    for byte in value {
        result.push(TABLE[usize::from(byte >> 4)] as char);
        result.push(TABLE[usize::from(byte & 0x0f)] as char);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn smtp_host_and_policy_bounds_are_conservative() {
        assert_eq!(
            normalize_hostname("Mail.Example.COM").unwrap(),
            "mail.example.com"
        );
        assert!(normalize_hostname("127.0.0.1").is_err());
        assert!(normalize_hostname("bad..example").is_err());
        let mut update = UpdateEmailPolicy {
            enabled: true,
            otp_enabled: true,
            magic_link_enabled: true,
            otp_digits: 6,
            otp_validity_seconds: 600,
            otp_max_attempts: 5,
            resend_after_seconds: 30,
            max_generations: 5,
            magic_validity_seconds: 600,
            signup_enabled: true,
            transferred_magic_link_enabled: false,
            allow_deployment_default: false,
            expected_policy_revision: 1,
            expected_security_revision: 1,
        };
        assert!(validate_policy(&update).is_ok());
        update.max_generations = 6;
        assert!(validate_policy(&update).is_err());
    }

    #[test]
    fn smtp_credential_is_canonical_and_input_is_cleared() {
        let mut input = Zeroizing::new(r#"{"password":"secret","username":"mailer"}"#.to_owned());
        let output = normalize_smtp_credential(&mut input).unwrap();
        assert!(input.is_empty());
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&output).unwrap(),
            json!({"username":"mailer", "password":"secret"})
        );
    }
}
