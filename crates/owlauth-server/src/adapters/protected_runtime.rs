use std::{collections::BTreeMap, sync::Arc};

use async_trait::async_trait;
use owlauth_key_provider::{
    ConfigurationSecretOpener, MaterialKind, OpaqueEnvelope, OpaqueHandle, OpenSecretRequest,
    ProviderErrorClass, ProviderId, RuntimeSigner as ProviderRuntimeSigner, SignRequest,
    SigningAlgorithm, SigningInput,
};
use sea_orm::DatabaseConnection;
use time::OffsetDateTime;
use uuid::Uuid;
use zeroize::Zeroizing;

use super::postgres::custody::{
    LiveProtectedMaterial, MaterialOwnerKind, ProtectedMaterialRepository,
    RuntimeReadinessCandidate,
};
use crate::{
    application::{
        ApplicationError, ProviderSecretResolver, RuntimeSigner, SmtpCredentialResolver,
        WebhookSecretResolver,
    },
    providers::ProviderRegistrations,
};

#[derive(Clone)]
pub(crate) struct PostgresProtectedRuntimeCustody {
    materials: ProtectedMaterialRepository,
    signers: BTreeMap<ProviderId, Arc<dyn ProviderRuntimeSigner>>,
    openers: BTreeMap<ProviderId, Arc<dyn ConfigurationSecretOpener>>,
}

impl std::fmt::Debug for PostgresProtectedRuntimeCustody {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PostgresProtectedRuntimeCustody")
            .field(
                "signer_provider_ids",
                &self.signers.keys().collect::<Vec<_>>(),
            )
            .field(
                "opener_provider_ids",
                &self.openers.keys().collect::<Vec<_>>(),
            )
            .finish_non_exhaustive()
    }
}

impl PostgresProtectedRuntimeCustody {
    #[cfg(test)]
    pub(crate) fn new<S, O>(
        database: DatabaseConnection,
        deployment_id: &str,
        provider_id: ProviderId,
        signer: S,
        opener: O,
    ) -> Result<Self, ApplicationError>
    where
        S: ProviderRuntimeSigner + 'static,
        O: ConfigurationSecretOpener + 'static,
    {
        if signer.provider_id() != provider_id || opener.provider_id() != provider_id {
            return Err(ApplicationError::Integrity);
        }
        let mut signers = BTreeMap::new();
        signers.insert(
            provider_id.clone(),
            Arc::new(signer) as Arc<dyn ProviderRuntimeSigner>,
        );
        let mut openers = BTreeMap::new();
        openers.insert(
            provider_id,
            Arc::new(opener) as Arc<dyn ConfigurationSecretOpener>,
        );
        Ok(Self {
            materials: ProtectedMaterialRepository::new(database, deployment_id)?,
            signers,
            openers,
        })
    }

    pub(crate) fn from_registrations(
        database: DatabaseConnection,
        deployment_id: &str,
        registrations: &ProviderRegistrations,
    ) -> Result<Self, ApplicationError> {
        Ok(Self {
            materials: ProtectedMaterialRepository::new(database, deployment_id)?,
            signers: registrations.runtime_signers().clone(),
            openers: registrations.secret_openers().clone(),
        })
    }

    async fn material(
        &self,
        reference: &str,
        expected_kind: MaterialKind,
    ) -> Result<super::postgres::custody::LiveProtectedMaterial, ApplicationError> {
        let material_id = Uuid::parse_str(reference).map_err(|_| ApplicationError::Integrity)?;
        let material = self.materials.load_live_by_id(material_id).await?;
        if material.reservation.material_kind != expected_kind {
            return Err(ApplicationError::Integrity);
        }
        Ok(material)
    }

    async fn open_configuration_material(
        &self,
        material: LiveProtectedMaterial,
    ) -> Result<Zeroizing<Vec<u8>>, ApplicationError> {
        let opener = self
            .openers
            .get(&material.reservation.provider_id)
            .ok_or(ApplicationError::Disabled)?;
        if !opener
            .supported_format_versions()
            .contains(material.reservation.provider_format_version)
        {
            return Err(ApplicationError::Integrity);
        }
        opener
            .open(OpenSecretRequest {
                context: material.reservation.context,
                envelope: OpaqueEnvelope::new(material.opaque_value)
                    .map_err(|_| ApplicationError::Integrity)?,
            })
            .await
            .map_err(map_provider_error)
            .map(owlauth_key_provider::SecretPlaintext::into_zeroizing)
    }

    async fn sign_material(
        &self,
        material: LiveProtectedMaterial,
        signing_input: &[u8],
    ) -> Result<Vec<u8>, ApplicationError> {
        if material.reservation.owner_kind != MaterialOwnerKind::SigningKey
            || material.reservation.material_kind != MaterialKind::SigningKey
        {
            return Err(ApplicationError::Integrity);
        }
        let signer = self
            .signers
            .get(&material.reservation.provider_id)
            .ok_or(ApplicationError::Disabled)?;
        let capabilities = signer.capabilities();
        if !capabilities.supports_algorithm(SigningAlgorithm::Ed25519)
            || !capabilities
                .format_versions()
                .contains(material.reservation.provider_format_version)
        {
            return Err(ApplicationError::Integrity);
        }
        let signature = signer
            .sign(SignRequest {
                algorithm: SigningAlgorithm::Ed25519,
                context: material.reservation.context,
                handle: OpaqueHandle::new(material.opaque_value)
                    .map_err(|_| ApplicationError::Integrity)?,
                signing_input: SigningInput::new(signing_input.to_vec())
                    .map_err(|_| ApplicationError::Integrity)?,
            })
            .await
            .map_err(map_provider_error)?;
        Ok(signature.as_bytes().to_vec())
    }

    pub(crate) async fn authenticate_readiness_candidate(
        &self,
        candidate: RuntimeReadinessCandidate,
    ) -> Result<(), ApplicationError> {
        match candidate.material.reservation.material_kind {
            MaterialKind::ConfigurationSecret => {
                if candidate.signing_public_jwk.is_some() {
                    return Err(ApplicationError::Integrity);
                }
                drop(self.open_configuration_material(candidate.material).await?);
                Ok(())
            }
            MaterialKind::SigningKey => {
                let public_jwk = candidate
                    .signing_public_jwk
                    .ok_or(ApplicationError::Integrity)?;
                let mut signing_input = b"owlauth:provider-readiness:v1\0".to_vec();
                signing_input
                    .extend_from_slice(candidate.material.reservation.context.canonical_bytes());
                let signature = self
                    .sign_material(candidate.material, &signing_input)
                    .await?;
                super::runtime_security::verify_ed25519(&public_jwk, &signing_input, &signature)
            }
        }
    }
}

#[async_trait]
impl RuntimeSigner for PostgresProtectedRuntimeCustody {
    async fn sign(
        &self,
        signer_ref: &str,
        signing_input: &[u8],
    ) -> Result<Vec<u8>, ApplicationError> {
        let material = self.material(signer_ref, MaterialKind::SigningKey).await?;
        self.sign_material(material, signing_input).await
    }

    fn verify(
        &self,
        public_jwk: &serde_json::Value,
        signing_input: &[u8],
        signature: &[u8],
    ) -> Result<(), ApplicationError> {
        super::runtime_security::verify_ed25519(public_jwk, signing_input, signature)
    }
}

#[async_trait]
impl ProviderSecretResolver for PostgresProtectedRuntimeCustody {
    async fn resolve(&self, secret_ref: &str) -> Result<Zeroizing<String>, ApplicationError> {
        let material = self
            .material(secret_ref, MaterialKind::ConfigurationSecret)
            .await?;
        if material.reservation.owner_kind != MaterialOwnerKind::ProviderSecret {
            return Err(ApplicationError::Integrity);
        }
        let plaintext = self.open_configuration_material(material).await?;
        String::from_utf8(plaintext.to_vec())
            .map(Zeroizing::new)
            .map_err(|_| ApplicationError::Integrity)
    }
}

#[async_trait]
impl WebhookSecretResolver for PostgresProtectedRuntimeCustody {
    async fn resolve(&self, reference: &str) -> Result<Zeroizing<Vec<u8>>, ApplicationError> {
        let material = self
            .material(reference, MaterialKind::ConfigurationSecret)
            .await?;
        if material.reservation.owner_kind != MaterialOwnerKind::WebhookSecret {
            return Err(ApplicationError::Integrity);
        }
        self.open_configuration_material(material).await
    }

    async fn erase(&self, reference: &str) -> Result<(), ApplicationError> {
        let material_id = Uuid::parse_str(reference).map_err(|_| ApplicationError::Integrity)?;
        let material = self.materials.load_reservation_by_id(material_id).await?;
        if material.owner_kind != MaterialOwnerKind::WebhookSecret {
            return Err(ApplicationError::Integrity);
        }
        self.materials
            .erase_by_id(material_id, OffsetDateTime::now_utc())
            .await
    }
}

#[async_trait]
impl SmtpCredentialResolver for PostgresProtectedRuntimeCustody {
    async fn resolve(&self, reference: &str) -> Result<Zeroizing<Vec<u8>>, ApplicationError> {
        let material = self
            .material(reference, MaterialKind::ConfigurationSecret)
            .await?;
        if !matches!(
            material.reservation.owner_kind,
            MaterialOwnerKind::ProjectSmtp
                | MaterialOwnerKind::DeploymentSmtp
                | MaterialOwnerKind::SmtpTestRecipient
        ) {
            return Err(ApplicationError::Integrity);
        }
        self.open_configuration_material(material).await
    }

    async fn resolve_checked(
        &self,
        reference: &str,
        expected_fingerprint: &[u8; 32],
    ) -> Result<Zeroizing<Vec<u8>>, ApplicationError> {
        let material = self
            .material(reference, MaterialKind::ConfigurationSecret)
            .await?;
        if !matches!(
            material.reservation.owner_kind,
            MaterialOwnerKind::ProjectSmtp | MaterialOwnerKind::DeploymentSmtp
        ) || material.safe_fingerprint.as_deref() != Some(expected_fingerprint.as_slice())
        {
            return Err(ApplicationError::Disabled);
        }
        self.open_configuration_material(material).await
    }

    async fn erase(&self, reference: &str) -> Result<(), ApplicationError> {
        let material_id = Uuid::parse_str(reference).map_err(|_| ApplicationError::Integrity)?;
        let material = self.materials.load_reservation_by_id(material_id).await?;
        if !matches!(
            material.owner_kind,
            MaterialOwnerKind::ProjectSmtp
                | MaterialOwnerKind::DeploymentSmtp
                | MaterialOwnerKind::SmtpTestRecipient
        ) {
            return Err(ApplicationError::Integrity);
        }
        self.materials
            .erase_by_id(material_id, OffsetDateTime::now_utc())
            .await
    }
}

#[allow(
    clippy::needless_pass_by_value,
    reason = "Result::map_err supplies the owned provider error directly"
)]
fn map_provider_error(error: owlauth_key_provider::ProviderError) -> ApplicationError {
    match error.class() {
        ProviderErrorClass::NotFound => ApplicationError::NotFound,
        ProviderErrorClass::Conflict => ApplicationError::IdempotencyConflict,
        ProviderErrorClass::Unavailable | ProviderErrorClass::PermissionDenied => {
            ApplicationError::ExternalStore
        }
        ProviderErrorClass::InvalidRequest
        | ProviderErrorClass::UnsupportedAlgorithm
        | ProviderErrorClass::Integrity => ApplicationError::Integrity,
        _ => ApplicationError::ExternalStore,
    }
}
