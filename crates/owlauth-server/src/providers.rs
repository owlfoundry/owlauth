use std::{collections::BTreeMap, fmt, sync::Arc};

use owlauth_key_provider::{
    ConfigurationSecretOpener, ConfigurationSecretSealer, MaterialKind, ProviderFormatVersion,
    ProviderId, RuntimeSigner, SigningAlgorithm, SigningKeyProvisioner,
};
use thiserror::Error;

use crate::config::PlaneMode;

/// Exact provider and provider-owned format selected for newly created material.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActiveProvider {
    provider_id: ProviderId,
    format_version: ProviderFormatVersion,
}

impl ActiveProvider {
    #[must_use]
    pub fn new(provider_id: ProviderId, format_version: ProviderFormatVersion) -> Self {
        Self {
            provider_id,
            format_version,
        }
    }

    #[must_use]
    pub fn provider_id(&self) -> &ProviderId {
        &self.provider_id
    }

    #[must_use]
    pub const fn format_version(&self) -> ProviderFormatVersion {
        self.format_version
    }
}

/// Safe failures produced while registering or validating statically linked provider capabilities.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum ProviderCompositionError {
    #[error("a provider capability registration is duplicated")]
    DuplicateCapability,
    #[error("a capability's provider ID differs from its registration ID")]
    ProviderIdMismatch,
    #[error("the selected process mode is missing a required provider capability")]
    MissingCapability,
    #[error("an active provider selection is missing")]
    MissingActiveProvider,
    #[error("an active provider does not support the selected format or algorithm")]
    UnsupportedSelection,
}

/// Immutable-after-start registrations for statically linked custody providers.
///
/// Custom binaries register only the capabilities needed by their selected process plane. The
/// server validates the complete set before opening serving pools and never substitutes the
/// bundled software provider into this registry.
#[derive(Clone, Default)]
pub struct ProviderRegistrations {
    signing_provisioners: BTreeMap<ProviderId, Arc<dyn SigningKeyProvisioner>>,
    runtime_signers: BTreeMap<ProviderId, Arc<dyn RuntimeSigner>>,
    secret_sealers: BTreeMap<ProviderId, Arc<dyn ConfigurationSecretSealer>>,
    secret_openers: BTreeMap<ProviderId, Arc<dyn ConfigurationSecretOpener>>,
    active_signing: Option<ActiveProvider>,
    active_secret: Option<ActiveProvider>,
}

impl fmt::Debug for ProviderRegistrations {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderRegistrations")
            .field(
                "signing_provisioner_ids",
                &self.signing_provisioners.keys().collect::<Vec<_>>(),
            )
            .field(
                "runtime_signer_ids",
                &self.runtime_signers.keys().collect::<Vec<_>>(),
            )
            .field(
                "secret_sealer_ids",
                &self.secret_sealers.keys().collect::<Vec<_>>(),
            )
            .field(
                "secret_opener_ids",
                &self.secret_openers.keys().collect::<Vec<_>>(),
            )
            .field("active_signing", &self.active_signing)
            .field("active_secret", &self.active_secret)
            .finish()
    }
}

impl ProviderRegistrations {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers one Control signing-key provisioner under its exact reviewed provider ID.
    ///
    /// # Errors
    ///
    /// Returns an error for a duplicate ID or when the capability reports another provider ID.
    pub fn register_signing_provisioner(
        &mut self,
        provider_id: ProviderId,
        capability: Arc<dyn SigningKeyProvisioner>,
    ) -> Result<&mut Self, ProviderCompositionError> {
        ensure_provider_id(&provider_id, &capability.provider_id())?;
        insert_unique(&mut self.signing_provisioners, provider_id, capability)?;
        Ok(self)
    }

    /// Registers one Runtime signer under its exact reviewed provider ID.
    ///
    /// # Errors
    ///
    /// Returns an error for a duplicate ID or when the capability reports another provider ID.
    pub fn register_runtime_signer(
        &mut self,
        provider_id: ProviderId,
        capability: Arc<dyn RuntimeSigner>,
    ) -> Result<&mut Self, ProviderCompositionError> {
        ensure_provider_id(&provider_id, &capability.provider_id())?;
        insert_unique(&mut self.runtime_signers, provider_id, capability)?;
        Ok(self)
    }

    /// Registers one Control configuration-secret sealer under its exact reviewed provider ID.
    ///
    /// # Errors
    ///
    /// Returns an error for a duplicate ID or when the capability reports another provider ID.
    pub fn register_secret_sealer(
        &mut self,
        provider_id: ProviderId,
        capability: Arc<dyn ConfigurationSecretSealer>,
    ) -> Result<&mut Self, ProviderCompositionError> {
        ensure_provider_id(&provider_id, &capability.provider_id())?;
        insert_unique(&mut self.secret_sealers, provider_id, capability)?;
        Ok(self)
    }

    /// Registers one Runtime/worker configuration-secret opener.
    ///
    /// # Errors
    ///
    /// Returns an error for a duplicate ID or when the capability reports another provider ID.
    pub fn register_secret_opener(
        &mut self,
        provider_id: ProviderId,
        capability: Arc<dyn ConfigurationSecretOpener>,
    ) -> Result<&mut Self, ProviderCompositionError> {
        ensure_provider_id(&provider_id, &capability.provider_id())?;
        insert_unique(&mut self.secret_openers, provider_id, capability)?;
        Ok(self)
    }

    pub fn select_active_signing_provider(&mut self, selection: ActiveProvider) -> &mut Self {
        self.active_signing = Some(selection);
        self
    }

    pub fn select_active_secret_provider(&mut self, selection: ActiveProvider) -> &mut Self {
        self.active_secret = Some(selection);
        self
    }

    /// Validates all capabilities and active selections required by a process plane.
    ///
    /// # Errors
    ///
    /// Returns a fail-closed composition error for missing or unsupported capabilities.
    pub fn validate_for_mode(&self, mode: PlaneMode) -> Result<(), ProviderCompositionError> {
        if mode.has_control() {
            let active_signing = self
                .active_signing
                .as_ref()
                .ok_or(ProviderCompositionError::MissingActiveProvider)?;
            let provisioner = self
                .signing_provisioners
                .get(active_signing.provider_id())
                .ok_or(ProviderCompositionError::MissingCapability)?;
            let signing_capabilities = provisioner.capabilities();
            if !signing_capabilities.supports_algorithm(SigningAlgorithm::Ed25519)
                || !signing_capabilities
                    .format_versions()
                    .contains(active_signing.format_version())
            {
                return Err(ProviderCompositionError::UnsupportedSelection);
            }

            let active_secret = self
                .active_secret
                .as_ref()
                .ok_or(ProviderCompositionError::MissingActiveProvider)?;
            let sealer = self
                .secret_sealers
                .get(active_secret.provider_id())
                .ok_or(ProviderCompositionError::MissingCapability)?;
            if !sealer
                .supported_format_versions()
                .contains(active_secret.format_version())
            {
                return Err(ProviderCompositionError::UnsupportedSelection);
            }
        }

        if mode.has_runtime() {
            if self.runtime_signers.is_empty() || self.secret_openers.is_empty() {
                return Err(ProviderCompositionError::MissingCapability);
            }
            if self.runtime_signers.values().any(|signer| {
                !signer
                    .capabilities()
                    .supports_algorithm(SigningAlgorithm::Ed25519)
            }) {
                return Err(ProviderCompositionError::UnsupportedSelection);
            }
        }

        if mode.has_control() && mode.has_runtime() {
            let active_signing = self
                .active_signing
                .as_ref()
                .ok_or(ProviderCompositionError::MissingActiveProvider)?;
            let signer = self
                .runtime_signers
                .get(active_signing.provider_id())
                .ok_or(ProviderCompositionError::MissingCapability)?;
            if !signer
                .capabilities()
                .format_versions()
                .contains(active_signing.format_version())
            {
                return Err(ProviderCompositionError::UnsupportedSelection);
            }

            let active_secret = self
                .active_secret
                .as_ref()
                .ok_or(ProviderCompositionError::MissingActiveProvider)?;
            let opener = self
                .secret_openers
                .get(active_secret.provider_id())
                .ok_or(ProviderCompositionError::MissingCapability)?;
            if !opener
                .supported_format_versions()
                .contains(active_secret.format_version())
            {
                return Err(ProviderCompositionError::UnsupportedSelection);
            }
        }
        Ok(())
    }

    pub(crate) fn active_signing(
        &self,
    ) -> Result<(ActiveProvider, Arc<dyn SigningKeyProvisioner>), ProviderCompositionError> {
        let selection = self
            .active_signing
            .clone()
            .ok_or(ProviderCompositionError::MissingActiveProvider)?;
        let capability = self
            .signing_provisioners
            .get(selection.provider_id())
            .cloned()
            .ok_or(ProviderCompositionError::MissingCapability)?;
        Ok((selection, capability))
    }

    pub(crate) fn active_secret(
        &self,
    ) -> Result<(ActiveProvider, Arc<dyn ConfigurationSecretSealer>), ProviderCompositionError>
    {
        let selection = self
            .active_secret
            .clone()
            .ok_or(ProviderCompositionError::MissingActiveProvider)?;
        let capability = self
            .secret_sealers
            .get(selection.provider_id())
            .cloned()
            .ok_or(ProviderCompositionError::MissingCapability)?;
        Ok((selection, capability))
    }

    pub(crate) fn supports_runtime_material(
        &self,
        provider_id: &ProviderId,
        format_version: ProviderFormatVersion,
        material_kind: MaterialKind,
    ) -> bool {
        match material_kind {
            MaterialKind::SigningKey => {
                self.runtime_signers.get(provider_id).is_some_and(|signer| {
                    let capabilities = signer.capabilities();
                    capabilities.supports_algorithm(SigningAlgorithm::Ed25519)
                        && capabilities.format_versions().contains(format_version)
                })
            }
            MaterialKind::ConfigurationSecret => self
                .secret_openers
                .get(provider_id)
                .is_some_and(|opener| opener.supported_format_versions().contains(format_version)),
        }
    }

    pub(crate) fn signing_provisioners(
        &self,
    ) -> &BTreeMap<ProviderId, Arc<dyn SigningKeyProvisioner>> {
        &self.signing_provisioners
    }

    pub(crate) fn secret_sealers(
        &self,
    ) -> &BTreeMap<ProviderId, Arc<dyn ConfigurationSecretSealer>> {
        &self.secret_sealers
    }

    pub(crate) fn runtime_signers(&self) -> &BTreeMap<ProviderId, Arc<dyn RuntimeSigner>> {
        &self.runtime_signers
    }

    pub(crate) fn secret_openers(
        &self,
    ) -> &BTreeMap<ProviderId, Arc<dyn ConfigurationSecretOpener>> {
        &self.secret_openers
    }
}

fn ensure_provider_id(
    registered: &ProviderId,
    reported: &ProviderId,
) -> Result<(), ProviderCompositionError> {
    if registered == reported {
        Ok(())
    } else {
        Err(ProviderCompositionError::ProviderIdMismatch)
    }
}

fn insert_unique<T>(
    registrations: &mut BTreeMap<ProviderId, T>,
    provider_id: ProviderId,
    capability: T,
) -> Result<(), ProviderCompositionError> {
    if registrations.contains_key(&provider_id) {
        return Err(ProviderCompositionError::DuplicateCapability);
    }
    registrations.insert(provider_id, capability);
    Ok(())
}
