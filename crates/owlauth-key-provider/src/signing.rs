use async_trait::async_trait;

use crate::{
    DestroyOutcome, OpaqueHandle, OperationId, ProtectionContext, ProviderError, ProviderId,
    Signature, SigningAlgorithm, SigningInput, SigningProviderCapabilities, SigningPublicKey,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProvisionSigningKeyRequest {
    pub operation_id: OperationId,
    pub algorithm: SigningAlgorithm,
    pub context: ProtectionContext,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InspectSigningKeyRequest {
    pub operation_id: OperationId,
    pub algorithm: SigningAlgorithm,
    pub context: ProtectionContext,
}

#[derive(Debug, Eq, PartialEq)]
pub struct DestroySigningKeyRequest {
    pub algorithm: SigningAlgorithm,
    pub context: ProtectionContext,
    pub handle: OpaqueHandle,
}

#[derive(Debug, Eq, PartialEq)]
pub struct ProvisionedSigningKey {
    pub handle: OpaqueHandle,
    pub public_key: SigningPublicKey,
}

#[derive(Debug, Eq, PartialEq)]
pub struct SignRequest {
    pub algorithm: SigningAlgorithm,
    pub context: ProtectionContext,
    pub handle: OpaqueHandle,
    pub signing_input: SigningInput,
}

/// Provider-owned provisioning model declared during composition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum SigningProvisioningSemantics {
    /// Provision creates or addresses an external object keyed by the stable operation ID.
    StableOperation,
    /// Provision returns a self-contained handle and creates no external object or durable effect.
    StatelessHandle,
}

/// Control capability for signing-key provisioning and reconciliation.
#[async_trait]
pub trait SigningKeyProvisioner: Send + Sync {
    /// Returns the immutable provider ID authenticated by this capability.
    fn provider_id(&self) -> ProviderId;

    fn capabilities(&self) -> SigningProviderCapabilities;

    /// Declares whether provisioning owns a stable external object or a self-contained handle.
    fn provisioning_semantics(&self) -> SigningProvisioningSemantics {
        SigningProvisioningSemantics::StableOperation
    }

    /// Provisions one result for an exact operation ID, algorithm, and context.
    ///
    /// [`SigningProvisioningSemantics::StableOperation`] retries and `inspect` must return a
    /// byte-identical opaque handle and public key and must not create another key. A provider must
    /// fail closed rather than return an alias or replacement handle for the same operation.
    /// [`SigningProvisioningSemantics::StatelessHandle`] may generate a fresh self-contained handle
    /// on retry only because it creates no external object or durable provider-side effect.
    async fn provision(
        &self,
        request: ProvisionSigningKeyRequest,
    ) -> Result<ProvisionedSigningKey, ProviderError>;

    /// Returns the byte-identical stable-operation result established by `provision`.
    ///
    /// Stateless-handle providers return `NotFound` with `ExactInputSafe` because no provider-side
    /// operation result exists to inspect; a discarded pre-commit handle has no orphaned effect.
    async fn inspect(
        &self,
        request: InspectSigningKeyRequest,
    ) -> Result<ProvisionedSigningKey, ProviderError>;

    async fn destroy(
        &self,
        request: DestroySigningKeyRequest,
    ) -> Result<DestroyOutcome, ProviderError>;
}

/// Runtime capability for signing one exact complete JWS signing input.
#[async_trait]
pub trait RuntimeSigner: Send + Sync {
    /// Returns the immutable provider ID authenticated by this capability.
    fn provider_id(&self) -> ProviderId;

    fn capabilities(&self) -> SigningProviderCapabilities;

    async fn sign(&self, request: SignRequest) -> Result<Signature, ProviderError>;
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;

    fn assert_object_safe(
        _provisioner: Option<Arc<dyn SigningKeyProvisioner>>,
        _signer: Option<Arc<dyn RuntimeSigner>>,
    ) {
    }

    #[test]
    fn signing_traits_are_object_safe() {
        assert_object_safe(None, None);
    }
}
