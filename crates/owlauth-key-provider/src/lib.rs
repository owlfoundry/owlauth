#![forbid(unsafe_code)]

//! Provider-neutral signing and configuration-secret custody capabilities for `OwlAuth`.
//!
//! This crate deliberately owns no server policy, persistence, HTTP contract, configuration parser,
//! or vendor integration. Implementations are statically composed into a server binary and receive
//! only bounded, exact-context requests for their assigned role.

mod context;
mod error;
mod secrets;
mod signing;
mod values;

pub use context::{
    ContextVersion, DeploymentId, FieldPurpose, MaterialId, MaterialKind, OwnerId, OwnerKind,
    ProjectId, ProtectionContext, ProtectionContextParts, Scope,
};
pub use error::{
    ProviderError, ProviderErrorClass, ProviderErrorCode, RetryClassification, ValueError,
};
pub use secrets::{
    ConfigurationSecretOpener, ConfigurationSecretSealer, OpenSecretRequest, SealSecretRequest,
    SealedSecret, SecretPlaintext,
};
pub use signing::{
    DestroySigningKeyRequest, InspectSigningKeyRequest, ProvisionSigningKeyRequest,
    ProvisionedSigningKey, RuntimeSigner, SignRequest, SigningKeyProvisioner,
    SigningProvisioningSemantics,
};
pub use values::{
    DestroyOutcome, OpaqueEnvelope, OpaqueHandle, OperationId, ProviderFormatVersion,
    ProviderFormatVersions, ProviderId, RequestFingerprint, Signature, SigningAlgorithm,
    SigningInput, SigningProviderCapabilities, SigningPublicKey,
};

/// Re-exported object-safe async trait convention for provider implementations.
pub use async_trait::async_trait;
