mod application;
#[allow(
    dead_code,
    reason = "email lane domain is exercised through Runtime and PostgreSQL"
)]
mod email;
#[allow(
    dead_code,
    reason = "authentication application and persistence integration follows this domain-only slice"
)]
mod identity;
#[allow(
    dead_code,
    reason = "identity mutation application and persistence integration follows this domain slice"
)]
mod identity_mutation;
mod key;
#[allow(
    dead_code,
    reason = "authentication application and persistence integration follows this domain-only slice"
)]
mod login;
#[allow(
    dead_code,
    reason = "domain transition matrix is exercised directly and persistence enforces the same states"
)]
mod managed_connection;
mod project;
#[allow(
    dead_code,
    reason = "authentication application and persistence integration follows this domain-only slice"
)]
mod projection;
mod provider;
#[allow(
    dead_code,
    reason = "authentication application and persistence integration follows this domain-only slice"
)]
mod session;
mod webhook;

pub(crate) use application::{ApplicationStatus, ApplicationType, BrowserOrigin, RedirectUri};
#[allow(unused_imports, reason = "email lane is integrated incrementally")]
pub(crate) use email::{
    CanonicalEmail, EmailChallengeState, EmailChallengeStatus, EmailProofPolicy,
    EmailValidationError, generate_decimal_otp,
};
#[allow(
    unused_imports,
    reason = "authentication application and persistence integration follows this domain-only slice"
)]
pub(crate) use identity::{
    BoundedProviderProfile, IdentitySourceKind, LocalProfileField, MaterializedUserProfile,
    ProfileDisplayName, ProfileLocale, ProfilePictureUrl, ProjectUserStatus, ProviderIssuer,
    ProviderSubject, UserProfileInputs, UserRevision,
};
#[allow(
    unused_imports,
    reason = "identity mutation application and persistence integration follows this domain slice"
)]
pub(crate) use identity_mutation::{
    ExistingIdentitySnapshot, IdentityKind, IdentityMutationEffect, IdentityMutationIntent,
    IdentityMutationKind, IdentityMutationPlan, IdentityMutationProofSlot,
    IdentityMutationSlotRole, IdentityMutationSlotState, IdentityMutationSlotTarget,
    IdentityMutationStatus, IdentityProofEvidence, IdentityProofReceiptSnapshot,
    IdentityProofReceiptStatus, InteractionBrowserBinding, ProofMethodAuthority,
    ProviderProofCapabilitySnapshot, RestoredIdentityMutationIntent,
    RestoredIdentityMutationProofSlot, RestoredIdentityProofReceipt,
    TrustedRuntimeProviderCallback,
};
pub(crate) use key::SigningKeyState;
#[allow(
    unused_imports,
    reason = "authentication application and persistence integration follows this domain-only slice"
)]
pub(crate) use login::LoginTransactionStatus;
#[allow(
    unused_imports,
    reason = "managed connection application lane uses this domain contract"
)]
pub(crate) use managed_connection::{
    ManagedConnectionEvent, ManagedConnectionLifecycle, ManagedConnectionState,
    ManagedProfileCapability, RenewalReplay,
};
pub(crate) use project::{
    DisplayName, MAX_ACCESS_TOKEN_LIFETIME_SECONDS, MIN_ACCESS_TOKEN_LIFETIME_SECONDS, OpaqueOwner,
    ProjectStatus, PublicId,
};
#[allow(
    unused_imports,
    reason = "authentication application and persistence integration follows this domain-only slice"
)]
pub(crate) use projection::{
    ProjectionRevision, USER_PROJECTION_SCHEMA_V1, UserProjection, UserProjectionSource,
};
#[allow(
    unused_imports,
    reason = "Google issuer fixtures and invariant tests consume this domain authority"
)]
pub(crate) use provider::GOOGLE_ISSUER;
pub(crate) use provider::{
    FixedProviderAuthorizationPolicy, GITHUB_ISSUER, GITHUB_SCOPES, GOOGLE_SCOPES,
    ManagedProfileCapabilities, NamedProviderProfile, ProviderConsentBehavior, ProviderEgressMode,
    ProviderEgressPolicy, ProviderKey, ProviderKind, ProviderOrigin, ProviderStatus,
    provider_callback_url,
};
#[allow(
    unused_imports,
    reason = "authentication application and persistence integration follows this domain-only slice"
)]
pub(crate) use session::{
    ApplicationSessionStatus, BrowserLogoutStatus, BrowserSessionStatus, HandoffStatus,
    RefreshFamilyStatus, RefreshGenerationStatus, RefreshPresentationDecision,
};
pub(crate) use webhook::{
    ApplicationUserEventType, MAX_WEBHOOK_DELIVERY_ATTEMPTS, MAX_WEBHOOK_ENDPOINTS_PER_APPLICATION,
    WebhookDeliveryOutcome, WebhookEndpointStatus, WebhookEndpointUrl, WebhookSubscriptions,
};

use thiserror::Error;

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub(crate) enum DomainError {
    #[error("value is empty")]
    Empty,
    #[error("value exceeds its maximum length")]
    TooLong,
    #[error("value contains unsupported characters")]
    InvalidCharacters,
    #[error("URL is not an exact supported value")]
    InvalidUrl,
    #[error("state transition is not allowed")]
    InvalidTransition,
    #[error("value is outside the supported bounds")]
    InvalidValue,
}
