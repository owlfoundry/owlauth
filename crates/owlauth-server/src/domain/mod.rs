mod application;
#[allow(
    dead_code,
    reason = "Block B application and persistence integration follows this domain-only slice"
)]
mod identity;
mod key;
#[allow(
    dead_code,
    reason = "Block B application and persistence integration follows this domain-only slice"
)]
mod login;
mod project;
#[allow(
    dead_code,
    reason = "Block B application and persistence integration follows this domain-only slice"
)]
mod projection;
mod provider;
#[allow(
    dead_code,
    reason = "Block B application and persistence integration follows this domain-only slice"
)]
mod session;

pub(crate) use application::{ApplicationStatus, ApplicationType, BrowserOrigin, RedirectUri};
#[allow(
    unused_imports,
    reason = "Block B application and persistence integration follows this domain-only slice"
)]
pub(crate) use identity::{
    ProfileDisplayName, ProfilePictureUrl, ProjectUserStatus, ProviderIssuer, ProviderSubject,
    UserRevision,
};
pub(crate) use key::SigningKeyState;
#[allow(
    unused_imports,
    reason = "Block B application and persistence integration follows this domain-only slice"
)]
pub(crate) use login::LoginTransactionStatus;
pub(crate) use project::{
    DisplayName, MAX_ACCESS_TOKEN_LIFETIME_SECONDS, MIN_ACCESS_TOKEN_LIFETIME_SECONDS, OpaqueOwner,
    ProjectStatus, PublicId,
};
#[allow(
    unused_imports,
    reason = "Block B application and persistence integration follows this domain-only slice"
)]
pub(crate) use projection::{
    ProjectionRevision, USER_PROJECTION_SCHEMA_V1, UserProjection, UserProjectionSource,
};
pub(crate) use provider::{ProviderKey, ProviderStatus};
#[allow(
    unused_imports,
    reason = "Block B application and persistence integration follows this domain-only slice"
)]
pub(crate) use session::{
    ApplicationSessionStatus, BrowserLogoutStatus, BrowserSessionStatus, HandoffStatus,
    RefreshFamilyStatus, RefreshGenerationStatus, RefreshPresentationDecision,
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
}
