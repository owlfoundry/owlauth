mod application;
mod key;
mod project;
mod provider;

pub(crate) use application::{ApplicationStatus, ApplicationType, BrowserOrigin, RedirectUri};
pub(crate) use key::SigningKeyState;
pub(crate) use project::{DisplayName, OpaqueOwner, ProjectStatus, PublicId};
pub(crate) use provider::{ProviderKey, ProviderStatus};

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
