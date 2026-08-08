use thiserror::Error;

use crate::domain::DomainError;

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub(crate) enum ApplicationError {
    #[error("request value is invalid")]
    InvalidInput,
    #[error("resource was not found")]
    NotFound,
    #[error("resource is disabled")]
    Disabled,
    #[error("resource revision conflicts with the request")]
    RevisionConflict,
    #[error("idempotency key conflicts with a different request")]
    IdempotencyConflict,
    #[error("operation is already in progress")]
    OperationInProgress,
    #[error("state transition is not allowed")]
    InvalidTransition,
    #[error("bounded resource capacity is exhausted")]
    CapacityExceeded,
    #[error("authoritative state failed an integrity check")]
    Integrity,
    #[error("authoritative persistence is unavailable")]
    Persistence,
    #[error("OIDC preflight rejected the issuer or discovered metadata")]
    ProviderPreflightRejected,
    #[error("OIDC preflight could not reach or validate the provider")]
    ProviderPreflightUnavailable,
    #[error("external secret or signer store is unavailable")]
    ExternalStore,
}

impl From<DomainError> for ApplicationError {
    fn from(_: DomainError) -> Self {
        Self::InvalidInput
    }
}
