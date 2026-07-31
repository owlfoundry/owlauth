use std::{error::Error as StdError, fmt};

/// Stable, cross-language error category.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ErrorCategory {
    Configuration,
    Protocol,
    Login,
    Handoff,
    Authentication,
    Session,
    Refresh,
    RateLimited,
    Transport,
    Timeout,
    Cancelled,
    Indeterminate,
}

/// Whether an Application may retry an operation.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetryPolicy {
    Never,
    SafeAfterDelay,
    ApplicationDecision,
}

/// Required handling for caller-owned pending or credential state.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LocalAction {
    None,
    DiscardPendingLogin,
    QuarantinePendingLogin,
    ClearCredentials,
    QuarantineCredentials,
    Reauthenticate,
}

/// A safe semantic Project Auth error.
#[derive(Clone, Eq, PartialEq)]
pub struct Error {
    category: ErrorCategory,
    code: String,
    message: String,
    request_id: Option<String>,
    retry: RetryPolicy,
    action: LocalAction,
    operation: &'static str,
    status: Option<u16>,
}

impl Error {
    pub(crate) fn new(
        category: ErrorCategory,
        code: impl Into<String>,
        message: impl Into<String>,
        retry: RetryPolicy,
        action: LocalAction,
        operation: &'static str,
    ) -> Self {
        Self {
            category,
            code: code.into(),
            message: message.into(),
            request_id: None,
            retry,
            action,
            operation,
            status: None,
        }
    }

    pub(crate) fn with_runtime(mut self, status: u16, request_id: Option<String>) -> Self {
        self.status = Some(status);
        self.request_id = request_id.filter(|value| value.len() <= 128);
        self
    }

    #[must_use]
    pub const fn category(&self) -> ErrorCategory {
        self.category
    }

    #[must_use]
    pub fn code(&self) -> &str {
        &self.code
    }

    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }

    #[must_use]
    pub fn request_id(&self) -> Option<&str> {
        self.request_id.as_deref()
    }

    #[must_use]
    pub const fn retry_policy(&self) -> RetryPolicy {
        self.retry
    }

    #[must_use]
    pub const fn local_action(&self) -> LocalAction {
        self.action
    }

    #[must_use]
    pub const fn operation(&self) -> &'static str {
        self.operation
    }

    #[must_use]
    pub const fn status(&self) -> Option<u16> {
        self.status
    }
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl fmt::Debug for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Error")
            .field("category", &self.category)
            .field("code", &self.code)
            .field("message", &self.message)
            .field("request_id", &self.request_id)
            .field("retry", &self.retry)
            .field("action", &self.action)
            .field("operation", &self.operation)
            .field("status", &self.status)
            .finish()
    }
}

impl StdError for Error {}

pub(crate) fn configuration(code: &str, message: &str) -> Error {
    Error::new(
        ErrorCategory::Configuration,
        code,
        message,
        RetryPolicy::Never,
        LocalAction::None,
        "configuration",
    )
}

pub(crate) fn protocol(operation: &'static str, code: &str) -> Error {
    Error::new(
        ErrorCategory::Protocol,
        code,
        "Runtime returned an invalid or incompatible response.",
        RetryPolicy::Never,
        LocalAction::None,
        operation,
    )
}
