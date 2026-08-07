"""Stable, secret-free OwlAuth SDK errors."""

from __future__ import annotations

from enum import StrEnum


class ErrorCategory(StrEnum):
    """Decision-relevant error categories shared by OwlAuth SDKs."""

    CONFIGURATION = "configuration"
    PROTOCOL = "protocol"
    LOGIN = "login"
    HANDOFF = "handoff"
    AUTHENTICATION = "authentication"
    SESSION = "session"
    REFRESH = "refresh"
    RATE_LIMITED = "rate_limited"
    TRANSPORT = "transport"
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"
    INDETERMINATE = "indeterminate"


class RetryDisposition(StrEnum):
    """Whether a caller may consider another request."""

    NEVER = "never"
    SAFE_AFTER_DELAY = "safe_after_delay"
    APPLICATION_DECISION = "application_decision"


class LocalAction(StrEnum):
    """Required action for caller-owned pending or credential state."""

    NONE = "none"
    DISCARD_PENDING = "discard_pending"
    QUARANTINE_PENDING = "quarantine_pending"
    INVALIDATE_CREDENTIALS = "invalidate_credentials"
    QUARANTINE_CREDENTIALS = "quarantine_credentials"
    REAUTHENTICATE = "reauthenticate"


class OwlAuthError(Exception):
    """Base error with stable fields and redacted formatting."""

    category = ErrorCategory.PROTOCOL

    def __init__(
        self,
        code: str,
        message: str,
        *,
        retry: RetryDisposition = RetryDisposition.NEVER,
        action: LocalAction = LocalAction.NONE,
        request_id: str | None = None,
        operation: str | None = None,
        status: int | None = None,
        retry_after_seconds: int | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.safe_message = message
        self.retry = retry
        self.action = action
        self.request_id = request_id
        self.operation = operation
        self.status = status
        self.retry_after_seconds = retry_after_seconds

    def __str__(self) -> str:
        request = f" request_id={self.request_id}" if self.request_id is not None else ""
        return f"{self.category.value}:{self.code}: {self.safe_message}{request}"

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}(category={self.category.value!r}, code={self.code!r}, "
            f"retry={self.retry.value!r}, action={self.action.value!r}, "
            f"operation={self.operation!r}, request_id={self.request_id!r}, "
            f"retry_after_seconds={self.retry_after_seconds!r})"
        )


class ConfigurationError(OwlAuthError):
    category = ErrorCategory.CONFIGURATION


class ProtocolError(OwlAuthError):
    category = ErrorCategory.PROTOCOL


class LoginError(OwlAuthError):
    category = ErrorCategory.LOGIN


class HandoffError(OwlAuthError):
    category = ErrorCategory.HANDOFF


class AuthenticationError(OwlAuthError):
    category = ErrorCategory.AUTHENTICATION


class SessionError(OwlAuthError):
    category = ErrorCategory.SESSION


class RefreshError(OwlAuthError):
    category = ErrorCategory.REFRESH


class RateLimitedError(OwlAuthError):
    category = ErrorCategory.RATE_LIMITED


class TransportError(OwlAuthError):
    category = ErrorCategory.TRANSPORT


class OwlAuthTimeoutError(OwlAuthError):
    category = ErrorCategory.TIMEOUT


class CancelledError(OwlAuthError):
    category = ErrorCategory.CANCELLED


class IndeterminateError(OwlAuthError):
    category = ErrorCategory.INDETERMINATE
