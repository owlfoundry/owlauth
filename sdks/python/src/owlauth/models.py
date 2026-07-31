"""Typed Project Auth protocol values with redacted credential formatting."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from threading import Lock
from typing import Any

from owlauth.errors import HandoffError, LocalAction, RetryDisposition


class _OneUseGuard:
    __slots__ = ("_consumed", "_lock")

    def __init__(self) -> None:
        self._consumed = False
        self._lock = Lock()

    def consume(self) -> None:
        with self._lock:
            if self._consumed:
                raise HandoffError(
                    "pending_login_consumed",
                    "The pending login has already been used.",
                    retry=RetryDisposition.NEVER,
                    action=LocalAction.DISCARD_PENDING,
                    operation="handoff",
                )
            self._consumed = True


@dataclass(frozen=True, slots=True, repr=False)
class SecretValue:
    """A credential that is revealed only by an explicit method call."""

    _value: str
    _kind: str = field(default="credential")

    def reveal(self) -> str:
        """Return raw credential material for deliberate Application custody."""
        return self._value

    def __repr__(self) -> str:
        return f"{type(self).__name__}(<redacted {self._kind}>)"

    __str__ = __repr__


@dataclass(frozen=True, slots=True)
class PublicProvider:
    key: str
    display_name: str
    kind: str


@dataclass(frozen=True, slots=True)
class PublicApplicationConfig:
    project_id: str
    project_display_name: str
    application_id: str
    application_display_name: str
    publishable_keys: tuple[str, ...]
    providers: tuple[PublicProvider, ...]
    login_available: bool


@dataclass(frozen=True, slots=True)
class PublicJwk:
    key_type: str
    curve: str
    algorithm: str
    use: str
    kid: str
    x: str


@dataclass(frozen=True, slots=True)
class JwksDocument:
    keys: tuple[PublicJwk, ...]
    revision: int
    signing_epoch: int


@dataclass(frozen=True, slots=True, repr=False)
class UserProjection:
    user_id: str
    user_revision: int
    projection_schema: str
    projection_revision: int
    display_name: str | None
    picture_url: str | None
    status: str
    created_at: datetime
    updated_at: datetime

    def __repr__(self) -> str:
        return (
            "UserProjection("
            f"user_id={self.user_id!r}, user_revision={self.user_revision!r}, "
            f"projection_schema={self.projection_schema!r}, "
            f"projection_revision={self.projection_revision!r}, "
            "display_name=<redacted>, picture_url=<redacted>, "
            f"status={self.status!r}, created_at={self.created_at!r}, "
            f"updated_at={self.updated_at!r})"
        )


@dataclass(frozen=True, slots=True, repr=False)
class PendingLogin:
    """Caller-held one-attempt PKCE state. Default formatting is redacted."""

    runtime_base_url: str
    project_id: str
    application_id: str
    redirect_uri: str
    hosted_url: str
    created_at: datetime
    expires_at: datetime
    _state: SecretValue
    _pkce_verifier: SecretValue
    _guard: _OneUseGuard = field(default_factory=_OneUseGuard, compare=False)
    _marker: object = field(default_factory=object, compare=False)

    def __repr__(self) -> str:
        return (
            "PendingLogin("
            f"runtime_base_url={self.runtime_base_url!r}, "
            f"project_id={self.project_id!r}, "
            f"application_id={self.application_id!r}, "
            "redirect_uri=<redacted>, hosted_url=<redacted>, "
            f"created_at={self.created_at!r}, "
            f"expires_at={self.expires_at!r}, "
            "state=<redacted>, pkce_verifier=<redacted>)"
        )


@dataclass(frozen=True, slots=True, repr=False)
class ValidatedCallback:
    """A locally validated handoff callback bound to one pending login."""

    _handoff: SecretValue
    _pending_marker: object = field(compare=False)

    def __repr__(self) -> str:
        return "ValidatedCallback(handoff=<redacted>)"


@dataclass(frozen=True, slots=True, repr=False)
class LoginStart:
    hosted_url: str
    pending: PendingLogin

    def __repr__(self) -> str:
        return f"LoginStart(hosted_url=<redacted>, pending={self.pending!r})"


@dataclass(frozen=True, slots=True, repr=False)
class CredentialPair:
    project_id: str
    application_id: str
    user_id: str
    session_id: str
    refresh_generation: int
    access_token: SecretValue
    refresh_token: SecretValue
    token_type: str
    access_expires_at: datetime
    session_expires_at: datetime
    projection: UserProjection

    def __repr__(self) -> str:
        return (
            "CredentialPair("
            f"project_id={self.project_id!r}, "
            f"application_id={self.application_id!r}, "
            f"user_id={self.user_id!r}, "
            f"session_id={self.session_id!r}, "
            f"refresh_generation={self.refresh_generation!r}, "
            "access_token=<redacted>, refresh_token=<redacted>, "
            f"token_type={self.token_type!r}, "
            f"access_expires_at={self.access_expires_at!r}, "
            f"session_expires_at={self.session_expires_at!r}, "
            "projection=<redacted>)"
        )


@dataclass(frozen=True, slots=True, repr=False)
class CurrentUser:
    project_id: str
    application_id: str
    user_id: str
    projection: UserProjection
    authenticated_at: datetime
    session_expires_at: datetime

    def __repr__(self) -> str:
        return (
            "CurrentUser("
            f"project_id={self.project_id!r}, application_id={self.application_id!r}, "
            f"user_id={self.user_id!r}, projection=<redacted>, "
            f"authenticated_at={self.authenticated_at!r}, "
            f"session_expires_at={self.session_expires_at!r})"
        )


@dataclass(frozen=True, slots=True, repr=False)
class BrowserLogoutPreparation:
    hosted_url: str
    expires_at: datetime

    def __repr__(self) -> str:
        return f"BrowserLogoutPreparation(hosted_url=<redacted>, expires_at={self.expires_at!r})"


@dataclass(frozen=True, slots=True)
class Completion:
    completed: bool


JsonObject = dict[str, Any]
