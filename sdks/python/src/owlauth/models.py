"""Typed Project Auth protocol values with redacted credential formatting."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from threading import Lock
from typing import Any, TypeVar

from owlauth.errors import HandoffError, LocalAction, RetryDisposition

_Snapshot = TypeVar("_Snapshot")


class _OneUseGuard:
    __slots__ = ("_state", "_lock")

    def __init__(self) -> None:
        self._state = "available"
        self._lock = Lock()

    @property
    def available(self) -> bool:
        with self._lock:
            return self._state == "available"

    @property
    def consumed(self) -> bool:
        with self._lock:
            return self._state == "consumed"

    def snapshot_if_available(self, factory: Callable[[], _Snapshot]) -> _Snapshot:
        """Linearize an explicit secret snapshot against exchange reservation."""
        with self._lock:
            if self._state != "available":
                raise ValueError("Reserved or consumed pending login state cannot be exported.")
            return factory()

    def reserve(self) -> None:
        with self._lock:
            if self._state != "available":
                raise HandoffError(
                    "pending_login_consumed",
                    "The pending login has already been used.",
                    retry=RetryDisposition.NEVER,
                    action=LocalAction.DISCARD_PENDING,
                    operation="exchange_handoff",
                )
            self._state = "reserved"

    def commit(self) -> None:
        with self._lock:
            if self._state == "reserved":
                self._state = "consumed"

    def release(self) -> None:
        with self._lock:
            if self._state == "reserved":
                self._state = "available"


class SecretValue:
    """A credential that is revealed only by an explicit method call.

    This is intentionally not a dataclass: generic ``dataclasses.asdict`` traversal must
    preserve the redacted wrapper instead of expanding its private raw value.
    """

    __slots__ = ("__value", "__kind")

    def __init__(self, value: str, kind: str = "credential") -> None:
        if not isinstance(value, str) or not value:
            raise ValueError("SecretValue requires non-empty text.")
        self.__value = value
        self.__kind = kind

    def reveal(self) -> str:
        """Return raw credential material for deliberate Application custody."""
        return self.__value

    def __repr__(self) -> str:
        return f"{type(self).__name__}(<redacted {self.__kind}>)"

    __str__ = __repr__

    def __copy__(self) -> SecretValue:
        return self

    def __deepcopy__(self, memo: dict[int, object]) -> SecretValue:
        del memo
        return self

    def __reduce__(self) -> object:
        raise TypeError("SecretValue cannot be serialized.")

    def __reduce_ex__(self, protocol: int) -> object:
        del protocol
        raise TypeError("SecretValue cannot be serialized.")

    def __getstate__(self) -> object:
        raise TypeError("SecretValue cannot be serialized.")


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
    email_available: bool
    email_otp_enabled: bool
    email_magic_link_enabled: bool
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
    locale: str | None
    verified_email: str | None
    status: str
    created_at: datetime
    updated_at: datetime

    def __repr__(self) -> str:
        return (
            "UserProjection("
            f"user_id={self.user_id!r}, user_revision={self.user_revision!r}, "
            f"projection_schema={self.projection_schema!r}, "
            f"projection_revision={self.projection_revision!r}, "
            "display_name=<redacted>, picture_url=<redacted>, locale=<redacted>, "
            "verified_email=<redacted>, "
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
    _client_marker: object = field(default_factory=object, init=False, compare=False)

    def export_record(self) -> dict[str, object]:
        """Explicitly export secret-bearing state for protected Application storage."""
        return self._guard.snapshot_if_available(
            lambda: {
                "schema_version": 1,
                "runtime_base_url": self.runtime_base_url,
                "project_id": self.project_id,
                "application_id": self.application_id,
                "redirect_uri": self.redirect_uri,
                "hosted_url": self.hosted_url,
                "created_at": self.created_at.isoformat(),
                "expires_at": self.expires_at.isoformat(),
                "state": self._state.reveal(),
                "pkce_verifier": self._pkce_verifier.reveal(),
            }
        )

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
    runtime_base_url: str
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
    _client_marker: object = field(default_factory=object, init=False, compare=False)

    def export_record(self) -> dict[str, object]:
        """Explicitly export one atomic secret-bearing credential generation."""
        return {
            "schema_version": 1,
            "runtime_base_url": self.runtime_base_url,
            "project_id": self.project_id,
            "application_id": self.application_id,
            "user_id": self.user_id,
            "session_id": self.session_id,
            "refresh_generation": self.refresh_generation,
            "access_token": self.access_token.reveal(),
            "refresh_token": self.refresh_token.reveal(),
            "token_type": self.token_type,
            "access_expires_at": self.access_expires_at.isoformat(),
            "session_expires_at": self.session_expires_at.isoformat(),
            "projection": {
                "user_id": self.projection.user_id,
                "user_revision": self.projection.user_revision,
                "projection_schema": self.projection.projection_schema,
                "projection_revision": self.projection.projection_revision,
                "display_name": self.projection.display_name,
                "picture_url": self.projection.picture_url,
                "locale": self.projection.locale,
                "verified_email": self.projection.verified_email,
                "status": self.projection.status,
                "created_at": self.projection.created_at.isoformat(),
                "updated_at": self.projection.updated_at.isoformat(),
            },
        }

    def __repr__(self) -> str:
        return (
            "CredentialPair("
            f"runtime_base_url={self.runtime_base_url!r}, "
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
