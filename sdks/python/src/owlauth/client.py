"""Synchronous, Project/Application-bound OwlAuth Runtime client."""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import ipaddress
import json
import re
import secrets
import unicodedata
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from functools import wraps
from typing import Any, Literal, ParamSpec, TypeVar, cast
from urllib.parse import parse_qsl, quote, unquote, urlencode, urljoin, urlsplit, urlunsplit

from owlauth._json import loads_strict_json
from owlauth.errors import (
    AuthenticationError,
    CancelledError,
    ConfigurationError,
    HandoffError,
    IndeterminateError,
    LocalAction,
    LoginError,
    OwlAuthError,
    OwlAuthTimeoutError,
    ProtocolError,
    RateLimitedError,
    RefreshError,
    RetryDisposition,
    SessionError,
    TransportError,
)
from owlauth.models import (
    BrowserLogoutPreparation,
    Completion,
    CredentialPair,
    CurrentUser,
    JsonObject,
    JwksDocument,
    LoginStart,
    PendingLogin,
    PublicApplicationConfig,
    PublicJwk,
    PublicProvider,
    SecretValue,
    UserProjection,
    ValidatedCallback,
    _OneUseGuard,
)
from owlauth.transport import FailureKind, StdlibTransport, Transport, TransportFailure

_MAX_JSON_BYTES = 65_536
_IDENTIFIER = re.compile(r"^[A-Za-z0-9_-]+$")
_REQUEST_ID = re.compile(r"^[A-Za-z0-9._:-]+$")
_PKCE_VERIFIER = re.compile(r"^[A-Za-z0-9_-]{43,128}$")
_BEARER_TOKEN = re.compile(r"^[A-Za-z0-9._~+/=-]+$")
_OPAQUE_TOKEN = re.compile(r"^[A-Za-z0-9._~-]+$")
_ALLOWED_ERROR_STATUSES = {
    "get_public_application_config": frozenset({400, 404, 429, 503}),
    "get_project_jwks": frozenset({404, 429, 503}),
    "start_login": frozenset({400, 404, 429, 503}),
    "exchange_handoff": frozenset({400, 409, 429, 503}),
    "refresh_session": frozenset({400, 409, 429, 503}),
    "get_current_user": frozenset({401, 429, 503}),
    "logout_application_session": frozenset({401, 429, 503}),
    "prepare_browser_logout": frozenset({401, 429, 503}),
}
_CREDENTIAL_RESPONSE_FIELDS = frozenset(
    {
        "project_id",
        "application_id",
        "user_id",
        "session_id",
        "refresh_generation",
        "access_token",
        "refresh_token",
        "token_type",
        "expires_in",
        "projection",
        "projection_revision",
        "session_expires_at",
    }
)
_CURRENT_USER_RESPONSE_FIELDS = frozenset(
    {
        "project_id",
        "application_id",
        "user_id",
        "projection",
        "projection_revision",
        "authenticated_at",
        "session_expires_at",
    }
)
_SENSITIVE_OPERATIONS = frozenset(
    {
        "exchange_handoff",
        "refresh_session",
        "logout_application_session",
        "prepare_browser_logout",
    }
)
_PROVIDER_KINDS = frozenset({"oidc", "google", "github"})
_Parameters = ParamSpec("_Parameters")
_Result = TypeVar("_Result")


def _bind_protocol_operation(
    operation: str,
) -> Callable[[Callable[_Parameters, _Result]], Callable[_Parameters, _Result]]:
    def decorate(function: Callable[_Parameters, _Result]) -> Callable[_Parameters, _Result]:
        @wraps(function)
        def wrapped(*args: _Parameters.args, **kwargs: _Parameters.kwargs) -> _Result:
            try:
                return function(*args, **kwargs)
            except ProtocolError as error:
                if error.operation is None:
                    error.operation = operation
                raise

        return wrapped

    return decorate


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _bind_client_value(value: _Result, marker: object) -> _Result:
    object.__setattr__(value, "_client_marker", marker)
    return value


@dataclass(frozen=True, slots=True)
class Client:
    """Immutable synchronous client bound to one Runtime, Project, and Application.

    The client is safe to share if its injected transport is safe to share. Pending login and
    credential values remain caller-owned; the client performs no persistence, navigation, or
    refresh coordination.
    """

    base_url: str
    project_id: str
    application_id: str
    publishable_key: str
    allow_insecure_loopback: bool = False
    timeout: float = 10.0
    transport: Transport = field(default_factory=StdlibTransport, repr=False, compare=False)
    _clock: Callable[[], datetime] = field(default=_utc_now, repr=False, compare=False)
    _entropy: Callable[[int], bytes] = field(default=secrets.token_bytes, repr=False, compare=False)
    _client_marker: object = field(default_factory=object, init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "base_url",
            _validate_runtime_base(self.base_url, self.allow_insecure_loopback),
        )
        _validate_identifier("project_id", self.project_id, 96)
        _validate_identifier("application_id", self.application_id, 96)
        _validate_identifier("publishable_key", self.publishable_key, 128)
        if not isinstance(self.timeout, (int, float)) or not (0 < float(self.timeout) <= 120):
            raise ConfigurationError("invalid_timeout", "The request timeout is invalid.")
        object.__setattr__(self, "timeout", float(self.timeout))
        now = self._clock()
        if not isinstance(now, datetime) or now.tzinfo is None:
            raise ConfigurationError("invalid_clock", "The configured clock must return UTC time.")

    def restore_pending_login(self, record: object) -> PendingLogin:
        """Restore an explicitly exported pending-login record into this exact client."""
        fields = {
            "schema_version",
            "runtime_base_url",
            "project_id",
            "application_id",
            "redirect_uri",
            "hosted_url",
            "created_at",
            "expires_at",
            "state",
            "pkce_verifier",
        }
        try:
            payload = _record_object(record, fields)
            if (
                not isinstance(payload["schema_version"], int)
                or isinstance(payload["schema_version"], bool)
                or payload["schema_version"] != 1
                or payload["runtime_base_url"] != self.base_url
                or payload["project_id"] != self.project_id
                or payload["application_id"] != self.application_id
            ):
                raise ValueError
            redirect_uri = _validate_redirect_uri(_record_string(payload, "redirect_uri", 2048))
            hosted_url = _record_string(payload, "hosted_url", 512)
            _require_runtime_url(self.base_url, hosted_url)
            created_at = _record_timestamp(payload, "created_at")
            expires_at = _record_timestamp(payload, "expires_at")
            state = _record_string(payload, "state", 1024)
            verifier = _record_string(payload, "pkce_verifier", 128)
            now = self._now()
            if (
                _PKCE_VERIFIER.fullmatch(verifier) is None
                or expires_at < created_at - timedelta(seconds=60)
                or expires_at > created_at + timedelta(minutes=11)
                or created_at > now + timedelta(seconds=60)
                or expires_at > now + timedelta(minutes=11)
                or now > expires_at + timedelta(seconds=60)
            ):
                raise ValueError
        except (OwlAuthError, KeyError, OverflowError, TypeError, ValueError) as error:
            raise ConfigurationError(
                "invalid_pending_record",
                "The pending-login record is invalid or belongs to another client.",
            ) from error
        return _bind_client_value(
            PendingLogin(
                runtime_base_url=self.base_url,
                project_id=self.project_id,
                application_id=self.application_id,
                redirect_uri=redirect_uri,
                hosted_url=hosted_url,
                created_at=created_at,
                expires_at=expires_at,
                _state=SecretValue(state, "application state"),
                _pkce_verifier=SecretValue(verifier, "PKCE verifier"),
            ),
            self._client_marker,
        )

    def restore_credentials(self, record: object) -> CredentialPair:
        """Restore an explicitly exported atomic credential pair into this exact client."""
        fields = {
            "schema_version",
            "runtime_base_url",
            "project_id",
            "application_id",
            "user_id",
            "session_id",
            "refresh_generation",
            "access_token",
            "refresh_token",
            "token_type",
            "access_expires_at",
            "session_expires_at",
            "projection",
        }
        try:
            payload = _record_object(record, fields)
            if (
                not isinstance(payload["schema_version"], int)
                or isinstance(payload["schema_version"], bool)
                or payload["schema_version"] != 1
                or payload["runtime_base_url"] != self.base_url
                or payload["project_id"] != self.project_id
                or payload["application_id"] != self.application_id
            ):
                raise ValueError
            user_id = _record_string(payload, "user_id", 96)
            session_id = _record_string(payload, "session_id", 64)
            generation = _record_positive_int(payload, "refresh_generation")
            access_token = _record_string(payload, "access_token", 16_384)
            refresh_token = _record_string(payload, "refresh_token", 256)
            if (
                _BEARER_TOKEN.fullmatch(access_token) is None
                or _OPAQUE_TOKEN.fullmatch(refresh_token) is None
                or payload["token_type"] != "Bearer"
            ):
                raise ValueError
            access_expires_at = _record_timestamp(payload, "access_expires_at")
            session_expires_at = _record_timestamp(payload, "session_expires_at")
            now = self._now()
            if access_expires_at > now + timedelta(
                minutes=61
            ) or session_expires_at < now - timedelta(seconds=60):
                raise ValueError
            projection = _projection(payload["projection"])
            if projection.user_id != user_id:
                raise ValueError
        except (OwlAuthError, KeyError, OverflowError, TypeError, ValueError) as error:
            raise ConfigurationError(
                "invalid_credential_record",
                "The credential record is invalid or belongs to another client.",
            ) from error
        return _bind_client_value(
            CredentialPair(
                runtime_base_url=self.base_url,
                project_id=self.project_id,
                application_id=self.application_id,
                user_id=user_id,
                session_id=session_id,
                refresh_generation=generation,
                access_token=SecretValue(access_token, "access token"),
                refresh_token=SecretValue(refresh_token, "refresh token"),
                token_type="Bearer",
                access_expires_at=access_expires_at,
                session_expires_at=session_expires_at,
                projection=projection,
            ),
            self._client_marker,
        )

    @_bind_protocol_operation("get_public_application_config")
    def get_public_configuration(self, *, timeout: float | None = None) -> PublicApplicationConfig:
        payload = self._request_json(
            "GET",
            f"v1/projects/{quote(self.project_id, safe='')}/auth/config?"
            + urlencode({"application_id": self.application_id}),
            operation="get_public_application_config",
            expected_status=200,
            timeout=timeout,
        )
        project_id = _string(payload, "project_public_id", 96)
        application_id = _string(payload, "application_public_id", 96)
        self._require_context(project_id, application_id)
        providers_value = _list(payload, "providers", 50)
        providers: list[PublicProvider] = []
        seen: set[str] = set()
        for item in providers_value:
            provider = _object(item)
            key = _string(provider, "key", 64)
            if key in seen:
                raise _protocol("invalid_response", "Runtime returned duplicate providers.")
            seen.add(key)
            kind = _string(provider, "kind", 32)
            if kind not in _PROVIDER_KINDS:
                raise _protocol(
                    "invalid_response", "Runtime returned an unsupported provider kind."
                )
            providers.append(
                PublicProvider(
                    key=key,
                    display_name=_string(provider, "display_name", 128),
                    kind=kind,
                )
            )
        keys = tuple(_string_value(value, 128) for value in _list(payload, "publishable_keys", 50))
        if self.publishable_key not in keys:
            raise _protocol(
                "context_mismatch",
                "Runtime returned a different publishable-key context.",
            )
        return PublicApplicationConfig(
            project_id=project_id,
            project_display_name=_string(payload, "project_display_name", 128),
            application_id=application_id,
            application_display_name=_string(payload, "application_display_name", 128),
            publishable_keys=keys,
            providers=tuple(providers),
            email_available=_boolean(payload, "email_available"),
            email_otp_enabled=_boolean(payload, "email_otp_enabled"),
            email_magic_link_enabled=_boolean(payload, "email_magic_link_enabled"),
            login_available=_boolean(payload, "login_available"),
        )

    @_bind_protocol_operation("get_project_jwks")
    def get_project_jwks(self, *, timeout: float | None = None) -> JwksDocument:
        payload = self._request_json(
            "GET",
            f"projects/{quote(self.project_id, safe='')}/.well-known/jwks.json",
            operation="get_project_jwks",
            expected_status=200,
            timeout=timeout,
        )
        keys: list[PublicJwk] = []
        seen: set[str] = set()
        for value in _list(payload, "keys", 100):
            key = _object(value)
            if set(key) != {"kty", "crv", "alg", "use", "kid", "x"}:
                raise _protocol("invalid_response", "Runtime returned an invalid signing key.")
            kid = _string(key, "kid", 128)
            if kid in seen:
                raise _protocol("invalid_response", "Runtime returned duplicate signing keys.")
            seen.add(kid)
            key_type = _string(key, "kty", 16)
            curve = _string(key, "crv", 16)
            algorithm = _string(key, "alg", 16)
            key_use = _string(key, "use", 16)
            x = _string(key, "x", 64)
            if (key_type, curve, algorithm, key_use) != ("OKP", "Ed25519", "EdDSA", "sig"):
                raise _protocol("invalid_response", "Runtime returned an unsupported signing key.")
            try:
                decoded_x = base64.b64decode(x + "=", altchars=b"-_", validate=True)
            except (ValueError, binascii.Error) as error:
                raise _protocol(
                    "invalid_response", "Runtime returned invalid signing material."
                ) from error
            if (
                len(decoded_x) != 32
                or base64.urlsafe_b64encode(decoded_x).rstrip(b"=").decode("ascii") != x
            ):
                raise _protocol("invalid_response", "Runtime returned invalid signing material.")
            keys.append(
                PublicJwk(
                    key_type=key_type,
                    curve=curve,
                    algorithm=algorithm,
                    use=key_use,
                    kid=kid,
                    x=x,
                )
            )
        return JwksDocument(
            keys=tuple(keys),
            revision=_positive_int(payload, "revision"),
            signing_epoch=_positive_int(payload, "signing_epoch"),
        )

    @_bind_protocol_operation("start_login")
    def begin_login(
        self,
        redirect_uri: str,
        *,
        state: str | None = None,
        presentation_hint: str | None = None,
        timeout: float | None = None,
    ) -> LoginStart:
        redirect = _validate_redirect_uri(redirect_uri)
        if presentation_hint is not None:
            _bounded_text("presentation_hint", presentation_hint, 64)
        verifier = _b64url(self._random_bytes(32))
        if len(verifier) != 43:
            raise ConfigurationError("invalid_entropy", "Entropy did not produce a PKCE verifier.")
        application_state = state if state is not None else _b64url(self._random_bytes(32))
        _bounded_text("state", application_state, 1024)
        challenge = _b64url(hashlib.sha256(verifier.encode("ascii")).digest())
        now = self._now()
        payload = self._request_json(
            "POST",
            f"v1/projects/{quote(self.project_id, safe='')}/auth/login/start",
            operation="start_login",
            expected_status=201,
            body={
                "application_id": self.application_id,
                "publishable_key": self.publishable_key,
                "redirect_uri": redirect,
                "pkce_challenge": challenge,
                "state": application_state,
                "presentation_hint": presentation_hint,
            },
            timeout=timeout,
        )
        hosted_url = _string(payload, "hosted_url", 512)
        _require_runtime_url(self.base_url, hosted_url)
        expires_at = _timestamp(payload, "expires_at")
        if expires_at < now - timedelta(seconds=60) or expires_at > now + timedelta(minutes=11):
            raise _protocol("invalid_login_expiry", "Runtime returned an invalid login expiry.")
        pending = _bind_client_value(
            PendingLogin(
                runtime_base_url=self.base_url,
                project_id=self.project_id,
                application_id=self.application_id,
                redirect_uri=redirect,
                hosted_url=hosted_url,
                created_at=now,
                expires_at=expires_at,
                _state=SecretValue(application_state, "application state"),
                _pkce_verifier=SecretValue(verifier, "PKCE verifier"),
            ),
            self._client_marker,
        )
        return LoginStart(hosted_url=hosted_url, pending=pending)

    @_bind_protocol_operation("exchange_handoff")
    def validate_callback(self, callback_url: str, pending: PendingLogin) -> ValidatedCallback:
        self._validate_pending_context(pending)
        if self._now() > pending.expires_at + timedelta(seconds=60):
            raise HandoffError(
                "pending_context_mismatch",
                "The pending login has expired.",
                action=LocalAction.DISCARD_PENDING,
                operation="exchange_handoff",
            )
        if not isinstance(callback_url, str) or len(callback_url) > 4096:
            raise _handoff_local("invalid_callback", "The callback URL is invalid.")
        try:
            expected = urlsplit(pending.redirect_uri)
            actual = urlsplit(callback_url)
        except ValueError as error:
            raise _handoff_local("invalid_callback", "The callback URL is invalid.") from error
        if actual.fragment or actual.username is not None or actual.password is not None:
            raise _handoff_local("invalid_callback", "The callback URL is invalid.")
        if (actual.scheme, actual.netloc, actual.path) != (
            expected.scheme,
            expected.netloc,
            expected.path,
        ):
            raise _handoff_local(
                "callback_context_mismatch", "The callback context does not match."
            )
        try:
            expected_query = parse_qsl(expected.query, keep_blank_values=True, max_num_fields=32)
            actual_query = parse_qsl(actual.query, keep_blank_values=True, max_num_fields=34)
        except ValueError as error:
            raise _handoff_local("invalid_callback", "The callback URL is invalid.") from error
        reserved = {"handoff", "state", "error"}
        if any(name in reserved for name, _ in expected_query):
            raise _handoff_local(
                "invalid_callback", "The registered redirect uses reserved fields."
            )
        values: dict[str, list[str]] = {}
        remaining: list[tuple[str, str]] = []
        for name, value in actual_query:
            if name in reserved:
                values.setdefault(name, []).append(value)
            else:
                remaining.append((name, value))
        if remaining != expected_query or any(len(items) != 1 for items in values.values()):
            raise _handoff_local("invalid_callback", "The callback URL is invalid.")
        returned_state = values.get("state", [""])[0]
        if not hmac.compare_digest(
            returned_state.encode("utf-8"), pending._state.reveal().encode("utf-8")
        ):
            raise _handoff_local("state_mismatch", "The callback state does not match.")
        if "error" in values:
            if "handoff" in values:
                raise _handoff_local("invalid_callback", "The callback URL is ambiguous.")
            raise HandoffError(
                "login_failed",
                "Sign-in did not complete.",
                action=LocalAction.DISCARD_PENDING,
                operation="exchange_handoff",
            )
        handoff = values.get("handoff", [""])[0]
        if not (1 <= len(handoff) <= 256) or "state" not in values:
            raise _handoff_local("invalid_callback", "The callback URL is invalid.")
        return ValidatedCallback(SecretValue(handoff, "handoff ticket"), pending._marker)

    @_bind_protocol_operation("exchange_handoff")
    def exchange_handoff(
        self,
        callback: ValidatedCallback,
        pending: PendingLogin,
        *,
        timeout: float | None = None,
    ) -> CredentialPair:
        self._validate_pending_context(pending)
        if callback._pending_marker is not pending._marker:
            raise _handoff_local("pending_context_mismatch", "The callback context does not match.")
        payload = self._request_json(
            "POST",
            f"v1/projects/{quote(self.project_id, safe='')}/auth/handoff/exchange",
            operation="exchange_handoff",
            expected_status=200,
            body={
                "application_id": self.application_id,
                "publishable_key": self.publishable_key,
                "handoff": callback._handoff.reveal(),
                "pkce_verifier": pending._pkce_verifier.reveal(),
            },
            timeout=timeout,
            one_use_guard=pending._guard,
        )
        try:
            return self._credential_pair(payload, previous=None)
        except ProtocolError as error:
            raise _indeterminate_protocol(error, "exchange_handoff", 200) from None

    @_bind_protocol_operation("exchange_handoff")
    def complete_login(
        self,
        callback_url: str,
        pending: PendingLogin,
        *,
        timeout: float | None = None,
    ) -> CredentialPair:
        callback = self.validate_callback(callback_url, pending)
        return self.exchange_handoff(callback, pending, timeout=timeout)

    @_bind_protocol_operation("refresh_session")
    def refresh(
        self, credentials: CredentialPair, *, timeout: float | None = None
    ) -> CredentialPair:
        self._validate_credentials_context(credentials)
        payload = self._request_json(
            "POST",
            f"v1/projects/{quote(self.project_id, safe='')}/auth/sessions/refresh",
            operation="refresh_session",
            expected_status=200,
            body={
                "application_id": self.application_id,
                "publishable_key": self.publishable_key,
                "refresh_token": credentials.refresh_token.reveal(),
            },
            timeout=timeout,
        )
        try:
            return self._credential_pair(payload, previous=credentials)
        except ProtocolError as error:
            raise _indeterminate_protocol(error, "refresh_session", 200) from None

    @_bind_protocol_operation("get_current_user")
    def current_user(
        self, credentials: CredentialPair, *, timeout: float | None = None
    ) -> CurrentUser:
        self._validate_credentials_context(credentials)
        payload = self._request_json(
            "GET",
            f"v1/projects/{quote(self.project_id, safe='')}/auth/users/me",
            operation="get_current_user",
            expected_status=200,
            authorization=credentials.access_token.reveal(),
            timeout=timeout,
        )
        if set(payload) != _CURRENT_USER_RESPONSE_FIELDS:
            raise _protocol("invalid_response", "Runtime returned an invalid current user.")
        project_id = _string(payload, "project_id", 96)
        application_id = _string(payload, "application_id", 96)
        self._require_context(project_id, application_id)
        projection = _projection(payload.get("projection"))
        user_id = _string(payload, "user_id", 96)
        if projection.user_id != user_id:
            raise _protocol("user_context_mismatch", "Runtime returned a mismatched user.")
        if _positive_int(payload, "projection_revision") != projection.projection_revision:
            raise _protocol(
                "projection_context_mismatch", "Runtime returned a mismatched projection."
            )
        authenticated_at = _timestamp(payload, "authenticated_at")
        session_expires_at = _timestamp(payload, "session_expires_at")
        if session_expires_at < self._now() - timedelta(seconds=60):
            raise _protocol("context_mismatch", "Runtime returned an expired session.")
        return CurrentUser(
            project_id=project_id,
            application_id=application_id,
            user_id=user_id,
            projection=projection,
            authenticated_at=authenticated_at,
            session_expires_at=session_expires_at,
        )

    @_bind_protocol_operation("logout_application_session")
    def logout_application(
        self, credentials: CredentialPair, *, timeout: float | None = None
    ) -> Completion:
        self._validate_credentials_context(credentials)
        payload = self._request_json(
            "POST",
            f"v1/projects/{quote(self.project_id, safe='')}/auth/sessions/logout",
            operation="logout_application_session",
            expected_status=200,
            authorization=credentials.access_token.reveal(),
            timeout=timeout,
        )
        try:
            completed = _boolean(payload, "completed")
            if not completed:
                raise _protocol(
                    "logout_not_completed", "Runtime did not confirm Application logout."
                )
            return Completion(completed=True)
        except ProtocolError as error:
            raise _indeterminate_protocol(error, "logout_application_session", 200) from None

    @_bind_protocol_operation("prepare_browser_logout")
    def prepare_browser_logout(
        self, credentials: CredentialPair, *, timeout: float | None = None
    ) -> BrowserLogoutPreparation:
        self._validate_credentials_context(credentials)
        payload = self._request_json(
            "POST",
            f"v1/projects/{quote(self.project_id, safe='')}/auth/browser-logout/prepare",
            operation="prepare_browser_logout",
            expected_status=201,
            authorization=credentials.access_token.reveal(),
            timeout=timeout,
        )
        try:
            hosted_url = _string(payload, "hosted_url", 512)
            _require_runtime_url(self.base_url, hosted_url)
            expires_at = _timestamp(payload, "expires_at")
            received_at = self._now()
            if expires_at < received_at - timedelta(
                seconds=60
            ) or expires_at > received_at + timedelta(minutes=2):
                raise _protocol(
                    "invalid_logout_expiry", "Runtime returned an invalid logout expiry."
                )
            return BrowserLogoutPreparation(hosted_url=hosted_url, expires_at=expires_at)
        except ProtocolError as error:
            raise _indeterminate_protocol(error, "prepare_browser_logout", 201) from None

    def _credential_pair(
        self, payload: JsonObject, *, previous: CredentialPair | None
    ) -> CredentialPair:
        if set(payload) != _CREDENTIAL_RESPONSE_FIELDS:
            raise _protocol("invalid_response", "Runtime returned invalid credentials.")
        project_id = _string(payload, "project_id", 96)
        application_id = _string(payload, "application_id", 96)
        self._require_context(project_id, application_id)
        user_id = _string(payload, "user_id", 96)
        session_id = _string(payload, "session_id", 64)
        generation = _positive_int(payload, "refresh_generation")
        projection = _projection(payload.get("projection"))
        projection_revision = _positive_int(payload, "projection_revision")
        if projection.user_id != user_id or projection.projection_revision != projection_revision:
            raise _protocol(
                "projection_context_mismatch", "Runtime returned a mismatched projection."
            )
        if previous is not None:
            if (
                previous.project_id != project_id
                or previous.application_id != application_id
                or previous.user_id != user_id
                or previous.session_id != session_id
                or generation != previous.refresh_generation + 1
            ):
                raise _protocol(
                    "credential_context_mismatch", "Runtime returned mismatched credentials."
                )
        token_type = _string(payload, "token_type", 16)
        if token_type != "Bearer":
            raise _protocol("unsupported_token_type", "Runtime returned an unsupported token type.")
        expires_in = _positive_int(payload, "expires_in")
        if not 1 <= expires_in <= 3600:
            raise _protocol("invalid_token_expiry", "Runtime returned an invalid token expiry.")
        now = self._now()
        session_expires_at = _timestamp(payload, "session_expires_at")
        if session_expires_at < now - timedelta(seconds=60):
            raise _protocol("invalid_session_expiry", "Runtime returned an invalid session expiry.")
        access_token = _string(payload, "access_token", 16_384)
        refresh_token = _string(payload, "refresh_token", 256)
        if (
            _BEARER_TOKEN.fullmatch(access_token) is None
            or _OPAQUE_TOKEN.fullmatch(refresh_token) is None
        ):
            raise _protocol("invalid_response", "Runtime returned an invalid token.")
        return _bind_client_value(
            CredentialPair(
                runtime_base_url=self.base_url,
                project_id=project_id,
                application_id=application_id,
                user_id=user_id,
                session_id=session_id,
                refresh_generation=generation,
                access_token=SecretValue(access_token, "access token"),
                refresh_token=SecretValue(refresh_token, "refresh token"),
                token_type=token_type,
                access_expires_at=now + timedelta(seconds=expires_in),
                session_expires_at=session_expires_at,
                projection=projection,
            ),
            self._client_marker,
        )

    def _validate_credentials_context(self, credentials: CredentialPair) -> None:
        if not isinstance(credentials, CredentialPair):
            raise ConfigurationError("invalid_credentials", "A credential pair is required.")
        if (
            credentials._client_marker is not self._client_marker
            or credentials.runtime_base_url != self.base_url
            or credentials.project_id != self.project_id
            or credentials.application_id != self.application_id
        ):
            raise _protocol(
                "credential_context_mismatch", "Credentials belong to another client context."
            )

    def _validate_pending_context(self, pending: PendingLogin) -> None:
        if not isinstance(pending, PendingLogin):
            raise ConfigurationError("invalid_pending_login", "A pending login is required.")
        if (
            pending._client_marker is not self._client_marker
            or pending.runtime_base_url != self.base_url
            or pending.project_id != self.project_id
            or pending.application_id != self.application_id
        ):
            raise _handoff_local(
                "pending_context_mismatch", "The pending login context does not match."
            )

    def _require_context(self, project_id: str, application_id: str) -> None:
        if project_id != self.project_id or application_id != self.application_id:
            raise _protocol("context_mismatch", "Runtime returned a different client context.")

    def _random_bytes(self, size: int) -> bytes:
        value = self._entropy(size)
        if not isinstance(value, bytes) or len(value) != size:
            raise ConfigurationError("invalid_entropy", "Entropy returned an invalid value.")
        return value

    def _now(self) -> datetime:
        value = self._clock()
        if not isinstance(value, datetime) or value.tzinfo is None:
            raise ConfigurationError("invalid_clock", "The configured clock must return UTC time.")
        return value.astimezone(UTC)

    def _request_json(
        self,
        method: str,
        relative_url: str,
        *,
        operation: str,
        expected_status: int,
        body: Mapping[str, Any] | None = None,
        authorization: str | None = None,
        timeout: float | None = None,
        one_use_guard: _OneUseGuard | None = None,
    ) -> JsonObject:
        request_timeout = self.timeout if timeout is None else _validate_timeout(timeout)
        url = _runtime_join(self.base_url, relative_url)
        encoded = None
        headers: dict[str, str] = {"Accept": "application/json"}
        if body is not None:
            encoded = json.dumps(body, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
            headers["Content-Type"] = "application/json"
        if authorization is not None:
            headers["Authorization"] = f"Bearer {authorization}"
        if one_use_guard is not None:
            one_use_guard.reserve()
        try:
            response = self.transport.request(
                method, url, headers=headers, body=encoded, timeout=request_timeout
            )
        except TransportFailure as failure:
            if one_use_guard is not None:
                if failure.dispatched:
                    one_use_guard.commit()
                else:
                    one_use_guard.release()
            raise _map_transport_failure(operation, failure) from None
        except Exception:
            if one_use_guard is not None:
                one_use_guard.commit()
            raise _map_transport_failure(
                operation, TransportFailure(FailureKind.TRANSPORT, dispatched=True)
            ) from None
        if one_use_guard is not None:
            one_use_guard.commit()
        try:
            if not isinstance(response.body, bytes) or len(response.body) > _MAX_JSON_BYTES:
                raise _protocol("invalid_response", "Runtime returned an oversized response.")
            if (
                len(response.headers) > 64
                or sum(len(str(name)) + len(str(value)) for name, value in response.headers.items())
                > 16_384
            ):
                raise _protocol("invalid_response", "Runtime returned oversized headers.")
            content_type = _header_value(response.headers, "content-type")
            if (
                content_type is None
                or content_type.split(";", 1)[0].strip().lower() != "application/json"
            ):
                raise _protocol("invalid_response", "Runtime returned a non-JSON response.")
            payload = _decode_json(response.body)
        except ProtocolError as error:
            if operation in _SENSITIVE_OPERATIONS:
                raise _indeterminate_protocol(error, operation, response.status) from None
            raise
        if response.status == expected_status:
            return payload
        if response.status not in _ALLOWED_ERROR_STATUSES[operation]:
            error = _protocol("invalid_response", "Runtime returned an unexpected status.")
            if operation in _SENSITIVE_OPERATIONS:
                raise _indeterminate_protocol(error, operation, response.status) from None
            raise error
        retry_after_seconds = None
        if response.status == 429:
            retry_after_seconds = _retry_after_seconds(response.headers)
            if retry_after_seconds is None or payload.get("code") != "rate_limited":
                error = _protocol(
                    "invalid_response", "Runtime returned invalid rate-limit guidance."
                )
                if operation in _SENSITIVE_OPERATIONS:
                    raise _indeterminate_protocol(error, operation, response.status) from None
                raise error
        raise _map_runtime_error(
            operation,
            response.status,
            payload,
            retry_after_seconds=retry_after_seconds,
        )


def _header_value(headers: Mapping[str, str], name: str) -> str | None:
    lowered = name.lower()
    values = [
        value
        for key, value in headers.items()
        if isinstance(key, str) and key.lower() == lowered and isinstance(value, str)
    ]
    return values[0] if len(values) == 1 else None


def _retry_after_seconds(headers: Mapping[str, str]) -> int | None:
    value = _header_value(headers, "retry-after")
    if value is None or len(value) > 6 or re.fullmatch(r"[0-9]+", value) is None:
        return None
    parsed = int(value)
    return parsed if parsed <= 86_400 else None


def _validate_runtime_base(value: str, allow_loopback: bool) -> str:
    if not isinstance(value, str) or len(value) > 2048:
        raise ConfigurationError("invalid_runtime_url", "The Runtime base URL is invalid.")
    try:
        parsed = urlsplit(value)
    except ValueError as error:
        raise ConfigurationError(
            "invalid_runtime_url", "The Runtime base URL is invalid."
        ) from error
    if (
        not parsed.scheme
        or not parsed.netloc
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise ConfigurationError("invalid_runtime_url", "The Runtime base URL is invalid.")
    if parsed.scheme != "https":
        loopback = parsed.hostname in {"localhost", "127.0.0.1", "::1"}
        if parsed.scheme != "http" or not allow_loopback or not loopback:
            raise ConfigurationError("https_required", "HTTPS is required for the Runtime URL.")
    path = parsed.path or "/"
    if _ambiguous_url_path(path):
        raise ConfigurationError("invalid_runtime_url", "The Runtime base URL is invalid.")
    if not path.endswith("/"):
        path += "/"
    return urlunsplit((parsed.scheme, parsed.netloc, path, "", ""))


def _validate_redirect_uri(value: str) -> str:
    if not isinstance(value, str) or not (8 <= len(value) <= 2048):
        raise ConfigurationError("invalid_redirect_uri", "The redirect URI is invalid.")
    lower = value.lower()
    if (
        not value.isascii()
        or "\\" in value
        or any(character.isspace() for character in value)
        or "%2f" in lower
        or "%5c" in lower
    ):
        raise ConfigurationError("invalid_redirect_uri", "The redirect URI is invalid.")
    scheme_match = re.match(r"^([A-Za-z][A-Za-z0-9+.-]*):", value)
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as error:
        raise ConfigurationError("invalid_redirect_uri", "The redirect URI is invalid.") from error
    if (
        not parsed.scheme
        or scheme_match is None
        or scheme_match.group(1) != parsed.scheme
        or parsed.fragment
        or parsed.username is not None
        or parsed.password is not None
        or parsed.hostname is not None
        and "*" in parsed.hostname
    ):
        raise ConfigurationError("invalid_redirect_uri", "The redirect URI is invalid.")
    if any(unquote(segment).lower() in {".", ".."} for segment in parsed.path.split("/")):
        raise ConfigurationError("invalid_redirect_uri", "The redirect URI is invalid.")
    scheme = parsed.scheme
    if scheme in {"https", "http"}:
        if parsed.hostname is None or not parsed.path.startswith("/"):
            raise ConfigurationError("invalid_redirect_uri", "The redirect URI is invalid.")
        if scheme == "http" and not _is_loopback_host(parsed.hostname):
            raise ConfigurationError("invalid_redirect_uri", "The redirect URI is invalid.")
        if (scheme, port) in {("http", 80), ("https", 443)}:
            raise ConfigurationError("invalid_redirect_uri", "The redirect URI is invalid.")
        canonical_host = f"[{parsed.hostname}]" if ":" in parsed.hostname else parsed.hostname
        canonical_authority = canonical_host if port is None else f"{canonical_host}:{port}"
        if parsed.netloc != canonical_authority:
            raise ConfigurationError("invalid_redirect_uri", "The redirect URI is invalid.")
    elif (
        "." not in scheme
        or parsed.netloc
        or not parsed.path
        or scheme
        in {
            "about",
            "blob",
            "data",
            "file",
            "ftp",
            "javascript",
            "mailto",
            "vbscript",
            "ws",
            "wss",
        }
    ):
        raise ConfigurationError("invalid_redirect_uri", "The redirect URI is invalid.")
    try:
        query = parse_qsl(parsed.query, keep_blank_values=True, max_num_fields=32)
    except ValueError as error:
        raise ConfigurationError("invalid_redirect_uri", "The redirect URI is invalid.") from error
    if any(name in {"handoff", "error", "state"} for name, _ in query):
        raise ConfigurationError("invalid_redirect_uri", "The redirect URI is invalid.")
    return value


def _is_loopback_host(hostname: str) -> bool:
    if hostname == "localhost":
        return True
    try:
        return ipaddress.ip_address(hostname).is_loopback
    except ValueError:
        return False


def _runtime_join(base: str, relative: str) -> str:
    if relative.startswith("/") or "\\" in relative:
        raise ConfigurationError("invalid_runtime_path", "The Runtime path is invalid.")
    joined = urljoin(base, relative)
    _require_runtime_url(base, joined)
    return joined


def _require_runtime_url(base: str, value: str) -> None:
    if not isinstance(value, str) or len(value) > 4096:
        raise _protocol("invalid_runtime_url", "Runtime returned an invalid URL.")
    try:
        expected = urlsplit(base)
        actual = urlsplit(value)
    except ValueError as error:
        raise _protocol("invalid_runtime_url", "Runtime returned an invalid URL.") from error
    if (
        actual.scheme != expected.scheme
        or actual.netloc != expected.netloc
        or actual.username is not None
        or actual.password is not None
        or actual.fragment
        or _ambiguous_url_path(actual.path)
        or not actual.path.startswith(expected.path)
    ):
        raise _protocol("runtime_origin_mismatch", "Runtime returned a URL outside its authority.")


def _ambiguous_url_path(path: str) -> bool:
    lower = path.lower()
    if "\\" in path or "%2f" in lower or "%5c" in lower or "%25" in lower:
        return True
    decoded = unquote(path)
    return any(segment.lower() in {".", ".."} for segment in decoded.split("/"))


def _validate_identifier(name: str, value: str, maximum: int) -> None:
    if (
        not isinstance(value, str)
        or not (1 <= len(value) <= maximum)
        or _IDENTIFIER.fullmatch(value) is None
    ):
        raise ConfigurationError(f"invalid_{name}", f"The {name} value is invalid.")


def _bounded_text(name: str, value: str, maximum: int) -> None:
    if not isinstance(value, str) or not (1 <= len(value) <= maximum) or not _valid_unicode(value):
        raise ConfigurationError(f"invalid_{name}", f"The {name} value is invalid.")


def _validate_timeout(value: float) -> float:
    if not isinstance(value, (int, float)) or not (0 < float(value) <= 120):
        raise ConfigurationError("invalid_timeout", "The request timeout is invalid.")
    return float(value)


def _decode_json(body: bytes) -> JsonObject:
    try:
        value = loads_strict_json(body)
    except (UnicodeDecodeError, UnicodeEncodeError, ValueError, RecursionError) as error:
        raise _protocol("invalid_response", "Runtime returned invalid JSON.") from error
    return _object(value)


def _valid_unicode(value: str) -> bool:
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return True


def _object(value: object) -> JsonObject:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise _protocol("invalid_response", "Runtime returned an invalid response.")
    return cast(JsonObject, value)


def _record_object(value: object, fields: set[str]) -> JsonObject:
    if (
        not isinstance(value, dict)
        or not all(isinstance(key, str) for key in value)
        or set(value) != fields
    ):
        raise ValueError
    return cast(JsonObject, value)


def _record_string(value: JsonObject, name: str, maximum: int) -> str:
    item = value[name]
    if not isinstance(item, str) or not (1 <= len(item) <= maximum) or not _valid_unicode(item):
        raise ValueError
    return item


def _record_positive_int(value: JsonObject, name: str) -> int:
    item = value[name]
    if (
        not isinstance(item, int)
        or isinstance(item, bool)
        or not 1 <= item <= 9_223_372_036_854_775_807
    ):
        raise ValueError
    return item


def _record_timestamp(value: JsonObject, name: str) -> datetime:
    text = _record_string(value, name, 64)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except (OverflowError, ValueError) as error:
        raise ValueError from error
    if parsed.tzinfo is None:
        raise ValueError
    try:
        return parsed.astimezone(UTC)
    except (OverflowError, ValueError) as error:
        raise ValueError from error


def _list(value: JsonObject, name: str, maximum: int) -> list[object]:
    item = value.get(name)
    if not isinstance(item, list) or len(item) > maximum:
        raise _protocol("invalid_response", "Runtime returned an invalid response.")
    return cast(list[object], item)


def _string(value: JsonObject, name: str, maximum: int) -> str:
    return _string_value(value.get(name), maximum)


def _string_value(value: object, maximum: int) -> str:
    if not isinstance(value, str) or not (1 <= len(value) <= maximum):
        raise _protocol("invalid_response", "Runtime returned an invalid response.")
    return value


def _boolean(value: JsonObject, name: str) -> bool:
    item = value.get(name)
    if not isinstance(item, bool):
        raise _protocol("invalid_response", "Runtime returned an invalid response.")
    return item


def _positive_int(value: JsonObject, name: str) -> int:
    item = value.get(name)
    if (
        not isinstance(item, int)
        or isinstance(item, bool)
        or not 1 <= item <= 9_223_372_036_854_775_807
    ):
        raise _protocol("invalid_response", "Runtime returned an invalid response.")
    return item


def _timestamp(value: JsonObject, name: str) -> datetime:
    text = _string(value, name, 64)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except (OverflowError, ValueError) as error:
        raise _protocol("invalid_timestamp", "Runtime returned an invalid timestamp.") from error
    if parsed.tzinfo is None:
        raise _protocol("invalid_timestamp", "Runtime returned an invalid timestamp.")
    try:
        return parsed.astimezone(UTC)
    except (OverflowError, ValueError) as error:
        raise _protocol("invalid_timestamp", "Runtime returned an invalid timestamp.") from error


def _optional_string(value: JsonObject, name: str, maximum: int) -> str | None:
    item = value.get(name)
    if item is None:
        return None
    return _string_value(item, maximum)


def _valid_projection_locale(value: str | None) -> bool:
    if value is None:
        return True
    encoded_length = len(value.encode("utf-8"))
    return (
        2 <= encoded_length <= 35
        and not value.startswith("-")
        and not value.endswith("-")
        and "--" not in value
        and all(
            character.isascii() and (character.isalnum() or character == "-") for character in value
        )
    )


def _valid_projection_email(value: str | None) -> bool:
    if value is None:
        return True
    encoded_length = len(value.encode("utf-8"))
    return 3 <= encoded_length <= 320 and not any(
        unicodedata.category(character) == "Cc" for character in value
    )


def _projection(value: object) -> UserProjection:
    payload = _object(value)
    fields = {
        "user_id",
        "user_revision",
        "projection_schema",
        "projection_revision",
        "display_name",
        "picture_url",
        "locale",
        "verified_email",
        "status",
        "created_at",
        "updated_at",
    }
    if set(payload) != fields:
        raise _protocol("invalid_projection", "Runtime returned an invalid user projection.")
    projection = UserProjection(
        user_id=_string(payload, "user_id", 96),
        user_revision=_positive_int(payload, "user_revision"),
        projection_schema=_string(payload, "projection_schema", 64),
        projection_revision=_positive_int(payload, "projection_revision"),
        display_name=_optional_string(payload, "display_name", 128),
        picture_url=_optional_string(payload, "picture_url", 2048),
        locale=_optional_string(payload, "locale", 35),
        verified_email=_optional_string(payload, "verified_email", 320),
        status=_string(payload, "status", 32),
        created_at=_timestamp(payload, "created_at"),
        updated_at=_timestamp(payload, "updated_at"),
    )
    if (
        projection.projection_schema != "owlauth.user.v1"
        or projection.status != "active"
        or not _valid_projection_locale(projection.locale)
        or not _valid_projection_email(projection.verified_email)
    ):
        raise _protocol("invalid_projection", "Runtime returned an invalid user projection.")
    return projection


def _map_transport_failure(operation: str, failure: TransportFailure) -> OwlAuthError:
    if failure.dispatched and operation in _SENSITIVE_OPERATIONS:
        action = (
            LocalAction.QUARANTINE_PENDING
            if operation == "exchange_handoff"
            else LocalAction.QUARANTINE_CREDENTIALS
        )
        return IndeterminateError(
            "outcome_indeterminate",
            "The Runtime operation outcome is unknown. Do not retry the credential.",
            retry=RetryDisposition.NEVER,
            action=action,
            operation=operation,
        )
    if failure.kind == FailureKind.RESPONSE_INVALID:
        return ProtocolError(
            "invalid_response",
            "Runtime returned an invalid or oversized response.",
            retry=RetryDisposition.NEVER,
            operation=operation,
        )
    if failure.kind == FailureKind.TIMEOUT:
        return OwlAuthTimeoutError(
            "timeout",
            "The Runtime request deadline elapsed.",
            retry=RetryDisposition.APPLICATION_DECISION,
            operation=operation,
        )
    if failure.kind == FailureKind.CANCELLED:
        return CancelledError(
            "cancelled",
            "The Runtime request was cancelled.",
            retry=RetryDisposition.APPLICATION_DECISION,
            operation=operation,
        )
    return TransportError(
        "transport_failure",
        "The Runtime request could not be completed.",
        retry=RetryDisposition.APPLICATION_DECISION,
        operation=operation,
    )


def _map_runtime_error(
    operation: str,
    status: int,
    payload: JsonObject,
    *,
    retry_after_seconds: int | None = None,
) -> OwlAuthError:
    fields = set(payload)
    code_value = payload.get("code")
    message_value = payload.get("message")
    if (
        fields != {"code", "message", "request_id"}
        or not isinstance(code_value, str)
        or not 1 <= len(code_value) <= 64
        or re.fullmatch(r"[a-z][a-z0-9_]*", code_value) is None
        or not isinstance(message_value, str)
        or not 1 <= len(message_value) <= 256
        or not isinstance(payload["request_id"], str)
        or not 1 <= len(payload["request_id"]) <= 128
    ):
        if operation in _SENSITIVE_OPERATIONS:
            action = (
                LocalAction.QUARANTINE_PENDING
                if operation == "exchange_handoff"
                else LocalAction.QUARANTINE_CREDENTIALS
            )
            return IndeterminateError(
                "invalid_response_after_dispatch",
                "Runtime may have committed the operation; do not replay it.",
                action=action,
                operation=operation,
                status=status,
            )
        return ProtocolError(
            "invalid_response",
            "Runtime returned an invalid error response.",
            retry=RetryDisposition.NEVER,
            operation=operation,
            status=status,
        )
    code = code_value
    request_value = payload.get("request_id")
    request_id = (
        request_value
        if isinstance(request_value, str)
        and 1 <= len(request_value) <= 128
        and _REQUEST_ID.fullmatch(request_value)
        else None
    )
    safe_message = "Runtime rejected the request."
    if status == 429 and code == "rate_limited":
        handoff = operation == "exchange_handoff"
        caller_decision = operation in {
            "refresh_session",
            "logout_application_session",
            "prepare_browser_logout",
        }
        return RateLimitedError(
            code,
            "Runtime admission policy rejected the request.",
            retry=(
                RetryDisposition.NEVER
                if handoff
                else (
                    RetryDisposition.APPLICATION_DECISION
                    if caller_decision
                    else RetryDisposition.SAFE_AFTER_DELAY
                )
            ),
            action=LocalAction.DISCARD_PENDING if handoff else LocalAction.NONE,
            request_id=request_id,
            operation=operation,
            status=status,
            retry_after_seconds=retry_after_seconds,
        )
    if status >= 500 and operation in _SENSITIVE_OPERATIONS:
        action = (
            LocalAction.QUARANTINE_PENDING
            if operation == "exchange_handoff"
            else LocalAction.QUARANTINE_CREDENTIALS
        )
        return IndeterminateError(
            "outcome_indeterminate",
            "The Runtime operation outcome is unknown. Do not retry the credential.",
            action=action,
            request_id=request_id,
            operation=operation,
            status=status,
        )
    error_type: type[OwlAuthError]
    action = LocalAction.NONE
    if operation == "start_login":
        error_type = LoginError
    elif operation == "exchange_handoff":
        error_type = HandoffError
        action = LocalAction.DISCARD_PENDING
    elif operation == "refresh_session":
        error_type = RefreshError
        action = LocalAction.INVALIDATE_CREDENTIALS
    elif operation == "get_current_user":
        error_type = AuthenticationError
        action = LocalAction.REAUTHENTICATE
    elif operation in {"logout_application_session", "prepare_browser_logout"}:
        error_type = SessionError
        action = LocalAction.REAUTHENTICATE
    elif code == "unknown" or status < 400 or status > 599:
        error_type = ProtocolError
    elif status == 401:
        error_type = AuthenticationError
        action = LocalAction.REAUTHENTICATE
    else:
        error_type = ProtocolError
    return error_type(
        code,
        safe_message,
        retry=RetryDisposition.NEVER,
        action=action,
        request_id=request_id,
        operation=operation,
        status=status,
    )


def _protocol(code: str, message: str) -> ProtocolError:
    return ProtocolError(code, message, retry=RetryDisposition.NEVER)


def _indeterminate_protocol(
    error: ProtocolError,
    operation: Literal[
        "exchange_handoff",
        "refresh_session",
        "logout_application_session",
        "prepare_browser_logout",
    ],
    status: int,
) -> IndeterminateError:
    del error
    action = (
        LocalAction.QUARANTINE_PENDING
        if operation == "exchange_handoff"
        else LocalAction.QUARANTINE_CREDENTIALS
    )
    return IndeterminateError(
        "invalid_response_after_dispatch",
        "Runtime may have committed the operation; do not replay it.",
        retry=RetryDisposition.NEVER,
        action=action,
        operation=operation,
        status=status,
    )


def _handoff_local(code: str, message: str) -> HandoffError:
    return HandoffError(
        code,
        message,
        retry=RetryDisposition.NEVER,
        action=LocalAction.DISCARD_PENDING,
        operation="exchange_handoff",
    )
