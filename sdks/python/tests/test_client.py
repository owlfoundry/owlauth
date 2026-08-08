from __future__ import annotations

import json
import pickle
from collections import deque
from collections.abc import Mapping
from copy import copy, deepcopy
from dataclasses import asdict, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import Event, Thread
from typing import Any
from urllib.parse import urlencode

import pytest
from owlauth import (
    Client,
    ConfigurationError,
    CredentialPair,
    FailureKind,
    HandoffError,
    IndeterminateError,
    LocalAction,
    OwlAuthTimeoutError,
    ProtocolError,
    RateLimitedError,
    RefreshError,
    SdkDebugEvent,
    SecretValue,
    TransportFailure,
    TransportResponse,
    load_conformance_corpus,
)

NOW = datetime(2026, 7, 31, 5, 0, tzinfo=UTC)
PROJECT = "project_public"
APPLICATION = "application_public"
PUBLISHABLE = "publishable_key"
REDIRECT = "https://app.example/callback"


class FakeTransport:
    def __init__(self, *outcomes: TransportResponse | TransportFailure) -> None:
        self.outcomes = deque(outcomes)
        self.requests: list[dict[str, Any]] = []

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str],
        body: bytes | None,
        timeout: float,
    ) -> TransportResponse:
        self.requests.append(
            {
                "method": method,
                "url": url,
                "headers": dict(headers),
                "body": body,
                "timeout": timeout,
            }
        )
        outcome = self.outcomes.popleft()
        if isinstance(outcome, TransportFailure):
            raise outcome
        return outcome


def response(status: int, value: object) -> TransportResponse:
    return TransportResponse(
        status=status,
        headers={"content-type": "application/json"},
        body=json.dumps(value).encode(),
    )


def make_client(transport: FakeTransport, **options: Any) -> Client:
    return Client(
        "https://auth.example/runtime",
        PROJECT,
        APPLICATION,
        PUBLISHABLE,
        transport=transport,
        _clock=lambda: NOW,
        _entropy=lambda size: bytes(range(size)),
        **options,
    )


def start_response() -> TransportResponse:
    return response(
        201,
        {
            "hosted_url": "https://auth.example/runtime/auth/interactions/opaque",
            "expires_at": (NOW + timedelta(minutes=10)).isoformat(),
        },
    )


def projection(revision: int = 1) -> dict[str, object]:
    return {
        "user_id": "usr_public",
        "user_revision": 1,
        "projection_schema": "owlauth.user.v1",
        "projection_revision": revision,
        "display_name": "A User",
        "picture_url": "https://images.example/avatar.png",
        "locale": "en-GB",
        "verified_email": None,
        "status": "active",
        "created_at": NOW.isoformat(),
        "updated_at": NOW.isoformat(),
    }


def credentials_response(generation: int = 1) -> TransportResponse:
    return response(
        200,
        {
            "project_id": PROJECT,
            "application_id": APPLICATION,
            "user_id": "usr_public",
            "session_id": "9c17dbca-21fe-4566-bb42-ae0e71e4873d",
            "refresh_generation": generation,
            "access_token": f"access-secret-{generation}",
            "refresh_token": f"refresh-secret-{generation}",
            "token_type": "Bearer",
            "expires_in": 300,
            "projection": projection(),
            "projection_revision": 1,
            "session_expires_at": (NOW + timedelta(days=30)).isoformat(),
        },
    )


def begun_login(transport: FakeTransport) -> tuple[Client, object]:
    client = make_client(transport)
    started = client.begin_login(REDIRECT)
    return client, started


def exchange_once() -> tuple[Client, FakeTransport, CredentialPair]:
    transport = FakeTransport(start_response(), credentials_response())
    client, started = begun_login(transport)
    callback = f"{REDIRECT}?handoff=handoff-secret&state={started.pending._state.reveal()}"
    credentials = client.complete_login(callback, started.pending)
    return client, transport, credentials


def restore_for(client: Client, credentials: CredentialPair) -> CredentialPair:
    return client.restore_credentials(credentials.export_record())


def test_runtime_url_policy_and_path_prefix_are_strict() -> None:
    with pytest.raises(ConfigurationError):
        Client("http://auth.example", PROJECT, APPLICATION, PUBLISHABLE)
    with pytest.raises(ConfigurationError):
        Client("https://user:pass@auth.example", PROJECT, APPLICATION, PUBLISHABLE)
    with pytest.raises(ConfigurationError):
        Client("https://[", PROJECT, APPLICATION, PUBLISHABLE)

    client = Client(
        "http://127.0.0.1:8080/prefix",
        PROJECT,
        APPLICATION,
        PUBLISHABLE,
        allow_insecure_loopback=True,
    )
    assert client.base_url == "http://127.0.0.1:8080/prefix/"


def test_begin_login_uses_deterministic_s256_and_returns_redacted_pending_state() -> None:
    transport = FakeTransport(start_response())
    client, started = begun_login(transport)

    request = transport.requests[0]
    body = json.loads(request["body"])
    assert body["pkce_challenge"] == "6oZqdX5MOLq_qBJ8vppAnT4fk6AP8UiP9zX8-Rev_9A"
    assert body["state"] == "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"
    assert request["url"].startswith(
        "https://auth.example/runtime/v1/projects/project_public/auth/login/start"
    )
    rendered = repr(started.pending)
    assert "AAECAw" not in rendered
    assert "opaque" not in rendered
    assert "redacted" in rendered
    assert started.hosted_url == "https://auth.example/runtime/auth/interactions/opaque"


def test_hosted_url_rejects_dot_and_backslash_escape_from_runtime_prefix() -> None:
    for hosted_url in [
        "https://auth.example/runtime/%2e%2e/control/login",
        "https://auth.example/runtime/..\\control/login",
        "https://auth.example/runtime/%2e%2e\\control/login",
        "https://auth.example/runtime/%2e%2e%5ccontrol/login",
        "https://auth.example/runtime/%2e%2e%2fcontrol/login",
        "https://auth.example/runtime/..%2fcontrol/login",
        "https://auth.example/runtime/%2f..%2fcontrol/login",
        "https://auth.example/runtime/%252e%252e/control/login",
    ]:
        escaped = response(
            201,
            {
                "hosted_url": hosted_url,
                "expires_at": (NOW + timedelta(minutes=10)).isoformat(),
            },
        )
        transport = FakeTransport(escaped)
        with pytest.raises(ProtocolError):
            make_client(transport).begin_login(REDIRECT)
        assert len(transport.requests) == 1


def test_runtime_base_rejects_ambiguous_path_forms_at_construction() -> None:
    for base_url in [
        "https://auth.example/runtime\\control",
        "https://auth.example/runtime/%5c/control",
        "https://auth.example/runtime/../control",
        "https://auth.example/runtime/%252e%252e/control",
    ]:
        with pytest.raises(ConfigurationError):
            Client(base_url, PROJECT, APPLICATION, PUBLISHABLE)


def test_local_state_and_hint_reject_surrogates_before_dispatch() -> None:
    transport = FakeTransport(start_response())
    client = make_client(transport)
    with pytest.raises(ConfigurationError):
        client.begin_login(REDIRECT, state="\ud800")
    with pytest.raises(ConfigurationError):
        client.begin_login(REDIRECT, presentation_hint="\ud800")
    assert not transport.requests

    started = client.begin_login(REDIRECT)
    record = started.pending.export_record()
    record["state"] = "\ud800"
    with pytest.raises(ConfigurationError):
        client.restore_pending_login(record)
    assert len(transport.requests) == 1


def test_unicode_application_state_round_trips_through_utf8_constant_time_validation() -> None:
    transport = FakeTransport(start_response(), credentials_response())
    client = make_client(transport)
    started = client.begin_login(REDIRECT, state="状态-Δ")
    callback = f"{REDIRECT}?{urlencode({'handoff': 'ticket', 'state': '状态-Δ'})}"

    credentials = client.complete_login(callback, started.pending)
    assert credentials.refresh_generation == 1
    assert len(transport.requests) == 2


def test_callback_mismatch_and_expiry_fail_before_network() -> None:
    transport = FakeTransport(start_response())
    client, started = begun_login(transport)

    with pytest.raises(HandoffError) as mismatch:
        client.validate_callback(f"{REDIRECT}?handoff=ticket&state=wrong-state", started.pending)
    assert mismatch.value.code == "state_mismatch"
    with pytest.raises(HandoffError) as malformed:
        client.validate_callback("https://[", started.pending)
    assert malformed.value.code == "invalid_callback"
    assert len(transport.requests) == 1

    expired_client = Client(
        client.base_url,
        PROJECT,
        APPLICATION,
        PUBLISHABLE,
        transport=transport,
        _clock=lambda: NOW + timedelta(minutes=11, seconds=1),
    )
    with pytest.raises(HandoffError) as expired:
        expired_client.validate_callback(
            f"{REDIRECT}?handoff=ticket&state={started.pending._state.reveal()}",
            started.pending,
        )
    assert expired.value.code == "pending_context_mismatch"
    assert len(transport.requests) == 1


def test_handoff_is_one_attempt_and_credentials_are_context_bound_and_redacted() -> None:
    client, transport, credentials = exchange_once()

    exchange = transport.requests[1]
    body = json.loads(exchange["body"])
    assert body["handoff"] == "handoff-secret"
    assert body["pkce_verifier"] == "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"
    assert credentials.project_id == PROJECT
    assert credentials.application_id == APPLICATION
    assert credentials.refresh_generation == 1
    assert credentials.access_token.reveal() == "access-secret-1"
    rendered = repr(credentials)
    assert "access-secret" not in rendered
    assert "refresh-secret" not in rendered

    assert len(transport.requests) == 2


def test_pending_cannot_be_exchanged_twice() -> None:
    transport = FakeTransport(start_response(), credentials_response())
    client, started = begun_login(transport)
    callback_url = f"{REDIRECT}?handoff=handoff-secret&state={started.pending._state.reveal()}"
    callback = client.validate_callback(callback_url, started.pending)
    client.exchange_handoff(callback, started.pending)

    with pytest.raises(HandoffError) as reused:
        client.exchange_handoff(callback, started.pending)
    assert reused.value.code == "pending_login_consumed"
    assert len(transport.requests) == 2


def test_handoff_reservation_releases_only_on_explicit_before_dispatch_failure() -> None:
    transport = FakeTransport(
        start_response(),
        TransportFailure(FailureKind.TIMEOUT, dispatched=False),
        credentials_response(),
    )
    client, started = begun_login(transport)
    callback = client.validate_callback(
        f"{REDIRECT}?handoff=handoff-secret&state={started.pending._state.reveal()}",
        started.pending,
    )

    with pytest.raises(OwlAuthTimeoutError):
        client.exchange_handoff(callback, started.pending)
    assert started.pending._guard.available
    assert not started.pending._guard.consumed

    credentials = client.exchange_handoff(callback, started.pending)
    assert credentials.refresh_generation == 1
    assert started.pending._guard.consumed
    assert len(transport.requests) == 3


def test_invalid_handoff_timeout_fails_before_reserving_or_dispatching() -> None:
    transport = FakeTransport(start_response())
    client, started = begun_login(transport)
    callback = client.validate_callback(
        f"{REDIRECT}?handoff=handoff-secret&state={started.pending._state.reveal()}",
        started.pending,
    )

    with pytest.raises(ConfigurationError):
        client.exchange_handoff(callback, started.pending, timeout=0)
    assert started.pending._guard.available
    assert len(transport.requests) == 1


def test_pending_record_snapshot_linearizes_against_exchange_reservation() -> None:
    transport = FakeTransport(start_response(), credentials_response())
    client, started = begun_login(transport)
    callback = client.validate_callback(
        f"{REDIRECT}?handoff=handoff-secret&state={started.pending._state.reveal()}",
        started.pending,
    )
    snapshot_entered = Event()
    release_snapshot = Event()
    exchange_started = Event()
    outcomes: list[object] = []

    class BlockingSecret(SecretValue):
        def reveal(self) -> str:
            snapshot_entered.set()
            assert release_snapshot.wait(timeout=5)
            return super().reveal()

    object.__setattr__(
        started.pending,
        "_state",
        BlockingSecret(started.pending._state.reveal(), "application state"),
    )

    def export() -> None:
        outcomes.append(started.pending.export_record())

    def exchange() -> None:
        exchange_started.set()
        outcomes.append(client.exchange_handoff(callback, started.pending))

    export_thread = Thread(target=export)
    exchange_thread = Thread(target=exchange)
    export_thread.start()
    assert snapshot_entered.wait(timeout=5)
    exchange_thread.start()
    assert exchange_started.wait(timeout=5)
    assert len(transport.requests) == 1
    release_snapshot.set()
    export_thread.join(timeout=5)
    exchange_thread.join(timeout=5)

    assert not export_thread.is_alive()
    assert not exchange_thread.is_alive()
    assert len(outcomes) == 2
    assert started.pending._guard.consumed
    assert len(transport.requests) == 2


def test_deep_json_after_handoff_dispatch_is_indeterminate() -> None:
    deeply_nested = b"[" * 20_000 + b"0" + b"]" * 20_000
    malformed = TransportResponse(
        status=200,
        headers={"content-type": "application/json"},
        body=deeply_nested,
    )
    transport = FakeTransport(start_response(), malformed)
    client, started = begun_login(transport)
    callback = f"{REDIRECT}?handoff=handoff-secret&state={started.pending._state.reveal()}"

    with pytest.raises(IndeterminateError) as captured:
        client.complete_login(callback, started.pending)

    assert captured.value.action is LocalAction.QUARANTINE_PENDING
    assert started.pending._guard.consumed
    assert len(transport.requests) == 2


def test_deep_json_after_refresh_dispatch_is_indeterminate() -> None:
    deeply_nested = b"[" * 20_000 + b"0" + b"]" * 20_000
    malformed = TransportResponse(
        status=200,
        headers={"content-type": "application/json"},
        body=deeply_nested,
    )
    transport = FakeTransport(start_response(), credentials_response(), malformed)
    client, started = begun_login(transport)
    callback = f"{REDIRECT}?handoff=handoff-secret&state={started.pending._state.reveal()}"
    credentials = client.complete_login(callback, started.pending)

    with pytest.raises(IndeterminateError) as captured:
        client.refresh(credentials)

    assert captured.value.action is LocalAction.QUARANTINE_CREDENTIALS
    assert len(transport.requests) == 3


def test_non_finite_json_after_browser_logout_dispatch_is_indeterminate() -> None:
    non_finite = TransportResponse(
        status=201,
        headers={"content-type": "application/json"},
        body=(
            b'{"hosted_url":"https://auth.example/runtime/logout",'
            b'"expires_at":"2026-07-31T05:01:00+00:00","future":NaN}'
        ),
    )
    transport = FakeTransport(start_response(), credentials_response(), non_finite)
    client, started = begun_login(transport)
    callback = f"{REDIRECT}?handoff=handoff-secret&state={started.pending._state.reveal()}"
    credentials = client.complete_login(callback, started.pending)

    with pytest.raises(IndeterminateError) as captured:
        client.prepare_browser_logout(credentials)

    assert captured.value.action is LocalAction.QUARANTINE_CREDENTIALS
    assert len(transport.requests) == 3


def test_surrogate_json_after_handoff_and_refresh_dispatch_is_indeterminate() -> None:
    for refresh in [False, True]:
        payload = json.loads(credentials_response(2 if refresh else 1).body)
        payload["projection"]["locale"] = "\ud800"
        invalid = response(200, payload)
        outcomes = (
            [start_response(), credentials_response(), invalid]
            if refresh
            else [start_response(), invalid]
        )
        transport = FakeTransport(*outcomes)
        client, started = begun_login(transport)
        callback = f"{REDIRECT}?handoff=handoff-secret&state={started.pending._state.reveal()}"
        if refresh:
            credentials = client.complete_login(callback, started.pending)
            with pytest.raises(IndeterminateError) as captured:
                client.refresh(credentials)
            assert captured.value.action is LocalAction.QUARANTINE_CREDENTIALS
        else:
            with pytest.raises(IndeterminateError) as captured:
                client.complete_login(callback, started.pending)
            assert captured.value.action is LocalAction.QUARANTINE_PENDING
            assert started.pending._guard.consumed


def test_response_framing_failure_uses_protocol_or_indeterminate_semantics() -> None:
    framing_failure = TransportFailure(FailureKind.RESPONSE_INVALID, dispatched=True)
    with pytest.raises(ProtocolError) as captured:
        make_client(FakeTransport(framing_failure)).get_public_configuration()
    assert captured.value.code == "invalid_response"
    assert captured.value.retry.value == "never"

    transport = FakeTransport(start_response(), framing_failure)
    client, started = begun_login(transport)
    callback = f"{REDIRECT}?handoff=handoff-secret&state={started.pending._state.reveal()}"
    with pytest.raises(IndeterminateError) as sensitive:
        client.complete_login(callback, started.pending)
    assert sensitive.value.action is LocalAction.QUARANTINE_PENDING


def test_malformed_handoff_success_quarantines_pending_without_retry_or_disclosure() -> None:
    malformed = TransportResponse(
        status=200,
        headers={"content-type": "application/json"},
        body=b'{"refresh_token":"response-refresh-secret"',
    )
    transport = FakeTransport(start_response(), malformed)
    client, started = begun_login(transport)
    callback = client.validate_callback(
        f"{REDIRECT}?handoff=handoff-secret&state={started.pending._state.reveal()}",
        started.pending,
    )

    with pytest.raises(IndeterminateError) as captured:
        client.exchange_handoff(callback, started.pending)

    error = captured.value
    assert error.code == "invalid_response_after_dispatch"
    assert error.action == LocalAction.QUARANTINE_PENDING
    assert error.retry.value == "never"
    assert error.operation == "exchange_handoff"
    assert error.status == 200
    assert len(transport.requests) == 2
    for secret in ("handoff-secret", "response-refresh-secret"):
        assert secret not in str(error)
        assert secret not in repr(error)


def test_mismatched_handoff_success_quarantines_pending_without_retry_or_disclosure() -> None:
    payload = json.loads(credentials_response().body)
    payload["project_id"] = "different_project"
    transport = FakeTransport(start_response(), response(200, payload))
    client, started = begun_login(transport)
    callback = client.validate_callback(
        f"{REDIRECT}?handoff=handoff-secret&state={started.pending._state.reveal()}",
        started.pending,
    )

    with pytest.raises(IndeterminateError) as captured:
        client.exchange_handoff(callback, started.pending)

    error = captured.value
    assert error.code == "invalid_response_after_dispatch"
    assert error.action == LocalAction.QUARANTINE_PENDING
    assert error.retry.value == "never"
    assert error.operation == "exchange_handoff"
    assert error.status == 200
    assert len(transport.requests) == 2
    for secret in ("handoff-secret", "access-secret-1", "refresh-secret-1"):
        assert secret not in str(error)
        assert secret not in repr(error)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("access_token", "bad\r\nheader"),
        ("refresh_token", "bad token"),
    ],
)
def test_invalid_handoff_token_grammar_quarantines_pending(field: str, value: str) -> None:
    payload = json.loads(credentials_response().body)
    payload[field] = value
    transport = FakeTransport(start_response(), response(200, payload))
    client, started = begun_login(transport)
    callback = client.validate_callback(
        f"{REDIRECT}?handoff=handoff-secret&state={started.pending._state.reveal()}",
        started.pending,
    )

    with pytest.raises(IndeterminateError) as captured:
        client.exchange_handoff(callback, started.pending)

    assert captured.value.code == "invalid_response_after_dispatch"
    assert captured.value.action is LocalAction.QUARANTINE_PENDING
    assert len(transport.requests) == 2


def test_malformed_refresh_success_quarantines_credentials_without_retry_or_disclosure() -> None:
    _, _, credentials = exchange_once()
    malformed = TransportResponse(
        status=200,
        headers={"content-type": "application/json"},
        body=b'{"refresh_token":"response-refresh-secret"',
    )
    transport = FakeTransport(malformed)
    client = make_client(transport)
    credentials = restore_for(client, credentials)

    with pytest.raises(IndeterminateError) as captured:
        client.refresh(credentials)

    error = captured.value
    assert error.code == "invalid_response_after_dispatch"
    assert error.action == LocalAction.QUARANTINE_CREDENTIALS
    assert error.retry.value == "never"
    assert error.operation == "refresh_session"
    assert error.status == 200
    assert len(transport.requests) == 1
    for secret in (credentials.refresh_token.reveal(), "response-refresh-secret"):
        assert secret not in str(error)
        assert secret not in repr(error)


def test_mismatched_refresh_success_quarantines_credentials_without_retry_or_disclosure() -> None:
    _, _, credentials = exchange_once()
    payload = json.loads(credentials_response(2).body)
    payload["application_id"] = "different_application"
    transport = FakeTransport(response(200, payload))
    client = make_client(transport)
    credentials = restore_for(client, credentials)

    with pytest.raises(IndeterminateError) as captured:
        client.refresh(credentials)

    error = captured.value
    assert error.code == "invalid_response_after_dispatch"
    assert error.action == LocalAction.QUARANTINE_CREDENTIALS
    assert error.retry.value == "never"
    assert error.operation == "refresh_session"
    assert error.status == 200
    assert len(transport.requests) == 1
    for secret in (
        credentials.refresh_token.reveal(),
        "access-secret-2",
        "refresh-secret-2",
    ):
        assert secret not in str(error)
        assert secret not in repr(error)


def test_refresh_current_user_and_logout_operations_have_exact_placement() -> None:
    client, _, credentials = exchange_once()
    transport = FakeTransport(
        credentials_response(2),
        response(
            200,
            {
                "project_id": PROJECT,
                "application_id": APPLICATION,
                "user_id": "usr_public",
                "projection": projection(),
                "projection_revision": 1,
                "authenticated_at": NOW.isoformat(),
                "session_expires_at": (NOW + timedelta(days=30)).isoformat(),
            },
        ),
        response(200, {"completed": True}),
        response(
            201,
            {
                "hosted_url": "https://auth.example/runtime/auth/browser-logout/preparation",
                "expires_at": (NOW + timedelta(minutes=1)).isoformat(),
            },
        ),
    )
    client = make_client(transport)
    credentials = restore_for(client, credentials)

    successor = client.refresh(credentials)
    current = client.current_user(successor)
    completion = client.logout_application(successor)
    browser_logout = client.prepare_browser_logout(successor)

    assert successor.refresh_generation == 2
    assert current.user_id == "usr_public"
    assert completion.completed
    assert browser_logout.hosted_url.endswith("/auth/browser-logout/preparation")
    refresh_body = json.loads(transport.requests[0]["body"])
    assert refresh_body["refresh_token"] == "refresh-secret-1"
    assert "refresh-secret" not in transport.requests[0]["url"]
    for request in transport.requests[1:]:
        assert request["headers"]["Authorization"] == "Bearer access-secret-2"


def test_sensitive_transport_failure_is_indeterminate_and_never_retried() -> None:
    transport = FakeTransport(
        start_response(),
        TransportFailure(FailureKind.TIMEOUT, dispatched=True),
    )
    client, started = begun_login(transport)
    callback = client.validate_callback(
        f"{REDIRECT}?handoff=handoff-secret&state={started.pending._state.reveal()}",
        started.pending,
    )

    with pytest.raises(IndeterminateError) as error:
        client.exchange_handoff(callback, started.pending)
    assert error.value.action == LocalAction.QUARANTINE_PENDING
    assert len(transport.requests) == 2
    assert "handoff-secret" not in str(error.value)
    assert "handoff-secret" not in repr(error.value)


@pytest.mark.parametrize("operation", ["refresh", "application_logout", "browser_logout"])
def test_sensitive_session_failures_are_indeterminate_without_retry(operation: str) -> None:
    _, _, credentials = exchange_once()
    transport = FakeTransport(TransportFailure(FailureKind.TRANSPORT, dispatched=True))
    client = make_client(transport)
    credentials = restore_for(client, credentials)

    with pytest.raises(IndeterminateError) as error:
        if operation == "refresh":
            client.refresh(credentials)
        elif operation == "application_logout":
            client.logout_application(credentials)
        else:
            client.prepare_browser_logout(credentials)
    assert error.value.action == LocalAction.QUARANTINE_CREDENTIALS
    assert error.value.retry.value == "never"
    assert len(transport.requests) == 1


def test_refresh_definitive_rejection_invalidates_family() -> None:
    client, _, credentials = exchange_once()
    transport = FakeTransport(
        response(
            409,
            {
                "code": "invalid_state",
                "message": "The refresh generation is no longer valid.",
                "request_id": "request-1",
            },
        )
    )
    client = make_client(transport)
    credentials = restore_for(client, credentials)

    with pytest.raises(RefreshError) as error:
        client.refresh(credentials)
    assert error.value.action == LocalAction.INVALIDATE_CREDENTIALS
    assert len(transport.requests) == 1


def test_public_config_jwks_and_malformed_or_mismatched_responses() -> None:
    transport = FakeTransport(
        response(
            200,
            {
                "project_public_id": PROJECT,
                "project_display_name": "Project",
                "application_public_id": APPLICATION,
                "application_display_name": "Application",
                "publishable_keys": [PUBLISHABLE],
                "providers": [{"key": "oidc", "display_name": "OIDC", "kind": "oidc"}],
                "email_available": False,
                "email_otp_enabled": False,
                "email_magic_link_enabled": False,
                "login_available": True,
            },
        ),
        response(
            200,
            {
                "keys": [
                    {
                        "kty": "OKP",
                        "crv": "Ed25519",
                        "alg": "EdDSA",
                        "use": "sig",
                        "kid": "key-1",
                        "x": "A" * 43,
                    }
                ],
                "revision": 1,
                "signing_epoch": 1,
            },
        ),
        response(200, {"project_public_id": "other"}),
    )
    client = make_client(transport)

    assert client.get_public_configuration().providers[0].key == "oidc"
    assert client.get_project_jwks().keys[0].algorithm == "EdDSA"
    with pytest.raises(ProtocolError):
        client.get_public_configuration()


def test_optional_debug_hook_emits_one_closed_redacted_completion_event() -> None:
    events: list[SdkDebugEvent] = []

    def debug_hook(event: SdkDebugEvent) -> None:
        events.append(event)
        raise RuntimeError("observer failure must be isolated")

    client = make_client(
        FakeTransport(
            response(
                200,
                {
                    "project_public_id": PROJECT,
                    "project_display_name": "Project",
                    "application_public_id": APPLICATION,
                    "application_display_name": "Application",
                    "publishable_keys": [PUBLISHABLE],
                    "providers": [],
                    "email_available": False,
                    "email_otp_enabled": False,
                    "email_magic_link_enabled": False,
                    "login_available": True,
                },
            )
        ),
        debug_hook=debug_hook,
    )
    client.get_public_configuration()
    assert len(events) == 1
    event = asdict(events[0])
    assert event["operation"] == "get_public_application_config"
    assert event["method"] == "GET"
    assert event["outcome"] == "success"
    assert event["status"] == 200
    serialized = json.dumps(event)
    assert PUBLISHABLE not in serialized
    assert "auth.example" not in serialized
    assert "publishable_key" not in serialized


def test_unknown_runtime_error_is_conservative_and_does_not_leak_credentials() -> None:
    secret = "recognizable-refresh-secret"
    transport = FakeTransport(
        response(
            418,
            {
                "code": "future_error",
                "message": secret,
                "request_id": "request-2",
            },
        )
    )
    client = make_client(transport)

    with pytest.raises(ProtocolError) as error:
        client.get_public_configuration()
    assert error.value.retry.value == "never"
    assert secret not in str(error.value)
    assert secret not in repr(error.value)


def test_rate_limit_requires_single_bounded_retry_after_and_exposes_it() -> None:
    valid = TransportResponse(
        status=429,
        headers={"content-type": "application/json", "retry-after": "7"},
        body=json.dumps(
            {"code": "rate_limited", "message": "slow down", "request_id": "request-1"}
        ).encode(),
    )
    with pytest.raises(RateLimitedError) as captured:
        make_client(FakeTransport(valid)).get_public_configuration()
    assert captured.value.retry_after_seconds == 7
    assert captured.value.retry.value == "safe_after_delay"

    for headers in (
        {"content-type": "application/json"},
        {"content-type": "application/json", "retry-after": "7.0"},
        {"content-type": "application/json", "retry-after": "86401"},
        {"content-type": "application/json", "retry-after": "9" * 5000},
        {
            "content-type": "application/json",
            "Retry-After": "7",
            "retry-after": "8",
        },
    ):
        invalid = TransportResponse(
            status=429,
            headers=headers,
            body=json.dumps(
                {"code": "rate_limited", "message": "slow down", "request_id": "request-1"}
            ).encode(),
        )
        with pytest.raises(ProtocolError) as error:
            make_client(FakeTransport(invalid)).get_public_configuration()
        assert error.value.code == "invalid_response"
        assert error.value.retry_after_seconds is None

    _, _, credentials = exchange_once()
    sensitive = TransportResponse(
        status=429,
        headers={"content-type": "application/json", "retry-after": "9" * 5000},
        body=json.dumps(
            {"code": "rate_limited", "message": "slow down", "request_id": "request-1"}
        ).encode(),
    )
    sensitive_client = make_client(FakeTransport(sensitive))
    credentials = restore_for(sensitive_client, credentials)
    with pytest.raises(IndeterminateError) as indeterminate:
        sensitive_client.refresh(credentials)
    assert indeterminate.value.action == LocalAction.QUARANTINE_CREDENTIALS


def test_extreme_json_numbers_and_timestamps_stay_in_public_error_taxonomy() -> None:
    extreme_number = TransportResponse(
        status=200,
        headers={"content-type": "application/json"},
        body=b'{"value":' + b"9" * 5000 + b"}",
    )
    with pytest.raises(ProtocolError):
        make_client(FakeTransport(extreme_number)).get_public_configuration()

    _, _, credentials = exchange_once()
    sensitive_client = make_client(FakeTransport(extreme_number))
    credentials = restore_for(sensitive_client, credentials)
    with pytest.raises(IndeterminateError) as malformed_refresh:
        sensitive_client.refresh(credentials)
    assert malformed_refresh.value.action == LocalAction.QUARANTINE_CREDENTIALS

    invalid_current = response(
        200,
        {
            "project_id": PROJECT,
            "application_id": APPLICATION,
            "user_id": "usr_public",
            "projection": projection(),
            "projection_revision": 1,
            "authenticated_at": "0001-01-01T00:00:00+23:59",
            "session_expires_at": (NOW + timedelta(days=30)).isoformat(),
        },
    )
    current_client = make_client(FakeTransport(invalid_current))
    credentials = restore_for(current_client, credentials)
    with pytest.raises(ProtocolError):
        current_client.current_user(credentials)

    malformed_credentials = json.loads(credentials_response().body)
    malformed_credentials["session_expires_at"] = "0001-01-01T00:00:00+23:59"
    handoff_transport = FakeTransport(start_response(), response(200, malformed_credentials))
    handoff_client, started = begun_login(handoff_transport)
    callback = f"{REDIRECT}?handoff=ticket&state={started.pending._state.reveal()}"
    with pytest.raises(IndeterminateError) as malformed_handoff:
        handoff_client.complete_login(callback, started.pending)
    assert malformed_handoff.value.action == LocalAction.QUARANTINE_PENDING


@pytest.mark.parametrize(
    "redirect_uri",
    [
        "https://app.example/callback",
        "http://127.0.0.2:43123/callback",
        "com.example.app:/callback",
    ],
)
def test_redirect_uri_policy_accepts_canonical_web_loopback_and_private_schemes(
    redirect_uri: str,
) -> None:
    transport = FakeTransport(start_response())
    started = make_client(transport).begin_login(redirect_uri)
    assert started.pending.redirect_uri == redirect_uri
    assert len(transport.requests) == 1


@pytest.mark.parametrize(
    "redirect_uri",
    [
        "http://app.example/callback",
        "myapp:/callback",
        "https://app.example/callback?state=reserved",
        "https://app.example/%2fcallback",
        "https://app.example\\callback",
        "https://APP.example/callback",
        "HTTPS://app.example/callback",
        "https://app.example/a/../callback",
        "https://app.example/%2e%2e/callback",
        "https://app.example",
    ],
)
def test_redirect_uri_policy_rejects_noncanonical_or_reserved_values_before_network(
    redirect_uri: str,
) -> None:
    transport = FakeTransport()
    with pytest.raises(ConfigurationError):
        make_client(transport).begin_login(redirect_uri)
    assert not transport.requests


def test_explicit_records_round_trip_strictly_without_io_and_bind_runtime_context() -> None:
    pending_transport = FakeTransport(start_response())
    client, started = begun_login(pending_transport)
    pending_record = started.pending.export_record()

    restore_transport = FakeTransport()
    restoring_client = make_client(restore_transport)
    restored_pending = restoring_client.restore_pending_login(pending_record)
    assert restored_pending.export_record() == pending_record
    assert not restore_transport.requests

    for invalid in (
        {**pending_record, "unexpected": True},
        {**pending_record, "runtime_base_url": "https://other.example/runtime/"},
        {**pending_record, "pkce_verifier": "invalid"},
        {**pending_record, "hosted_url": "https://auth.example/runtime/" + "x" * 513},
        {
            **pending_record,
            "created_at": "2099-01-01T00:00:00+00:00",
            "expires_at": "2099-01-01T00:10:00+00:00",
        },
        {**pending_record, "created_at": "0001-01-01T00:00:00+23:59"},
    ):
        with pytest.raises(ConfigurationError):
            restoring_client.restore_pending_login(invalid)
    assert not restore_transport.requests

    _, _, credentials = exchange_once()
    credential_record = credentials.export_record()
    restored_credentials = restoring_client.restore_credentials(credential_record)
    assert restored_credentials.export_record() == credential_record
    assert not restore_transport.requests

    for invalid in (
        {**credential_record, "unexpected": True},
        {**credential_record, "application_id": "another_application"},
        {**credential_record, "access_token": "bad\r\nheader"},
        {**credential_record, "refresh_token": "bad token"},
        {**credential_record, "refresh_generation": 0},
        {**credential_record, "refresh_generation": 9_223_372_036_854_775_808},
        {**credential_record, "session_expires_at": "0001-01-01T00:00:00+23:59"},
    ):
        with pytest.raises(ConfigurationError):
            restoring_client.restore_credentials(invalid)
    assert not restore_transport.requests

    forged_credentials = replace(
        restored_credentials,
        runtime_base_url="https://other.example/runtime/",
    )
    forged_client = Client(
        "https://other.example/runtime/",
        PROJECT,
        APPLICATION,
        PUBLISHABLE,
        transport=FakeTransport(),
        _clock=lambda: NOW,
    )
    with pytest.raises(ProtocolError) as forged:
        forged_client.current_user(forged_credentials)
    assert forged.value.code == "credential_context_mismatch"
    assert not forged_client.transport.requests

    replaced_pending = replace(restored_pending)
    with pytest.raises(HandoffError) as forged_pending:
        restoring_client.validate_callback(REDIRECT, replaced_pending)
    assert forged_pending.value.code == "pending_context_mismatch"
    assert not restore_transport.requests

    mismatched_contexts = [
        ("https://other.example/runtime/", PROJECT, APPLICATION),
        ("https://auth.example/another-runtime/", PROJECT, APPLICATION),
        ("https://auth.example/runtime/", "another_project", APPLICATION),
        ("https://auth.example/runtime/", PROJECT, "another_application"),
    ]
    for base_url, project_id, application_id in mismatched_contexts:
        other_transport = FakeTransport()
        other_client = Client(
            base_url,
            project_id,
            application_id,
            PUBLISHABLE,
            transport=other_transport,
            _clock=lambda: NOW,
        )
        with pytest.raises(ProtocolError) as mismatch:
            other_client.current_user(credentials)
        assert mismatch.value.code == "credential_context_mismatch"
        assert not other_transport.requests


def test_shared_conformance_corpus_and_referenced_fixtures_load() -> None:
    root = Path(__file__).parents[2]
    cases = root / "spec" / "conformance" / "cases.json"
    if not cases.exists():
        cases = Path(__file__).parents[3] / "sdks" / "spec" / "conformance" / "cases.json"
    corpus = load_conformance_corpus(cases)

    assert corpus.schema_version == 3
    assert corpus.cases
    assert len({case.name for case in corpus.cases}) == len(corpus.cases)
    assert all(case.definition["operationId"] for case in corpus.cases)


def test_secret_value_resists_generic_dataclass_serialization() -> None:
    token = SecretValue("recognizable-secret", "access token")
    assert token.reveal() == "recognizable-secret"
    assert copy(token) is token
    assert deepcopy(token) is token
    assert "recognizable-secret" not in str(token)
    assert "recognizable-secret" not in repr(token)
    with pytest.raises(TypeError):
        pickle.dumps(token)

    _, _, credentials = exchange_once()
    serialized = asdict(credentials)
    assert isinstance(serialized["access_token"], SecretValue)
    assert isinstance(serialized["refresh_token"], SecretValue)
    rendered = json.dumps(serialized, default=repr)
    assert "access-secret" not in rendered
    assert "refresh-secret" not in rendered


def test_user_projection_requires_exact_schema_and_explicit_nullable_fields() -> None:
    def current_response(wire_projection: dict[str, object]) -> TransportResponse:
        return response(
            200,
            {
                "project_id": PROJECT,
                "application_id": APPLICATION,
                "user_id": "usr_public",
                "projection": wire_projection,
                "projection_revision": 1,
                "authenticated_at": NOW.isoformat(),
                "session_expires_at": (NOW + timedelta(days=30)).isoformat(),
            },
        )

    _, _, credentials = exchange_once()
    nullable = projection()
    nullable["locale"] = None
    nullable["verified_email"] = None
    accepted_client = make_client(FakeTransport(current_response(nullable)))
    accepted = accepted_client.current_user(restore_for(accepted_client, credentials))
    assert accepted.projection.locale is None
    assert accepted.projection.verified_email is None

    fixture_path = (
        Path(__file__).parents[2] / "spec" / "fixtures" / "user-projection-invalid-values.json"
    )
    fixture = json.loads(fixture_path.read_text())
    fixture_invalid = [
        {**fixture["projection"], patch["field"]: patch["value"]}
        for patch in fixture["invalidPatches"]
    ]
    wrong_schema = {**projection(), "projection_schema": "owlauth.project_user.v1"}
    missing_locale = projection()
    del missing_locale["locale"]
    unknown_field = {**projection(), "unexpected": True}
    for invalid in (wrong_schema, missing_locale, unknown_field, *fixture_invalid):
        invalid_client = make_client(FakeTransport(current_response(invalid)))
        with pytest.raises(ProtocolError):
            invalid_client.current_user(restore_for(invalid_client, credentials))
