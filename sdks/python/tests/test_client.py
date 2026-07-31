from __future__ import annotations

import json
from collections import deque
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from owlauth import (
    Client,
    ConfigurationError,
    CredentialPair,
    FailureKind,
    HandoffError,
    IndeterminateError,
    LocalAction,
    ProtocolError,
    RefreshError,
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


def test_runtime_url_policy_and_path_prefix_are_strict() -> None:
    with pytest.raises(ConfigurationError):
        Client("http://auth.example", PROJECT, APPLICATION, PUBLISHABLE)
    with pytest.raises(ConfigurationError):
        Client("https://user:pass@auth.example", PROJECT, APPLICATION, PUBLISHABLE)

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


def test_callback_mismatch_and_expiry_fail_before_network() -> None:
    transport = FakeTransport(start_response())
    client, started = begun_login(transport)

    with pytest.raises(HandoffError) as mismatch:
        client.validate_callback(f"{REDIRECT}?handoff=ticket&state=wrong-state", started.pending)
    assert mismatch.value.code == "state_mismatch"
    assert len(transport.requests) == 1

    expired_client = Client(
        client.base_url,
        PROJECT,
        APPLICATION,
        PUBLISHABLE,
        transport=transport,
        _clock=lambda: NOW + timedelta(minutes=11),
    )
    with pytest.raises(HandoffError) as expired:
        expired_client.validate_callback(
            f"{REDIRECT}?handoff=ticket&state={started.pending._state.reveal()}",
            started.pending,
        )
    assert expired.value.code == "pending_login_expired"
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

    with pytest.raises(ProtocolError) as captured:
        client.exchange_handoff(callback, started.pending)

    error = captured.value
    assert error.code == "invalid_json"
    assert error.action == LocalAction.QUARANTINE_PENDING
    assert error.retry.value == "never"
    assert error.operation == "handoff"
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

    with pytest.raises(ProtocolError) as captured:
        client.exchange_handoff(callback, started.pending)

    error = captured.value
    assert error.code == "context_mismatch"
    assert error.action == LocalAction.QUARANTINE_PENDING
    assert error.retry.value == "never"
    assert error.operation == "handoff"
    assert error.status == 200
    assert len(transport.requests) == 2
    for secret in ("handoff-secret", "access-secret-1", "refresh-secret-1"):
        assert secret not in str(error)
        assert secret not in repr(error)


def test_malformed_refresh_success_quarantines_credentials_without_retry_or_disclosure() -> None:
    _, _, credentials = exchange_once()
    malformed = TransportResponse(
        status=200,
        headers={"content-type": "application/json"},
        body=b'{"refresh_token":"response-refresh-secret"',
    )
    transport = FakeTransport(malformed)
    client = make_client(transport)

    with pytest.raises(ProtocolError) as captured:
        client.refresh(credentials)

    error = captured.value
    assert error.code == "invalid_json"
    assert error.action == LocalAction.QUARANTINE_CREDENTIALS
    assert error.retry.value == "never"
    assert error.operation == "refresh"
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

    with pytest.raises(ProtocolError) as captured:
        client.refresh(credentials)

    error = captured.value
    assert error.code == "context_mismatch"
    assert error.action == LocalAction.QUARANTINE_CREDENTIALS
    assert error.retry.value == "never"
    assert error.operation == "refresh"
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
                "expires_at": (NOW + timedelta(minutes=5)).isoformat(),
            },
        ),
    )
    client = make_client(transport)

    successor = client.refresh(credentials)
    current = client.current_user(successor)
    completion = client.logout_application(successor.access_token)
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


def test_shared_conformance_corpus_and_referenced_fixtures_load() -> None:
    root = Path(__file__).parents[2]
    cases = root / "spec" / "conformance" / "cases.json"
    if not cases.exists():
        cases = Path(__file__).parents[3] / "sdks" / "spec" / "conformance" / "cases.json"
    corpus = load_conformance_corpus(cases)

    assert corpus.schema_version == 2
    assert corpus.cases
    assert len({case.name for case in corpus.cases}) == len(corpus.cases)
    health = next((case for case in corpus.cases if case.name == "health response"), None)
    if health is not None:
        assert health.fixture == health.expected


def test_secret_value_requires_explicit_reveal() -> None:
    token = SecretValue("recognizable-secret", "access token")
    assert token.reveal() == "recognizable-secret"
    assert "recognizable-secret" not in str(token)
    assert "recognizable-secret" not in repr(token)
