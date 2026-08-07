from __future__ import annotations

import base64
import json
from collections import deque
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from owlauth import (
    Client,
    HandoffError,
    OwlAuthError,
    ProtocolError,
    TransportResponse,
    load_conformance_corpus,
)
from owlauth.transport import FailureKind, TransportFailure

CORPUS_PATH = Path(__file__).parents[2] / "spec" / "conformance" / "cases.json"
FIXTURES = Path(__file__).parents[2] / "spec" / "fixtures"
NOW = datetime(2099, 1, 1, tzinfo=UTC)
BASE_URL = "https://runtime.conformance.example/"
REDIRECT = "https://application.example/callback"


class FixtureTransport:
    def __init__(self, *outcomes: TransportResponse | TransportFailure) -> None:
        self.outcomes = deque(outcomes)
        self.requests: list[tuple[str, bytes | None]] = []

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str],
        body: bytes | None,
        timeout: float,
    ) -> TransportResponse:
        del url, headers, timeout
        self.requests.append((method, body))
        outcome = self.outcomes.popleft()
        if isinstance(outcome, TransportFailure):
            raise outcome
        return outcome


def load_fixture(name: str) -> dict[str, Any]:
    return json.loads((FIXTURES / name).read_text())


def wire_response(wrapper: dict[str, Any]) -> TransportResponse:
    exchange = wrapper["exchange"]
    body = exchange["body"]
    encoding = body["encoding"]
    if encoding == "json":
        encoded = json.dumps(body["value"], separators=(",", ":")).encode()
    elif encoding == "text":
        encoded = body["value"].encode()
    elif encoding == "empty":
        encoded = b""
    elif encoding == "base64":
        encoded = base64.b64decode(body["value"], validate=True)
    elif encoding == "repeat":
        encoded = body["value"].encode() * body["count"]
    else:  # pragma: no cover - strict loader rejects this first
        raise AssertionError(encoding)
    return TransportResponse(status=exchange["status"], headers=exchange["headers"], body=encoded)


def transport_failure(wrapper: dict[str, Any]) -> TransportFailure:
    exchange = wrapper["exchange"]
    kind = {
        "transport": FailureKind.TRANSPORT,
        "timeout": FailureKind.TIMEOUT,
        "cancelled": FailureKind.CANCELLED,
    }[exchange["failureKind"]]
    return TransportFailure(kind, dispatched=exchange["requestPhase"] != "before_dispatch")


def context(definition: dict[str, Any]) -> dict[str, str]:
    return definition["configuredContext"]


def client_for(
    definition: dict[str, Any],
    transport: FixtureTransport,
    *,
    clock_offset: int = 0,
) -> Client:
    configured = context(definition)
    return Client(
        BASE_URL,
        configured["projectId"],
        configured["applicationId"],
        configured["publishableKey"],
        transport=transport,
        _clock=lambda: NOW + timedelta(seconds=clock_offset),
        _entropy=lambda size: b"A" * size,
    )


def begin(client: Client):  # noqa: ANN202
    return client.begin_login(REDIRECT)


def callback_url(kind: str, state: str) -> str:
    if kind == "success":
        return f"{REDIRECT}?handoff=synthetic-handoff&state={state}"
    if kind == "error":
        return f"{REDIRECT}?error=provider_rejected&state={state}"
    if kind == "ambiguous":
        return f"{REDIRECT}?handoff=synthetic-handoff&error=provider_rejected&state={state}"
    if kind == "state_mismatch":
        return f"{REDIRECT}?handoff=synthetic-handoff&state=wrong"
    raise AssertionError(kind)


def invoke_callback(case: Any, start: dict[str, Any]) -> tuple[object, FixtureTransport, object]:
    exchange = case.fixture["exchange"]
    transport = FixtureTransport(wire_response(start))
    configured = context(case.definition)
    clock_offset = [0]
    sdk = Client(
        BASE_URL,
        configured["projectId"],
        configured["applicationId"],
        configured["publishableKey"],
        transport=transport,
        _clock=lambda: NOW + timedelta(seconds=clock_offset[0]),
        _entropy=lambda size: b"A" * size,
    )
    started = begin(sdk)
    clock_offset[0] = exchange["clockOffsetSeconds"]
    result: object = None
    for attempt in exchange["attempts"]:
        url = callback_url(attempt, started.pending._state.reveal())
        try:
            result = sdk.validate_callback(url, started.pending)
        except OwlAuthError:
            if attempt != exchange["attempts"][-1]:
                continue
            raise
    return result, transport, started.pending


def invoke_http(case: Any, setup: dict[str, Any]) -> tuple[object, FixtureTransport, object | None]:
    target = wire_response(case.fixture)
    precondition = case.definition["precondition"]
    pending = None
    if precondition == "none":
        transport = FixtureTransport(target)
    elif precondition == "pending_login":
        transport = FixtureTransport(wire_response(setup["login"]), target)
    elif precondition == "credential_pair":
        transport = FixtureTransport(
            wire_response(setup["login"]), wire_response(setup["credential"]), target
        )
    else:  # pragma: no cover
        raise AssertionError(precondition)
    sdk = client_for(case.definition, transport)
    operation = case.definition["operationId"]
    if operation == "get_public_application_config":
        result = sdk.get_public_configuration()
    elif operation == "get_project_jwks":
        result = sdk.get_project_jwks()
    elif operation == "start_login":
        result = begin(sdk)
        pending = result.pending
    elif operation == "exchange_handoff":
        started = begin(sdk)
        pending = started.pending
        state = started.pending._state.reveal()
        result = sdk.complete_login(callback_url("success", state), started.pending)
    elif operation == "refresh_session":
        started = begin(sdk)
        pending = started.pending
        credentials = sdk.complete_login(
            callback_url("success", started.pending._state.reveal()), started.pending
        )
        result = sdk.refresh(credentials)
    elif operation in {
        "get_current_user",
        "logout_application_session",
        "prepare_browser_logout",
    }:
        started = begin(sdk)
        pending = started.pending
        credentials = sdk.complete_login(
            callback_url("success", started.pending._state.reveal()), started.pending
        )
        if operation == "get_current_user":
            result = sdk.current_user(credentials)
        elif operation == "logout_application_session":
            result = sdk.logout_application(credentials)
        else:
            result = sdk.prepare_browser_logout(credentials)
    else:  # pragma: no cover
        raise AssertionError(operation)
    return result, transport, pending


def invoke_transport(
    case: Any, setup: dict[str, Any]
) -> tuple[object, FixtureTransport, object | None]:
    failure = transport_failure(case.fixture)
    precondition = case.definition["precondition"]
    if precondition == "none":
        transport = FixtureTransport(failure)
    elif precondition == "pending_login":
        transport = FixtureTransport(wire_response(setup["login"]), failure)
    elif precondition == "credential_pair":
        transport = FixtureTransport(
            wire_response(setup["login"]), wire_response(setup["credential"]), failure
        )
    else:  # pragma: no cover
        raise AssertionError(precondition)
    sdk = client_for(case.definition, transport)
    operation = case.definition["operationId"]
    pending = None
    if operation == "get_public_application_config":
        result = sdk.get_public_configuration()
    elif operation == "exchange_handoff":
        started = begin(sdk)
        pending = started.pending
        result = sdk.complete_login(
            callback_url("success", started.pending._state.reveal()), started.pending
        )
    elif operation == "refresh_session":
        started = begin(sdk)
        pending = started.pending
        credentials = sdk.complete_login(
            callback_url("success", started.pending._state.reveal()), started.pending
        )
        result = sdk.refresh(credentials)
    else:  # pragma: no cover
        raise AssertionError(operation)
    return result, transport, pending


def invoke_case(case: Any, setup: dict[str, Any]) -> tuple[object, FixtureTransport, object | None]:
    kind = case.fixture["exchange"]["kind"]
    if kind == "callback":
        return invoke_callback(case, setup["login"])
    if kind == "transportFailure":
        return invoke_transport(case, setup)
    return invoke_http(case, setup)


def assert_pending_disposition(case: Any, setup: dict[str, Any]) -> None:
    operation = case.definition["operationId"]
    if operation == "start_login":
        transport = FixtureTransport(wire_response(case.fixture))
        started = begin(client_for(case.definition, transport))
        assert started.pending._guard.consumed is False, case.name
        assert len(transport.requests) == 1, case.name
        return
    if case.definition["precondition"] != "pending_login":
        return

    kind = case.fixture["exchange"]["kind"]
    outcomes: list[TransportResponse | TransportFailure] = [wire_response(setup["login"])]
    if kind == "http":
        outcomes.append(wire_response(case.fixture))
    elif kind == "transportFailure":
        outcomes.append(transport_failure(case.fixture))
    transport = FixtureTransport(*outcomes)
    sdk = client_for(case.definition, transport)
    started = begin(sdk)
    if kind == "callback":
        for attempt in case.fixture["exchange"]["attempts"]:
            try:
                sdk.validate_callback(
                    callback_url(attempt, started.pending._state.reveal()), started.pending
                )
            except OwlAuthError:
                pass
        assert case.expected["pendingDisposition"] in {"preserved", "discard_required"}
        assert started.pending._guard.consumed is False, case.name
        assert len(transport.requests) == 1, case.name
        return

    assert case.expected["pendingDisposition"] in {
        "preserved",
        "discard_required",
        "quarantined",
    }
    callback = sdk.validate_callback(
        callback_url("success", started.pending._state.reveal()), started.pending
    )
    try:
        sdk.exchange_handoff(callback, started.pending)
    except OwlAuthError:
        pass
    consumed = case.expected["pendingDisposition"] != "preserved"
    assert started.pending._guard.consumed is consumed, case.name
    assert len(transport.requests) == 2, case.name
    if consumed:
        request_count = len(transport.requests)
        with pytest.raises(HandoffError):
            sdk.exchange_handoff(callback, started.pending)
        assert len(transport.requests) == request_count, case.name


def assert_request(case: Any, transport: FixtureTransport) -> None:
    request = case.fixture["exchange"].get("request")
    if request is None:
        return
    method, body = transport.requests[-1]
    assert method == request["method"], case.name
    assert (body is None) == (request["body"] == "absent"), case.name


def assert_success(case: Any, result: object) -> None:
    values = case.expected.get("values", {})
    operation = case.definition["operationId"]
    if operation == "get_public_application_config":
        assert result.project_id == values["projectId"]
        assert result.application_id == values["applicationId"]
        assert [provider.key for provider in result.providers] == values["providerKeys"]
        assert result.login_available is values["loginAvailable"]
    elif operation == "get_project_jwks":
        assert [key.kid for key in result.keys] == values["keyIds"]
        assert result.revision == values["revision"]
        assert result.signing_epoch == values["signingEpoch"]
    elif operation == "start_login":
        assert result.pending is not None
    elif operation == "get_current_user":
        assert result.project_id == values["projectId"]
        assert result.application_id == values["applicationId"]
        assert result.user_id == values["userId"]
        assert result.projection.projection_revision == values["projectionRevision"]
    elif operation == "logout_application_session":
        assert result.completed is values["completed"]
    elif operation == "prepare_browser_logout":
        assert result.hosted_url.startswith(BASE_URL)


def test_every_required_shared_case_executes_through_the_public_sdk() -> None:
    corpus = load_conformance_corpus(CORPUS_PATH)
    assert corpus.schema_version == 3
    setup = {
        "login": load_fixture("login-start.json"),
        "credential": load_fixture("credential-pair.json"),
    }
    for case in corpus.cases:
        sentinels = case.fixture.get("redactionSentinels", [])
        try:
            result, transport, pending = invoke_case(case, setup)
        except OwlAuthError as error:
            expected = case.expected
            assert expected["outcome"] == "error", case.name
            assert error.category.value == expected["category"], case.name
            assert error.code == expected["code"], case.name
            assert error.operation == case.definition["operationId"], case.name
            assert error.retry.value == expected["retry"], case.name
            assert error.action.value == expected["action"], case.name
            assert error.retry_after_seconds == expected.get("retryAfterSeconds"), case.name
            exchange = case.fixture.get("exchange")
            if expected["category"] == "indeterminate" and exchange.get("kind") == "http":
                assert error.status == exchange["status"], case.name
            rendered = f"{error!s} {error!r}"
            for sentinel in sentinels:
                assert sentinel not in rendered, case.name
            continue

        assert case.expected["outcome"] == "success", case.name
        assert_request(case, transport)
        assert_success(case, result)
        rendered = f"{result!s} {result!r}"
        for sentinel in sentinels:
            assert sentinel not in rendered, case.name
        if case.expected["pendingDisposition"] == "preserved" and pending is not None:
            assert pending._guard.consumed is False, case.name

    for case in corpus.cases:
        assert_pending_disposition(case, setup)


def valid_minimal_corpus(fixture_ref: str = "../fixtures/value.json") -> dict[str, Any]:
    return {
        "schemaVersion": 3,
        "requiredCaseNames": ["case"],
        "cases": [
            {
                "name": "case",
                "required": True,
                "capability": "public_configuration",
                "operationId": "get_public_application_config",
                "fixture": fixture_ref,
                "precondition": "none",
                "requestPhase": "response_received",
                "responseReceived": True,
                "evidenceLevel": "deterministic",
                "configuredContext": {
                    "projectId": "project",
                    "applicationId": "application",
                    "publishableKey": "key",
                },
                "expected": {
                    "outcome": "success",
                    "pendingDisposition": "not_applicable",
                    "credentialDisposition": "not_applicable",
                },
            }
        ],
    }


def write_fixture(root: Path) -> Path:
    conformance = root / "conformance"
    fixtures = root / "fixtures"
    conformance.mkdir()
    fixtures.mkdir()
    (fixtures / "value.json").write_text(
        json.dumps(
            {
                "schemaVersion": 3,
                "synthetic": True,
                "exchange": {
                    "kind": "http",
                    "status": 200,
                    "headers": {"content-type": "application/json"},
                    "body": {"encoding": "json", "value": {}},
                },
            }
        )
    )
    return conformance / "cases.json"


@pytest.mark.parametrize(
    "body",
    [
        b'{"value":NaN}',
        b'{"value":Infinity}',
        b'{"value":1e999}',
        b'{"value":"\\ud800"}',
        b"[" * 20_000 + b"0" + b"]" * 20_000,
    ],
)
def test_conformance_loader_rejects_non_rfc_or_unsafe_json(tmp_path: Path, body: bytes) -> None:
    path = tmp_path / "cases.json"
    path.write_bytes(body)
    with pytest.raises(ProtocolError):
        load_conformance_corpus(path)


@pytest.mark.parametrize(
    "failure",
    ["schema", "unknown", "missing_required", "duplicate", "reference", "capability"],
)
def test_conformance_loader_fails_closed(tmp_path: Path, failure: str) -> None:
    path = write_fixture(tmp_path)
    corpus = valid_minimal_corpus()
    if failure == "schema":
        corpus["schemaVersion"] = 99
    elif failure == "unknown":
        corpus["cases"][0]["unknownRequiredField"] = True
    elif failure == "missing_required":
        del corpus["cases"][0]["operationId"]
    elif failure == "duplicate":
        corpus["cases"].append(dict(corpus["cases"][0]))
    elif failure == "capability":
        corpus["cases"][0]["operationId"] = "future_operation"
    elif failure == "coverage":
        corpus["requiredCaseNames"] = ["different case"]
    else:
        corpus["cases"][0]["fixture"] = "../fixtures/missing.json"
    path.write_text(json.dumps(corpus))

    with pytest.raises(ProtocolError):
        load_conformance_corpus(path)
