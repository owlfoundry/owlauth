"""Strict loader for the shared language-neutral conformance corpus."""

from __future__ import annotations

import base64
import binascii
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from owlauth.errors import ProtocolError

_SCHEMA_VERSION = 3
_OPERATION_IDS = frozenset(
    {
        "get_public_application_config",
        "get_project_jwks",
        "start_login",
        "exchange_handoff",
        "refresh_session",
        "get_current_user",
        "logout_application_session",
        "prepare_browser_logout",
    }
)
_REQUEST_PHASES = frozenset({"before_dispatch", "possibly_dispatched", "response_received"})
_PRECONDITIONS = frozenset({"none", "pending_login", "credential_pair"})
_PENDING_DISPOSITIONS = frozenset(
    {"not_applicable", "preserved", "discard_required", "quarantined", "consumed"}
)
_CREDENTIAL_DISPOSITIONS = frozenset(
    {
        "not_applicable",
        "preserved",
        "replaced",
        "cleared",
        "invalidated",
        "quarantined",
        "reauthentication_required",
    }
)


@dataclass(frozen=True, slots=True)
class ConformanceCase:
    name: str
    fixture_path: Path
    fixture: dict[str, Any]
    expected: dict[str, Any]
    definition: dict[str, Any]


@dataclass(frozen=True, slots=True)
class ConformanceCorpus:
    schema_version: int
    cases: tuple[ConformanceCase, ...]


def load_conformance_corpus(path: str | Path) -> ConformanceCorpus:
    """Load schema v3 cases and fail closed on every structural ambiguity."""
    source = Path(path).resolve()
    base = source.parent.resolve()
    fixture_root = (base.parent / "fixtures").resolve()
    document = _read_json(source)
    _exact_object(document, {"schemaVersion", "requiredCaseNames", "cases"})
    if document["schemaVersion"] != _SCHEMA_VERSION or not isinstance(document["cases"], list):
        raise _invalid("unsupported_conformance_schema")
    required_names_value = document["requiredCaseNames"]
    if not isinstance(required_names_value, list) or not required_names_value:
        raise _invalid()
    required_names = tuple(_bounded_string(value, 128) for value in required_names_value)
    if len(set(required_names)) != len(required_names):
        raise _invalid()

    names: set[str] = set()
    cases: list[ConformanceCase] = []
    for definition_value in document["cases"]:
        definition = _object(definition_value)
        _exact_object(
            definition,
            {
                "name",
                "required",
                "capability",
                "operationId",
                "fixture",
                "precondition",
                "requestPhase",
                "responseReceived",
                "evidenceLevel",
                "configuredContext",
                "expected",
            },
            {"platformCapability"},
        )
        name = _bounded_string(definition["name"], 128)
        if name in names:
            raise _invalid()
        names.add(name)
        if definition["required"] is not True:
            raise _invalid()
        _bounded_string(definition["capability"], 64)
        if definition["operationId"] not in _OPERATION_IDS:
            raise _invalid("unsupported_required_capability")
        fixture_ref = _bounded_string(definition["fixture"], 256)
        if definition["precondition"] not in _PRECONDITIONS:
            raise _invalid()
        phase = definition["requestPhase"]
        if phase not in _REQUEST_PHASES or not isinstance(definition["responseReceived"], bool):
            raise _invalid()
        if definition["responseReceived"] is not (phase == "response_received"):
            raise _invalid()
        if definition["evidenceLevel"] != "deterministic":
            raise _invalid()
        if "platformCapability" in definition:
            _bounded_string(definition["platformCapability"], 64)
        context = _object(definition["configuredContext"])
        _exact_object(context, {"projectId", "applicationId", "publishableKey"})
        for value in context.values():
            _bounded_string(value, 128)
        expected = _validate_expected(definition["expected"])

        fixture_path = (base / fixture_ref).resolve()
        if fixture_path == fixture_root or fixture_root not in fixture_path.parents:
            raise ProtocolError("conformance_path_escape", "Conformance fixture path escapes root.")
        fixture = _validate_fixture(_read_json(fixture_path))
        exchange = fixture["exchange"]
        if exchange["kind"] == "transportFailure":
            if exchange["requestPhase"] != phase or definition["responseReceived"]:
                raise _invalid()
        elif exchange["kind"] == "callback":
            if phase != "before_dispatch" or definition["responseReceived"]:
                raise _invalid()
        elif phase != "response_received" or not definition["responseReceived"]:
            raise _invalid()
        cases.append(
            ConformanceCase(
                name=name,
                fixture_path=fixture_path,
                fixture=fixture,
                expected=expected,
                definition=definition,
            )
        )
    if not cases or names != set(required_names) or len(cases) != len(required_names):
        raise _invalid()
    return ConformanceCorpus(schema_version=_SCHEMA_VERSION, cases=tuple(cases))


def _validate_expected(value: object) -> dict[str, Any]:
    expected = _object(value)
    common = {"outcome", "pendingDisposition", "credentialDisposition"}
    outcome = expected.get("outcome")
    if outcome == "success":
        _exact_object(expected, common, {"values"})
        if "values" in expected:
            values = _object(expected["values"])
            if not all(isinstance(key, str) for key in values):
                raise _invalid()
    elif outcome == "error":
        _exact_object(expected, common | {"category", "code", "retry", "action"})
        for field in ("category", "code", "retry", "action"):
            _bounded_string(expected[field], 64)
    else:
        raise _invalid()
    if expected["pendingDisposition"] not in _PENDING_DISPOSITIONS:
        raise _invalid()
    if expected["credentialDisposition"] not in _CREDENTIAL_DISPOSITIONS:
        raise _invalid()
    if outcome == "error":
        pending_actions = {
            "discard_required": "discard_pending",
            "quarantined": "quarantine_pending",
        }
        credential_actions = {
            "invalidated": "invalidate_credentials",
            "quarantined": "quarantine_credentials",
            "reauthentication_required": "reauthenticate",
        }
        disposition = expected["pendingDisposition"]
        credential_disposition = expected["credentialDisposition"]
        required = pending_actions.get(disposition) or credential_actions.get(
            credential_disposition
        )
        if required is not None and expected["action"] != required:
            raise _invalid()
        if credential_disposition == "preserved" and expected["action"] != "none":
            raise _invalid()
    return expected


def _validate_fixture(value: object) -> dict[str, Any]:
    fixture = _object(value)
    _exact_object(fixture, {"schemaVersion", "synthetic", "exchange"}, {"redactionSentinels"})
    if fixture["schemaVersion"] != _SCHEMA_VERSION or fixture["synthetic"] is not True:
        raise _invalid()
    sentinels = fixture.get("redactionSentinels", [])
    if not isinstance(sentinels, list) or not all(
        isinstance(item, str) and 1 <= len(item) <= 256 for item in sentinels
    ):
        raise _invalid()
    exchange = _object(fixture["exchange"])
    kind = exchange.get("kind")
    if kind == "http":
        _exact_object(exchange, {"kind", "status", "headers", "body"}, {"request"})
        status = exchange["status"]
        if not isinstance(status, int) or isinstance(status, bool) or not 100 <= status <= 599:
            raise _invalid()
        headers = _object(exchange["headers"])
        if not all(
            isinstance(name, str)
            and isinstance(item, str)
            and 1 <= len(name) <= 128
            and len(item) <= 512
            for name, item in headers.items()
        ):
            raise _invalid()
        body = _object(exchange["body"])
        encoding = body.get("encoding")
        if encoding == "json":
            _exact_object(body, {"encoding", "value"})
        elif encoding == "text":
            _exact_object(body, {"encoding", "value"})
            value = _bounded_string(body["value"], 65_536)
            if len(value.encode("utf-8")) > 65_536:
                raise _invalid()
        elif encoding == "empty":
            _exact_object(body, {"encoding"})
        elif encoding == "base64":
            _exact_object(body, {"encoding", "value"})
            encoded = _bounded_string(body["value"], 87_384)
            try:
                decoded = base64.b64decode(encoded, validate=True)
            except (ValueError, binascii.Error) as error:
                raise _invalid() from error
            if len(decoded) > 65_536:
                raise _invalid()
        elif encoding == "repeat":
            _exact_object(body, {"encoding", "value", "count"})
            if not isinstance(body["value"], str) or len(body["value"].encode()) != 1:
                raise _invalid()
            if not isinstance(body["count"], int) or not 0 <= body["count"] <= 65_537:
                raise _invalid()
        else:
            raise _invalid()
        if "request" in exchange:
            request = _object(exchange["request"])
            _exact_object(request, {"method", "body"})
            if request["method"] not in {"GET", "POST"} or request["body"] not in {
                "absent",
                "json",
            }:
                raise _invalid()
    elif kind == "callback":
        _exact_object(exchange, {"kind", "attempts", "clockOffsetSeconds"})
        attempts = exchange["attempts"]
        if (
            not isinstance(attempts, list)
            or not attempts
            or not all(
                item in {"success", "error", "ambiguous", "state_mismatch"} for item in attempts
            )
        ):
            raise _invalid()
        offset = exchange["clockOffsetSeconds"]
        if not isinstance(offset, int) or isinstance(offset, bool) or not 0 <= offset <= 86_400:
            raise _invalid()
    elif kind == "transportFailure":
        _exact_object(exchange, {"kind", "failureKind", "requestPhase"})
        if exchange["failureKind"] not in {"transport", "timeout", "cancelled"}:
            raise _invalid()
        if exchange["requestPhase"] not in {"before_dispatch", "possibly_dispatched"}:
            raise _invalid()
    else:
        raise _invalid()
    return fixture


def _read_json(path: Path) -> Any:
    try:
        body = path.read_bytes()
        if len(body) > 1_048_576:
            raise _invalid()
        return json.loads(body.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise _invalid() from error


def _object(value: object) -> dict[str, Any]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise _invalid()
    return value


def _exact_object(
    value: object, required: set[str], optional: set[str] | None = None
) -> dict[str, Any]:
    item = _object(value)
    optional = optional or set()
    if not required.issubset(item) or set(item) - required - optional:
        raise _invalid()
    return item


def _bounded_string(value: object, maximum: int) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= maximum:
        raise _invalid()
    return value


def _invalid(code: str = "invalid_conformance_corpus") -> ProtocolError:
    return ProtocolError(code, "The conformance corpus is invalid.")
