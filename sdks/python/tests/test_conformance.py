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
    CredentialPair,
    OwlAuthError,
    ProtocolError,
    SecretValue,
    TransportResponse,
    load_conformance_corpus,
)

CORPUS_PATH = Path(__file__).parents[2] / "spec" / "conformance" / "cases.json"
NOW = datetime(2099, 1, 1, tzinfo=UTC)
REDIRECT = "https://application.example/callback"


class FixtureTransport:
    def __init__(self, *responses: TransportResponse) -> None:
        self.responses = deque(responses)
        self.request_count = 0

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str],
        body: bytes | None,
        timeout: float,
    ) -> TransportResponse:
        del method, url, headers, body, timeout
        self.request_count += 1
        return self.responses.popleft()


def wire_response(wrapper: dict[str, Any]) -> TransportResponse:
    return TransportResponse(
        status=wrapper["responseStatus"],
        headers={"content-type": "application/json"},
        body=json.dumps(wrapper["response"]).encode(),
    )


def start_response() -> TransportResponse:
    return TransportResponse(
        status=201,
        headers={"content-type": "application/json"},
        body=json.dumps(
            {
                "hosted_url": "https://runtime.example/auth/interactions/synthetic",
                "expires_at": (NOW + timedelta(minutes=10)).isoformat(),
            }
        ).encode(),
    )


def client_for(case: dict[str, Any], transport: FixtureTransport) -> Client:
    context = case.get("configuredContext") or {
        "projectId": "prj_conformance",
        "applicationId": "app_conformance",
        "publishableKey": "owl_app_conformance",
    }
    return Client(
        "https://runtime.example/",
        context["projectId"],
        context["applicationId"],
        context["publishableKey"],
        transport=transport,
        _clock=lambda: NOW,
        _entropy=lambda size: b"A" * size,
    )


def credential_wrapper(cases_by_operation: dict[str, Any]) -> dict[str, Any]:
    return cases_by_operation["credential_response"].fixture


def login_exchange(client: Client) -> CredentialPair:
    started = client.begin_login(REDIRECT)
    callback = f"{REDIRECT}?handoff=synthetic-handoff&state={started.pending._state.reveal()}"
    return client.complete_login(callback, started.pending)


def invoke_case(case: Any, cases_by_operation: dict[str, Any]) -> tuple[object, int]:
    definition = case.definition
    operation = definition["operation"]
    fixture = case.fixture
    if operation == "public_configuration":
        transport = FixtureTransport(wire_response(fixture))
        result = client_for(definition, transport).get_public_configuration()
    elif operation in {"handoff", "credential_response"}:
        transport = FixtureTransport(start_response(), wire_response(fixture))
        result = login_exchange(client_for(definition, transport))
    elif operation == "refresh":
        transport = FixtureTransport(
            start_response(),
            wire_response(credential_wrapper(cases_by_operation)),
            wire_response(fixture),
        )
        client = client_for(definition, transport)
        result = client.refresh(login_exchange(client))
    elif operation in {"current_user", "current_user_response"}:
        transport = FixtureTransport(wire_response(fixture))
        result = client_for(definition, transport).current_user(
            SecretValue("synthetic-access", "access token")
        )
    else:
        pytest.fail(f"required conformance operation is unsupported: {operation}")
    return result, transport.request_count


def test_every_required_shared_case_executes_through_the_public_sdk() -> None:
    corpus = load_conformance_corpus(CORPUS_PATH)
    assert corpus.schema_version == 2
    cases_by_operation = {case.definition["operation"]: case for case in corpus.cases}

    for case in corpus.cases:
        if case.definition["required"] is not True:
            continue
        expected = case.expected
        sentinels = case.fixture.get("redactionSentinels", [])
        try:
            result, request_count = invoke_case(case, cases_by_operation)
        except OwlAuthError as error:
            assert expected["outcome"] == "error", case.name
            assert error.category.value == expected["category"], case.name
            assert error.code == expected["code"], case.name
            assert error.retry.value == expected["retry"], case.name
            assert error.action.value == expected["action"], case.name
            rendered = f"{error!s} {error!r}"
            for sentinel in sentinels:
                assert sentinel not in rendered, case.name
            continue

        assert expected["outcome"] == "success", case.name
        assert request_count >= 1
        if case.definition["operation"] == "public_configuration":
            assert result.project_id == expected["projectId"]
            assert result.application_id == expected["applicationId"]
            assert [provider.key for provider in result.providers] == expected["providerKeys"]
            assert result.login_available is expected["loginAvailable"]
        elif case.definition["operation"] == "credential_response":
            assert result.project_id == expected["projectId"]
            assert result.application_id == expected["applicationId"]
            assert result.user_id == expected["userId"]
            assert result.refresh_generation == expected["refreshGeneration"]
            assert result.projection.projection_revision == expected["projectionRevision"]
        elif case.definition["operation"] == "current_user_response":
            assert result.project_id == expected["projectId"]
            assert result.application_id == expected["applicationId"]
            assert result.user_id == expected["userId"]
            assert result.projection.projection_revision == expected["projectionRevision"]
        rendered = f"{result!s} {result!r}"
        for sentinel in sentinels:
            assert sentinel not in rendered, case.name


def valid_minimal_corpus(fixture_ref: str = "../fixtures/value.json") -> dict[str, Any]:
    return {
        "schemaVersion": 2,
        "cases": [
            {
                "name": "case",
                "fixture": fixture_ref,
                "required": True,
                "capability": "test",
                "operation": "test",
                "minimumCorpusSchema": 2,
                "expected": {"outcome": "success"},
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
                "schemaVersion": 2,
                "synthetic": True,
                "responseStatus": 200,
                "response": {},
            }
        )
    )
    return conformance / "cases.json"


@pytest.mark.parametrize(
    "failure", ["schema", "unknown", "missing_required", "duplicate", "reference"]
)
def test_conformance_loader_fails_closed(tmp_path: Path, failure: str) -> None:
    path = write_fixture(tmp_path)
    corpus = valid_minimal_corpus()
    if failure == "schema":
        corpus["schemaVersion"] = 99
    elif failure == "unknown":
        corpus["cases"][0]["unknownRequiredField"] = True
    elif failure == "missing_required":
        del corpus["cases"][0]["operation"]
    elif failure == "duplicate":
        corpus["cases"].append(dict(corpus["cases"][0]))
    else:
        corpus["cases"][0]["fixture"] = "../fixtures/missing.json"
    path.write_text(json.dumps(corpus))

    with pytest.raises(ProtocolError):
        load_conformance_corpus(path)
