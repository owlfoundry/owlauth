#!/usr/bin/env python3
"""Focused tests for the SDK contract normalizer and drift gate."""

from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
from copy import deepcopy
from pathlib import Path
from typing import Any

SCRIPT_PATH = Path(__file__).with_name("sdk-contract.py")
SPEC = importlib.util.spec_from_file_location("sdk_contract", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
sdk_contract = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = sdk_contract
SPEC.loader.exec_module(sdk_contract)


def policy(*, operations: tuple[str, ...] = ("claimed",)) -> Any:
    return sdk_contract.SurfacePolicy(
        schema_version=1,
        normalizer_version=1,
        runtime_operations=operations,
        allowed_shared_operation_ids=frozenset({"get_liveness", "get_readiness"}),
        forbidden_security_schemes=frozenset(
            {"operator_api_key", "project_client_key"}
        ),
    )


def operation(operation_id: str, schema: str = "ClaimedResponse") -> dict[str, Any]:
    return {
        "operationId": operation_id,
        "summary": "ignored prose",
        "security": [{"project_bearer": []}],
        "responses": {
            "200": {
                "description": "ignored prose",
                "content": {
                    "application/json": {
                        "schema": {"$ref": f"#/components/schemas/{schema}"}
                    }
                },
            }
        },
    }


def document(*, claimed: bool, control_claim: bool = False) -> dict[str, Any]:
    paths: dict[str, Any] = {
        "/health/live": {"get": {"operationId": "get_liveness", "responses": {"200": {}}}},
        "/health/ready": {"get": {"operationId": "get_readiness", "responses": {"200": {}}}},
    }
    if claimed:
        paths["/claimed"] = {"get": operation("claimed")}
    if control_claim:
        paths["/control-claimed"] = {"post": operation("claimed")}
    security_name = "operator_api_key" if control_claim else "project_bearer"
    return {
        "openapi": "3.1.0",
        "info": {"title": "ignored", "version": "9.9.9"},
        "paths": paths,
        "components": {
            "securitySchemes": {
                security_name: {"type": "http", "scheme": "bearer"},
                **(
                    {"project_bearer": {"type": "http", "scheme": "bearer"}}
                    if control_claim
                    else {}
                ),
            },
            "schemas": {
                "ClaimedResponse": {
                    "description": "ignored prose",
                    "type": "object",
                    "required": ["value"],
                    "properties": {"value": {"type": "string"}},
                }
            },
        },
    }


def assert_contract_error(callable_value: Any, text: str) -> None:
    try:
        callable_value()
    except sdk_contract.ContractError as error:
        assert text in str(error), str(error)
        return
    raise AssertionError(f"expected ContractError containing {text!r}")


def test_normalization_is_deterministic_and_ignores_unclaimed_changes() -> None:
    runtime = document(claimed=True)
    control = document(claimed=False)
    first = sdk_contract.normalized_surface(runtime, control, policy())
    second_runtime = deepcopy(runtime)
    second_runtime["info"]["version"] = "10.0.0"
    second_runtime["paths"]["/unclaimed"] = {
        "post": {"operationId": "new_unclaimed_operation", "responses": {"204": {}}}
    }
    second = sdk_contract.normalized_surface(second_runtime, control, policy())
    assert first == second
    rendered = sdk_contract.canonical_json(first, pretty=True)
    assert rendered == sdk_contract.canonical_json(second, pretty=True)
    assert b"ignored prose" not in rendered
    assert b"ClaimedResponse" in rendered


def test_wire_fields_named_like_annotations_are_preserved() -> None:
    runtime = document(claimed=True)
    control = document(claimed=False)
    first = sdk_contract.normalized_surface(runtime, control, policy())
    properties = runtime["components"]["schemas"]["ClaimedResponse"]["properties"]
    properties["description"] = {"type": "integer", "description": "ignored prose"}
    properties["title"] = {"type": "string"}
    second = sdk_contract.normalized_surface(runtime, control, policy())
    assert first != second
    selected_properties = second["components"]["schemas"]["ClaimedResponse"]["properties"]
    assert selected_properties["description"] == {"type": "integer"}
    assert selected_properties["title"] == {"type": "string"}


def test_literal_json_keywords_are_opaque_and_dependency_names_are_preserved() -> None:
    runtime = document(claimed=True)
    control = document(claimed=False)
    schema = runtime["components"]["schemas"]["ClaimedResponse"]
    schema["properties"]["literal"] = {
        "const": {"description": "wire-value", "x-field": 1, "$ref": "literal-not-a-reference"}
    }
    schema["properties"]["choice"] = {
        "enum": [{"title": "wire-value", "$ref": "also-literal"}]
    }
    schema["properties"]["defaulted"] = {
        "type": "object",
        "default": {"description": "wire-default", "x-field": 2},
    }
    schema["dependentRequired"] = {"description": ["value"]}
    normalized = sdk_contract.normalized_surface(runtime, control, policy())
    retained = normalized["components"]["schemas"]["ClaimedResponse"]
    assert retained["properties"]["literal"]["const"]["description"] == "wire-value"
    assert retained["properties"]["literal"]["const"]["x-field"] == 1
    assert retained["properties"]["choice"]["enum"][0]["title"] == "wire-value"
    assert retained["properties"]["defaulted"]["default"]["description"] == "wire-default"
    assert retained["dependentRequired"]["description"] == ["value"]

    first = sdk_contract.canonical_json(normalized, pretty=True)
    schema["properties"]["literal"]["const"]["description"] = "changed-wire-value"
    second = sdk_contract.canonical_json(
        sdk_contract.normalized_surface(runtime, control, policy()), pretty=True
    )
    assert first != second


def test_references_in_removed_annotations_are_not_followed() -> None:
    runtime = document(claimed=True)
    control = document(claimed=False)
    runtime["components"]["schemas"]["ClaimedResponse"]["examples"] = [
        {"$ref": "control.json#/components/examples/NotWireContract"}
    ]
    normalized = sdk_contract.normalized_surface(runtime, control, policy())
    assert "examples" not in normalized["components"]["schemas"]["ClaimedResponse"]


def test_claimed_change_and_snapshot_drift_are_visible() -> None:
    runtime = document(claimed=True)
    control = document(claimed=False)
    first = sdk_contract.normalized_surface(runtime, control, policy())
    runtime["components"]["schemas"]["ClaimedResponse"]["required"].append("revision")
    runtime["components"]["schemas"]["ClaimedResponse"]["properties"]["revision"] = {
        "type": "integer"
    }
    second = sdk_contract.normalized_surface(runtime, control, policy())
    assert first != second
    with tempfile.TemporaryDirectory() as temporary_directory:
        snapshot = Path(temporary_directory) / "snapshot.json"
        snapshot.write_bytes(sdk_contract.canonical_json(first, pretty=True))
        assert_contract_error(
            lambda: sdk_contract.check_snapshot(
                snapshot, sdk_contract.canonical_json(second, pretty=True)
            ),
            "SDK contract drift detected",
        )


def test_missing_duplicate_and_dangling_operations_fail() -> None:
    runtime = document(claimed=False)
    control = document(claimed=False)
    assert_contract_error(
        lambda: sdk_contract.normalized_surface(runtime, control, policy()), "are missing"
    )

    duplicate = document(claimed=True)
    duplicate["paths"]["/duplicate"] = {"post": operation("claimed")}
    assert_contract_error(
        lambda: sdk_contract.normalized_surface(duplicate, control, policy()), "is duplicated"
    )

    dangling = document(claimed=True)
    dangling["paths"]["/claimed"]["get"] = operation("claimed", "Missing")
    assert_contract_error(
        lambda: sdk_contract.normalized_surface(dangling, control, policy()),
        "dangling OpenAPI reference",
    )


def test_external_reference_and_unexpected_plane_overlap_fail() -> None:
    runtime = document(claimed=True)
    control = document(claimed=False)
    runtime["paths"]["/claimed"]["get"]["responses"]["200"]["content"]["application/json"][
        "schema"
    ] = {"$ref": "control.json#/components/schemas/ControlSecret"}
    assert_contract_error(
        lambda: sdk_contract.normalized_surface(runtime, control, policy()),
        "external or cross-document reference",
    )

    runtime = document(claimed=True)
    control = document(claimed=False)
    runtime["paths"]["/shared"] = {
        "get": {"operationId": "unexpected_shared", "responses": {"200": {}}}
    }
    control["paths"]["/shared"] = {
        "get": {"operationId": "unexpected_shared", "responses": {"200": {}}}
    }
    assert_contract_error(
        lambda: sdk_contract.normalized_surface(runtime, control, policy()),
        "unexpectedly share operation IDs",
    )


def test_same_http_operation_with_different_ids_fails() -> None:
    runtime = document(claimed=True)
    control = document(claimed=False)
    runtime["paths"]["/shared-http"] = {
        "post": {"operationId": "runtime_name", "responses": {"204": {}}}
    }
    control["paths"]["/shared-http"] = {
        "post": {"operationId": "control_name", "responses": {"204": {}}}
    }
    assert_contract_error(
        lambda: sdk_contract.normalized_surface(runtime, control, policy()),
        "unexpectedly share HTTP operation",
    )


def test_allowed_shared_operation_identity_and_contract_must_match() -> None:
    runtime = document(claimed=True)
    control = document(claimed=False)
    control["paths"]["/health/live"]["get"]["responses"] = {"204": {}}
    assert_contract_error(
        lambda: sdk_contract.normalized_surface(runtime, control, policy()),
        "contracts differ",
    )

    control = document(claimed=False)
    control["paths"]["/health/live-moved"] = control["paths"].pop("/health/live")
    assert_contract_error(
        lambda: sdk_contract.normalized_surface(runtime, control, policy()),
        "different method/path identities",
    )


def test_claimed_client_overlap_and_client_security_fail() -> None:
    runtime = document(claimed=True)
    client = document(claimed=False)
    client["paths"]["/client-claimed"] = {"post": operation("claimed")}
    assert_contract_error(
        lambda: sdk_contract.normalized_surface(
            runtime, document(claimed=False), policy(), client=client
        ),
        "Runtime and Client unexpectedly share operation IDs",
    )

    runtime = document(claimed=True)
    runtime["paths"]["/claimed"]["get"]["security"] = [{"project_client_key": []}]
    runtime["components"]["securitySchemes"]["project_client_key"] = {
        "type": "http",
        "scheme": "bearer",
    }
    assert_contract_error(
        lambda: sdk_contract.normalized_surface(
            runtime,
            document(claimed=False),
            policy(),
            client=document(claimed=False),
        ),
        "forbidden security schemes",
    )


def test_claimed_control_overlap_and_management_security_fail() -> None:
    runtime = document(claimed=True)
    control = document(claimed=False, control_claim=True)
    del control["paths"]["/control-claimed"]
    control["paths"]["/claimed"] = {"get": operation("claimed")}
    overlap_policy = sdk_contract.SurfacePolicy(
        schema_version=1,
        normalizer_version=1,
        runtime_operations=("claimed",),
        allowed_shared_operation_ids=frozenset(
            {"get_liveness", "get_readiness", "claimed"}
        ),
        forbidden_security_schemes=frozenset(
            {"operator_api_key", "project_client_key"}
        ),
    )
    assert_contract_error(
        lambda: sdk_contract.normalized_surface(runtime, control, overlap_policy),
        "leak into Control",
    )

    runtime = document(claimed=True)
    runtime["paths"]["/claimed"]["get"]["security"] = [{"operator_api_key": []}]
    runtime["components"]["securitySchemes"]["operator_api_key"] = {
        "type": "http",
        "scheme": "bearer",
    }
    assert_contract_error(
        lambda: sdk_contract.normalized_surface(runtime, document(claimed=False), policy()),
        "forbidden security schemes",
    )


def test_policy_is_strict() -> None:
    value = {
        "schemaVersion": 1,
        "normalizerVersion": 1,
        "runtimeOperations": ["claimed"],
        "allowedSharedOperationIds": ["get_liveness", "get_readiness"],
        "forbiddenSecuritySchemes": ["operator_api_key", "project_client_key"],
    }
    with tempfile.TemporaryDirectory() as temporary_directory:
        path = Path(temporary_directory) / "policy.json"
        path.write_text(json.dumps(value), encoding="utf-8")
        assert sdk_contract.load_policy(path).runtime_operations == ("claimed",)
        value["unknown"] = True
        path.write_text(json.dumps(value), encoding="utf-8")
        assert_contract_error(lambda: sdk_contract.load_policy(path), "unknown fields")


def main() -> None:
    test_normalization_is_deterministic_and_ignores_unclaimed_changes()
    test_wire_fields_named_like_annotations_are_preserved()
    test_literal_json_keywords_are_opaque_and_dependency_names_are_preserved()
    test_references_in_removed_annotations_are_not_followed()
    test_claimed_change_and_snapshot_drift_are_visible()
    test_missing_duplicate_and_dangling_operations_fail()
    test_external_reference_and_unexpected_plane_overlap_fail()
    test_same_http_operation_with_different_ids_fails()
    test_allowed_shared_operation_identity_and_contract_must_match()
    test_claimed_client_overlap_and_client_security_fail()
    test_claimed_control_overlap_and_management_security_fail()
    test_policy_is_strict()
    print("SDK contract tests passed")


if __name__ == "__main__":
    main()
