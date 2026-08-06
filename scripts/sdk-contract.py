#!/usr/bin/env python3
"""Validate the generated Runtime contract claimed by the public SDKs."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

REPOSITORY_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_POLICY = REPOSITORY_ROOT / "sdks/spec/contract/sdk-surface.json"
DEFAULT_SNAPSHOT = REPOSITORY_ROOT / "sdks/spec/contract/runtime-project-auth.normalized.json"
HTTP_METHODS = frozenset({"delete", "get", "head", "options", "patch", "post", "put", "trace"})
ANNOTATION_KEYS = frozenset(
    {
        "description",
        "example",
        "examples",
        "externalDocs",
        "summary",
        "tags",
        "title",
    }
)
ARBITRARY_NAME_MAPS = frozenset(
    {
        "$defs",
        "callbacks",
        "content",
        "dependentRequired",
        "dependentSchemas",
        "encoding",
        "headers",
        "links",
        "mapping",
        "patternProperties",
        "properties",
        "responses",
        "security",
    }
)
OPAQUE_JSON_KEYS = frozenset({"const", "default", "enum"})
POLICY_KEYS = frozenset(
    {
        "schemaVersion",
        "normalizerVersion",
        "runtimeOperations",
        "allowedSharedOperationIds",
        "forbiddenSecuritySchemes",
    }
)


class ContractError(RuntimeError):
    """Raised when the generated SDK contract is unsafe or stale."""


@dataclass(frozen=True)
class SurfacePolicy:
    schema_version: int
    normalizer_version: int
    runtime_operations: tuple[str, ...]
    allowed_shared_operation_ids: frozenset[str]
    forbidden_security_schemes: frozenset[str]


@dataclass(frozen=True)
class Operation:
    operation_id: str
    method: str
    path: str
    value: dict[str, Any]
    path_parameters: list[Any]


def canonical_json(value: Any, *, pretty: bool) -> bytes:
    options: dict[str, Any] = {
        "ensure_ascii": False,
        "sort_keys": True,
    }
    if pretty:
        options["indent"] = 2
        text = json.dumps(value, **options) + "\n"
    else:
        options["separators"] = (",", ":")
        text = json.dumps(value, **options)
    return text.encode("utf-8")


def sha256_hex(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ContractError(f"cannot read JSON from {path}: {error}") from error


def require_string_list(value: Any, field: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not value:
        raise ContractError(f"policy field {field!r} must be a non-empty string array")
    if not all(isinstance(item, str) and item for item in value):
        raise ContractError(f"policy field {field!r} must contain non-empty strings")
    if len(set(value)) != len(value):
        raise ContractError(f"policy field {field!r} contains duplicates")
    return tuple(value)


def load_policy(path: Path) -> SurfacePolicy:
    value = load_json(path)
    if not isinstance(value, dict):
        raise ContractError("SDK surface policy must be a JSON object")
    unknown = set(value) - POLICY_KEYS
    missing = POLICY_KEYS - set(value)
    if unknown:
        raise ContractError(f"SDK surface policy has unknown fields: {sorted(unknown)}")
    if missing:
        raise ContractError(f"SDK surface policy is missing fields: {sorted(missing)}")
    if value["schemaVersion"] != 1:
        raise ContractError(f"unsupported SDK surface policy schema: {value['schemaVersion']!r}")
    if value["normalizerVersion"] != 1:
        raise ContractError(f"unsupported SDK contract normalizer: {value['normalizerVersion']!r}")
    operations = require_string_list(value["runtimeOperations"], "runtimeOperations")
    shared = require_string_list(value["allowedSharedOperationIds"], "allowedSharedOperationIds")
    forbidden = require_string_list(value["forbiddenSecuritySchemes"], "forbiddenSecuritySchemes")
    return SurfacePolicy(
        schema_version=1,
        normalizer_version=1,
        runtime_operations=operations,
        allowed_shared_operation_ids=frozenset(shared),
        forbidden_security_schemes=frozenset(forbidden),
    )


def document_operations(document: Any, plane: str) -> dict[str, Operation]:
    if not isinstance(document, dict):
        raise ContractError(f"{plane} OpenAPI document must be an object")
    if document.get("openapi") != "3.1.0":
        raise ContractError(f"{plane} OpenAPI document must use OpenAPI 3.1.0")
    paths = document.get("paths")
    if not isinstance(paths, dict):
        raise ContractError(f"{plane} OpenAPI document has no Paths Object")
    operations: dict[str, Operation] = {}
    for path, path_item in paths.items():
        if not isinstance(path, str) or not isinstance(path_item, dict):
            raise ContractError(f"{plane} OpenAPI contains a malformed path item")
        path_parameters = path_item.get("parameters", [])
        if not isinstance(path_parameters, list):
            raise ContractError(f"{plane} path {path!r} has malformed parameters")
        for method, operation in path_item.items():
            if method.lower() not in HTTP_METHODS:
                continue
            if not isinstance(operation, dict):
                raise ContractError(f"{plane} operation {method.upper()} {path} must be an object")
            operation_id = operation.get("operationId")
            if not isinstance(operation_id, str) or not operation_id:
                raise ContractError(f"{plane} operation {method.upper()} {path} has no operationId")
            if operation_id in operations:
                previous = operations[operation_id]
                raise ContractError(
                    f"{plane} operationId {operation_id!r} is duplicated by "
                    f"{previous.method} {previous.path} and {method.upper()} {path}"
                )
            operations[operation_id] = Operation(
                operation_id=operation_id,
                method=method.upper(),
                path=path,
                value=operation,
                path_parameters=path_parameters,
            )
    return operations


def decode_pointer_segment(segment: str) -> str:
    return segment.replace("~1", "/").replace("~0", "~")


def resolve_reference(document: Mapping[str, Any], reference: str) -> Any:
    if not reference.startswith("#/"):
        raise ContractError(f"external or cross-document reference is forbidden: {reference}")
    current: Any = document
    for raw_segment in reference[2:].split("/"):
        segment = decode_pointer_segment(raw_segment)
        if not isinstance(current, dict) or segment not in current:
            raise ContractError(f"dangling OpenAPI reference: {reference}")
        current = current[segment]
    return current


def references_in(value: Any, *, arbitrary_names: bool = False) -> Iterable[str]:
    if isinstance(value, dict):
        if not arbitrary_names and "$ref" in value:
            reference = value["$ref"]
            if not isinstance(reference, str):
                raise ContractError("OpenAPI $ref value must be a string")
            yield reference
        for key, child in value.items():
            if not arbitrary_names and (key == "$ref" or key in OPAQUE_JSON_KEYS):
                continue
            yield from references_in(
                child,
                arbitrary_names=key in ARBITRARY_NAME_MAPS,
            )
    elif isinstance(value, list):
        for child in value:
            yield from references_in(child, arbitrary_names=arbitrary_names)


def referenced_security_schemes(operation: Mapping[str, Any]) -> set[str]:
    security = operation.get("security", [])
    if not isinstance(security, list):
        raise ContractError("OpenAPI operation security must be an array")
    names: set[str] = set()
    for requirement in security:
        if not isinstance(requirement, dict):
            raise ContractError("OpenAPI security requirement must be an object")
        for name, scopes in requirement.items():
            if not isinstance(name, str) or not isinstance(scopes, list):
                raise ContractError("OpenAPI security requirement is malformed")
            names.add(name)
    return names


def strip_annotations(value: Any, *, arbitrary_names: bool = False) -> Any:
    if isinstance(value, dict):
        retained: dict[str, Any] = {}
        for key, child in value.items():
            if not arbitrary_names and (key in ANNOTATION_KEYS or key.startswith("x-")):
                continue
            retained[key] = (
                child
                if not arbitrary_names and key in OPAQUE_JSON_KEYS
                else strip_annotations(
                    child,
                    arbitrary_names=key in ARBITRARY_NAME_MAPS,
                )
            )
        return retained
    if isinstance(value, list):
        return [strip_annotations(child, arbitrary_names=arbitrary_names) for child in value]
    return value


def component_reference(reference: str) -> tuple[str, str] | None:
    segments = reference[2:].split("/") if reference.startswith("#/") else []
    if len(segments) != 3 or segments[0] != "components":
        return None
    return decode_pointer_segment(segments[1]), decode_pointer_segment(segments[2])


def normalized_surface(
    runtime: Mapping[str, Any],
    control: Mapping[str, Any],
    policy: SurfacePolicy,
    *,
    client: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    runtime_operations = document_operations(runtime, "Runtime")
    control_operations = document_operations(control, "Control")
    non_runtime_planes: list[tuple[str, dict[str, Operation]]] = [
        ("Control", control_operations)
    ]
    if client is not None:
        non_runtime_planes.append(("Client", document_operations(client, "Client")))

    runtime_identities = {
        (operation.method, operation.path): operation for operation in runtime_operations.values()
    }
    for plane_name, plane_operations in non_runtime_planes:
        operation_id_overlap = set(runtime_operations) & set(plane_operations)
        unexpected_overlap = operation_id_overlap - policy.allowed_shared_operation_ids
        missing_allowed_overlap = policy.allowed_shared_operation_ids - operation_id_overlap
        if unexpected_overlap:
            raise ContractError(
                f"Runtime and {plane_name} unexpectedly share operation IDs: "
                f"{sorted(unexpected_overlap)}"
            )
        if missing_allowed_overlap:
            raise ContractError(
                f"declared Runtime/{plane_name} shared operation IDs are no longer shared: "
                f"{sorted(missing_allowed_overlap)}"
            )

        plane_identities = {
            (operation.method, operation.path): operation
            for operation in plane_operations.values()
        }
        for identity in sorted(set(runtime_identities) & set(plane_identities)):
            runtime_operation = runtime_identities[identity]
            plane_operation = plane_identities[identity]
            if (
                runtime_operation.operation_id != plane_operation.operation_id
                or runtime_operation.operation_id not in policy.allowed_shared_operation_ids
            ):
                raise ContractError(
                    f"Runtime and {plane_name} unexpectedly share HTTP operation "
                    f"{identity[0]} {identity[1]} as "
                    f"{runtime_operation.operation_id!r}/{plane_operation.operation_id!r}"
                )
            if strip_annotations(runtime_operation.value) != strip_annotations(
                plane_operation.value
            ):
                raise ContractError(
                    f"shared Runtime and {plane_name} operation contracts differ: "
                    f"{runtime_operation.operation_id}"
                )
        for operation_id in policy.allowed_shared_operation_ids:
            runtime_operation = runtime_operations[operation_id]
            plane_operation = plane_operations[operation_id]
            if (runtime_operation.method, runtime_operation.path) != (
                plane_operation.method,
                plane_operation.path,
            ):
                raise ContractError(
                    f"shared Runtime/{plane_name} operation {operation_id!r} "
                    "has different method/path identities"
                )

    claimed = set(policy.runtime_operations)
    missing = claimed - set(runtime_operations)
    if missing:
        raise ContractError(f"claimed Runtime operations are missing: {sorted(missing)}")
    for plane_name, plane_operations in non_runtime_planes:
        leakage = claimed & set(plane_operations)
        if leakage:
            raise ContractError(
                f"claimed Runtime operations leak into {plane_name}: {sorted(leakage)}"
            )

    selected: dict[str, Any] = {}
    reference_queue: list[str] = []
    security_names: set[str] = set()
    root_security = runtime.get("security", [])
    for operation_id in sorted(claimed):
        operation = runtime_operations[operation_id]
        contract = dict(operation.value)
        contract["security"] = contract.get("security", root_security)
        if operation.path_parameters:
            contract["pathParameters"] = operation.path_parameters
        retained_contract = strip_annotations(contract)
        selected[operation_id] = {
            "method": operation.method,
            "path": operation.path,
            "contract": retained_contract,
        }
        reference_queue.extend(references_in(retained_contract))
        security_names.update(referenced_security_schemes(retained_contract))

    forbidden = security_names & policy.forbidden_security_schemes
    if forbidden:
        raise ContractError(f"claimed Runtime surface uses forbidden security schemes: {sorted(forbidden)}")

    components = runtime.get("components", {})
    if not isinstance(components, dict):
        raise ContractError("Runtime OpenAPI components must be an object")
    security_schemes = components.get("securitySchemes", {})
    if not isinstance(security_schemes, dict):
        raise ContractError("Runtime OpenAPI securitySchemes must be an object")
    for name in sorted(security_names):
        if name not in security_schemes:
            raise ContractError(f"claimed Runtime surface references missing security scheme: {name}")
        reference_queue.append(f"#/components/securitySchemes/{name}")

    collected_references: set[str] = set()
    normalized_components: dict[str, dict[str, Any]] = {}
    while reference_queue:
        reference = reference_queue.pop()
        if reference in collected_references:
            continue
        collected_references.add(reference)
        target = resolve_reference(runtime, reference)
        component = component_reference(reference)
        if component is None:
            raise ContractError(
                "claimed Runtime surface references unsupported non-component pointer: "
                f"{reference}"
            )
        category, name = component
        retained_target = strip_annotations(target)
        normalized_components.setdefault(category, {})[name] = retained_target
        reference_queue.extend(references_in(retained_target))

    serialized = canonical_json(
        {"operations": selected, "components": normalized_components}, pretty=False
    ).decode("utf-8")
    for forbidden_name in policy.forbidden_security_schemes:
        if forbidden_name in serialized:
            raise ContractError(
                f"claimed Runtime surface contains forbidden management vocabulary: {forbidden_name}"
            )

    return {
        "schemaVersion": policy.schema_version,
        "normalizerVersion": policy.normalizer_version,
        "openapi": runtime["openapi"],
        "operations": selected,
        "components": normalized_components,
    }


def export_documents(
    root: Path,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    with tempfile.TemporaryDirectory(prefix="owlauth-sdk-contract-") as temporary_directory:
        temporary = Path(temporary_directory)
        documents: list[dict[str, Any]] = []
        for plane in ("runtime", "client", "control"):
            output = temporary / f"{plane}.json"
            command = [
                "cargo",
                "run",
                "--quiet",
                "--locked",
                "--package",
                "owlauth-types",
                "--bin",
                "export-openapi",
                "--",
                plane,
                str(output),
            ]
            try:
                subprocess.run(command, cwd=root, check=True)
            except (OSError, subprocess.CalledProcessError) as error:
                raise ContractError(f"failed to export {plane} OpenAPI: {error}") from error
            value = load_json(output)
            if not isinstance(value, dict):
                raise ContractError(f"exported {plane} OpenAPI must be an object")
            documents.append(value)
        return documents[0], documents[1], documents[2]


def source_commit(root: Path) -> str:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=root,
            check=True,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError) as error:
        raise ContractError(f"cannot determine source commit: {error}") from error
    return result.stdout.strip()


def package_version(root: Path, relative: str) -> str:
    try:
        text = (root / relative).read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        raise ContractError(f"cannot read package version from {relative}: {error}") from error
    package = re.search(r"^\[package\]$(.*?)(?=^\[|\Z)", text, flags=re.MULTILINE | re.DOTALL)
    if package is None:
        raise ContractError(f"cannot find [package] in {relative}")
    version = re.search(r'^version = "([^"]+)"$', package.group(1), flags=re.MULTILINE)
    if version is None:
        raise ContractError(f"cannot find package version in {relative}")
    return version.group(1)


def provenance(
    root: Path,
    runtime: Mapping[str, Any],
    normalized: Mapping[str, Any],
    policy_path: Path,
    policy: SurfacePolicy,
) -> dict[str, Any]:
    runtime_digest = sha256_hex(canonical_json(runtime, pretty=False))
    normalized_digest = sha256_hex(canonical_json(normalized, pretty=False))
    policy_value = load_json(policy_path)
    return {
        "schemaVersion": 1,
        "sourceCommit": source_commit(root),
        "owlauthTypesVersion": package_version(root, "crates/owlauth-types/Cargo.toml"),
        "owlauthServerVersion": package_version(root, "crates/owlauth-server/Cargo.toml"),
        "openapiVersion": runtime["openapi"],
        "fullRuntimeSha256": runtime_digest,
        "claimedSurfaceSha256": normalized_digest,
        "policySha256": sha256_hex(canonical_json(policy_value, pretty=False)),
        "normalizerVersion": policy.normalizer_version,
        "claimedOperationIds": list(policy.runtime_operations),
    }


def write_bytes(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    try:
        temporary.write_bytes(content)
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def check_snapshot(path: Path, expected: bytes) -> None:
    try:
        actual = path.read_bytes()
    except OSError as error:
        raise ContractError(f"cannot read SDK contract snapshot {path}: {error}") from error
    if actual != expected:
        raise ContractError(
            "SDK contract drift detected; the claimed Runtime surface changed. "
            "Review server compatibility and all three clients, then run "
            "`python3 scripts/sdk-contract.py update`."
        )


def parse_arguments(arguments: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("check", "update"))
    parser.add_argument("--policy", type=Path, default=DEFAULT_POLICY)
    parser.add_argument("--snapshot", type=Path, default=DEFAULT_SNAPSHOT)
    parser.add_argument("--provenance", type=Path)
    parser.add_argument("--runtime-openapi", type=Path)
    parser.add_argument("--client-openapi", type=Path)
    parser.add_argument("--control-openapi", type=Path)
    return parser.parse_args(arguments)


def run(arguments: list[str]) -> None:
    options = parse_arguments(arguments)
    provided_openapi = [
        options.runtime_openapi,
        options.client_openapi,
        options.control_openapi,
    ]
    if any(path is not None for path in provided_openapi) and not all(
        path is not None for path in provided_openapi
    ):
        raise ContractError(
            "--runtime-openapi, --client-openapi, and --control-openapi must be provided together"
        )
    policy_path = options.policy.resolve()
    snapshot_path = options.snapshot.resolve()
    policy = load_policy(policy_path)
    if options.runtime_openapi is None:
        runtime, client, control = export_documents(REPOSITORY_ROOT)
    else:
        runtime_value = load_json(options.runtime_openapi)
        client_value = load_json(options.client_openapi)
        control_value = load_json(options.control_openapi)
        if not all(
            isinstance(value, dict)
            for value in (runtime_value, client_value, control_value)
        ):
            raise ContractError("OpenAPI inputs must be JSON objects")
        runtime, client, control = runtime_value, client_value, control_value
    normalized = normalized_surface(runtime, control, policy, client=client)
    rendered = canonical_json(normalized, pretty=True)
    if options.action == "update":
        write_bytes(snapshot_path, rendered)
        print(f"updated {snapshot_path.relative_to(REPOSITORY_ROOT)}")
    else:
        check_snapshot(snapshot_path, rendered)
        print(
            "SDK contract is current: "
            f"{len(policy.runtime_operations)} operations, "
            f"sha256:{sha256_hex(canonical_json(normalized, pretty=False))}"
        )
    if options.provenance is not None:
        evidence = provenance(REPOSITORY_ROOT, runtime, normalized, policy_path, policy)
        write_bytes(options.provenance, canonical_json(evidence, pretty=True))


def main() -> int:
    try:
        run(sys.argv[1:])
    except ContractError as error:
        message = str(error)
        if os.environ.get("GITHUB_ACTIONS") == "true":
            escaped = message.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
            print(f"::error title=SDK contract requires review::{escaped}", file=sys.stderr)
        print(f"SDK contract check failed: {message}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
