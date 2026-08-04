#!/usr/bin/env python3
"""Aggregate digest-bound SDK qualification and same-server evidence."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

from sdk_artifact import canonical_json, load_json, sha256_file, validate_descriptor

COMPONENT_MATRICES = {
    "typescript": {("node", value) for value in ("20", "22", "24")}
    | {("browser-bundle", "vite-8.1.5")},
    "python": {("python", value) for value in ("3.11", "3.12", "3.13", "3.14")},
    "rust": {("rust", "stable")},
}
BROWSERS = {"chromium", "firefox"}
SAME_SERVER_COMPONENTS = {
    "chromium": set(COMPONENT_MATRICES),
    "firefox": {"typescript"},
}
FAULT_INJECTED_OPERATION_IDS = [
    "exchange_handoff",
    "refresh_session",
    "logout_application_session",
]
SHA256 = re.compile(r"^[0-9a-f]{64}$")


class EvidenceError(RuntimeError):
    """Raised when qualification evidence is incomplete or inconsistent."""


def exact_object(value: object, fields: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise EvidenceError(f"{label} has invalid fields")
    return value


def descriptor(path: Path) -> dict[str, Any]:
    raw = path.read_bytes()
    value = load_json(path)
    if raw != canonical_json(value):
        raise EvidenceError(f"candidate descriptor is not canonical: {path}")
    return dict(validate_descriptor(value))


def qualification_results(
    root: Path, descriptors: dict[str, tuple[Path, dict[str, Any]]]
) -> dict[str, set[tuple[str, str]]]:
    observed = {component: set() for component in COMPONENT_MATRICES}
    paths = sorted(root.glob("**/result.json"))
    if not paths:
        raise EvidenceError("no exact-artifact result fragments were found")
    for path in paths:
        result = exact_object(
            load_json(path),
            {
                "schemaVersion",
                "candidateDescriptorSha256",
                "archiveSha256",
                "component",
                "version",
                "matrix",
                "status",
                "workflowRunId",
                "workflowRunAttempt",
            },
            "qualification result",
        )
        component = result["component"]
        if component not in descriptors:
            raise EvidenceError("qualification result has an unsupported component")
        descriptor_path, candidate = descriptors[component]
        coordinate = candidate["coordinate"]
        matrix = exact_object(result["matrix"], {"kind", "value"}, "result matrix")
        identity = (matrix["kind"], matrix["value"])
        if (
            result["schemaVersion"] != 1
            or result["status"] != "passed"
            or result["candidateDescriptorSha256"] != sha256_file(descriptor_path)
            or result["archiveSha256"] != candidate["archive"]["sha256"]
            or result["version"] != coordinate["version"]
            or result["workflowRunId"] != coordinate["workflowRunId"]
            or result["workflowRunAttempt"] != coordinate["workflowRunAttempt"]
            or identity not in COMPONENT_MATRICES[component]
            or identity in observed[component]
        ):
            raise EvidenceError(f"qualification result is inconsistent: {path}")
        observed[component].add(identity)
    for component, required in COMPONENT_MATRICES.items():
        if observed[component] != required:
            raise EvidenceError(f"{component} exact-artifact matrix is incomplete")
    return observed


def browser_results(
    root: Path, descriptors: dict[str, tuple[Path, dict[str, Any]]]
) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    seen: set[str] = set()
    for path in sorted(root.glob("project-auth-*.json")):
        value = exact_object(
            load_json(path),
            {
                "assignments",
                "browser",
                "candidates",
                "evidence",
                "schemaVersion",
                "serverCommit",
                "status",
            },
            "same-server result",
        )
        browser = value["browser"]
        if browser not in BROWSERS or browser in seen:
            raise EvidenceError("same-server browser matrix is invalid")
        seen.add(browser)
        if value["schemaVersion"] != 1 or value["status"] != "passed":
            raise EvidenceError("same-server result did not pass")
        candidates = exact_object(value["candidates"], set(descriptors), "same-server candidates")
        for component, (_, candidate) in descriptors.items():
            identity = exact_object(
                candidates[component], {"sha256", "version"}, "same-server candidate"
            )
            if (
                identity["sha256"] != candidate["archive"]["sha256"]
                or identity["version"] != candidate["coordinate"]["version"]
                or value["serverCommit"] != candidate["coordinate"]["sourceCommit"]
            ):
                raise EvidenceError("same-server candidate identity differs")
        expected_components = SAME_SERVER_COMPONENTS[browser]
        assignments = exact_object(
            value["assignments"],
            {"backendCustody", "browserDirect", "sdks"},
            "same-server assignments",
        )
        sdk_assignments = exact_object(
            assignments["sdks"], expected_components, "same-server SDK assignments"
        )
        project_ids: list[str] = []
        application_ids: list[str] = []
        for label, raw_assignment in {
            "backendCustody": assignments["backendCustody"],
            "browserDirect": assignments["browserDirect"],
            **sdk_assignments,
        }.items():
            assignment = exact_object(
                raw_assignment, {"application", "project"}, f"{label} assignment"
            )
            if not all(
                isinstance(assignment[field], str) and assignment[field] for field in assignment
            ):
                raise EvidenceError("same-server assignment identity is malformed")
            project_ids.append(assignment["project"])
            application_ids.append(assignment["application"])
        if len(set(project_ids)) != len(project_ids) or len(set(application_ids)) != len(
            application_ids
        ):
            raise EvidenceError("same-server Project/Application assignments are not isolated")
        evidence = exact_object(
            value["evidence"],
            {
                "exactArtifacts",
                "faultInjectedOperationIds",
                "observedOperationIds",
                "sharedRuntime",
            },
            "same-server evidence",
        )
        if evidence["exactArtifacts"] is not True or evidence["sharedRuntime"] is not True:
            raise EvidenceError("same-server result does not prove exact shared artifacts")
        observed_operations = exact_object(
            evidence["observedOperationIds"],
            expected_components,
            "same-server observed operations",
        )
        fault_operations = exact_object(
            evidence["faultInjectedOperationIds"],
            expected_components,
            "same-server fault operations",
        )
        for component in expected_components:
            claimed = descriptors[component][1]["contract"]["claimedOperationIds"]
            observed = observed_operations[component]
            if (
                not isinstance(observed, list)
                or not all(isinstance(operation, str) for operation in observed)
                or len(set(observed)) != len(observed)
                or set(observed) != set(claimed)
            ):
                raise EvidenceError("same-server operation coverage differs from the candidate")
            faults = fault_operations[component]
            if (
                not isinstance(faults, list)
                or not all(isinstance(operation, str) for operation in faults)
                or len(set(faults)) != len(faults)
                or set(faults) != set(FAULT_INJECTED_OPERATION_IDS)
            ):
                raise EvidenceError("same-server fault coverage is incomplete")
        results.append(value)
    if seen != BROWSERS:
        raise EvidenceError("same-server browser evidence is incomplete")
    return results


def aggregate(options: argparse.Namespace) -> None:
    paths = {
        "typescript": options.typescript_descriptor,
        "python": options.python_descriptor,
        "rust": options.rust_descriptor,
    }
    descriptors = {component: (path, descriptor(path)) for component, path in paths.items()}
    coordinates = [candidate["coordinate"] for _, candidate in descriptors.values()]
    commits = {coordinate["sourceCommit"] for coordinate in coordinates}
    runs = {
        (coordinate["workflowRunId"], coordinate["workflowRunAttempt"])
        for coordinate in coordinates
    }
    contracts = {
        (
            candidate["contract"]["fullRuntimeSha256"],
            candidate["contract"]["claimedSurfaceSha256"],
            candidate["contract"]["policySha256"],
        )
        for _, candidate in descriptors.values()
    }
    corpora = {
        (candidate["corpus"]["schemaVersion"], candidate["corpus"]["sha256"])
        for _, candidate in descriptors.values()
    }
    if len(commits) != 1 or len(runs) != 1 or len(contracts) != 1 or len(corpora) != 1:
        raise EvidenceError("SDK candidates do not share one source/run/contract/corpus coordinate")
    matrices = qualification_results(options.results_directory, descriptors)
    browsers = browser_results(options.e2e_directory, descriptors)
    options.output_directory.mkdir(parents=True, exist_ok=True)
    summaries: list[str] = []
    for component, (descriptor_path, candidate) in descriptors.items():
        claimed = candidate["contract"]["claimedOperationIds"]
        component_browsers = [
            result for result in browsers if component in result["evidence"]["observedOperationIds"]
        ]
        manifest = {
            "archive": candidate["archive"],
            "candidateDescriptorSha256": sha256_file(descriptor_path),
            "capabilities": [
                {
                    "operationId": operation,
                    "exactArtifact": "passed",
                    "sameServer": "passed",
                }
                for operation in claimed
            ],
            "contract": candidate["contract"],
            "coordinate": candidate["coordinate"],
            "corpus": candidate["corpus"],
            "qualification": {
                "browserMatrix": [result["browser"] for result in component_browsers],
                "exactArtifactMatrix": [
                    {"kind": kind, "value": value} for kind, value in sorted(matrices[component])
                ],
                "faultInjectedOperationIds": FAULT_INJECTED_OPERATION_IDS,
                "sameServerAssignments": [
                    {"browser": result["browser"], "assignments": result["assignments"]}
                    for result in component_browsers
                ],
                "sameServerCommit": next(iter(commits)),
            },
            "schemaVersion": 1,
            "status": "passed",
        }
        output = options.output_directory / f"{component}-final-evidence.json"
        output.write_bytes(canonical_json(manifest))
        version = candidate["coordinate"]["version"]
        archive_sha = candidate["archive"]["sha256"]
        surface_sha = candidate["contract"]["claimedSurfaceSha256"]
        summaries.append(
            f"- {component} {version}: archive `{archive_sha}`, claimed surface `{surface_sha}`"
        )
    (options.output_directory / "summary.md").write_text(
        "## SDK compatibility evidence\n\n"
        "Exact candidate archives passed their declared runtime matrices and one shared-server "
        "Project Auth topology at the source commit recorded in each manifest. This is exact "
        "commit evidence, not a broad server compatibility range.\n\n"
        + "\n".join(summaries)
        + "\n",
        encoding="utf-8",
    )


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--typescript-descriptor", type=Path, required=True)
    parser.add_argument("--python-descriptor", type=Path, required=True)
    parser.add_argument("--rust-descriptor", type=Path, required=True)
    parser.add_argument("--results-directory", type=Path, required=True)
    parser.add_argument("--e2e-directory", type=Path, required=True)
    parser.add_argument("--output-directory", type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    try:
        aggregate(parse_arguments())
    except (EvidenceError, OSError, ValueError, json.JSONDecodeError) as error:
        print(f"SDK evidence error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
