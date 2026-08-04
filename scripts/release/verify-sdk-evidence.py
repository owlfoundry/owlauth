#!/usr/bin/env python3
"""Verify one final SDK evidence manifest against its immutable candidate descriptor."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sdk_artifact import (  # noqa: E402
    canonical_json,
    load_json,
    sha256_file,
    validate_descriptor,
)

MATRICES = {
    "typescript": {("node", value) for value in ("20", "22", "24")}
    | {("browser-bundle", "vite-8.1.5")},
    "python": {("python", value) for value in ("3.11", "3.12", "3.13", "3.14")},
    "rust": {("rust", "stable")},
}
SAME_SERVER_COMPONENTS = {
    "chromium": set(MATRICES),
    "firefox": {"typescript"},
}
FAULT_INJECTED_OPERATION_IDS = [
    "exchange_handoff",
    "refresh_session",
    "logout_application_session",
]


class EvidenceVerificationError(RuntimeError):
    """Raised when final evidence is not bound to the release candidate."""


def exact(value: object, fields: set[str], label: str) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != fields:
        raise EvidenceVerificationError(f"{label} has invalid fields")
    return value


def verify(options: argparse.Namespace) -> str:
    descriptor_raw = options.descriptor.read_bytes()
    descriptor_value = load_json(options.descriptor)
    if descriptor_raw != canonical_json(descriptor_value):
        raise EvidenceVerificationError("candidate descriptor is not canonical")
    descriptor = validate_descriptor(descriptor_value)
    manifest_raw = options.manifest.read_bytes()
    manifest_value = load_json(options.manifest)
    if manifest_raw != canonical_json(manifest_value):
        raise EvidenceVerificationError("final evidence manifest is not canonical")
    manifest = exact(
        manifest_value,
        {
            "archive",
            "candidateDescriptorSha256",
            "capabilities",
            "contract",
            "coordinate",
            "corpus",
            "qualification",
            "schemaVersion",
            "status",
        },
        "final evidence manifest",
    )
    coordinate = descriptor["coordinate"]
    component = coordinate["component"]
    if component != options.component:
        raise EvidenceVerificationError("final evidence component differs")
    if (
        manifest["schemaVersion"] != 1
        or manifest["status"] != "passed"
        or manifest["candidateDescriptorSha256"] != sha256_file(options.descriptor)
        or manifest["archive"] != descriptor["archive"]
        or manifest["contract"] != descriptor["contract"]
        or manifest["coordinate"] != coordinate
        or manifest["corpus"] != descriptor["corpus"]
    ):
        raise EvidenceVerificationError("final evidence differs from the candidate descriptor")
    expected = {
        "version": options.version,
        "sourceCommit": options.source_commit,
        "workflowRunId": options.workflow_run_id,
        "workflowRunAttempt": options.workflow_run_attempt,
        "tag": options.tag,
    }
    for field, value in expected.items():
        if value is not None and coordinate[field] != value:
            raise EvidenceVerificationError(f"final evidence coordinate {field} differs")
    capabilities = manifest["capabilities"]
    claimed = descriptor["contract"]["claimedOperationIds"]
    if not isinstance(capabilities, list) or capabilities != [
        {"operationId": operation, "exactArtifact": "passed", "sameServer": "passed"}
        for operation in claimed
    ]:
        raise EvidenceVerificationError("final evidence capability coverage is incomplete")
    qualification = exact(
        manifest["qualification"],
        {
            "browserMatrix",
            "exactArtifactMatrix",
            "faultInjectedOperationIds",
            "sameServerAssignments",
            "sameServerCommit",
        },
        "final qualification",
    )
    matrices = qualification["exactArtifactMatrix"]
    if not isinstance(matrices, list):
        raise EvidenceVerificationError("final exact-artifact matrix is malformed")
    observed: set[tuple[object, object]] = set()
    for item in matrices:
        matrix = exact(item, {"kind", "value"}, "final matrix entry")
        observed.add((matrix["kind"], matrix["value"]))
    expected_browsers = ["chromium", "firefox"] if component == "typescript" else ["chromium"]
    same_server_assignments = qualification["sameServerAssignments"]
    if (
        observed != MATRICES[component]
        or qualification["browserMatrix"] != expected_browsers
        or qualification["faultInjectedOperationIds"] != FAULT_INJECTED_OPERATION_IDS
        or qualification["sameServerCommit"] != coordinate["sourceCommit"]
        or not isinstance(same_server_assignments, list)
        or len(same_server_assignments) != len(expected_browsers)
    ):
        raise EvidenceVerificationError("final qualification coverage is incomplete")
    observed_browsers: list[str] = []
    for raw_entry in same_server_assignments:
        entry = exact(raw_entry, {"assignments", "browser"}, "same-server assignment entry")
        browser = entry["browser"]
        if not isinstance(browser, str) or browser not in SAME_SERVER_COMPONENTS:
            raise EvidenceVerificationError("same-server assignment browser is invalid")
        observed_browsers.append(browser)
        assignments = exact(
            entry["assignments"],
            {"backendCustody", "browserDirect", "sdks"},
            "same-server assignments",
        )
        sdk_assignments = exact(
            assignments["sdks"],
            SAME_SERVER_COMPONENTS[browser],
            "same-server SDK assignments",
        )
        if component not in sdk_assignments:
            raise EvidenceVerificationError("component same-server assignment is absent")
        project_ids: list[str] = []
        application_ids: list[str] = []
        for label, raw_assignment in {
            "backendCustody": assignments["backendCustody"],
            "browserDirect": assignments["browserDirect"],
            **sdk_assignments,
        }.items():
            assignment = exact(raw_assignment, {"application", "project"}, f"{label} assignment")
            if not all(isinstance(value, str) and value for value in assignment.values()):
                raise EvidenceVerificationError("same-server assignment identity is malformed")
            project_ids.append(assignment["project"])  # type: ignore[arg-type]
            application_ids.append(assignment["application"])  # type: ignore[arg-type]
        if len(set(project_ids)) != len(project_ids) or len(set(application_ids)) != len(
            application_ids
        ):
            raise EvidenceVerificationError(
                "same-server Project/Application assignments are not isolated"
            )
    if observed_browsers != expected_browsers:
        raise EvidenceVerificationError("same-server assignment browsers differ")
    digest = sha256_file(options.manifest)
    if not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise EvidenceVerificationError("final evidence digest is invalid")
    return digest


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--component", choices=MATRICES, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--descriptor", type=Path, required=True)
    parser.add_argument("--version")
    parser.add_argument("--source-commit")
    parser.add_argument("--workflow-run-id")
    parser.add_argument("--workflow-run-attempt")
    parser.add_argument("--tag")
    return parser.parse_args()


def main() -> int:
    try:
        print(verify(parse_arguments()))
    except (EvidenceVerificationError, OSError, ValueError) as error:
        print(f"SDK evidence verification error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
