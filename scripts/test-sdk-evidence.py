"""Focused tests for final SDK evidence aggregation."""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

SCRIPT_DIRECTORY = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIRECTORY))

from sdk_artifact import canonical_json, sha256_file  # noqa: E402
from sdk_evidence import (  # noqa: E402
    COMPONENT_MATRICES,
    FAULT_INJECTED_OPERATION_IDS,
    EvidenceError,
    aggregate,
)

COMMIT = "1" * 40
RUN_ID = "123"
ATTEMPT = "2"


def candidate(component: str) -> dict[str, object]:
    version = "0.0.1"
    return {
        "archive": {
            "fileName": f"{component}.archive",
            "sha256": ("2" if component == "typescript" else "3" if component == "python" else "4")
            * 64,
            "size": 10,
            "packageName": "owlauth-client",
            "runtimeVersion": version,
            "fileCount": 1,
        },
        "contract": {
            "fullRuntimeSha256": "5" * 64,
            "claimedSurfaceSha256": "6" * 64,
            "policySha256": "7" * 64,
            "claimedOperationIds": ["get_public_application_config", "get_project_jwks"],
        },
        "coordinate": {
            "sourceCommit": COMMIT,
            "component": component,
            "version": version,
            "tag": None,
            "buildConfiguration": f"{component}-build",
            "workflowRunId": RUN_ID,
            "workflowRunAttempt": ATTEMPT,
        },
        "corpus": {"schemaVersion": 3, "sha256": "8" * 64, "requiredCaseCount": 1},
    }


def write_inputs(root: Path) -> tuple[SimpleNamespace, dict[str, dict[str, object]]]:
    descriptors: dict[str, Path] = {}
    candidates = {component: candidate(component) for component in COMPONENT_MATRICES}
    for component in candidates:
        path = root / f"{component}-candidate.json"
        path.write_bytes(canonical_json({"component": component}))
        descriptors[component] = path
    results = root / "results"
    for component, matrices in COMPONENT_MATRICES.items():
        for index, (kind, value) in enumerate(sorted(matrices)):
            directory = results / f"{component}-{index}"
            directory.mkdir(parents=True)
            document = {
                "schemaVersion": 1,
                "candidateDescriptorSha256": sha256_file(descriptors[component]),
                "archiveSha256": candidates[component]["archive"]["sha256"],  # type: ignore[index]
                "component": component,
                "version": "0.0.1",
                "matrix": {"kind": kind, "value": value},
                "status": "passed",
                "workflowRunId": RUN_ID,
                "workflowRunAttempt": ATTEMPT,
            }
            (directory / "result.json").write_bytes(canonical_json(document))
    e2e = root / "e2e"
    e2e.mkdir()
    identities = {
        component: {
            "sha256": value["archive"]["sha256"],  # type: ignore[index]
            "version": "0.0.1",
        }
        for component, value in candidates.items()
    }
    for browser in ("chromium", "firefox"):
        sdks = ["typescript"] if browser == "firefox" else sorted(candidates)
        assignment = lambda name: {  # noqa: E731
            "application": f"app-{browser}-{name}",
            "project": f"project-{browser}-{name}",
        }
        document = {
            "assignments": {
                "backendCustody": assignment("backend"),
                "browserDirect": assignment("browser"),
                "sdks": {sdk: assignment(sdk) for sdk in sdks},
            },
            "browser": browser,
            "candidates": identities,
            "evidence": {
                "exactArtifacts": True,
                "faultInjectedOperationIds": {sdk: FAULT_INJECTED_OPERATION_IDS for sdk in sdks},
                "observedOperationIds": {
                    sdk: candidates[sdk]["contract"]["claimedOperationIds"]  # type: ignore[index]
                    for sdk in sdks
                },
                "sharedRuntime": True,
            },
            "schemaVersion": 1,
            "serverCommit": COMMIT,
            "status": "passed",
        }
        (e2e / f"project-auth-{browser}.json").write_bytes(canonical_json(document))
    return (
        SimpleNamespace(
            typescript_descriptor=descriptors["typescript"],
            python_descriptor=descriptors["python"],
            rust_descriptor=descriptors["rust"],
            results_directory=results,
            e2e_directory=e2e,
            output_directory=root / "output",
        ),
        candidates,
    )


def test_aggregate_and_missing_matrix(root: Path) -> None:
    options, candidates = write_inputs(root)
    with patch(
        "sdk_evidence.descriptor", side_effect=lambda path: candidates[path.name.split("-")[0]]
    ):
        aggregate(options)
    for component in COMPONENT_MATRICES:
        manifest = json.loads(
            (options.output_directory / f"{component}-final-evidence.json").read_text()
        )
        assert manifest["status"] == "passed"
        assert manifest["qualification"]["sameServerCommit"] == COMMIT
        assert len(manifest["qualification"]["sameServerAssignments"]) == (
            2 if component == "typescript" else 1
        )
    assert (options.output_directory / "summary.md").is_file()

    chromium_path = options.e2e_directory / "project-auth-chromium.json"
    chromium = json.loads(chromium_path.read_text())
    rust_project = chromium["assignments"]["sdks"]["rust"]["project"]
    chromium["assignments"]["sdks"]["rust"]["project"] = chromium["assignments"]["sdks"]["python"][
        "project"
    ]
    chromium_path.write_bytes(canonical_json(chromium))
    with patch(
        "sdk_evidence.descriptor", side_effect=lambda path: candidates[path.name.split("-")[0]]
    ):
        try:
            aggregate(options)
        except EvidenceError:
            pass
        else:
            raise AssertionError("shared SDK Project assignment must fail")
    chromium["assignments"]["sdks"]["rust"]["project"] = rust_project

    chromium["evidence"]["observedOperationIds"]["python"].pop()
    chromium_path.write_bytes(canonical_json(chromium))
    with patch(
        "sdk_evidence.descriptor", side_effect=lambda path: candidates[path.name.split("-")[0]]
    ):
        try:
            aggregate(options)
        except EvidenceError:
            pass
        else:
            raise AssertionError("incomplete same-server operation evidence must fail")
    chromium["evidence"]["observedOperationIds"]["python"] = candidates["python"]["contract"][
        "claimedOperationIds"
    ]
    chromium_path.write_bytes(canonical_json(chromium))

    next(options.results_directory.glob("typescript-*/result.json")).unlink()
    with patch(
        "sdk_evidence.descriptor", side_effect=lambda path: candidates[path.name.split("-")[0]]
    ):
        try:
            aggregate(options)
        except EvidenceError:
            pass
        else:
            raise AssertionError("an incomplete exact-artifact matrix must fail")


def main() -> None:
    with tempfile.TemporaryDirectory() as temporary_directory:
        test_aggregate_and_missing_matrix(Path(temporary_directory))
    print("SDK evidence tests passed")


if __name__ == "__main__":
    main()
