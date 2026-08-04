"""Focused tests for release-time final SDK evidence verification."""

from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

SCRIPT = Path(__file__).with_name("verify-sdk-evidence.py")
SPEC = importlib.util.spec_from_file_location("verify_sdk_evidence", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load final evidence verifier")
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from sdk_artifact import canonical_json  # noqa: E402

COMMIT = "1" * 40


def candidate() -> dict[str, object]:
    return {
        "archive": {"sha256": "2" * 64},
        "contract": {
            "claimedOperationIds": ["get_public_application_config"],
            "claimedSurfaceSha256": "3" * 64,
        },
        "coordinate": {
            "component": "rust",
            "version": "0.0.1",
            "sourceCommit": COMMIT,
            "workflowRunId": "123",
            "workflowRunAttempt": "2",
            "tag": "rust-v0.0.1",
        },
        "corpus": {"schemaVersion": 3, "sha256": "4" * 64},
    }


def options(root: Path, descriptor: Path, manifest: Path) -> SimpleNamespace:
    return SimpleNamespace(
        component="rust",
        descriptor=descriptor,
        manifest=manifest,
        version="0.0.1",
        source_commit=COMMIT,
        workflow_run_id="123",
        workflow_run_attempt="2",
        tag="rust-v0.0.1",
    )


def test_verification_and_mutation(root: Path) -> None:
    descriptor_path = root / "candidate.json"
    descriptor_path.write_bytes(canonical_json({"synthetic": True}))
    value = candidate()
    manifest = {
        "archive": value["archive"],
        "candidateDescriptorSha256": MODULE.sha256_file(descriptor_path),
        "capabilities": [
            {
                "operationId": "get_public_application_config",
                "exactArtifact": "passed",
                "sameServer": "passed",
            }
        ],
        "contract": value["contract"],
        "coordinate": value["coordinate"],
        "corpus": value["corpus"],
        "qualification": {
            "browserMatrix": ["chromium"],
            "exactArtifactMatrix": [{"kind": "rust", "value": "stable"}],
            "faultInjectedOperationIds": [
                "exchange_handoff",
                "refresh_session",
                "logout_application_session",
            ],
            "sameServerAssignments": [
                {
                    "browser": "chromium",
                    "assignments": {
                        "backendCustody": {
                            "application": "backend-app",
                            "project": "backend-project",
                        },
                        "browserDirect": {
                            "application": "browser-app",
                            "project": "browser-project",
                        },
                        "sdks": {
                            "python": {
                                "application": "python-app",
                                "project": "python-project",
                            },
                            "rust": {
                                "application": "rust-app",
                                "project": "rust-project",
                            },
                            "typescript": {
                                "application": "typescript-app",
                                "project": "typescript-project",
                            },
                        },
                    },
                }
            ],
            "sameServerCommit": COMMIT,
        },
        "schemaVersion": 1,
        "status": "passed",
    }
    manifest_path = root / "rust-final-evidence.json"
    manifest_path.write_bytes(canonical_json(manifest))
    with patch.object(MODULE, "validate_descriptor", return_value=value):
        assert len(MODULE.verify(options(root, descriptor_path, manifest_path))) == 64

    def assert_invalid(mutated: dict[str, object], message: str) -> None:
        manifest_path.write_bytes(canonical_json(mutated))
        with patch.object(MODULE, "validate_descriptor", return_value=value):
            try:
                MODULE.verify(options(root, descriptor_path, manifest_path))
            except MODULE.EvidenceVerificationError:
                pass
            else:
                raise AssertionError(message)

    mutated = json.loads(canonical_json(manifest))
    assignments = mutated["qualification"]["sameServerAssignments"][0]["assignments"]["sdks"]
    assignments["rust"]["project"] = assignments["python"]["project"]
    assert_invalid(mutated, "shared Project assignment must fail")

    mutated = json.loads(canonical_json(manifest))
    mutated["qualification"]["faultInjectedOperationIds"].pop()
    assert_invalid(mutated, "incomplete ambiguity evidence must fail")

    mutated = json.loads(canonical_json(manifest))
    mutated["qualification"]["exactArtifactMatrix"] = []
    assert_invalid(mutated, "incomplete final evidence must fail")


def main() -> None:
    with tempfile.TemporaryDirectory() as temporary_directory:
        test_verification_and_mutation(Path(temporary_directory))
    print("SDK final evidence verification tests passed")


if __name__ == "__main__":
    main()
