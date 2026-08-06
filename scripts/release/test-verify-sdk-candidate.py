#!/usr/bin/env python3
"""Tests for release-coordinate verification of immutable SDK candidates."""

from __future__ import annotations

import importlib.util
import io
import json
import sys
import tempfile
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

REPOSITORY_ROOT = Path(__file__).resolve().parent.parent.parent
HELPERS_PATH = REPOSITORY_ROOT / "scripts/test-sdk-artifact.py"
HELPERS_SPEC = importlib.util.spec_from_file_location("sdk_artifact_test_helpers", HELPERS_PATH)
assert HELPERS_SPEC is not None and HELPERS_SPEC.loader is not None
helpers = importlib.util.module_from_spec(HELPERS_SPEC)
HELPERS_SPEC.loader.exec_module(helpers)

VERIFIER_PATH = REPOSITORY_ROOT / "scripts/release/verify-sdk-candidate.py"
VERIFIER_SPEC = importlib.util.spec_from_file_location("verify_sdk_candidate", VERIFIER_PATH)
assert VERIFIER_SPEC is not None and VERIFIER_SPEC.loader is not None
verifier = importlib.util.module_from_spec(VERIFIER_SPEC)
VERIFIER_SPEC.loader.exec_module(verifier)

RELEASE_VERSION = "1.2.3"
TAG = f"typescript-v{RELEASE_VERSION}"


def invoke(archive: Path, descriptor: Path, *overrides: str) -> SimpleNamespace:
    arguments = [
        str(VERIFIER_PATH),
        "--component",
        "typescript",
        "--version",
        RELEASE_VERSION,
        "--source-commit",
        helpers.COMMIT,
        "--workflow-run-id",
        "123",
        "--workflow-run-attempt",
        "2",
        "--build-configuration",
        "typescript-npm-pack-v1",
        "--tag",
        TAG,
        "--descriptor",
        str(descriptor),
        "--archive",
        str(archive),
    ]
    arguments.extend(overrides)
    stdout = io.StringIO()
    stderr = io.StringIO()
    with patch.object(sys, "argv", arguments), redirect_stdout(stdout), redirect_stderr(stderr):
        returncode = verifier.main()
    return SimpleNamespace(
        returncode=returncode,
        stdout=stdout.getvalue(),
        stderr=stderr.getvalue(),
    )


def candidate(root: Path) -> tuple[Path, Path]:
    surface = root / "typescript-artifact-surface.json"
    helpers.typescript_surface_manifest(surface, version=RELEASE_VERSION)
    helpers.sdk_artifact.TYPESCRIPT_ARTIFACT_SURFACE_PATH = surface

    manifest = root / "package.json"
    manifest_document = json.loads(
        (helpers.REPOSITORY_ROOT / "sdks/typescript/package.json").read_text(encoding="utf-8")
    )
    manifest_document["version"] = RELEASE_VERSION
    manifest.write_text(json.dumps(manifest_document, indent=2) + "\n", encoding="utf-8")
    helpers.sdk_artifact.MANIFEST_PATHS["typescript"] = manifest

    archive = root / f"owlauth-client-{RELEASE_VERSION}.tgz"
    provenance = root / "contract.json"
    descriptor = root / "candidate.json"
    helpers.contract(provenance)
    helpers.typescript_archive(archive, version=RELEASE_VERSION)
    options = SimpleNamespace(
        component="typescript",
        archive=archive,
        contract_provenance=provenance,
        output=descriptor,
        source_commit=helpers.COMMIT,
        workflow_run_id="123",
        workflow_run_attempt="2",
        build_configuration=None,
        tag=TAG,
        upload_metadata=None,
    )
    descriptor.write_bytes(helpers.canonical_json(helpers.build_descriptor(options)))
    return archive, descriptor


def test_exact_candidate_and_coordinate_mutations(root: Path) -> None:
    archive, descriptor = candidate(root)
    valid = invoke(archive, descriptor)
    assert valid.returncode == 0, valid.stderr
    assert len(valid.stdout.strip()) == 64

    mutations = (
        ("--component", "python"),
        ("--version", "9.9.9"),
        ("--source-commit", "9" * 40),
        ("--workflow-run-id", "999"),
        ("--workflow-run-attempt", "9"),
        ("--build-configuration", "other-build"),
        ("--tag", "typescript-v9.9.9"),
    )
    for flag, value in mutations:
        result = invoke(archive, descriptor, flag, value)
        assert result.returncode != 0, (flag, result.stdout)

    archive.write_bytes(archive.read_bytes() + b"changed")
    assert invoke(archive, descriptor).returncode != 0
    assert invoke(root / "missing.tgz", descriptor).returncode != 0
    assert invoke(archive, root / "missing.json").returncode != 0


def main() -> None:
    with tempfile.TemporaryDirectory() as temporary_directory:
        test_exact_candidate_and_coordinate_mutations(Path(temporary_directory))
    print("SDK release candidate verifier tests passed")


if __name__ == "__main__":
    main()
