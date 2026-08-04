#!/usr/bin/env python3
"""Tests for release-coordinate verification of immutable SDK candidates."""

from __future__ import annotations

import importlib.util
import subprocess
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace

REPOSITORY_ROOT = Path(__file__).resolve().parent.parent.parent
HELPERS_PATH = REPOSITORY_ROOT / "scripts/test-sdk-artifact.py"
SPEC = importlib.util.spec_from_file_location("sdk_artifact_test_helpers", HELPERS_PATH)
assert SPEC is not None and SPEC.loader is not None
helpers = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(helpers)

VERIFIER = REPOSITORY_ROOT / "scripts/release/verify-sdk-candidate.py"
TAG = f"typescript-v{helpers.VERSION}"


def invoke(archive: Path, descriptor: Path, *overrides: str) -> subprocess.CompletedProcess[str]:
    arguments = [
        sys.executable,
        str(VERIFIER),
        "--component",
        "typescript",
        "--version",
        helpers.VERSION,
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
    return subprocess.run(arguments, capture_output=True, text=True, check=False)


def candidate(root: Path) -> tuple[Path, Path]:
    archive = root / f"owlauth-client-{helpers.VERSION}.tgz"
    provenance = root / "contract.json"
    descriptor = root / "candidate.json"
    helpers.contract(provenance)
    helpers.typescript_archive(archive)
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
