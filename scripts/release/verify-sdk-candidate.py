#!/usr/bin/env python3
"""Verify that a downloaded SDK candidate exactly matches a release coordinate."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from types import SimpleNamespace

SCRIPTS_DIRECTORY = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(SCRIPTS_DIRECTORY))

from sdk_artifact import ArtifactError, verify_candidate  # noqa: E402


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--component", choices=("typescript", "python", "rust"), required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--workflow-run-id", required=True)
    parser.add_argument("--workflow-run-attempt", required=True)
    parser.add_argument("--build-configuration", required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--descriptor", type=Path, required=True)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--upload-metadata", type=Path)
    parser.add_argument("--distribution-directory", type=Path)
    return parser.parse_args()


def main() -> int:
    options = parse_arguments()
    verification = SimpleNamespace(
        descriptor=options.descriptor,
        archive=options.archive,
        component=options.component,
        version=options.version,
        source_commit=options.source_commit,
        workflow_run_id=options.workflow_run_id,
        workflow_run_attempt=options.workflow_run_attempt,
        build_configuration=options.build_configuration,
        tag=options.tag,
        upload_metadata=options.upload_metadata,
        distribution_directory=options.distribution_directory,
    )
    try:
        descriptor = verify_candidate(verification)
    except (ArtifactError, OSError, UnicodeError, ValueError) as error:
        print(f"SDK release candidate verification failed: {error}", file=sys.stderr)
        return 1
    print(descriptor["archive"]["sha256"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
