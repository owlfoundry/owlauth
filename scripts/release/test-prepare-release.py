#!/usr/bin/env python3
"""Tests for deterministic development and release version preparation."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

SCRIPT_DIRECTORY = Path(__file__).resolve().parent
REPOSITORY_ROOT = SCRIPT_DIRECTORY.parent.parent
sys.path.insert(0, str(SCRIPT_DIRECTORY))

from prepare_release import (  # noqa: E402
    CARGO_DEVELOPMENT_VERSION,
    NPM_DEVELOPMENT_VERSION,
    PYTHON_DEVELOPMENT_VERSION,
    PrepareError,
    prepare_release,
    release_from_environment,
    validate_development_state,
    validate_prepared_release_state,
)

FILES = (
    "Cargo.lock",
    "uv.lock",
    "crates/owlauth-cli/Cargo.toml",
    "crates/owlauth-key-provider/Cargo.toml",
    "crates/owlauth-server/Cargo.toml",
    "crates/owlauth-server/web/package.json",
    "crates/owlauth-types/Cargo.toml",
    "docs/package.json",
    "sdks/python/pyproject.toml",
    "sdks/python/src/owlauth/__init__.py",
    "sdks/rust/Cargo.toml",
    "sdks/typescript/package.json",
    "sdks/typescript/src/index.ts",
)


def copy_release_files(destination: Path) -> None:
    for relative in FILES:
        source = REPOSITORY_ROOT / relative
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)


def snapshot(root: Path) -> dict[str, bytes]:
    return {relative: (root / relative).read_bytes() for relative in FILES}


def changed_files(before: dict[str, bytes], after: dict[str, bytes]) -> set[str]:
    return {relative for relative in FILES if before[relative] != after[relative]}


def toml_version(path: Path, section: str) -> str:
    text = path.read_text(encoding="utf-8")
    match = re.search(
        rf"^\[{re.escape(section)}\]$(.*?)(?=^\[|\Z)",
        text,
        flags=re.MULTILINE | re.DOTALL,
    )
    assert match is not None
    versions = re.findall(r'^version = "([^"]+)"$', match.group(1), flags=re.MULTILINE)
    assert len(versions) == 1
    return versions[0]


def locked_version(path: Path, package: str) -> str:
    text = path.read_text(encoding="utf-8")
    matches = re.findall(
        rf'^\[\[package\]\]\nname = "{re.escape(package)}"\nversion = "([^"]+)"$',
        text,
        flags=re.MULTILINE,
    )
    assert len(matches) == 1
    return matches[0]


def assert_prepare_error(function: object) -> None:
    try:
        function()  # type: ignore[operator]
    except PrepareError:
        return
    raise AssertionError("release preparation must fail")


def test_development_state(root: Path) -> None:
    validate_development_state(root)
    assert (
        toml_version(root / "crates/owlauth-server/Cargo.toml", "package")
        == CARGO_DEVELOPMENT_VERSION
    )
    assert (
        toml_version(root / "sdks/python/pyproject.toml", "project") == PYTHON_DEVELOPMENT_VERSION
    )
    package = json.loads((root / "sdks/typescript/package.json").read_text(encoding="utf-8"))
    assert package["version"] == NPM_DEVELOPMENT_VERSION


def test_server(root: Path) -> None:
    before = snapshot(root)
    prepare_release("server", "1.2.3-beta.1+build.5", root)
    version = "1.2.3-beta.1+build.5"
    assert toml_version(root / "crates/owlauth-key-provider/Cargo.toml", "package") == version
    assert toml_version(root / "crates/owlauth-types/Cargo.toml", "package") == version
    assert toml_version(root / "crates/owlauth-server/Cargo.toml", "package") == version
    assert (
        toml_version(root / "crates/owlauth-cli/Cargo.toml", "package") == CARGO_DEVELOPMENT_VERSION
    )
    server = (root / "crates/owlauth-server/Cargo.toml").read_text(encoding="utf-8")
    cli = (root / "crates/owlauth-cli/Cargo.toml").read_text(encoding="utf-8")
    assert f'owlauth-key-provider = {{ version = "={version}"' in server
    assert f'owlauth-types = {{ version = "={version}"' in server
    assert f'owlauth-types = {{ version = "={version}"' in cli
    for package in ("owlauth-key-provider", "owlauth-types", "owlauth-server"):
        assert locked_version(root / "Cargo.lock", package) == version
    assert changed_files(before, snapshot(root)) == {
        "Cargo.lock",
        "crates/owlauth-cli/Cargo.toml",
        "crates/owlauth-key-provider/Cargo.toml",
        "crates/owlauth-server/Cargo.toml",
        "crates/owlauth-types/Cargo.toml",
    }
    validate_prepared_release_state("server", version, root)
    prepared = snapshot(root)
    prepare_release("server", version, root)
    assert snapshot(root) == prepared


def test_cli(root: Path) -> None:
    before = snapshot(root)
    prepare_release("cli", "2.3.4", root)
    assert toml_version(root / "crates/owlauth-cli/Cargo.toml", "package") == "2.3.4"
    assert toml_version(root / "crates/owlauth-types/Cargo.toml", "package") == "2.3.4"
    assert (
        toml_version(root / "crates/owlauth-server/Cargo.toml", "package")
        == CARGO_DEVELOPMENT_VERSION
    )
    assert 'owlauth-types = { version = "=2.3.4"' in (
        root / "crates/owlauth-cli/Cargo.toml"
    ).read_text(encoding="utf-8")
    assert 'owlauth-types = { version = "=2.3.4"' in (
        root / "crates/owlauth-server/Cargo.toml"
    ).read_text(encoding="utf-8")
    assert locked_version(root / "Cargo.lock", "owlauth-cli") == "2.3.4"
    assert locked_version(root / "Cargo.lock", "owlauth-types") == "2.3.4"
    assert changed_files(before, snapshot(root)) == {
        "Cargo.lock",
        "crates/owlauth-cli/Cargo.toml",
        "crates/owlauth-server/Cargo.toml",
        "crates/owlauth-types/Cargo.toml",
    }
    validate_prepared_release_state("cli", "2.3.4", root)
    prepared = snapshot(root)
    prepare_release("cli", "2.3.4", root)
    assert snapshot(root) == prepared


def test_sdks(root: Path) -> None:
    prepare_release("typescript", "3.4.5", root)
    package = json.loads((root / "sdks/typescript/package.json").read_text(encoding="utf-8"))
    assert package["version"] == "3.4.5"
    assert 'export const VERSION = "3.4.5";' in (root / "sdks/typescript/src/index.ts").read_text(
        encoding="utf-8"
    )

    prepare_release("python", "4.5.6", root)
    assert toml_version(root / "sdks/python/pyproject.toml", "project") == "4.5.6"
    assert locked_version(root / "uv.lock", "owlauth-client") == "4.5.6"
    assert '__version__ = "4.5.6"' in (root / "sdks/python/src/owlauth/__init__.py").read_text(
        encoding="utf-8"
    )

    prepare_release("rust", "5.6.7", root)
    assert toml_version(root / "sdks/rust/Cargo.toml", "package") == "5.6.7"
    assert locked_version(root / "Cargo.lock", "owlauth-client") == "5.6.7"
    # This root contains three different prepared SDK states, so each state is
    # validated independently in fresh roots by the entrypoint test below.


def test_invalid_versions(root: Path) -> None:
    assert_prepare_error(lambda: prepare_release("cli", "01.2.3", root))
    assert_prepare_error(lambda: prepare_release("cli", CARGO_DEVELOPMENT_VERSION, root))
    assert_prepare_error(lambda: prepare_release("typescript", NPM_DEVELOPMENT_VERSION, root))
    assert_prepare_error(lambda: prepare_release("python", "1.0.0-alpha.1", root))


def test_missing_and_duplicate_fields(root: Path) -> None:
    key_provider = root / "crates/owlauth-key-provider/Cargo.toml"
    key_provider.write_text(
        key_provider.read_text(encoding="utf-8").replace(
            f'version = "{CARGO_DEVELOPMENT_VERSION}"',
            f'version = "{CARGO_DEVELOPMENT_VERSION}"\nversion = "9.9.9"',
            1,
        ),
        encoding="utf-8",
    )
    assert_prepare_error(lambda: prepare_release("server", "1.2.3", root))

    copy_release_files(root)
    cli = root / "crates/owlauth-cli/Cargo.toml"
    cli.write_text(
        cli.read_text(encoding="utf-8").replace("owlauth-types =", "missing-types =", 1),
        encoding="utf-8",
    )
    assert_prepare_error(lambda: prepare_release("cli", "1.2.3", root))


def test_entrypoint_is_idempotent_and_rejects_stale_state(root: Path) -> None:
    command = [sys.executable, str(SCRIPT_DIRECTORY / "prepare_release.py"), "cli", "6.7.8"]
    for _ in range(2):
        result = subprocess.run(command, cwd=root, capture_output=True, text=True, check=False)
        assert result.returncode == 0, result.stderr
    validate_prepared_release_state("cli", "6.7.8", root)

    server = root / "crates/owlauth-server/Cargo.toml"
    server.write_text(
        server.read_text(encoding="utf-8").replace(
            f'version = "{CARGO_DEVELOPMENT_VERSION}"', 'version = "9.9.9"', 1
        ),
        encoding="utf-8",
    )
    result = subprocess.run(command, cwd=root, capture_output=True, text=True, check=False)
    assert result.returncode == 1


def test_environment_detection() -> None:
    with patch.dict(
        os.environ,
        {"GITHUB_REF_TYPE": "tag", "GITHUB_REF_NAME": "python-v1.2.3"},
        clear=True,
    ):
        assert release_from_environment() == ("python", "1.2.3")
    with patch.dict(
        os.environ,
        {"GITHUB_REF_TYPE": "branch", "GITHUB_REF_NAME": "main"},
        clear=True,
    ):
        assert release_from_environment() is None


def with_copy(test: object) -> None:
    with tempfile.TemporaryDirectory() as temporary_directory:
        root = Path(temporary_directory)
        copy_release_files(root)
        test(root)  # type: ignore[operator]


def main() -> None:
    for test in (
        test_development_state,
        test_server,
        test_cli,
        test_sdks,
        test_invalid_versions,
        test_missing_and_duplicate_fields,
        test_entrypoint_is_idempotent_and_rejects_stale_state,
    ):
        with_copy(test)
    test_environment_detection()
    print("release preparation tests passed")


if __name__ == "__main__":
    main()
