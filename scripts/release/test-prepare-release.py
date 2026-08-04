#!/usr/bin/env python3
"""Tests for deterministic release version preparation."""

from __future__ import annotations

import json
import os
import re
import shutil
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

SCRIPT_DIRECTORY = Path(__file__).resolve().parent
REPOSITORY_ROOT = SCRIPT_DIRECTORY.parent.parent
sys.path.insert(0, str(SCRIPT_DIRECTORY))

from prepare_release import PrepareError, prepare_release, release_from_environment  # noqa: E402

FILES = (
    "Cargo.lock",
    "uv.lock",
    "crates/owlauth-cli/Cargo.toml",
    "crates/owlauth-server/Cargo.toml",
    "crates/owlauth-types/Cargo.toml",
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


def toml_version(path: Path, section: str) -> str:
    text = path.read_text(encoding="utf-8")
    match = re.search(
        rf"^\[{re.escape(section)}\]$(.*?)(?=^\[|\Z)",
        text,
        flags=re.MULTILINE | re.DOTALL,
    )
    assert match is not None
    version = re.search(r'^version = "([^"]+)"$', match.group(1), flags=re.MULTILINE)
    assert version is not None
    return version.group(1)


def locked_version(path: Path, package: str) -> str:
    text = path.read_text(encoding="utf-8")
    match = re.search(
        rf'^\[\[package\]\]\nname = "{re.escape(package)}"\nversion = "([^"]+)"$',
        text,
        flags=re.MULTILINE,
    )
    assert match is not None
    return match.group(1)


def test_components(root: Path) -> None:
    prepare_release("server", "1.2.3", root)
    assert toml_version(root / "crates/owlauth-server/Cargo.toml", "package") == "1.2.3"
    assert toml_version(root / "crates/owlauth-types/Cargo.toml", "package") == "1.2.3"
    assert 'owlauth-types = { version = "=1.2.3"' in (
        root / "crates/owlauth-server/Cargo.toml"
    ).read_text(encoding="utf-8")
    assert locked_version(root / "Cargo.lock", "owlauth-server") == "1.2.3"
    assert locked_version(root / "Cargo.lock", "owlauth-types") == "1.2.3"

    prepare_release("cli", "2.3.4-beta.1+build.5", root)
    assert toml_version(root / "crates/owlauth-cli/Cargo.toml", "package") == "2.3.4-beta.1+build.5"
    assert locked_version(root / "Cargo.lock", "owlauth-cli") == "2.3.4-beta.1+build.5"

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


def test_invalid_version(root: Path) -> None:
    try:
        prepare_release("cli", "01.2.3", root)
    except PrepareError:
        return
    raise AssertionError("invalid SemVer must fail")


def test_python_rejects_normalized_version(root: Path) -> None:
    try:
        prepare_release("python", "1.0.0-alpha.1", root)
    except PrepareError:
        return
    raise AssertionError("Python release versions that PEP 440 normalizes must fail")


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


def main() -> None:
    with tempfile.TemporaryDirectory() as temporary_directory:
        root = Path(temporary_directory)
        copy_release_files(root)
        test_components(root)
    with tempfile.TemporaryDirectory() as temporary_directory:
        root = Path(temporary_directory)
        copy_release_files(root)
        test_invalid_version(root)
        test_python_rejects_normalized_version(root)
    test_environment_detection()
    print("release preparation tests passed")


if __name__ == "__main__":
    main()
