#!/usr/bin/env python3
"""Apply a release tag version to component manifests and lockfiles."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path

TAG_PREFIXES = {
    "server": "server-v",
    "cli": "cli-v",
    "typescript": "typescript-v",
    "python": "python-v",
    "rust": "rust-v",
}

NUMERIC_IDENTIFIER = r"(?:0|[1-9][0-9]*)"
PRERELEASE_IDENTIFIER = r"(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)"
SEMVER_PATTERN = re.compile(
    rf"^{NUMERIC_IDENTIFIER}\.{NUMERIC_IDENTIFIER}\.{NUMERIC_IDENTIFIER}"
    rf"(?:-{PRERELEASE_IDENTIFIER}(?:\.{PRERELEASE_IDENTIFIER})*)?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$"
)


class PrepareError(RuntimeError):
    """Raised when release metadata cannot be updated safely."""


def replace_once(path: Path, pattern: str, replacement: str) -> None:
    text = path.read_text(encoding="utf-8")
    updated, count = re.subn(pattern, replacement, text, count=1, flags=re.MULTILINE)
    if count != 1:
        raise PrepareError(f"expected exactly one version field in {path}")
    path.write_text(updated, encoding="utf-8")


def set_toml_version(path: Path, section: str, version: str) -> None:
    escaped = re.escape(section)
    pattern = rf'(\[{escaped}\]\n(?:(?!\[).*(?:\n|$))*?^version = ")[^"]+("$)'
    replace_once(path, pattern, rf"\g<1>{version}\g<2>")


def set_locked_package_version(path: Path, package: str, version: str) -> None:
    escaped = re.escape(package)
    pattern = rf'(\[\[package\]\]\nname = "{escaped}"\nversion = ")[^"]+("$)'
    replace_once(path, pattern, rf"\g<1>{version}\g<2>")


def set_json_version(path: Path, version: str) -> None:
    document = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(document, dict) or not isinstance(document.get("version"), str):
        raise PrepareError(f"missing string version field in {path}")
    document["version"] = version
    path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")


def prepare_release(component: str, version: str, root: Path = Path(".")) -> None:
    if component not in TAG_PREFIXES:
        raise PrepareError(f"unsupported release component: {component}")
    if not SEMVER_PATTERN.fullmatch(version):
        raise PrepareError(f"invalid release SemVer: {version}")

    if component == "server":
        set_toml_version(root / "crates/owlauth-types/Cargo.toml", "package", version)
        set_toml_version(root / "crates/owlauth-server/Cargo.toml", "package", version)
        replace_once(
            root / "crates/owlauth-server/Cargo.toml",
            r'(owlauth-types = \{ version = "=)[^"]+("[^\n]*$)',
            rf"\g<1>{version}\g<2>",
        )
        set_locked_package_version(root / "Cargo.lock", "owlauth-types", version)
        set_locked_package_version(root / "Cargo.lock", "owlauth-server", version)
    elif component == "cli":
        set_toml_version(root / "crates/owlauth-cli/Cargo.toml", "package", version)
        set_locked_package_version(root / "Cargo.lock", "owlauth-cli", version)
    elif component == "typescript":
        set_json_version(root / "sdks/typescript/package.json", version)
    elif component == "python":
        set_toml_version(root / "sdks/python/pyproject.toml", "project", version)
        set_locked_package_version(root / "uv.lock", "owlauth-client", version)
        replace_once(
            root / "sdks/python/src/owlauth/__init__.py",
            r'^__version__ = "[^"]+"$',
            f'__version__ = "{version}"',
        )
    elif component == "rust":
        set_toml_version(root / "sdks/rust/Cargo.toml", "package", version)
        set_locked_package_version(root / "Cargo.lock", "owlauth-client", version)


def release_from_environment() -> tuple[str, str] | None:
    if os.environ.get("GITHUB_REF_TYPE") != "tag":
        return None
    ref_name = os.environ.get("GITHUB_REF_NAME", "")
    for component, prefix in TAG_PREFIXES.items():
        if ref_name.startswith(prefix):
            return component, ref_name.removeprefix(prefix)
    return None


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("component", nargs="?", choices=TAG_PREFIXES)
    parser.add_argument("version", nargs="?")
    args = parser.parse_args()

    if (args.component is None) != (args.version is None):
        parser.error("component and version must be provided together")

    release = (
        (args.component, args.version)
        if args.component is not None and args.version is not None
        else release_from_environment()
    )
    if release is None:
        print("no release tag detected; manifests unchanged")
        return 0

    component, version = release
    try:
        prepare_release(component, version)
    except PrepareError as error:
        print(f"release preparation failed: {error}", file=sys.stderr)
        return 1
    print(f"prepared {component} manifests for {version}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
