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
CARGO_DEVELOPMENT_VERSION = "0.0.0-dev"
NPM_DEVELOPMENT_VERSION = "0.0.0-dev"
PYTHON_DEVELOPMENT_VERSION = "0.0.0.dev0"

NUMERIC_IDENTIFIER = r"(?:0|[1-9][0-9]*)"
PRERELEASE_IDENTIFIER = r"(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)"
SEMVER_PATTERN = re.compile(
    rf"^{NUMERIC_IDENTIFIER}\.{NUMERIC_IDENTIFIER}\.{NUMERIC_IDENTIFIER}"
    rf"(?:-{PRERELEASE_IDENTIFIER}(?:\.{PRERELEASE_IDENTIFIER})*)?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$"
)
STABLE_SEMVER_PATTERN = re.compile(
    rf"^{NUMERIC_IDENTIFIER}\.{NUMERIC_IDENTIFIER}\.{NUMERIC_IDENTIFIER}$"
)


class PrepareError(RuntimeError):
    """Raised when release metadata cannot be updated safely."""


def replace_once(path: Path, pattern: str, replacement: str, *, label: str) -> None:
    text = path.read_text(encoding="utf-8")
    updated, count = re.subn(pattern, replacement, text, flags=re.MULTILINE)
    if count != 1:
        raise PrepareError(f"expected exactly one {label} in {path}, found {count}")
    path.write_text(updated, encoding="utf-8")


def set_toml_version(path: Path, section: str, version: str) -> None:
    text = path.read_text(encoding="utf-8")
    escaped = re.escape(section)
    section_match = re.search(
        rf"^\[{escaped}\]\n(?P<body>.*?)(?=^\[|\Z)",
        text,
        flags=re.MULTILINE | re.DOTALL,
    )
    if section_match is None:
        raise PrepareError(f"missing [{section}] section in {path}")
    body = section_match.group("body")
    updated_body, count = re.subn(
        r'^(version = ")[^"]+("$)',
        rf"\g<1>{version}\g<2>",
        body,
        flags=re.MULTILINE,
    )
    if count != 1:
        raise PrepareError(
            f"expected exactly one version field in [{section}] of {path}, found {count}"
        )
    updated = text[: section_match.start("body")] + updated_body + text[section_match.end("body") :]
    path.write_text(updated, encoding="utf-8")


def set_locked_package_version(path: Path, package: str, version: str) -> None:
    escaped = re.escape(package)
    pattern = rf'(\[\[package\]\]\nname = "{escaped}"\nversion = ")[^"]+("$)'
    replace_once(
        path,
        pattern,
        rf"\g<1>{version}\g<2>",
        label=f"lock entry for {package}",
    )


def set_internal_dependency(path: Path, package: str, version: str) -> None:
    escaped = re.escape(package)
    replace_once(
        path,
        rf'({escaped} = \{{ version = "=)[^"]+("[^\n]*$)',
        rf"\g<1>{version}\g<2>",
        label=f"exact {package} dependency",
    )


def set_json_version(path: Path, version: str) -> None:
    document = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(document, dict) or not isinstance(document.get("version"), str):
        raise PrepareError(f"missing string version field in {path}")
    document["version"] = version
    path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")


def read_toml_version(path: Path, section: str) -> str:
    text = path.read_text(encoding="utf-8")
    match = re.search(
        rf"^\[{re.escape(section)}\]\n(?P<body>.*?)(?=^\[|\Z)",
        text,
        flags=re.MULTILINE | re.DOTALL,
    )
    if match is None:
        raise PrepareError(f"missing [{section}] section in {path}")
    versions = re.findall(r'^version = "([^"]+)"$', match.group("body"), flags=re.MULTILINE)
    if len(versions) != 1:
        raise PrepareError(
            f"expected exactly one version field in [{section}] of {path}, found {len(versions)}"
        )
    return versions[0]


def read_locked_package_version(path: Path, package: str) -> str:
    matches = re.findall(
        rf'^\[\[package\]\]\nname = "{re.escape(package)}"\nversion = "([^"]+)"$',
        path.read_text(encoding="utf-8"),
        flags=re.MULTILINE,
    )
    if len(matches) != 1:
        raise PrepareError(f"expected exactly one lock entry for {package} in {path}")
    return matches[0]


def read_internal_dependency(path: Path, package: str) -> str:
    matches = re.findall(
        rf'^{re.escape(package)} = \{{ version = "=([^"]+)"[^\n]*$',
        path.read_text(encoding="utf-8"),
        flags=re.MULTILINE,
    )
    if len(matches) != 1:
        raise PrepareError(f"expected exactly one exact {package} dependency in {path}")
    return matches[0]


def require_version(actual: object, expected: str, *, label: str) -> None:
    if actual != expected:
        raise PrepareError(f"{label} must use version {expected}, got {actual}")


def release_overrides(component: str, version: str) -> dict[str, str]:
    if component == "server":
        names = (
            "cargo:owlauth-key-provider",
            "cargo:owlauth-server",
            "cargo:owlauth-types",
            "dependency:cli:owlauth-types",
            "dependency:server:owlauth-key-provider",
            "dependency:server:owlauth-types",
            "lock:owlauth-key-provider",
            "lock:owlauth-server",
            "lock:owlauth-types",
        )
    elif component == "cli":
        names = (
            "cargo:owlauth-cli",
            "cargo:owlauth-types",
            "dependency:cli:owlauth-types",
            "dependency:server:owlauth-types",
            "lock:owlauth-cli",
            "lock:owlauth-types",
        )
    elif component == "typescript":
        names = ("typescript",)
    elif component == "python":
        names = ("python",)
    elif component == "rust":
        names = ("cargo:owlauth-client", "lock:owlauth-client")
    else:
        raise PrepareError(f"unsupported release component: {component}")
    return dict.fromkeys(names, version)


def validate_version_state(root: Path = Path("."), overrides: dict[str, str] | None = None) -> None:
    expected = overrides or {}
    cargo_manifests = {
        "owlauth-cli": "crates/owlauth-cli/Cargo.toml",
        "owlauth-key-provider": "crates/owlauth-key-provider/Cargo.toml",
        "owlauth-server": "crates/owlauth-server/Cargo.toml",
        "owlauth-types": "crates/owlauth-types/Cargo.toml",
        "owlauth-client": "sdks/rust/Cargo.toml",
    }
    for package, relative in cargo_manifests.items():
        require_version(
            read_toml_version(root / relative, "package"),
            expected.get(f"cargo:{package}", CARGO_DEVELOPMENT_VERSION),
            label=relative,
        )
        require_version(
            read_locked_package_version(root / "Cargo.lock", package),
            expected.get(f"lock:{package}", CARGO_DEVELOPMENT_VERSION),
            label=f"Cargo.lock {package}",
        )

    dependencies = (
        ("cli", "crates/owlauth-cli/Cargo.toml", "owlauth-types"),
        ("server", "crates/owlauth-server/Cargo.toml", "owlauth-key-provider"),
        ("server", "crates/owlauth-server/Cargo.toml", "owlauth-types"),
    )
    for owner, manifest, package in dependencies:
        require_version(
            read_internal_dependency(root / manifest, package),
            expected.get(f"dependency:{owner}:{package}", CARGO_DEVELOPMENT_VERSION),
            label=f"{manifest} {package}",
        )

    typescript_expected = expected.get("typescript", NPM_DEVELOPMENT_VERSION)
    typescript_package = json.loads(
        (root / "sdks/typescript/package.json").read_text(encoding="utf-8")
    )
    require_version(
        typescript_package.get("version"),
        typescript_expected,
        label="sdks/typescript/package.json",
    )
    typescript_constant = re.findall(
        r'^export const VERSION = "([^"]+)";$',
        (root / "sdks/typescript/src/index.ts").read_text(encoding="utf-8"),
        flags=re.MULTILINE,
    )
    if typescript_constant != [typescript_expected]:
        raise PrepareError("TypeScript runtime version constant differs from expected state")

    for relative in ("crates/owlauth-server/web/package.json", "docs/package.json"):
        package = json.loads((root / relative).read_text(encoding="utf-8"))
        require_version(package.get("version"), NPM_DEVELOPMENT_VERSION, label=relative)

    python_expected = expected.get("python", PYTHON_DEVELOPMENT_VERSION)
    require_version(
        read_toml_version(root / "sdks/python/pyproject.toml", "project"),
        python_expected,
        label="sdks/python/pyproject.toml",
    )
    require_version(
        read_locked_package_version(root / "uv.lock", "owlauth-client"),
        python_expected,
        label="uv.lock owlauth-client",
    )
    python_constant = re.findall(
        r'^__version__ = "([^"]+)"$',
        (root / "sdks/python/src/owlauth/__init__.py").read_text(encoding="utf-8"),
        flags=re.MULTILINE,
    )
    if python_constant != [python_expected]:
        raise PrepareError("Python runtime version constant differs from expected state")


def validate_development_state(root: Path = Path(".")) -> None:
    validate_version_state(root)


def validate_prepared_release_state(component: str, version: str, root: Path = Path(".")) -> None:
    validate_version_state(root, release_overrides(component, version))


def prepare_release(component: str, version: str, root: Path = Path(".")) -> None:
    if component not in TAG_PREFIXES:
        raise PrepareError(f"unsupported release component: {component}")
    if not SEMVER_PATTERN.fullmatch(version):
        raise PrepareError(f"invalid release SemVer: {version}")
    if version in {CARGO_DEVELOPMENT_VERSION, NPM_DEVELOPMENT_VERSION}:
        raise PrepareError(f"development sentinel is not a publishable release: {version}")
    if component == "python" and not STABLE_SEMVER_PATTERN.fullmatch(version):
        raise PrepareError(
            "Python release versions must use stable X.Y.Z SemVer so package metadata "
            "is not normalized to a different PEP 440 version"
        )

    if component == "server":
        set_toml_version(root / "crates/owlauth-types/Cargo.toml", "package", version)
        set_toml_version(root / "crates/owlauth-server/Cargo.toml", "package", version)
        set_toml_version(root / "crates/owlauth-key-provider/Cargo.toml", "package", version)
        set_internal_dependency(
            root / "crates/owlauth-server/Cargo.toml", "owlauth-key-provider", version
        )
        set_internal_dependency(root / "crates/owlauth-server/Cargo.toml", "owlauth-types", version)
        # Every workspace path requirement must follow the temporarily materialized
        # types version, even though a server release does not publish the CLI.
        set_internal_dependency(root / "crates/owlauth-cli/Cargo.toml", "owlauth-types", version)
        set_locked_package_version(root / "Cargo.lock", "owlauth-key-provider", version)
        set_locked_package_version(root / "Cargo.lock", "owlauth-types", version)
        set_locked_package_version(root / "Cargo.lock", "owlauth-server", version)
    elif component == "cli":
        # The CLI uses reviewed public DTOs through an exact registry dependency.
        # Its tag therefore materializes and publishes owlauth-types at the same
        # otherwise-independent version. verify-release.sh enforces one strictly
        # increasing server/CLI sequence in this shared crate namespace.
        set_toml_version(root / "crates/owlauth-types/Cargo.toml", "package", version)
        set_toml_version(root / "crates/owlauth-cli/Cargo.toml", "package", version)
        set_internal_dependency(root / "crates/owlauth-cli/Cargo.toml", "owlauth-types", version)
        set_internal_dependency(root / "crates/owlauth-server/Cargo.toml", "owlauth-types", version)
        set_locked_package_version(root / "Cargo.lock", "owlauth-types", version)
        set_locked_package_version(root / "Cargo.lock", "owlauth-cli", version)
    elif component == "typescript":
        set_json_version(root / "sdks/typescript/package.json", version)
        replace_once(
            root / "sdks/typescript/src/index.ts",
            r'^export const VERSION = "[^"]+";$',
            f'export const VERSION = "{version}";',
            label="TypeScript runtime version constant",
        )
    elif component == "python":
        set_toml_version(root / "sdks/python/pyproject.toml", "project", version)
        set_locked_package_version(root / "uv.lock", "owlauth-client", version)
        replace_once(
            root / "sdks/python/src/owlauth/__init__.py",
            r'^__version__ = "[^"]+"$',
            f'__version__ = "{version}"',
            label="Python runtime version constant",
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
        try:
            validate_development_state()
        except (PrepareError, OSError, UnicodeError, json.JSONDecodeError) as error:
            print(f"development version validation failed: {error}", file=sys.stderr)
            return 1
        print("no release tag detected; development manifests verified unchanged")
        return 0

    component, version = release
    try:
        # A release tag may materialize only a reviewed development checkout or
        # its exact already-prepared state, never arbitrary stale manifests.
        try:
            validate_development_state()
        except PrepareError as development_error:
            try:
                validate_prepared_release_state(component, version)
            except PrepareError as prepared_error:
                raise PrepareError(
                    "manifests match neither development nor requested release state: "
                    f"{development_error}; {prepared_error}"
                ) from prepared_error
        prepare_release(component, version)
        validate_prepared_release_state(component, version)
    except (PrepareError, OSError, UnicodeError, json.JSONDecodeError) as error:
        print(f"release preparation failed: {error}", file=sys.stderr)
        return 1
    print(f"prepared {component} manifests for {version}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
