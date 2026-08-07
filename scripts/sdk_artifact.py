#!/usr/bin/env python3
"""Inspect and bind immutable SDK candidate archives to their build coordinate."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tarfile
import tomllib
import zipfile
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from email.parser import Parser
from pathlib import Path, PurePosixPath
from typing import Any

REPOSITORY_ROOT = Path(__file__).resolve().parent.parent
CORPUS_PATH = REPOSITORY_ROOT / "sdks/spec/conformance/cases.json"
TYPESCRIPT_ARTIFACT_SURFACE_PATH = (
    REPOSITORY_ROOT / "sdks/spec/contract/typescript-artifact-surface.json"
)
BUILD_CONFIGURATIONS = {
    "typescript": "typescript-npm-pack-v1",
    "python": "python-hatch-wheel-v1",
    "rust": "rust-cargo-package-v1",
}
PACKAGE_NAMES = {
    "typescript": "@owlauth/client",
    "python": "owlauth-client",
    "rust": "owlauth-client",
}
MANIFEST_PATHS = {
    "typescript": REPOSITORY_ROOT / "sdks/typescript/package.json",
    "python": REPOSITORY_ROOT / "sdks/python/pyproject.toml",
    "rust": REPOSITORY_ROOT / "sdks/rust/Cargo.toml",
}
FORBIDDEN_CONTENT = (
    b"OWLAUTH_CONTROL_API_KEY",
    b"control_api_key",
    b"operator_api_key",
    b"x-owlauth-operator-key",
    b"project_server_key",
    b"projectclientkey",
    b"owl_server_v1.",
    b"server-openapi.json",
    b"/v1/projects/{project_id}/tokens/introspect",
    b"/v1/projects/{project_id}/users/lookup",
    b"introspect_project_token",
    b"lookup_project_user",
    b"get_application_user_projection",
    b"/control/",
    b"/Users/",
    b"/home/runner/work/",
    b"runtime-openapi.json",
    b"control-openapi.json",
)
SEMVER = re.compile(
    r"^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
    r"(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$"
)
STABLE_SEMVER = re.compile(r"^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$")
PYTHON_DEVELOPMENT_VERSION = "0.0.0.dev0"
DEVELOPMENT_VERSIONS = {
    "typescript": "0.0.0-dev",
    "python": PYTHON_DEVELOPMENT_VERSION,
    "rust": "0.0.0-dev",
}
MAX_ARCHIVE_BYTES = 16 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 256
MAX_EXPANDED_BYTES = 32 * 1024 * 1024
MAX_MEMBER_BYTES = 2 * 1024 * 1024


class ArtifactError(RuntimeError):
    """Raised when a candidate archive or descriptor is invalid."""


def validate_candidate_version(component: str, version: str, tag: object) -> None:
    if component == "python":
        if not STABLE_SEMVER.fullmatch(version) and version != PYTHON_DEVELOPMENT_VERSION:
            raise ArtifactError("Python candidate version is invalid")
    elif not SEMVER.fullmatch(version):
        raise ArtifactError("candidate version is invalid SemVer")

    development_version = DEVELOPMENT_VERSIONS[component]
    if tag is None:
        if version != development_version:
            raise ArtifactError("untagged candidate must use its exact development sentinel")
        return
    if not isinstance(tag, str):
        raise ArtifactError("candidate release tag must be a string or null")
    if version == development_version:
        raise ArtifactError("development sentinel cannot be authorized by a release tag")
    if tag != f"{component}-v{version}":
        raise ArtifactError("candidate release tag differs from its component and version")
    if component == "python" and not STABLE_SEMVER.fullmatch(version):
        raise ArtifactError("tagged Python candidates must use stable SemVer")


@dataclass(frozen=True)
class ArchiveIdentity:
    component: str
    package_name: str
    version: str
    files: tuple[str, ...]
    source_commit: str | None = None
    source_dirty: bool | None = None


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as source:
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as error:
        raise ArtifactError(f"cannot read {path}: {error}") from error
    return digest.hexdigest()


def canonical_json(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, separators=(",", ": ")) + "\n").encode()


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ArtifactError(f"cannot read JSON from {path}: {error}") from error


def write_bytes(path: Path, value: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    try:
        temporary.write_bytes(value)
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def exact_object(
    value: object, required: set[str], optional: set[str] = frozenset(), *, label: str
) -> Mapping[str, Any]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise ArtifactError(f"{label} must be an object")
    fields = set(value)
    if not required <= fields or fields - required - optional:
        raise ArtifactError(f"{label} has invalid fields")
    return value


def require_string(value: object, *, label: str, maximum: int = 512) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise ArtifactError(f"{label} must be a non-empty bounded string")
    return value


def safe_member_path(name: str) -> PurePosixPath:
    path = PurePosixPath(name)
    if not name or path.is_absolute() or ".." in path.parts or "" in path.parts:
        raise ArtifactError(f"archive contains unsafe path: {name!r}")
    return path


def scan_content(path: str, content: bytes) -> None:
    if len(content) > MAX_MEMBER_BYTES:
        raise ArtifactError(f"archive member is unexpectedly large: {path}")
    lowered = content.lower()
    for marker in FORBIDDEN_CONTENT:
        candidate = marker in content if marker.startswith(b"/") else marker.lower() in lowered
        if candidate:
            raise ArtifactError(
                f"archive member contains forbidden build or credential data: {path}"
            )


def require_reviewed_source_files(
    files: Mapping[str, bytes],
    *,
    archive_prefix: str,
    source_directory: Path,
    names: Iterable[str],
    label: str,
) -> None:
    for name in names:
        archive_name = f"{archive_prefix}{name}"
        source_path = source_directory / name
        try:
            reviewed = source_path.read_bytes()
        except OSError as error:
            raise ArtifactError(
                f"cannot read reviewed {label} source {source_path}: {error}"
            ) from error
        if files.get(archive_name) != reviewed:
            raise ArtifactError(
                f"{label} archive code differs from the exact reviewed checkout: {archive_name}"
            )


def require_reviewed_typescript_surface(files: Mapping[str, bytes], version: str) -> None:
    manifest = exact_object(
        load_json(TYPESCRIPT_ARTIFACT_SURFACE_PATH),
        {"schemaVersion", "normalization", "files"},
        label="TypeScript artifact surface manifest",
    )
    if manifest["schemaVersion"] != 1:
        raise ArtifactError("TypeScript artifact surface schema version is unsupported")
    expected = manifest["files"]
    if not isinstance(expected, dict) or not all(
        isinstance(name, str) and isinstance(digest, str) and re.fullmatch(r"[0-9a-f]{64}", digest)
        for name, digest in expected.items()
    ):
        raise ArtifactError("TypeScript artifact surface manifest is invalid")
    actual_names = {PurePosixPath(name).name for name in files if name.startswith("package/dist/")}
    if set(expected) != actual_names:
        raise ArtifactError("TypeScript reviewed artifact surface file set differs")
    version_bytes = version.encode()
    for name, expected_digest in expected.items():
        content = files[f"package/dist/{name}"]
        if name in {"index.js", "index.d.ts"}:
            if version_bytes not in content:
                raise ArtifactError(f"TypeScript {name} does not contain the exact package version")
            content = content.replace(version_bytes, b"<VERSION>")
        if sha256_bytes(content) != expected_digest:
            raise ArtifactError(
                f"TypeScript archive code differs from the reviewed artifact surface: {name}"
            )


def require_bounded_archive(path: Path) -> None:
    try:
        size = path.stat().st_size
    except OSError as error:
        raise ArtifactError(f"cannot inspect archive {path}: {error}") from error
    if size <= 0 or size > MAX_ARCHIVE_BYTES:
        raise ArtifactError(f"archive compressed size is outside the allowed bound: {path}")


def read_tar(path: Path) -> dict[str, bytes]:
    require_bounded_archive(path)
    files: dict[str, bytes] = {}
    member_count = 0
    expanded_bytes = 0
    try:
        with tarfile.open(path, "r:gz") as archive:
            for member in archive:
                member_count += 1
                if member_count > MAX_ARCHIVE_MEMBERS:
                    raise ArtifactError("archive contains too many members")
                safe_member_path(member.name)
                if member.isdir():
                    continue
                if not member.isfile() or member.issym() or member.islnk():
                    raise ArtifactError(f"archive contains a non-regular entry: {member.name}")
                if member.size > MAX_MEMBER_BYTES:
                    raise ArtifactError(f"archive member is unexpectedly large: {member.name}")
                expanded_bytes += member.size
                if expanded_bytes > MAX_EXPANDED_BYTES:
                    raise ArtifactError("archive expanded size exceeds the allowed bound")
                source = archive.extractfile(member)
                if source is None:
                    raise ArtifactError(f"cannot read archive member: {member.name}")
                content = source.read(MAX_MEMBER_BYTES + 1)
                if len(content) != member.size:
                    raise ArtifactError(
                        f"archive member size differs from its header: {member.name}"
                    )
                if member.name in files:
                    raise ArtifactError(f"archive contains duplicate member: {member.name}")
                scan_content(member.name, content)
                files[member.name] = content
    except (OSError, tarfile.TarError) as error:
        raise ArtifactError(f"cannot inspect tar archive {path}: {error}") from error
    return files


def read_wheel(path: Path) -> dict[str, bytes]:
    require_bounded_archive(path)
    files: dict[str, bytes] = {}
    expanded_bytes = 0
    try:
        with zipfile.ZipFile(path) as archive:
            members = archive.infolist()
            if len(members) > MAX_ARCHIVE_MEMBERS:
                raise ArtifactError("wheel contains too many members")
            for member in members:
                safe_member_path(member.filename)
                if member.is_dir():
                    continue
                mode = member.external_attr >> 16
                if mode and (mode & 0o170000) not in (0, 0o100000):
                    raise ArtifactError(f"wheel contains a non-regular entry: {member.filename}")
                if member.file_size > MAX_MEMBER_BYTES:
                    raise ArtifactError(f"wheel member is unexpectedly large: {member.filename}")
                expanded_bytes += member.file_size
                if expanded_bytes > MAX_EXPANDED_BYTES:
                    raise ArtifactError("wheel expanded size exceeds the allowed bound")
                if member.filename in files:
                    raise ArtifactError(f"wheel contains duplicate member: {member.filename}")
                content = archive.read(member)
                if len(content) != member.file_size:
                    raise ArtifactError(
                        f"wheel member size differs from its header: {member.filename}"
                    )
                scan_content(member.filename, content)
                files[member.filename] = content
    except (OSError, zipfile.BadZipFile) as error:
        raise ArtifactError(f"cannot inspect wheel {path}: {error}") from error
    return files


def inspect_typescript(path: Path) -> ArchiveIdentity:
    files = read_tar(path)
    expected = {
        "package/LICENSE",
        "package/README.md",
        "package/package.json",
        "package/dist/client.d.ts",
        "package/dist/client.js",
        "package/dist/errors.d.ts",
        "package/dist/errors.js",
        "package/dist/index.d.ts",
        "package/dist/index.js",
        "package/dist/types.d.ts",
        "package/dist/types.js",
    }
    if set(files) != expected:
        missing = sorted(expected - set(files))
        extra = sorted(set(files) - expected)
        raise ArtifactError(
            f"TypeScript package file set differs: missing={missing}, extra={extra}"
        )
    package = json.loads(files["package/package.json"])
    exact_object(
        package,
        {
            "name",
            "version",
            "description",
            "license",
            "author",
            "repository",
            "bugs",
            "homepage",
            "type",
            "packageManager",
            "main",
            "types",
            "exports",
            "files",
            "scripts",
            "publishConfig",
            "engines",
            "devDependencies",
        },
        label="npm package metadata",
    )
    if package["name"] != PACKAGE_NAMES["typescript"] or package["license"] != "BSD-3-Clause":
        raise ArtifactError("TypeScript package identity or license is invalid")
    if files["package/LICENSE"] != (REPOSITORY_ROOT / "sdks/typescript/LICENSE").read_bytes():
        raise ArtifactError("TypeScript package license bytes differ from the declared BSD license")
    if files["package/README.md"] != (REPOSITORY_ROOT / "sdks/typescript/README.md").read_bytes():
        raise ArtifactError("TypeScript package README differs from the checked-out source")
    version = require_string(package["version"], label="npm version", maximum=128)
    if not SEMVER.fullmatch(version):
        raise ArtifactError("npm package version is not SemVer")
    exports = package.get("exports")
    if not isinstance(exports, dict) or set(exports) != {"."}:
        raise ArtifactError("TypeScript package must expose exactly one root entry point")
    if b"VERSION" not in files["package/dist/index.js"]:
        raise ArtifactError("TypeScript package does not expose its runtime version")
    require_reviewed_typescript_surface(files, version)
    return ArchiveIdentity("typescript", package["name"], version, tuple(sorted(files)))


def inspect_python(path: Path) -> ArchiveIdentity:
    if not path.name.endswith(".whl"):
        raise ArtifactError("Python candidate must be one wheel")
    files = read_wheel(path)
    dist_infos = {name.split("/", 1)[0] for name in files if ".dist-info/" in name}
    if len(dist_infos) != 1:
        raise ArtifactError("wheel must contain exactly one dist-info directory")
    dist_info = next(iter(dist_infos))
    expected_modules = {
        "owlauth/__init__.py",
        "owlauth/_json.py",
        "owlauth/client.py",
        "owlauth/conformance.py",
        "owlauth/errors.py",
        "owlauth/models.py",
        "owlauth/py.typed",
        "owlauth/transport.py",
    }
    expected_metadata = {
        f"{dist_info}/METADATA",
        f"{dist_info}/RECORD",
        f"{dist_info}/WHEEL",
        f"{dist_info}/licenses/LICENSE",
    }
    if set(files) != expected_modules | expected_metadata:
        missing = sorted((expected_modules | expected_metadata) - set(files))
        extra = sorted(set(files) - (expected_modules | expected_metadata))
        raise ArtifactError(f"Python wheel file set differs: missing={missing}, extra={extra}")
    metadata = Parser().parsestr(files[f"{dist_info}/METADATA"].decode("utf-8"))
    if (
        metadata["Name"] != PACKAGE_NAMES["python"]
        or metadata["License-Expression"] != "BSD-3-Clause"
    ):
        raise ArtifactError("Python wheel identity or license is invalid")
    if (
        files[f"{dist_info}/licenses/LICENSE"]
        != (REPOSITORY_ROOT / "sdks/python/LICENSE").read_bytes()
    ):
        raise ArtifactError("Python wheel license bytes differ from the declared BSD license")
    if metadata.get_payload() != (REPOSITORY_ROOT / "sdks/python/README.md").read_text(
        encoding="utf-8"
    ):
        raise ArtifactError("Python wheel README metadata differs from the checked-out source")
    version = require_string(metadata["Version"], label="wheel version", maximum=128)
    if not STABLE_SEMVER.fullmatch(version) and version != PYTHON_DEVELOPMENT_VERSION:
        raise ArtifactError(
            "Python wheel version is neither stable SemVer nor the development sentinel"
        )
    if f'__version__ = "{version}"'.encode() not in files["owlauth/__init__.py"]:
        raise ArtifactError("Python runtime version differs from wheel metadata")
    require_reviewed_source_files(
        files,
        archive_prefix="owlauth/",
        source_directory=REPOSITORY_ROOT / "sdks/python/src/owlauth",
        names=(
            "__init__.py",
            "_json.py",
            "client.py",
            "conformance.py",
            "errors.py",
            "models.py",
            "py.typed",
            "transport.py",
        ),
        label="Python SDK",
    )
    return ArchiveIdentity("python", metadata["Name"], version, tuple(sorted(files)))


def inspect_rust(path: Path) -> ArchiveIdentity:
    files = read_tar(path)
    roots = {PurePosixPath(name).parts[0] for name in files}
    if len(roots) != 1:
        raise ArtifactError("crate archive must contain one package root")
    root = next(iter(roots))
    prefix = f"{root}/"
    relative = {name.removeprefix(prefix): content for name, content in files.items()}
    expected = {
        ".cargo_vcs_info.json",
        "Cargo.lock",
        "Cargo.toml",
        "Cargo.toml.orig",
        "LICENSE",
        "README.md",
        "src/client.rs",
        "src/error.rs",
        "src/lib.rs",
        "src/models.rs",
        "src/transport.rs",
    }
    if set(relative) != expected:
        missing = sorted(expected - set(relative))
        extra = sorted(set(relative) - expected)
        raise ArtifactError(f"Rust crate file set differs: missing={missing}, extra={extra}")
    manifest = tomllib.loads(relative["Cargo.toml"].decode("utf-8"))
    package = manifest.get("package")
    if not isinstance(package, dict) or package.get("name") != PACKAGE_NAMES["rust"]:
        raise ArtifactError("Rust crate identity is invalid")
    version = require_string(package.get("version"), label="crate version", maximum=128)
    if not SEMVER.fullmatch(version) or root != f"owlauth-client-{version}":
        raise ArtifactError("Rust crate root or version is invalid")
    if package.get("license") != "BSD-3-Clause":
        raise ArtifactError("Rust crate license is invalid")
    if relative["LICENSE"] != (REPOSITORY_ROOT / "sdks/rust/LICENSE").read_bytes():
        raise ArtifactError("Rust crate license bytes differ from the declared BSD license")
    if relative["README.md"] != (REPOSITORY_ROOT / "sdks/rust/README.md").read_bytes():
        raise ArtifactError("Rust crate README differs from the checked-out source")
    for table_name in ("dependencies", "dev-dependencies", "build-dependencies"):
        table = manifest.get(table_name, {})
        if not isinstance(table, dict):
            raise ArtifactError(f"invalid Cargo {table_name}")
        for name, dependency in table.items():
            if name in {"owlauth-server", "owlauth-types"}:
                raise ArtifactError("Rust SDK must not depend on server implementation packages")
            if isinstance(dependency, dict) and ({"path", "git"} & set(dependency)):
                raise ArtifactError("published Rust dependencies must not use path or git sources")
    vcs = json.loads(relative[".cargo_vcs_info.json"])
    git = exact_object(vcs, {"git", "path_in_vcs"}, label="crate VCS metadata")["git"]
    git_fields = exact_object(git, {"sha1"}, {"dirty"}, label="crate Git metadata")
    vcs_commit = require_string(git_fields["sha1"], label="crate source commit", maximum=40)
    if not re.fullmatch(r"[0-9a-f]{40}", vcs_commit):
        raise ArtifactError("crate source commit is invalid")
    source_dirty = git_fields.get("dirty", False)
    if not isinstance(source_dirty, bool):
        raise ArtifactError("crate dirty marker is invalid")
    if b"pub const VERSION" not in relative["src/lib.rs"]:
        raise ArtifactError("Rust crate does not expose its runtime version")
    require_reviewed_source_files(
        relative,
        archive_prefix="src/",
        source_directory=REPOSITORY_ROOT / "sdks/rust/src",
        names=("client.rs", "error.rs", "lib.rs", "models.rs", "transport.rs"),
        label="Rust SDK",
    )
    return ArchiveIdentity(
        "rust",
        package["name"],
        version,
        tuple(sorted(files)),
        vcs_commit,
        source_dirty,
    )


def inspect_archive(component: str, path: Path) -> ArchiveIdentity:
    if not path.is_file():
        raise ArtifactError(f"candidate archive does not exist: {path}")
    if component == "typescript":
        return inspect_typescript(path)
    if component == "python":
        return inspect_python(path)
    if component == "rust":
        return inspect_rust(path)
    raise ArtifactError(f"unsupported SDK component: {component}")


def manifest_digest(component: str) -> str:
    path = MANIFEST_PATHS[component]
    return sha256_file(path)


def source_commit() -> str:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=REPOSITORY_ROOT,
            check=True,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError) as error:
        raise ArtifactError(f"cannot determine source commit: {error}") from error
    commit = result.stdout.strip()
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ArtifactError("source commit is not a full Git SHA")
    return commit


def effective_tag(component: str) -> str | None:
    if os.environ.get("GITHUB_REF_TYPE") != "tag":
        return None
    ref_name = os.environ.get("GITHUB_REF_NAME", "")
    prefix = f"{component}-v"
    return ref_name if ref_name.startswith(prefix) else None


def validate_contract(value: object, expected_commit: str) -> Mapping[str, Any]:
    contract = exact_object(
        value,
        {
            "schemaVersion",
            "sourceCommit",
            "owlauthTypesVersion",
            "owlauthServerVersion",
            "openapiVersion",
            "fullRuntimeSha256",
            "claimedSurfaceSha256",
            "policySha256",
            "normalizerVersion",
            "claimedOperationIds",
        },
        label="contract provenance",
    )
    if contract["schemaVersion"] != 1 or contract["sourceCommit"] != expected_commit:
        raise ArtifactError("contract provenance does not match the candidate source commit")
    for field in ("fullRuntimeSha256", "claimedSurfaceSha256", "policySha256"):
        if not isinstance(contract[field], str) or not re.fullmatch(
            r"[0-9a-f]{64}", contract[field]
        ):
            raise ArtifactError(f"contract provenance has invalid {field}")
    operations = contract["claimedOperationIds"]
    if (
        not isinstance(operations, list)
        or len(operations) != 8
        or not all(isinstance(item, str) for item in operations)
    ):
        raise ArtifactError("contract provenance has invalid claimed operations")
    return contract


def corpus_provenance(corpus_path: Path = CORPUS_PATH) -> dict[str, Any]:
    value = load_json(corpus_path)
    if not isinstance(value, dict) or value.get("schemaVersion") != 3:
        raise ArtifactError("shared SDK corpus must use schema version 3")
    names = value.get("requiredCaseNames")
    if (
        not isinstance(names, list)
        or not names
        or not all(isinstance(name, str) for name in names)
        or len(set(names)) != len(names)
    ):
        raise ArtifactError("shared SDK corpus required-case manifest is invalid")
    cases = value.get("cases")
    if not isinstance(cases, list) or not cases:
        raise ArtifactError("shared SDK corpus cases are invalid")
    fixture_root = (corpus_path.parent.parent / "fixtures").resolve()
    referenced: set[Path] = set()
    for case in cases:
        if not isinstance(case, dict) or not isinstance(case.get("fixture"), str):
            raise ArtifactError("shared SDK corpus fixture reference is invalid")
        fixture = (corpus_path.parent / case["fixture"]).resolve()
        if (
            not fixture.is_relative_to(fixture_root)
            or fixture.suffix != ".json"
            or not fixture.is_file()
        ):
            raise ArtifactError("shared SDK corpus fixture escapes its authority root")
        referenced.add(fixture)
    fixture_files = {path.resolve() for path in fixture_root.glob("*.json") if path.is_file()}
    if not referenced.issubset(fixture_files):
        raise ArtifactError("shared SDK corpus references an untracked fixture")
    authority_root = corpus_path.parent.parent.resolve()
    files = [corpus_path.resolve(), *sorted(fixture_files)]
    tree = {
        "schemaVersion": 1,
        "files": [
            {
                "path": path.relative_to(authority_root).as_posix(),
                "sha256": sha256_file(path),
            }
            for path in files
        ],
    }
    return {
        "schemaVersion": 3,
        "sha256": sha256_bytes(canonical_json(tree)),
        "requiredCaseCount": len(names),
    }


def cargo_upload_metadata(cargo_metadata_path: Path) -> dict[str, Any]:
    value = load_json(cargo_metadata_path)
    packages = value.get("packages") if isinstance(value, dict) else None
    if not isinstance(packages, list):
        raise ArtifactError("Cargo metadata must contain packages")
    candidates = [
        item for item in packages if isinstance(item, dict) and item.get("name") == "owlauth-client"
    ]
    if len(candidates) != 1:
        raise ArtifactError("Cargo metadata must contain exactly one owlauth-client package")
    package = candidates[0]
    dependencies = package.get("dependencies")
    if not isinstance(dependencies, list):
        raise ArtifactError("Cargo metadata package dependencies are invalid")
    encoded_dependencies = []
    for dependency in dependencies:
        if not isinstance(dependency, dict):
            raise ArtifactError("Cargo metadata dependency is invalid")
        source = dependency.get("source")
        if source is not None and not isinstance(source, str):
            raise ArtifactError("Cargo dependency source is invalid")
        if dependency.get("path") is not None or (source is not None and source.startswith("git+")):
            raise ArtifactError("Rust upload metadata cannot contain path or Git dependencies")
        encoded_dependencies.append(
            {
                "name": require_string(dependency.get("name"), label="dependency name"),
                "version_req": require_string(
                    dependency.get("req"), label="dependency requirement"
                ),
                "features": dependency.get("features", []),
                "optional": dependency.get("optional", False),
                "default_features": dependency.get("uses_default_features", True),
                "target": dependency.get("target"),
                "kind": dependency.get("kind") or "normal",
                "registry": dependency.get("registry"),
                "explicit_name_in_toml": dependency.get("rename"),
            }
        )
    manifest_path = Path(
        require_string(package.get("manifest_path"), label="Cargo manifest path", maximum=4096)
    )
    readme_path = package.get("readme")
    readme = None
    readme_file = None
    if readme_path is not None:
        path = Path(require_string(readme_path, label="Cargo README path", maximum=4096))
        if not path.is_absolute():
            path = manifest_path.parent / path
        try:
            readme = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as error:
            raise ArtifactError(f"cannot read Cargo README: {error}") from error
        readme_file = path.name
    license_file_value = package.get("license_file")
    license_file = Path(license_file_value).name if isinstance(license_file_value, str) else None
    return {
        "name": PACKAGE_NAMES["rust"],
        "vers": require_string(package.get("version"), label="Cargo package version"),
        "deps": encoded_dependencies,
        "features": package.get("features", {}),
        "authors": package.get("authors", []),
        "description": package.get("description"),
        "documentation": package.get("documentation"),
        "homepage": package.get("homepage"),
        "readme": readme,
        "readme_file": readme_file,
        "keywords": package.get("keywords", []),
        "categories": package.get("categories", []),
        "license": package.get("license"),
        "license_file": license_file,
        "repository": package.get("repository"),
        "badges": {},
        "links": package.get("links"),
        "rust_version": package.get("rust_version"),
    }


def _registry_requirement(value: object) -> str:
    requirement = require_string(value, label="crate dependency requirement", maximum=128)
    if re.fullmatch(r"[0-9]+(?:\.[0-9]+){1,2}(?:-[0-9A-Za-z.-]+)?", requirement):
        return f"^{requirement}"
    if requirement.startswith("^"):
        return requirement
    raise ArtifactError("crate dependency uses an unsupported non-caret requirement")


def _crate_dependency(
    alias: str, value: object, *, kind: str, target: str | None
) -> dict[str, Any]:
    if isinstance(value, str):
        dependency: Mapping[str, Any] = {"version": value}
    elif isinstance(value, dict):
        dependency = value
    else:
        raise ArtifactError("crate dependency specification is invalid")
    if {"path", "git", "registry"} & set(dependency):
        raise ArtifactError("Rust SDK registry metadata cannot use path, Git, or other registries")
    package_name = dependency.get("package", alias)
    name = require_string(package_name, label="crate dependency package name")
    explicit_name = alias if name != alias else None
    features = dependency.get("features", [])
    if not isinstance(features, list) or not all(isinstance(item, str) for item in features):
        raise ArtifactError("crate dependency features are invalid")
    optional = dependency.get("optional", False)
    default_features = dependency.get("default-features", True)
    if not isinstance(optional, bool) or not isinstance(default_features, bool):
        raise ArtifactError("crate dependency boolean flags are invalid")
    return {
        "name": name,
        "version_req": _registry_requirement(dependency.get("version")),
        "features": features,
        "optional": optional,
        "default_features": default_features,
        "target": target,
        "kind": kind,
        "registry": None,
        "explicit_name_in_toml": explicit_name,
    }


def _manifest_dependencies(manifest: Mapping[str, Any]) -> list[dict[str, Any]]:
    encoded: list[dict[str, Any]] = []
    sections = (
        ("dependencies", "normal"),
        ("dev-dependencies", "dev"),
        ("build-dependencies", "build"),
    )
    for section, kind in sections:
        dependencies = manifest.get(section, {})
        if not isinstance(dependencies, dict):
            raise ArtifactError(f"crate {section} table is invalid")
        for alias, value in dependencies.items():
            encoded.append(_crate_dependency(alias, value, kind=kind, target=None))
    targets = manifest.get("target", {})
    if not isinstance(targets, dict):
        raise ArtifactError("crate target dependency tables are invalid")
    for target, target_tables in targets.items():
        if not isinstance(target, str) or not isinstance(target_tables, dict):
            raise ArtifactError("crate target dependency table is invalid")
        for section, kind in sections:
            dependencies = target_tables.get(section, {})
            if not isinstance(dependencies, dict):
                raise ArtifactError("crate target dependencies are invalid")
            for alias, value in dependencies.items():
                encoded.append(_crate_dependency(alias, value, kind=kind, target=target))
    return encoded


def crate_upload_metadata(archive_path: Path) -> dict[str, Any]:
    files = read_tar(archive_path)
    roots = {PurePosixPath(name).parts[0] for name in files}
    if len(roots) != 1:
        raise ArtifactError("crate archive must contain one package root")
    root = next(iter(roots))
    prefix = f"{root}/"
    relative = {name.removeprefix(prefix): content for name, content in files.items()}
    try:
        manifest = tomllib.loads(relative["Cargo.toml"].decode("utf-8"))
        readme = relative["README.md"].decode("utf-8")
    except (KeyError, UnicodeError, tomllib.TOMLDecodeError) as error:
        raise ArtifactError("crate archive metadata inputs are invalid") from error
    package = manifest.get("package")
    if not isinstance(package, dict):
        raise ArtifactError("crate package metadata is invalid")
    features = manifest.get("features", {})
    if not isinstance(features, dict):
        raise ArtifactError("crate feature metadata is invalid")
    readme_file = package.get("readme")
    if readme_file != "README.md":
        raise ArtifactError("crate README path must remain README.md")
    license_file = package.get("license-file")
    if license_file is not None and not isinstance(license_file, str):
        raise ArtifactError("crate license file metadata is invalid")
    return {
        "name": require_string(package.get("name"), label="crate package name"),
        "vers": require_string(package.get("version"), label="crate package version"),
        "deps": _manifest_dependencies(manifest),
        "features": features,
        "authors": package.get("authors", []),
        "description": package.get("description"),
        "documentation": package.get("documentation"),
        "homepage": package.get("homepage"),
        "readme": readme,
        "readme_file": readme_file,
        "keywords": package.get("keywords", []),
        "categories": package.get("categories", []),
        "license": package.get("license"),
        "license_file": license_file,
        "repository": package.get("repository"),
        "badges": {},
        "links": package.get("links"),
        "rust_version": package.get("rust-version"),
    }


def validate_upload_metadata(
    path: Path, identity: ArchiveIdentity, archive_path: Path
) -> dict[str, Any]:
    value = load_json(path)
    metadata = exact_object(
        value,
        {
            "name",
            "vers",
            "deps",
            "features",
            "authors",
            "description",
            "documentation",
            "homepage",
            "readme",
            "readme_file",
            "keywords",
            "categories",
            "license",
            "license_file",
            "repository",
            "badges",
            "links",
            "rust_version",
        },
        label="crates.io upload metadata",
    )
    if metadata["name"] != identity.package_name or metadata["vers"] != identity.version:
        raise ArtifactError("crates.io upload metadata identity differs from the crate archive")
    if (
        metadata["license"] != "BSD-3-Clause"
        or not isinstance(metadata["deps"], list)
        or not isinstance(metadata["features"], dict)
        or not all(
            isinstance(name, str)
            and isinstance(enabled, list)
            and all(isinstance(item, str) for item in enabled)
            for name, enabled in metadata["features"].items()
        )
        or not isinstance(metadata["readme"], str)
        or not metadata["readme"].startswith("# ")
        or metadata["readme_file"] != "README.md"
        or metadata["badges"] != {}
    ):
        raise ArtifactError("crates.io upload metadata package fields are invalid")
    dependency_keys: set[tuple[object, ...]] = set()
    for dependency_value in metadata["deps"]:
        dependency = exact_object(
            dependency_value,
            {
                "name",
                "version_req",
                "features",
                "optional",
                "default_features",
                "target",
                "kind",
                "registry",
                "explicit_name_in_toml",
            },
            label="crates.io upload dependency",
        )
        name = require_string(dependency["name"], label="upload dependency name")
        requirement = require_string(
            dependency["version_req"], label="upload dependency requirement"
        )
        features = dependency["features"]
        if (
            not isinstance(features, list)
            or not all(isinstance(item, str) for item in features)
            or not isinstance(dependency["optional"], bool)
            or not isinstance(dependency["default_features"], bool)
            or dependency["kind"] not in {"normal", "dev", "build"}
            or dependency["registry"] is not None
            or (dependency["target"] is not None and not isinstance(dependency["target"], str))
            or (
                dependency["explicit_name_in_toml"] is not None
                and not isinstance(dependency["explicit_name_in_toml"], str)
            )
        ):
            raise ArtifactError("crates.io upload dependency fields are invalid")
        key = (
            name,
            requirement,
            dependency["kind"],
            dependency["target"],
            dependency["explicit_name_in_toml"],
        )
        if key in dependency_keys:
            raise ArtifactError("crates.io upload metadata contains duplicate dependencies")
        dependency_keys.add(key)
    expected = crate_upload_metadata(archive_path)
    if dict(metadata) != expected:
        raise ArtifactError("crates.io upload metadata differs from the exact crate archive")
    return dict(metadata)


def build_descriptor(options: argparse.Namespace) -> dict[str, Any]:
    archive = options.archive.resolve()
    identity = inspect_archive(options.component, archive)
    commit = options.source_commit or source_commit()
    contract = validate_contract(load_json(options.contract_provenance), commit)
    if identity.source_commit is not None and identity.source_commit != commit:
        raise ArtifactError("crate archive source commit differs from the candidate coordinate")
    tag = options.tag if options.tag is not None else effective_tag(options.component)
    if identity.source_dirty and os.environ.get("GITHUB_REF_TYPE") != "tag":
        raise ArtifactError("ordinary Rust candidates must be packaged from a clean Git worktree")
    coordinate = {
        "sourceCommit": commit,
        "component": options.component,
        "version": identity.version,
        "tag": tag,
        "buildConfiguration": options.build_configuration
        or BUILD_CONFIGURATIONS[options.component],
        "workflowRunId": options.workflow_run_id,
        "workflowRunAttempt": options.workflow_run_attempt,
    }
    descriptor: dict[str, Any] = {
        "schemaVersion": 1,
        "coordinate": coordinate,
        "effectiveManifestSha256": manifest_digest(options.component),
        "archive": {
            "fileName": archive.name,
            "sha256": sha256_file(archive),
            "size": archive.stat().st_size,
            "packageName": identity.package_name,
            "runtimeVersion": identity.version,
            "fileCount": len(identity.files),
        },
        "contract": dict(contract),
        "corpus": corpus_provenance(),
    }
    if options.component == "rust":
        if options.upload_metadata is None:
            raise ArtifactError("Rust candidates require crates.io upload metadata")
        validate_upload_metadata(options.upload_metadata, identity, archive)
        descriptor["cratesIoUploadMetadata"] = {
            "fileName": options.upload_metadata.name,
            "sha256": sha256_file(options.upload_metadata),
            "size": options.upload_metadata.stat().st_size,
        }
    elif options.upload_metadata is not None:
        raise ArtifactError("only Rust candidates may include crates.io upload metadata")
    return descriptor


def validate_descriptor(value: object) -> Mapping[str, Any]:
    descriptor = exact_object(
        value,
        {"schemaVersion", "coordinate", "effectiveManifestSha256", "archive", "contract", "corpus"},
        {"cratesIoUploadMetadata"},
        label="candidate descriptor",
    )
    if descriptor["schemaVersion"] != 1:
        raise ArtifactError("unsupported candidate descriptor schema")
    coordinate = exact_object(
        descriptor["coordinate"],
        {
            "sourceCommit",
            "component",
            "version",
            "tag",
            "buildConfiguration",
            "workflowRunId",
            "workflowRunAttempt",
        },
        label="candidate coordinate",
    )
    component = coordinate["component"]
    if component not in BUILD_CONFIGURATIONS:
        raise ArtifactError("candidate descriptor has an unsupported component")
    commit = require_string(coordinate["sourceCommit"], label="candidate source commit", maximum=40)
    version = require_string(coordinate["version"], label="candidate version", maximum=128)
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ArtifactError("candidate source commit is invalid")
    tag = coordinate["tag"]
    validate_candidate_version(component, version, tag)
    if coordinate["buildConfiguration"] != BUILD_CONFIGURATIONS[component]:
        raise ArtifactError("candidate build configuration is invalid")
    require_string(coordinate["workflowRunId"], label="workflow run ID", maximum=128)
    require_string(coordinate["workflowRunAttempt"], label="workflow run attempt", maximum=32)
    manifest_sha = descriptor["effectiveManifestSha256"]
    if not isinstance(manifest_sha, str) or not re.fullmatch(r"[0-9a-f]{64}", manifest_sha):
        raise ArtifactError("candidate effective manifest digest is invalid")
    archive = exact_object(
        descriptor["archive"],
        {"fileName", "sha256", "size", "packageName", "runtimeVersion", "fileCount"},
        label="candidate archive",
    )
    expected_names = {
        "typescript": f"owlauth-client-{version}.tgz",
        "python": f"owlauth_client-{version}-py3-none-any.whl",
        "rust": f"owlauth-client-{version}.crate",
    }
    if (
        archive["packageName"] != PACKAGE_NAMES[component]
        or archive["runtimeVersion"] != version
        or archive["fileName"] != expected_names[component]
        or not isinstance(archive["sha256"], str)
        or not re.fullmatch(r"[0-9a-f]{64}", archive["sha256"])
        or not isinstance(archive["size"], int)
        or isinstance(archive["size"], bool)
        or archive["size"] <= 0
        or not isinstance(archive["fileCount"], int)
        or isinstance(archive["fileCount"], bool)
        or archive["fileCount"] <= 0
    ):
        raise ArtifactError("candidate archive identity or metadata is invalid")
    validate_contract(descriptor["contract"], commit)
    corpus = exact_object(
        descriptor["corpus"],
        {"schemaVersion", "sha256", "requiredCaseCount"},
        label="candidate corpus provenance",
    )
    if (
        corpus["schemaVersion"] != 3
        or not isinstance(corpus["sha256"], str)
        or not re.fullmatch(r"[0-9a-f]{64}", corpus["sha256"])
        or not isinstance(corpus["requiredCaseCount"], int)
        or isinstance(corpus["requiredCaseCount"], bool)
        or corpus["requiredCaseCount"] <= 0
    ):
        raise ArtifactError("candidate corpus provenance is invalid")
    upload_metadata = descriptor.get("cratesIoUploadMetadata")
    if component == "rust":
        metadata = exact_object(
            upload_metadata,
            {"fileName", "sha256", "size"},
            label="crates.io upload metadata provenance",
        )
        if (
            metadata["fileName"] != f"owlauth-client-{version}.upload.json"
            or not isinstance(metadata["sha256"], str)
            or not re.fullmatch(r"[0-9a-f]{64}", metadata["sha256"])
            or not isinstance(metadata["size"], int)
            or isinstance(metadata["size"], bool)
            or metadata["size"] <= 0
        ):
            raise ArtifactError("crates.io upload metadata provenance is invalid")
    elif upload_metadata is not None:
        raise ArtifactError("non-Rust candidates cannot contain crates.io upload metadata")
    return descriptor


def verify_candidate(options: argparse.Namespace) -> Mapping[str, Any]:
    descriptor_path = options.descriptor.resolve()
    raw = descriptor_path.read_bytes()
    value = load_json(descriptor_path)
    if raw != canonical_json(value):
        raise ArtifactError("candidate descriptor is not canonical JSON")
    descriptor = validate_descriptor(value)
    coordinate = descriptor["coordinate"]
    component = coordinate["component"]
    if descriptor["effectiveManifestSha256"] != manifest_digest(component):
        raise ArtifactError("candidate effective manifest differs from the checked-out source")
    if descriptor["corpus"] != corpus_provenance():
        raise ArtifactError("candidate corpus provenance differs from the checked-out corpus")
    archive_value = descriptor["archive"]
    archive = options.archive.resolve()
    identity = inspect_archive(coordinate["component"], archive)
    checks = {
        "component": options.component,
        "version": options.version,
        "sourceCommit": options.source_commit,
        "workflowRunId": options.workflow_run_id,
        "workflowRunAttempt": options.workflow_run_attempt,
        "buildConfiguration": options.build_configuration,
        "tag": options.tag,
    }
    for field, expected in checks.items():
        if expected is not None and coordinate[field] != expected:
            raise ArtifactError(f"candidate coordinate {field} does not match")
    if archive.name != archive_value["fileName"]:
        raise ArtifactError("candidate archive filename does not match the descriptor")
    if (
        sha256_file(archive) != archive_value["sha256"]
        or archive.stat().st_size != archive_value["size"]
    ):
        raise ArtifactError("candidate archive bytes do not match the descriptor")
    if (
        identity.version != coordinate["version"]
        or identity.package_name != archive_value["packageName"]
        or (
            identity.source_commit is not None
            and identity.source_commit != coordinate["sourceCommit"]
        )
    ):
        raise ArtifactError("candidate package identity does not match the descriptor")
    if coordinate["component"] == "python" and options.distribution_directory is not None:
        distributions = sorted(
            item.name
            for item in options.distribution_directory.iterdir()
            if item.is_file()
            and (
                item.name.endswith(".whl")
                or item.name.endswith(".tar.gz")
                or item.name.endswith(".zip")
            )
        )
        if distributions != [archive.name]:
            raise ArtifactError(
                "Python candidate directory must contain exactly the described wheel"
            )
    metadata_value = descriptor.get("cratesIoUploadMetadata")
    if coordinate["component"] == "rust":
        if options.upload_metadata is None or not isinstance(metadata_value, dict):
            raise ArtifactError("Rust candidate verification requires upload metadata")
        validate_upload_metadata(options.upload_metadata, identity, archive)
        if (
            options.upload_metadata.name != metadata_value.get("fileName")
            or sha256_file(options.upload_metadata) != metadata_value.get("sha256")
            or options.upload_metadata.stat().st_size != metadata_value.get("size")
        ):
            raise ArtifactError("crates.io upload metadata does not match the descriptor")
    return descriptor


def result_fragment(options: argparse.Namespace) -> dict[str, Any]:
    descriptor = verify_candidate(options)
    return {
        "schemaVersion": 1,
        "candidateDescriptorSha256": sha256_file(options.descriptor),
        "archiveSha256": descriptor["archive"]["sha256"],
        "component": descriptor["coordinate"]["component"],
        "version": descriptor["coordinate"]["version"],
        "matrix": {"kind": options.matrix_kind, "value": options.matrix_value},
        "status": "passed",
        "workflowRunId": descriptor["coordinate"]["workflowRunId"],
        "workflowRunAttempt": descriptor["coordinate"]["workflowRunAttempt"],
    }


def add_verification_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--descriptor", type=Path, required=True)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--component", choices=BUILD_CONFIGURATIONS)
    parser.add_argument("--version")
    parser.add_argument("--source-commit", dest="source_commit")
    parser.add_argument("--workflow-run-id")
    parser.add_argument("--workflow-run-attempt")
    parser.add_argument("--build-configuration")
    parser.add_argument("--tag")
    parser.add_argument("--upload-metadata", type=Path)
    parser.add_argument("--distribution-directory", type=Path)


def parse_arguments(arguments: Iterable[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="action", required=True)

    inspect_parser = subparsers.add_parser("inspect")
    inspect_parser.add_argument("--component", choices=BUILD_CONFIGURATIONS, required=True)
    inspect_parser.add_argument("--archive", type=Path, required=True)

    metadata_parser = subparsers.add_parser("rust-upload-metadata")
    metadata_parser.add_argument("--archive", type=Path, required=True)
    metadata_parser.add_argument("--output", type=Path, required=True)

    describe_parser = subparsers.add_parser("describe")
    describe_parser.add_argument("--component", choices=BUILD_CONFIGURATIONS, required=True)
    describe_parser.add_argument("--archive", type=Path, required=True)
    describe_parser.add_argument("--contract-provenance", type=Path, required=True)
    describe_parser.add_argument("--output", type=Path, required=True)
    describe_parser.add_argument("--source-commit", dest="source_commit")
    describe_parser.add_argument(
        "--workflow-run-id", default=os.environ.get("GITHUB_RUN_ID", "local")
    )
    describe_parser.add_argument(
        "--workflow-run-attempt", default=os.environ.get("GITHUB_RUN_ATTEMPT", "1")
    )
    describe_parser.add_argument("--build-configuration")
    describe_parser.add_argument("--tag")
    describe_parser.add_argument("--upload-metadata", type=Path)

    verify_parser = subparsers.add_parser("verify")
    add_verification_arguments(verify_parser)

    result_parser = subparsers.add_parser("result")
    add_verification_arguments(result_parser)
    result_parser.add_argument("--matrix-kind", required=True)
    result_parser.add_argument("--matrix-value", required=True)
    result_parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args(list(arguments))


def run(arguments: Iterable[str]) -> None:
    options = parse_arguments(arguments)
    if options.action == "inspect":
        identity = inspect_archive(options.component, options.archive.resolve())
        print(f"verified {identity.package_name} {identity.version} ({len(identity.files)} files)")
    elif options.action == "rust-upload-metadata":
        write_bytes(options.output, canonical_json(crate_upload_metadata(options.archive)))
    elif options.action == "describe":
        descriptor = build_descriptor(options)
        write_bytes(options.output, canonical_json(descriptor))
        print(sha256_file(options.output))
    elif options.action == "verify":
        descriptor = verify_candidate(options)
        print(descriptor["archive"]["sha256"])
    elif options.action == "result":
        fragment = result_fragment(options)
        write_bytes(options.output, canonical_json(fragment))
        print(fragment["archiveSha256"])


def main() -> int:
    try:
        run(sys.argv[1:])
    except (
        ArtifactError,
        OSError,
        UnicodeError,
        json.JSONDecodeError,
        tomllib.TOMLDecodeError,
    ) as error:
        print(f"SDK artifact verification failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
