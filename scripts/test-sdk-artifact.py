#!/usr/bin/env python3
"""Focused tests for immutable SDK candidate inspection and verification."""

from __future__ import annotations

import hashlib
import io
import json
import re
import shutil
import sys
import tarfile
import tempfile
import zipfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

SCRIPT_DIRECTORY = Path(__file__).resolve().parent
REPOSITORY_ROOT = SCRIPT_DIRECTORY.parent
sys.path.insert(0, str(SCRIPT_DIRECTORY))

import sdk_artifact  # noqa: E402
from sdk_artifact import (  # noqa: E402
    ArtifactError,
    build_descriptor,
    canonical_json,
    corpus_provenance,
    crate_upload_metadata,
    effective_tag,
    inspect_archive,
    read_tar,
    read_wheel,
    validate_candidate_version,
    validate_upload_metadata,
    verify_candidate,
)


def manifest_version(path: Path, section: str) -> str:
    text = path.read_text(encoding="utf-8")
    match = re.search(
        rf"^\[{re.escape(section)}\]\n(?P<body>.*?)(?=^\[|\Z)",
        text,
        flags=re.MULTILINE | re.DOTALL,
    )
    assert match is not None
    version = re.search(r'^version = "([^"]+)"$', match.group("body"), flags=re.MULTILINE)
    assert version is not None
    return version.group(1)


TYPESCRIPT_VERSION = json.loads((REPOSITORY_ROOT / "sdks/typescript/package.json").read_text())[
    "version"
]
PYTHON_VERSION = manifest_version(REPOSITORY_ROOT / "sdks/python/pyproject.toml", "project")
RUST_VERSION = manifest_version(REPOSITORY_ROOT / "sdks/rust/Cargo.toml", "package")
COMPONENT_VERSIONS = {
    "typescript": TYPESCRIPT_VERSION,
    "python": PYTHON_VERSION,
    "rust": RUST_VERSION,
}
# Imported by the focused TypeScript release-candidate verifier tests.
VERSION = TYPESCRIPT_VERSION
COMMIT = "1" * 40


def add_tar_file(archive: tarfile.TarFile, name: str, content: bytes) -> None:
    member = tarfile.TarInfo(name)
    member.size = len(content)
    member.mode = 0o644
    archive.addfile(member, io.BytesIO(content))


def typescript_dist(
    *, version: str = TYPESCRIPT_VERSION, injected: bytes = b""
) -> dict[str, bytes]:
    return {
        "client.d.ts": b"export {};\n",
        "client.js": b"export {};\n" + injected,
        "errors.d.ts": b"export {};\n",
        "errors.js": b"export {};\n",
        "index.d.ts": f'export declare const VERSION = "{version}";\n'.encode(),
        "index.js": f'export const VERSION = "{version}";\n'.encode(),
        "types.d.ts": b"export {};\n",
        "types.js": b"export {};\n",
    }


def typescript_surface_manifest(path: Path, *, version: str = TYPESCRIPT_VERSION) -> None:
    digests: dict[str, str] = {}
    for name, content in typescript_dist(version=version).items():
        if name in {"index.js", "index.d.ts"}:
            content = content.replace(version.encode(), b"<VERSION>")
        digests[name] = hashlib.sha256(content).hexdigest()
    path.write_bytes(
        canonical_json(
            {
                "schemaVersion": 1,
                "normalization": "test fixture",
                "files": digests,
            }
        )
    )


def typescript_archive(
    path: Path,
    *,
    version: str = TYPESCRIPT_VERSION,
    unsafe: bool = False,
    injected: bytes = b"",
) -> None:
    package_document = json.loads(
        (REPOSITORY_ROOT / "sdks/typescript/package.json").read_text(encoding="utf-8")
    )
    package_document["version"] = version
    package = (json.dumps(package_document, indent=2) + "\n").encode()
    dist = typescript_dist(version=version, injected=injected)
    contents = {
        "package/LICENSE": (REPOSITORY_ROOT / "sdks/typescript/LICENSE").read_bytes(),
        "package/README.md": (REPOSITORY_ROOT / "sdks/typescript/README.md").read_bytes(),
        "package/package.json": package,
        **{f"package/dist/{name}": content for name, content in dist.items()},
    }
    if unsafe:
        contents["package/../escape"] = b"escape"
    with tarfile.open(path, "w:gz") as archive:
        for name, content in contents.items():
            add_tar_file(archive, name, content)


def python_wheel(path: Path, *, injected: bytes = b"") -> None:
    dist = f"owlauth_client-{PYTHON_VERSION}.dist-info"
    contents = {
        "owlauth/__init__.py": (
            REPOSITORY_ROOT / "sdks/python/src/owlauth/__init__.py"
        ).read_bytes(),
        "owlauth/_json.py": (
            REPOSITORY_ROOT / "sdks/python/src/owlauth/_json.py"
        ).read_bytes(),
        "owlauth/client.py": (REPOSITORY_ROOT / "sdks/python/src/owlauth/client.py").read_bytes()
        + injected,
        "owlauth/conformance.py": (
            REPOSITORY_ROOT / "sdks/python/src/owlauth/conformance.py"
        ).read_bytes(),
        "owlauth/errors.py": (REPOSITORY_ROOT / "sdks/python/src/owlauth/errors.py").read_bytes(),
        "owlauth/models.py": (REPOSITORY_ROOT / "sdks/python/src/owlauth/models.py").read_bytes(),
        "owlauth/py.typed": (REPOSITORY_ROOT / "sdks/python/src/owlauth/py.typed").read_bytes(),
        "owlauth/transport.py": (
            REPOSITORY_ROOT / "sdks/python/src/owlauth/transport.py"
        ).read_bytes(),
        f"{dist}/METADATA": (
            f"Metadata-Version: 2.4\nName: owlauth-client\nVersion: {PYTHON_VERSION}\n"
            "License-Expression: BSD-3-Clause\n\n"
            + (REPOSITORY_ROOT / "sdks/python/README.md").read_text()
        ).encode(),
        f"{dist}/RECORD": b"",
        f"{dist}/WHEEL": b"Wheel-Version: 1.0\nTag: py3-none-any\n",
        f"{dist}/licenses/LICENSE": (REPOSITORY_ROOT / "sdks/python/LICENSE").read_bytes(),
    }
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, content in contents.items():
            archive.writestr(name, content)


def rust_crate(path: Path, *, injected: bytes = b"") -> None:
    package_root = f"owlauth-client-{RUST_VERSION}"
    manifest = f'''[package]
name = "owlauth-client"
version = "{RUST_VERSION}"
edition = "2024"
description = "Rust Project Auth client for OwlAuth"
readme = "README.md"
keywords = ["authentication", "identity", "project-auth", "client"]
categories = ["authentication", "api-bindings"]
license = "BSD-3-Clause"
repository = "https://github.com/owlfoundry/owlauth"

[dependencies.serde]
version = "1.0.229"
features = ["derive"]

[dev-dependencies.tokio]
version = "1.53.1"
features = ["macros", "rt"]
'''.encode()
    files = {
        ".cargo_vcs_info.json": canonical_json(
            {"git": {"sha1": COMMIT}, "path_in_vcs": "sdks/rust"}
        ),
        "Cargo.lock": b"version = 4\n",
        "Cargo.toml": manifest,
        "Cargo.toml.orig": manifest,
        "LICENSE": (REPOSITORY_ROOT / "sdks/rust/LICENSE").read_bytes(),
        "README.md": (REPOSITORY_ROOT / "sdks/rust/README.md").read_bytes(),
        "src/client.rs": (REPOSITORY_ROOT / "sdks/rust/src/client.rs").read_bytes() + injected,
        "src/error.rs": (REPOSITORY_ROOT / "sdks/rust/src/error.rs").read_bytes(),
        "src/lib.rs": (REPOSITORY_ROOT / "sdks/rust/src/lib.rs").read_bytes(),
        "src/models.rs": (REPOSITORY_ROOT / "sdks/rust/src/models.rs").read_bytes(),
        "src/transport.rs": (REPOSITORY_ROOT / "sdks/rust/src/transport.rs").read_bytes(),
    }
    with tarfile.open(path, "w:gz") as archive:
        for name, content in files.items():
            add_tar_file(archive, f"{package_root}/{name}", content)


def contract(path: Path) -> None:
    value = {
        "schemaVersion": 1,
        "sourceCommit": COMMIT,
        "owlauthTypesVersion": "0.0.1",
        "owlauthServerVersion": "0.0.1",
        "openapiVersion": "3.1.0",
        "fullRuntimeSha256": "2" * 64,
        "claimedSurfaceSha256": "3" * 64,
        "policySha256": "4" * 64,
        "normalizerVersion": 1,
        "claimedOperationIds": [
            "get_public_application_config",
            "get_project_jwks",
            "start_login",
            "exchange_handoff",
            "refresh_session",
            "get_current_user",
            "logout_application_session",
            "prepare_browser_logout",
        ],
    }
    path.write_bytes(canonical_json(value))


def describe(component: str, archive: Path, provenance: Path, output: Path) -> None:
    options = SimpleNamespace(
        component=component,
        archive=archive,
        contract_provenance=provenance,
        output=output,
        source_commit=COMMIT,
        workflow_run_id="123",
        workflow_run_attempt="2",
        build_configuration=None,
        tag=None,
        upload_metadata=None,
    )
    output.write_bytes(canonical_json(build_descriptor(options)))


def verification(component: str, archive: Path, descriptor: Path) -> SimpleNamespace:
    return SimpleNamespace(
        descriptor=descriptor,
        archive=archive,
        component=component,
        version=COMPONENT_VERSIONS[component],
        source_commit=COMMIT,
        workflow_run_id="123",
        workflow_run_attempt="2",
        build_configuration=f"{component}-npm-pack-v1" if component == "typescript" else None,
        tag=None,
        upload_metadata=None,
        distribution_directory=None,
    )


def assert_fails(function: object) -> None:
    try:
        function()  # type: ignore[operator]
    except (ArtifactError, OSError, tarfile.TarError, zipfile.BadZipFile):
        return
    raise AssertionError("invalid candidate must fail")


def test_typescript_descriptor_and_mutations(root: Path) -> None:
    surface = root / "typescript-artifact-surface.json"
    typescript_surface_manifest(surface)
    sdk_artifact.TYPESCRIPT_ARTIFACT_SURFACE_PATH = surface
    archive = root / f"owlauth-client-{TYPESCRIPT_VERSION}.tgz"
    provenance = root / "contract.json"
    descriptor = root / "candidate.json"
    contract(provenance)
    typescript_archive(archive)
    identity = inspect_archive("typescript", archive)
    assert identity.version == TYPESCRIPT_VERSION and len(identity.files) == 11
    describe("typescript", archive, provenance, descriptor)
    options = verification("typescript", archive, descriptor)
    assert verify_candidate(options)["archive"]["fileName"] == archive.name

    fields = {
        "component": "python",
        "version": "9.9.9",
        "source_commit": "9" * 40,
        "workflow_run_id": "other",
        "workflow_run_attempt": "9",
        "build_configuration": "other-build",
        "tag": "typescript-v9.9.9",
    }
    for field, bad_value in fields.items():
        mutated = SimpleNamespace(**vars(options))
        setattr(mutated, field, bad_value)
        assert_fails(lambda mutated=mutated: verify_candidate(mutated))

    changed = root / "changed.tgz"
    shutil.copyfile(archive, changed)
    with changed.open("ab") as target:
        target.write(b"changed")
    mutated = SimpleNamespace(**vars(options))
    mutated.archive = changed
    assert_fails(lambda: verify_candidate(mutated))

    unsafe = root / "unsafe.tgz"
    typescript_archive(unsafe, unsafe=True)
    assert_fails(lambda: inspect_archive("typescript", unsafe))


def test_python_rejects_extra_distribution(root: Path) -> None:
    archive = root / f"owlauth_client-{PYTHON_VERSION}-py3-none-any.whl"
    provenance = root / "python-contract.json"
    descriptor = root / "python-candidate.json"
    contract(provenance)
    python_wheel(archive)
    describe("python", archive, provenance, descriptor)
    options = verification("python", archive, descriptor)
    options.build_configuration = "python-hatch-wheel-v1"
    options.distribution_directory = root
    assert verify_candidate(options)["coordinate"]["component"] == "python"

    tagged_descriptor = root / "tagged-python-candidate.json"
    tagged = json.loads(descriptor.read_text(encoding="utf-8"))
    tagged["coordinate"]["tag"] = f"python-v{PYTHON_VERSION}"
    tagged_descriptor.write_bytes(canonical_json(tagged))
    tagged_options = SimpleNamespace(**vars(options))
    tagged_options.descriptor = tagged_descriptor
    assert_fails(lambda: verify_candidate(tagged_options))

    extra = root / "owlauth_client-0.0.1.tar.gz"
    extra.write_bytes(b"forbidden sdist")
    assert_fails(lambda: verify_candidate(options))


def test_rust_upload_metadata_is_reconstructed_from_exact_crate(root: Path) -> None:
    archive_path = root / f"owlauth-client-{RUST_VERSION}.crate"
    package_root = f"owlauth-client-{RUST_VERSION}"
    manifest = f'''[package]
name = "owlauth-client"
version = "{RUST_VERSION}"
edition = "2024"
description = "Rust Project Auth client for OwlAuth"
readme = "README.md"
keywords = ["authentication", "identity", "project-auth", "client"]
categories = ["authentication", "api-bindings"]
license = "BSD-3-Clause"
repository = "https://github.com/owlfoundry/owlauth"

[dependencies.serde]
version = "1.0.229"
features = ["derive"]

[dev-dependencies.tokio]
version = "1.53.1"
features = ["macros", "rt"]
'''.encode()
    files = {
        ".cargo_vcs_info.json": canonical_json(
            {"git": {"sha1": COMMIT}, "path_in_vcs": "sdks/rust"}
        ),
        "Cargo.lock": b"version = 4\n",
        "Cargo.toml": manifest,
        "Cargo.toml.orig": manifest,
        "LICENSE": (REPOSITORY_ROOT / "sdks/rust/LICENSE").read_bytes(),
        "README.md": (REPOSITORY_ROOT / "sdks/rust/README.md").read_bytes(),
        "src/client.rs": (REPOSITORY_ROOT / "sdks/rust/src/client.rs").read_bytes(),
        "src/error.rs": (REPOSITORY_ROOT / "sdks/rust/src/error.rs").read_bytes(),
        "src/lib.rs": (REPOSITORY_ROOT / "sdks/rust/src/lib.rs").read_bytes(),
        "src/models.rs": (REPOSITORY_ROOT / "sdks/rust/src/models.rs").read_bytes(),
        "src/transport.rs": (REPOSITORY_ROOT / "sdks/rust/src/transport.rs").read_bytes(),
    }
    with tarfile.open(archive_path, "w:gz") as archive:
        for name, content in files.items():
            add_tar_file(archive, f"{package_root}/{name}", content)
    identity = inspect_archive("rust", archive_path)
    result = crate_upload_metadata(archive_path)
    assert result["readme"] == (REPOSITORY_ROOT / "sdks/rust/README.md").read_text()
    assert result["deps"][0]["version_req"] == "^1.0.229"
    assert result["deps"][0]["kind"] == "normal"
    assert result["deps"][1]["kind"] == "dev"

    metadata_path = root / f"owlauth-client-{RUST_VERSION}.upload.json"
    metadata_path.write_bytes(canonical_json(result))
    assert validate_upload_metadata(metadata_path, identity, archive_path) == result
    mutated = json.loads(metadata_path.read_text())
    mutated["deps"][0]["version_req"] = "^9.0.0"
    metadata_path.write_bytes(canonical_json(mutated))
    assert_fails(lambda: validate_upload_metadata(metadata_path, identity, archive_path))


def test_sdk_archives_reject_client_plane_contamination(root: Path) -> None:
    surface = root / "typescript-artifact-surface.json"
    typescript_surface_manifest(surface)
    sdk_artifact.TYPESCRIPT_ARTIFACT_SURFACE_PATH = surface
    markers = (
        b"project_client_key",
        b"owl_client_v1.AAAAAAAAAAAAAAAAAAAAAA.secret",
        b"/v1/projects/{project_id}/tokens/introspect",
        b"owlauth-client-openapi.json",
        b"listProjectUsers(`/v1/projects/${projectId}/users`)",
        b"list_project_users(f'/v1/projects/{project_id}/users')",
        b'list_project_users(format!("/v1/projects/{project_id}/users"))',
    )
    for index, marker in enumerate(markers):
        typescript = root / f"contaminated-{index}.tgz"
        typescript_archive(typescript, injected=marker)
        assert_fails(lambda path=typescript: inspect_archive("typescript", path))

        python = root / f"contaminated-{index}.whl"
        python_wheel(python, injected=marker)
        assert_fails(lambda path=python: inspect_archive("python", path))

        rust = root / f"contaminated-{index}.crate"
        rust_crate(rust, injected=marker)
        assert_fails(lambda path=rust: inspect_archive("rust", path))


def test_archive_resource_bounds(root: Path) -> None:
    tar_path = root / "bounded.tgz"
    with tarfile.open(tar_path, "w:gz") as archive:
        for index in range(3):
            add_tar_file(archive, f"package/{index}", b"ab")
    with patch("sdk_artifact.MAX_ARCHIVE_BYTES", tar_path.stat().st_size - 1):
        assert_fails(lambda: read_tar(tar_path))
    with patch("sdk_artifact.MAX_ARCHIVE_MEMBERS", 2):
        assert_fails(lambda: read_tar(tar_path))
    with patch("sdk_artifact.MAX_EXPANDED_BYTES", 5):
        assert_fails(lambda: read_tar(tar_path))

    wheel_path = root / "bounded.whl"
    with zipfile.ZipFile(wheel_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for index in range(3):
            archive.writestr(f"package/{index}", b"ab")
    with patch("sdk_artifact.MAX_ARCHIVE_BYTES", wheel_path.stat().st_size - 1):
        assert_fails(lambda: read_wheel(wheel_path))
    with patch("sdk_artifact.MAX_ARCHIVE_MEMBERS", 2):
        assert_fails(lambda: read_wheel(wheel_path))
    with patch("sdk_artifact.MAX_EXPANDED_BYTES", 5):
        assert_fails(lambda: read_wheel(wheel_path))


def test_corpus_digest_covers_fixture_tree(root: Path) -> None:
    conformance = root / "spec/conformance"
    fixtures = root / "spec/fixtures"
    conformance.mkdir(parents=True)
    fixtures.mkdir(parents=True)
    fixture = fixtures / "response.json"
    fixture.write_bytes(canonical_json({"status": 200}))
    cases = conformance / "cases.json"
    document = {
        "schemaVersion": 3,
        "requiredCaseNames": ["one"],
        "cases": [{"name": "one", "fixture": "../fixtures/response.json"}],
    }
    cases.write_bytes(canonical_json(document))
    initial = corpus_provenance(cases)
    fixture.write_bytes(canonical_json({"status": 201}))
    assert corpus_provenance(cases)["sha256"] != initial["sha256"]

    fixture.write_bytes(canonical_json({"status": 200}))
    shared = fixtures / "shared.json"
    shared.write_bytes(canonical_json({"setup": True}))
    assert corpus_provenance(cases)["sha256"] != initial["sha256"]

    document["cases"][0]["fixture"] = "../../outside.json"
    cases.write_bytes(canonical_json(document))
    assert_fails(lambda: corpus_provenance(cases))


def test_candidate_versions_require_exact_tag_authority() -> None:
    valid = (
        ("typescript", TYPESCRIPT_VERSION, None),
        ("python", PYTHON_VERSION, None),
        ("rust", RUST_VERSION, None),
        ("typescript", "1.2.3", "typescript-v1.2.3"),
        ("python", "2.3.4", "python-v2.3.4"),
        ("rust", "3.4.5-rc.1", "rust-v3.4.5-rc.1"),
    )
    for component, version, tag in valid:
        validate_candidate_version(component, version, tag)

    invalid = (
        ("typescript", "1.2.3", None),
        ("python", "2.3.4", None),
        ("rust", "3.4.5", None),
        ("typescript", TYPESCRIPT_VERSION, f"typescript-v{TYPESCRIPT_VERSION}"),
        ("python", PYTHON_VERSION, f"python-v{PYTHON_VERSION}"),
        ("rust", RUST_VERSION, f"rust-v{RUST_VERSION}"),
        ("python", "2.3.4-rc.1", "python-v2.3.4-rc.1"),
        ("rust", "3.4.5", "typescript-v3.4.5"),
    )
    for component, version, tag in invalid:
        assert_fails(
            lambda component=component, version=version, tag=tag: validate_candidate_version(
                component, version, tag
            )
        )


def test_release_tag_is_component_scoped() -> None:
    with patch.dict(
        "os.environ",
        {"GITHUB_REF_TYPE": "tag", "GITHUB_REF_NAME": "python-v1.2.3"},
        clear=True,
    ):
        assert effective_tag("python") == "python-v1.2.3"
        assert effective_tag("typescript") is None
        assert effective_tag("rust") is None


def main() -> None:
    with tempfile.TemporaryDirectory() as temporary_directory:
        root = Path(temporary_directory)
        test_typescript_descriptor_and_mutations(root)
    with tempfile.TemporaryDirectory() as temporary_directory:
        root = Path(temporary_directory)
        test_python_rejects_extra_distribution(root)
    with tempfile.TemporaryDirectory() as temporary_directory:
        root = Path(temporary_directory)
        test_rust_upload_metadata_is_reconstructed_from_exact_crate(root)
    with tempfile.TemporaryDirectory() as temporary_directory:
        root = Path(temporary_directory)
        test_sdk_archives_reject_client_plane_contamination(root)
    with tempfile.TemporaryDirectory() as temporary_directory:
        root = Path(temporary_directory)
        test_archive_resource_bounds(root)
    with tempfile.TemporaryDirectory() as temporary_directory:
        root = Path(temporary_directory)
        test_corpus_digest_covers_fixture_tree(root)
    test_candidate_versions_require_exact_tag_authority()
    test_release_tag_is_component_scoped()
    print("SDK artifact tests passed")


if __name__ == "__main__":
    main()
