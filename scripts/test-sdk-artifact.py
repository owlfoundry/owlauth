#!/usr/bin/env python3
"""Focused tests for immutable SDK candidate inspection and verification."""

from __future__ import annotations

import io
import json
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
    validate_upload_metadata,
    verify_candidate,
)

VERSION = json.loads((REPOSITORY_ROOT / "sdks/typescript/package.json").read_text())["version"]
COMMIT = "1" * 40


def add_tar_file(archive: tarfile.TarFile, name: str, content: bytes) -> None:
    member = tarfile.TarInfo(name)
    member.size = len(content)
    member.mode = 0o644
    archive.addfile(member, io.BytesIO(content))


def typescript_archive(path: Path, *, unsafe: bool = False) -> None:
    package = (REPOSITORY_ROOT / "sdks/typescript/package.json").read_bytes()
    contents = {
        "package/LICENSE": (REPOSITORY_ROOT / "sdks/typescript/LICENSE").read_bytes(),
        "package/README.md": (REPOSITORY_ROOT / "sdks/typescript/README.md").read_bytes(),
        "package/package.json": package,
        "package/dist/client.d.ts": b"export {};\n",
        "package/dist/client.js": b"export {};\n",
        "package/dist/errors.d.ts": b"export {};\n",
        "package/dist/errors.js": b"export {};\n",
        "package/dist/index.d.ts": b"export declare const VERSION: string;\n",
        "package/dist/index.js": f'export const VERSION = "{VERSION}";\n'.encode(),
        "package/dist/types.d.ts": b"export {};\n",
        "package/dist/types.js": b"export {};\n",
    }
    if unsafe:
        contents["package/../escape"] = b"escape"
    with tarfile.open(path, "w:gz") as archive:
        for name, content in contents.items():
            add_tar_file(archive, name, content)


def python_wheel(path: Path) -> None:
    dist = f"owlauth_client-{VERSION}.dist-info"
    contents = {
        "owlauth/__init__.py": f'__version__ = "{VERSION}"\n'.encode(),
        "owlauth/client.py": b"",
        "owlauth/conformance.py": b"",
        "owlauth/errors.py": b"",
        "owlauth/models.py": b"",
        "owlauth/py.typed": b"",
        "owlauth/transport.py": b"",
        f"{dist}/METADATA": (
            f"Metadata-Version: 2.4\nName: owlauth-client\nVersion: {VERSION}\n"
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
        version=VERSION,
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
    archive = root / f"owlauth-client-{VERSION}.tgz"
    provenance = root / "contract.json"
    descriptor = root / "candidate.json"
    contract(provenance)
    typescript_archive(archive)
    identity = inspect_archive("typescript", archive)
    assert identity.version == VERSION and len(identity.files) == 11
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
    archive = root / f"owlauth_client-{VERSION}-py3-none-any.whl"
    provenance = root / "python-contract.json"
    descriptor = root / "python-candidate.json"
    contract(provenance)
    python_wheel(archive)
    describe("python", archive, provenance, descriptor)
    options = verification("python", archive, descriptor)
    options.build_configuration = "python-hatch-wheel-v1"
    options.distribution_directory = root
    assert verify_candidate(options)["coordinate"]["component"] == "python"
    extra = root / "owlauth_client-0.0.1.tar.gz"
    extra.write_bytes(b"forbidden sdist")
    assert_fails(lambda: verify_candidate(options))


def test_rust_upload_metadata_is_reconstructed_from_exact_crate(root: Path) -> None:
    archive_path = root / f"owlauth-client-{VERSION}.crate"
    package_root = f"owlauth-client-{VERSION}"
    manifest = f'''[package]
name = "owlauth-client"
version = "{VERSION}"
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
        "src/client.rs": b"",
        "src/error.rs": b"",
        "src/lib.rs": b'pub const VERSION: &str = env!("CARGO_PKG_VERSION");\n',
        "src/models.rs": b"",
        "src/transport.rs": b"",
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

    metadata_path = root / f"owlauth-client-{VERSION}.upload.json"
    metadata_path.write_bytes(canonical_json(result))
    assert validate_upload_metadata(metadata_path, identity, archive_path) == result
    mutated = json.loads(metadata_path.read_text())
    mutated["deps"][0]["version_req"] = "^9.0.0"
    metadata_path.write_bytes(canonical_json(mutated))
    assert_fails(lambda: validate_upload_metadata(metadata_path, identity, archive_path))


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
        test_archive_resource_bounds(root)
    with tempfile.TemporaryDirectory() as temporary_directory:
        root = Path(temporary_directory)
        test_corpus_digest_covers_fixture_tree(root)
    test_release_tag_is_component_scoped()
    print("SDK artifact tests passed")


if __name__ == "__main__":
    main()
