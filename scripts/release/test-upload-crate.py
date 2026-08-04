#!/usr/bin/env python3
"""Protocol tests for exact-byte crate upload against a disposable registry."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import struct
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from typing import Any

SCRIPT = Path(__file__).with_name("upload-crate.py")
SPEC = importlib.util.spec_from_file_location("upload_crate", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
upload_crate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(upload_crate)

METADATA = {
    "name": "owlauth-client",
    "vers": "1.2.3",
    "deps": [],
    "features": {},
    "authors": [],
    "description": "test",
    "documentation": None,
    "homepage": None,
    "readme": "test",
    "readme_file": "README.md",
    "keywords": [],
    "categories": [],
    "license": "BSD-3-Clause",
    "license_file": None,
    "repository": None,
    "badges": {},
    "links": None,
    "rust_version": None,
}
METADATA_BYTES = upload_crate.canonical_json(METADATA)
CRATE_BYTES = b"qualified-crate-bytes"
CHECKSUM = hashlib.sha256(CRATE_BYTES).hexdigest()


class RegistryState:
    checksum: str | None = None
    uploads = 0
    redirect = False
    malformed_lookup = False
    publish_status = 200
    stored_checksum_override: str | None = None
    captured_metadata: bytes | None = None
    captured_crate: bytes | None = None
    authorization: str | None = None


def handler_for(state: RegistryState) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: Any) -> None:
            del format, args

        def json_response(self, status: int, value: object) -> None:
            body = json.dumps(value).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:
            if state.redirect:
                self.send_response(302)
                self.send_header("Location", self.path)
                self.end_headers()
                return
            if state.malformed_lookup:
                body = b"not-json"
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            if self.path != "/api/v1/crates/owlauth-client/1.2.3":
                self.json_response(404, {"errors": [{"detail": "not found"}]})
            elif state.checksum is None:
                self.json_response(404, {"errors": [{"detail": "not found"}]})
            else:
                self.json_response(200, {"version": {"checksum": state.checksum}})

        def do_PUT(self) -> None:
            assert self.path == "/api/v1/crates/new"
            assert self.headers.get("Content-Type") == "application/octet-stream"
            state.authorization = self.headers.get("Authorization")
            content = self.rfile.read(int(self.headers["Content-Length"]))
            metadata_length = struct.unpack("<I", content[:4])[0]
            metadata_start = 4
            metadata_end = metadata_start + metadata_length
            crate_length = struct.unpack("<I", content[metadata_end : metadata_end + 4])[0]
            crate_start = metadata_end + 4
            state.captured_metadata = content[metadata_start:metadata_end]
            state.captured_crate = content[crate_start : crate_start + crate_length]
            assert crate_start + crate_length == len(content)
            state.uploads += 1
            state.checksum = (
                state.stored_checksum_override or hashlib.sha256(state.captured_crate).hexdigest()
            )
            self.json_response(
                state.publish_status,
                {"warnings": {"invalid_categories": [], "other": []}},
            )

    return Handler


def options(base_url: str) -> SimpleNamespace:
    return SimpleNamespace(
        registry_base_url=base_url,
        timeout=2.0,
        poll_attempts=2,
        poll_delay=0.0,
    )


def run_registry(state: RegistryState, test: Any) -> None:
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler_for(state))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        test(f"http://127.0.0.1:{server.server_port}")
    finally:
        server.shutdown()
        thread.join()
        server.server_close()


def with_preflight(base_url: str) -> tuple[SimpleNamespace, Any]:
    original = upload_crate.preflight
    upload_crate.preflight = lambda unused: (
        METADATA,
        METADATA_BYTES,
        CRATE_BYTES,
        "secret-token",
        base_url,
    )
    return options(base_url), original


def test_exact_upload() -> None:
    state = RegistryState()

    def exercise(base_url: str) -> None:
        args, original = with_preflight(base_url)
        try:
            assert upload_crate.upload(args) == CHECKSUM
        finally:
            upload_crate.preflight = original
        assert state.uploads == 1
        assert state.captured_metadata == METADATA_BYTES
        assert state.captured_crate == CRATE_BYTES
        assert state.authorization == "secret-token"

    run_registry(state, exercise)


def test_existing_checksum_is_idempotent() -> None:
    state = RegistryState()
    state.checksum = CHECKSUM

    def exercise(base_url: str) -> None:
        args, original = with_preflight(base_url)
        try:
            assert upload_crate.upload(args) == CHECKSUM
        finally:
            upload_crate.preflight = original
        assert state.uploads == 0

    run_registry(state, exercise)


def test_publish_conflict_accepts_only_the_same_checksum() -> None:
    state = RegistryState()
    state.publish_status = 409

    def exercise(base_url: str) -> None:
        args, original = with_preflight(base_url)
        try:
            assert upload_crate.upload(args) == CHECKSUM
        finally:
            upload_crate.preflight = original
        assert state.uploads == 1

    run_registry(state, exercise)


def test_post_upload_checksum_mismatch_fails() -> None:
    state = RegistryState()
    state.stored_checksum_override = "0" * 64

    def exercise(base_url: str) -> None:
        args, original = with_preflight(base_url)
        try:
            try:
                upload_crate.upload(args)
            except upload_crate.UploadError:
                pass
            else:
                raise AssertionError("post-upload checksum mismatch must fail")
        finally:
            upload_crate.preflight = original

    run_registry(state, exercise)


def test_registry_authentication_and_malformed_response_fail() -> None:
    for publish_status, malformed_lookup in ((403, False), (200, True)):
        state = RegistryState()
        state.publish_status = publish_status
        state.malformed_lookup = malformed_lookup

        def exercise(base_url: str) -> None:
            args, original = with_preflight(base_url)
            try:
                try:
                    upload_crate.upload(args)
                except upload_crate.UploadError as error:
                    assert "secret-token" not in str(error)
                else:
                    raise AssertionError("registry protocol failure must fail")
            finally:
                upload_crate.preflight = original

        run_registry(state, exercise)


def test_existing_different_checksum_fails() -> None:
    state = RegistryState()
    state.checksum = "0" * 64

    def exercise(base_url: str) -> None:
        args, original = with_preflight(base_url)
        try:
            try:
                upload_crate.upload(args)
            except upload_crate.UploadError:
                pass
            else:
                raise AssertionError("different registry bytes must fail")
        finally:
            upload_crate.preflight = original
        assert state.uploads == 0

    run_registry(state, exercise)


def test_redirect_is_refused() -> None:
    state = RegistryState()
    state.redirect = True

    def exercise(base_url: str) -> None:
        args, original = with_preflight(base_url)
        try:
            try:
                upload_crate.upload(args)
            except upload_crate.UploadError:
                pass
            else:
                raise AssertionError("registry redirects must fail")
        finally:
            upload_crate.preflight = original
        assert state.uploads == 0

    run_registry(state, exercise)


def test_preflight_binds_token_metadata_and_archive() -> None:
    with tempfile.TemporaryDirectory() as temporary_directory:
        root = Path(temporary_directory)
        archive = root / "owlauth-client-1.2.3.crate"
        metadata = root / "owlauth-client-1.2.3.upload.json"
        descriptor = root / "candidate.json"
        archive.write_bytes(CRATE_BYTES)
        metadata.write_bytes(METADATA_BYTES)
        descriptor.write_text("{}\n")
        args = SimpleNamespace(
            token_env="TEST_CRATES_TOKEN",
            registry_base_url="http://127.0.0.1:1234",
            allow_http_loopback=True,
            poll_attempts=1,
            poll_delay=0.0,
            timeout=1.0,
            descriptor=descriptor,
            archive=archive,
            metadata=metadata,
            expected_version="1.2.3",
            expected_source_commit="1" * 40,
            expected_workflow_run_id="123",
            expected_workflow_run_attempt="2",
            expected_tag="rust-v1.2.3",
        )
        original = upload_crate.verify_candidate

        def qualified_candidate(verification: SimpleNamespace) -> dict[str, object]:
            assert verification.version == "1.2.3"
            assert verification.source_commit == "1" * 40
            assert verification.workflow_run_id == "123"
            assert verification.workflow_run_attempt == "2"
            assert verification.tag == "rust-v1.2.3"
            return {
                "archive": {"sha256": CHECKSUM},
                "coordinate": {"component": "rust", "tag": "rust-v1.2.3"},
            }

        upload_crate.verify_candidate = qualified_candidate
        try:
            os.environ.pop("TEST_CRATES_TOKEN", None)
            try:
                upload_crate.preflight(args)
            except upload_crate.UploadError as error:
                assert "TEST_CRATES_TOKEN" in str(error)
            else:
                raise AssertionError("missing registry token must fail")
            os.environ["TEST_CRATES_TOKEN"] = "secret-token"
            result = upload_crate.preflight(args)
            assert result[1] == METADATA_BYTES
            assert result[2] == CRATE_BYTES
            assert result[3] == "secret-token"
            archive.write_bytes(b"changed")
            try:
                upload_crate.preflight(args)
            except upload_crate.UploadError as error:
                assert "secret-token" not in str(error)
            else:
                raise AssertionError("changed crate bytes must fail preflight")
            archive.write_bytes(CRATE_BYTES)
            upload_crate.verify_candidate = lambda unused: {
                "archive": {"sha256": CHECKSUM},
                "coordinate": {"component": "rust", "tag": None},
            }
            try:
                upload_crate.preflight(args)
            except upload_crate.UploadError:
                pass
            else:
                raise AssertionError("ordinary candidates must not reach the mutation boundary")
            args.expected_tag = "server-v1.2.3"
            try:
                upload_crate.preflight(args)
            except upload_crate.UploadError:
                pass
            else:
                raise AssertionError("cross-component tags must not reach the mutation boundary")
        finally:
            upload_crate.verify_candidate = original
            os.environ.pop("TEST_CRATES_TOKEN", None)


def test_registry_url_policy() -> None:
    assert upload_crate.registry_base_url("https://crates.io", False) == "https://crates.io"
    assert upload_crate.registry_base_url("http://127.0.0.1:1234", True).startswith("http://")
    for value in ("http://crates.io", "https://user@crates.io", "https://crates.io/path"):
        try:
            upload_crate.registry_base_url(value, False)
        except upload_crate.UploadError:
            continue
        raise AssertionError(f"unsafe registry URL accepted: {value}")


def main() -> None:
    test_exact_upload()
    test_existing_checksum_is_idempotent()
    test_publish_conflict_accepts_only_the_same_checksum()
    test_post_upload_checksum_mismatch_fails()
    test_registry_authentication_and_malformed_response_fail()
    test_existing_different_checksum_fails()
    test_redirect_is_refused()
    test_preflight_binds_token_metadata_and_archive()
    test_registry_url_policy()
    print("exact crate uploader tests passed")


if __name__ == "__main__":
    main()
