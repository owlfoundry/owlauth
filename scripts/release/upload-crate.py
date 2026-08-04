#!/usr/bin/env python3
"""Upload one previously qualified .crate archive without rebuilding it."""

from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import os
import struct
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from types import SimpleNamespace
from typing import Any

SCRIPTS_DIRECTORY = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(SCRIPTS_DIRECTORY))

from sdk_artifact import (  # noqa: E402
    ArtifactError,
    canonical_json,
    load_json,
    verify_candidate,
)

MAX_CRATE_BYTES = 20 * 1024 * 1024
MAX_RESPONSE_BYTES = 64 * 1024
USER_AGENT = "owlauth-exact-crate-uploader/1"


class UploadError(RuntimeError):
    """Raised when an exact-byte crate upload cannot be proven safe."""


class RefuseRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self, request: Any, file_pointer: Any, code: int, message: str, headers: Any, new_url: str
    ) -> None:
        del request, file_pointer, code, message, headers, new_url
        return None


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--metadata", type=Path, required=True)
    parser.add_argument("--descriptor", type=Path, required=True)
    parser.add_argument("--expected-version", required=True)
    parser.add_argument("--expected-source-commit", required=True)
    parser.add_argument("--expected-workflow-run-id", required=True)
    parser.add_argument("--expected-workflow-run-attempt", required=True)
    parser.add_argument("--expected-tag", required=True)
    parser.add_argument("--registry-base-url", default="https://crates.io")
    parser.add_argument("--token-env", default="CARGO_REGISTRY_TOKEN")
    parser.add_argument("--allow-http-loopback", action="store_true")
    parser.add_argument("--poll-attempts", type=int, default=12)
    parser.add_argument("--poll-delay", type=float, default=5.0)
    parser.add_argument("--timeout", type=float, default=20.0)
    return parser.parse_args()


def registry_base_url(value: str, allow_http_loopback: bool) -> str:
    parsed = urllib.parse.urlsplit(value)
    if (
        not parsed.netloc
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.path not in ("", "/")
    ):
        raise UploadError("registry base URL must be one origin root")
    loopback = parsed.hostname in {"127.0.0.1", "::1", "localhost"}
    if parsed.scheme != "https" and not (
        parsed.scheme == "http" and allow_http_loopback and loopback
    ):
        raise UploadError("registry base URL must use HTTPS")
    return value.rstrip("/")


def read_json_response(response: Any) -> Any:
    content_type = response.headers.get_content_type()
    if content_type != "application/json":
        raise UploadError("registry returned a non-JSON response")
    try:
        content = response.read(MAX_RESPONSE_BYTES + 1)
    except (OSError, http.client.HTTPException) as error:
        raise UploadError("registry response was truncated") from error
    if len(content) > MAX_RESPONSE_BYTES:
        raise UploadError("registry returned an oversized response")
    try:
        return json.loads(content)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise UploadError("registry returned malformed JSON") from error


def request_json(
    opener: urllib.request.OpenerDirector,
    url: str,
    *,
    method: str,
    timeout: float,
    body: bytes | None = None,
    token: str | None = None,
) -> tuple[int, Any]:
    headers = {"Accept": "application/json", "User-Agent": USER_AGENT}
    if body is not None:
        headers["Content-Type"] = "application/octet-stream"
    if token is not None:
        headers["Authorization"] = token
    request = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        response = opener.open(request, timeout=timeout)
    except urllib.error.HTTPError as error:
        if error.code in {404, 409}:
            return error.code, None
        raise UploadError(f"registry request failed with HTTP {error.code}") from None
    except (OSError, urllib.error.URLError) as error:
        raise UploadError(f"registry request failed: {type(error).__name__}") from None
    with response:
        status = response.status
        value = read_json_response(response)
    if not 200 <= status < 300:
        raise UploadError(f"registry request failed with HTTP {status}")
    if isinstance(value, dict) and value.get("errors"):
        raise UploadError("registry returned an application error")
    return status, value


def registry_checksum(
    opener: urllib.request.OpenerDirector,
    base_url: str,
    name: str,
    version: str,
    timeout: float,
) -> str | None:
    path = "/api/v1/crates/{}/{}".format(
        urllib.parse.quote(name, safe=""), urllib.parse.quote(version, safe="")
    )
    status, value = request_json(opener, base_url + path, method="GET", timeout=timeout)
    if status == 404:
        return None
    if not isinstance(value, dict) or not isinstance(value.get("version"), dict):
        raise UploadError("registry version lookup has an invalid shape")
    checksum = value["version"].get("checksum")
    if not isinstance(checksum, str) or len(checksum) != 64:
        raise UploadError("registry version lookup omitted its checksum")
    try:
        int(checksum, 16)
    except ValueError as error:
        raise UploadError("registry returned an invalid checksum") from error
    return checksum.lower()


def preflight(options: argparse.Namespace) -> tuple[dict[str, Any], bytes, bytes, str, str]:
    expected_tag = f"rust-v{options.expected_version}"
    if options.expected_tag != expected_tag:
        raise UploadError("expected Rust release tag does not match the release version")
    base_url = registry_base_url(options.registry_base_url, options.allow_http_loopback)
    if options.poll_attempts < 1 or options.poll_attempts > 60:
        raise UploadError("poll attempts must be between 1 and 60")
    if options.poll_delay < 0 or options.poll_delay > 30 or options.timeout <= 0:
        raise UploadError("poll delay or request timeout is invalid")
    verification = SimpleNamespace(
        descriptor=options.descriptor,
        archive=options.archive,
        component="rust",
        version=options.expected_version,
        source_commit=options.expected_source_commit,
        workflow_run_id=options.expected_workflow_run_id,
        workflow_run_attempt=options.expected_workflow_run_attempt,
        build_configuration="rust-cargo-package-v1",
        tag=options.expected_tag,
        upload_metadata=options.metadata,
        distribution_directory=None,
    )
    descriptor = dict(verify_candidate(verification))
    coordinate = descriptor["coordinate"]
    if coordinate["tag"] != expected_tag or coordinate["component"] != "rust":
        raise UploadError("crate uploader accepts only tag-qualified Rust release candidates")
    token = os.environ.get(options.token_env, "")
    if not token or len(token) > 4096 or "\n" in token or "\r" in token:
        raise UploadError(f"{options.token_env} must contain one bounded registry token")
    metadata = load_json(options.metadata)
    raw_metadata = options.metadata.read_bytes()
    if not raw_metadata or len(raw_metadata) > 1024 * 1024:
        raise UploadError("crates.io upload metadata size is invalid")
    if raw_metadata != canonical_json(metadata):
        raise UploadError("crates.io upload metadata is not canonical JSON")
    if not isinstance(metadata, dict):
        raise UploadError("crates.io upload metadata must be an object")
    archive_bytes = options.archive.read_bytes()
    if not archive_bytes or len(archive_bytes) > MAX_CRATE_BYTES:
        raise UploadError("crate archive size is invalid")
    if hashlib.sha256(archive_bytes).hexdigest() != descriptor["archive"]["sha256"]:
        raise UploadError("crate archive changed after candidate verification")
    return metadata, raw_metadata, archive_bytes, token, base_url


def wait_for_checksum(
    opener: urllib.request.OpenerDirector,
    base_url: str,
    name: str,
    version: str,
    expected_checksum: str,
    *,
    attempts: int,
    delay: float,
    timeout: float,
) -> str:
    for attempt in range(attempts):
        checksum = registry_checksum(opener, base_url, name, version, timeout)
        if checksum is not None:
            if checksum != expected_checksum:
                raise UploadError("registry checksum differs from the qualified crate bytes")
            return expected_checksum
        if attempt + 1 < attempts:
            time.sleep(delay)
    raise UploadError("registry did not expose the qualified candidate checksum")


def upload(options: argparse.Namespace) -> str:
    metadata, raw_metadata, archive_bytes, token, base_url = preflight(options)
    name = metadata["name"]
    version = metadata["vers"]
    expected_checksum = hashlib.sha256(archive_bytes).hexdigest()
    opener = urllib.request.build_opener(RefuseRedirects())
    existing = registry_checksum(opener, base_url, name, version, options.timeout)
    if existing is not None:
        if existing != expected_checksum:
            raise UploadError("registry already contains different bytes for this crate version")
        return expected_checksum
    body = (
        struct.pack("<I", len(raw_metadata))
        + raw_metadata
        + struct.pack("<I", len(archive_bytes))
        + archive_bytes
    )
    status, value = request_json(
        opener,
        base_url + "/api/v1/crates/new",
        method="PUT",
        timeout=options.timeout,
        body=body,
        token=token,
    )
    if status != 409 and not isinstance(value, dict):
        raise UploadError("registry publish response has an invalid shape")
    return wait_for_checksum(
        opener,
        base_url,
        name,
        version,
        expected_checksum,
        attempts=options.poll_attempts,
        delay=options.poll_delay,
        timeout=options.timeout,
    )


def main() -> int:
    options = parse_arguments()
    try:
        checksum = upload(options)
    except (ArtifactError, UploadError, OSError, UnicodeError, ValueError) as error:
        print(f"exact crate upload failed: {error}", file=sys.stderr)
        return 1
    print(checksum)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
