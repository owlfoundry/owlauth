#!/usr/bin/env python3
"""Reject a stale local development environment before starting infrastructure."""

from __future__ import annotations

import re
import shlex
import sys
from pathlib import Path

ASSIGNMENT = re.compile(r"^([A-Z][A-Z0-9_]*)=(.*)$")
KNOWN_ENVIRONMENT_BLOCK = re.compile(
    r"const KNOWN_ENVIRONMENT_KEYS: &\[&str\] = &\[(.*?)\];",
    re.DOTALL,
)
KNOWN_ENVIRONMENT_KEY = re.compile(r'"(OWLAUTH_[A-Z0-9_]+)"')
SERVER_CONFIG = (
    Path(__file__).resolve().parents[1] / "crates" / "owlauth-server" / "src" / "config.rs"
)


def assignments(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for line_number, raw_line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            words = shlex.split(line, comments=True, posix=True)
        except ValueError as error:
            raise ValueError(f"{path}:{line_number}: invalid shell assignment") from error
        if len(words) != 1:
            raise ValueError(f"{path}:{line_number}: expected one KEY=value assignment")
        match = ASSIGNMENT.fullmatch(words[0])
        if match is None:
            raise ValueError(f"{path}:{line_number}: expected KEY=value")
        values[match.group(1)] = match.group(2)
    return values


def known_environment_keys(path: Path = SERVER_CONFIG) -> set[str]:
    source = path.read_text(encoding="utf-8")
    block = KNOWN_ENVIRONMENT_BLOCK.search(source)
    if block is None:
        raise ValueError(f"{path}: KNOWN_ENVIRONMENT_KEYS not found")
    keys = set(KNOWN_ENVIRONMENT_KEY.findall(block.group(1)))
    if not keys:
        raise ValueError(f"{path}: KNOWN_ENVIRONMENT_KEYS is empty")
    return keys


def main() -> int:
    template_path = Path(".env.example")
    local_path = Path(".env")
    if not local_path.is_file():
        print("Missing .env; run: cp .env.example .env", file=sys.stderr)
        return 1

    try:
        template = assignments(template_path)
        local = assignments(local_path)
        known = known_environment_keys()
    except (OSError, UnicodeError, ValueError) as error:
        print(f"Cannot validate the local development environment: {error}", file=sys.stderr)
        return 1

    missing = sorted(template.keys() - local.keys())
    empty = sorted(key for key in template.keys() & local.keys() if local[key] == "")
    unknown = sorted(
        key
        for key in template.keys() | local.keys()
        if key.startswith("OWLAUTH_") and key not in known
    )
    if not missing and not empty and not unknown:
        return 0

    print("Local .env is out of date with .env.example.", file=sys.stderr)
    if missing:
        print("Missing settings:", file=sys.stderr)
        for key in missing:
            print(f"  {key}", file=sys.stderr)
    if empty:
        print("Empty settings:", file=sys.stderr)
        for key in empty:
            print(f"  {key}", file=sys.stderr)
    if unknown:
        print("Unknown or obsolete settings:", file=sys.stderr)
        for key in unknown:
            print(f"  {key}", file=sys.stderr)
    print(
        "Refresh it with `cp .env .env.backup && cp .env.example .env`, then "
        "reapply intentional local overrides; never reuse the disposable example "
        "secrets outside development.",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
