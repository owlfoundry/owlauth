#!/usr/bin/env python3
"""Tests for the shared server/CLI crate version sequence verifier."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

SCRIPT = Path(__file__).with_name("verify-shared-crate-version.py")


def verify(version: str, current_tag: str, tags: tuple[str, ...]) -> int:
    refs = "".join(
        f"{'1' * 40}\trefs/tags/{tag}\n{'2' * 40}\trefs/tags/{tag}^{{}}\n" for tag in tags
    )
    return subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--version",
            version,
            "--current-tag",
            current_tag,
        ],
        input=refs,
        text=True,
        capture_output=True,
        check=False,
    ).returncode


def main() -> None:
    assert verify("1.0.0", "server-v1.0.0", ("cli-v0.9.9", "server-v1.0.0")) == 0
    assert verify("1.0.0-beta.2", "cli-v1.0.0-beta.2", ("server-v1.0.0-beta.1",)) == 0
    assert verify("1.0.0", "server-v1.0.0", ("cli-v1.0.0-beta.9",)) == 0
    assert verify("0.9.9", "server-v0.9.9", ("cli-v1.0.0",)) == 1
    assert verify("1.0.0+two", "server-v1.0.0+two", ("cli-v1.0.0+one",)) == 1
    assert verify("01.0.0", "server-v01.0.0", ()) == 2
    print("shared crate version sequence tests passed")


if __name__ == "__main__":
    main()
