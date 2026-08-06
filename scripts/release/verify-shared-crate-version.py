#!/usr/bin/env python3
"""Require server/CLI tags to advance the shared owlauth-types version sequence."""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass
from functools import total_ordering

NUMERIC = r"(?:0|[1-9][0-9]*)"
PRERELEASE_IDENTIFIER = r"(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)"
SEMVER = re.compile(
    rf"^(?P<major>{NUMERIC})\.(?P<minor>{NUMERIC})\.(?P<patch>{NUMERIC})"
    rf"(?:-(?P<prerelease>{PRERELEASE_IDENTIFIER}(?:\.{PRERELEASE_IDENTIFIER})*))?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$"
)
TAG = re.compile(r"^(?:server|cli)-v(?P<version>.+)$")


@total_ordering
@dataclass(frozen=True)
class Version:
    text: str
    core: tuple[int, int, int]
    prerelease: tuple[str, ...] | None

    @classmethod
    def parse(cls, value: str) -> Version | None:
        match = SEMVER.fullmatch(value)
        if match is None:
            return None
        prerelease = match.group("prerelease")
        return cls(
            value,
            tuple(int(match.group(name)) for name in ("major", "minor", "patch")),
            None if prerelease is None else tuple(prerelease.split(".")),
        )

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, Version):
            return NotImplemented
        if self.core != other.core:
            return self.core < other.core
        if self.prerelease is None:
            return False
        if other.prerelease is None:
            return True
        for index in range(min(len(self.prerelease), len(other.prerelease))):
            left = self.prerelease[index]
            right = other.prerelease[index]
            if left == right:
                continue
            left_numeric = left.isdigit()
            right_numeric = right.isdigit()
            if left_numeric and right_numeric:
                return int(left) < int(right)
            if left_numeric != right_numeric:
                return left_numeric
            return left < right
        return len(self.prerelease) < len(other.prerelease)


def remote_tags(lines: list[str]) -> set[str]:
    tags: set[str] = set()
    for line in lines:
        fields = line.split()
        if len(fields) != 2 or not fields[1].startswith("refs/tags/"):
            continue
        name = fields[1].removeprefix("refs/tags/").removesuffix("^{}")
        if TAG.fullmatch(name):
            tags.add(name)
    return tags


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", required=True)
    parser.add_argument("--current-tag", required=True)
    args = parser.parse_args()

    candidate = Version.parse(args.version)
    if candidate is None:
        print(f"invalid candidate SemVer: {args.version}", file=sys.stderr)
        return 2

    previous: list[tuple[Version, str]] = []
    for tag in remote_tags(sys.stdin.readlines()):
        if tag == args.current_tag:
            continue
        match = TAG.fullmatch(tag)
        assert match is not None
        version = Version.parse(match.group("version"))
        if version is not None:
            previous.append((version, tag))
    if not previous:
        return 0

    latest, latest_tag = max(previous, key=lambda item: item[0])
    if not latest < candidate:
        print(
            f"shared owlauth-types release version {args.version} must be greater than "
            f"existing {latest_tag} ({latest.text})",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
