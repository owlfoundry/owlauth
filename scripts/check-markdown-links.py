#!/usr/bin/env python3
"""Validate relative file links in tracked Markdown documents."""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path
from urllib.parse import unquote, urlsplit

FENCED_BLOCK = re.compile(
    r"^[ \t]*(?P<fence>`{3,}|~{3,})[^\n]*\n.*?^[ \t]*(?P=fence)[ \t]*$",
    re.MULTILINE | re.DOTALL,
)
INLINE_LINK = re.compile(
    r"!?\[[^\]\n]*\]\(\s*(?P<target><[^>\n]+>|[^)\s]+)"
    r"(?:\s+(?:\"[^\"]*\"|'[^']*'|\([^)]*\)))?\s*\)",
)
REFERENCE_LINK = re.compile(
    r"^[ \t]{0,3}\[[^\]\n]+\]:[ \t]*(?P<target><[^>\n]+>|\S+)",
    re.MULTILINE,
)


def tracked_markdown_files(repository: Path) -> list[Path]:
    result = subprocess.run(
        ["git", "ls-files", "-z", "--", "*.md"],
        cwd=repository,
        check=True,
        capture_output=True,
    )
    return [repository / os.fsdecode(name) for name in result.stdout.split(b"\0") if name]


def relative_path(target: str) -> str | None:
    target = target.removeprefix("<").removesuffix(">")
    parsed = urlsplit(target)
    if parsed.scheme or parsed.netloc or target.startswith(("/", "#")):
        return None
    path = unquote(parsed.path)
    return path or None


def main() -> int:
    repository = Path(
        subprocess.check_output(["git", "rev-parse", "--show-toplevel"], text=True).strip()
    )
    failures: list[str] = []
    files = tracked_markdown_files(repository)

    for source in files:
        content = source.read_text(encoding="utf-8")
        searchable = FENCED_BLOCK.sub(lambda match: "\n" * match.group(0).count("\n"), content)
        for match in (*INLINE_LINK.finditer(searchable), *REFERENCE_LINK.finditer(searchable)):
            target = relative_path(match.group("target"))
            if target is None or (source.parent / target).exists():
                continue
            line = searchable.count("\n", 0, match.start()) + 1
            failures.append(
                f"{source.relative_to(repository)}:{line}: missing link target {target!r}"
            )

    if failures:
        print("\n".join(sorted(failures)))
        return 1

    print(f"Validated relative links in {len(files)} tracked Markdown files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
