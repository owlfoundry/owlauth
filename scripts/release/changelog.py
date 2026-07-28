#!/usr/bin/env python3
"""Validate squash PR titles and generate component release notes."""

from __future__ import annotations

import re
import subprocess
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

COMPONENT_TAG_PREFIXES = {
    "server": "server-v",
    "cli": "cli-v",
    "typescript": "typescript-v",
    "python": "python-v",
    "rust": "rust-v",
}
RELEASE_SCOPES = frozenset(COMPONENT_TAG_PREFIXES) | {"all"}
INTERNAL_SCOPES = frozenset({"repo", "docs", "plugin", "deps-dev"})
ALLOWED_SCOPES = RELEASE_SCOPES | INTERNAL_SCOPES
SECTIONS = {
    "security": "Security",
    "feat": "Added",
    "fix": "Fixed",
    "perf": "Performance",
    "refactor": "Changed",
    "docs": "Documentation",
    "deps": "Dependencies",
}
SECTION_ORDER = (
    "Breaking Changes",
    "Security",
    "Added",
    "Fixed",
    "Performance",
    "Changed",
    "Documentation",
    "Dependencies",
)
ALLOWED_TYPES = frozenset(SECTIONS) | {"chore", "ci", "test", "style"}
RELEASE_FACING_TYPES = frozenset({"security", "feat", "fix", "perf", "refactor", "deps"})
TITLE_PATTERN = re.compile(
    r"^(?P<type>[a-z]+)(?:\((?P<scopes>[a-z][a-z0-9-]*(?:\+[a-z][a-z0-9-]*)*)\))?"
    r"(?P<breaking>!)?: (?P<summary>.+?)(?: \(#(?P<pr>[1-9][0-9]*)\))?$"
)


class ChangelogError(ValueError):
    """Raised for invalid release-note input."""


@dataclass(frozen=True)
class PullRequestTitle:
    change_type: str
    scopes: tuple[str, ...]
    breaking: bool
    summary: str
    number: int | None

    def applies_to(self, component: str) -> bool:
        return "all" in self.scopes or component in self.scopes

    @property
    def section(self) -> str | None:
        if self.breaking:
            return "Breaking Changes"
        return SECTIONS.get(self.change_type)


def parse_title(title: str) -> PullRequestTitle:
    match = TITLE_PATTERN.fullmatch(title.strip())
    if match is None:
        raise ChangelogError(
            "title must match <type>(<scope>[+<scope>...])[!]: <summary>"
        )

    change_type = match.group("type")
    if change_type not in ALLOWED_TYPES:
        raise ChangelogError(f"unsupported change type: {change_type}")

    scopes = tuple(match.group("scopes").split("+")) if match.group("scopes") else ()
    unknown_scopes = sorted(set(scopes) - ALLOWED_SCOPES)
    if unknown_scopes:
        raise ChangelogError(f"unsupported scope: {', '.join(unknown_scopes)}")
    if len(scopes) != len(set(scopes)):
        raise ChangelogError("scopes must not be repeated")
    if "all" in scopes and len(scopes) != 1:
        raise ChangelogError("the all scope cannot be combined with another scope")
    if change_type in RELEASE_FACING_TYPES and not set(scopes).intersection(RELEASE_SCOPES):
        raise ChangelogError(f"{change_type} requires a release component scope")
    if match.group("breaking") and not set(scopes).intersection(RELEASE_SCOPES):
        raise ChangelogError("a breaking change requires a release component scope")

    summary = match.group("summary")
    if summary[-1] == ".":
        raise ChangelogError("summary must not end with a period")
    if summary[0].isalpha() and not summary[0].islower():
        raise ChangelogError("summary must start with a lowercase letter")

    number = int(match.group("pr")) if match.group("pr") else None
    return PullRequestTitle(
        change_type=change_type,
        scopes=scopes,
        breaking=bool(match.group("breaking")),
        summary=summary,
        number=number,
    )


def git(*arguments: str, cwd: Path) -> str:
    result = subprocess.run(
        ["git", *arguments],
        cwd=cwd,
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise ChangelogError(result.stderr.strip() or "git command failed")
    return result.stdout


def previous_tag(component: str, reference: str, cwd: Path) -> str | None:
    prefix = COMPONENT_TAG_PREFIXES[component]
    tags = git(
        "tag",
        "--merged",
        reference,
        "--list",
        f"{prefix}*",
        "--sort=-version:refname",
        cwd=cwd,
    ).splitlines()
    return tags[0] if tags else None


def commit_titles(reference: str, start_tag: str | None, cwd: Path) -> list[str]:
    revision = f"{start_tag}..{reference}" if start_tag else reference
    return git(
        "log",
        "--first-parent",
        "--reverse",
        "--format=%s",
        revision,
        cwd=cwd,
    ).splitlines()


def render_notes(
    *,
    component: str,
    version: str,
    titles: Sequence[str],
    start_tag: str | None,
    repository_url: str = "https://github.com/owlfoundry/owlauth",
) -> str:
    if component not in COMPONENT_TAG_PREFIXES:
        raise ChangelogError(f"unsupported component: {component}")

    entries: dict[str, list[str]] = defaultdict(list)
    for raw_title in titles:
        try:
            title = parse_title(raw_title)
        except ChangelogError:
            # Legacy commits predate title enforcement and cannot be classified safely.
            continue
        section = title.section
        if section is None or not title.applies_to(component):
            continue
        summary = title.summary[0].upper() + title.summary[1:]
        if title.number is not None:
            summary += f" ([#{title.number}]({repository_url}/pull/{title.number}))"
        entries[section].append(f"- {summary}")

    if not entries:
        raise ChangelogError(f"no releasable {component} changes were found")

    blocks: list[str] = []
    for section in SECTION_ORDER:
        section_entries = entries.get(section)
        if section_entries:
            blocks.append(f"## {section}\n\n" + "\n".join(section_entries))

    tag = f"{COMPONENT_TAG_PREFIXES[component]}{version}"
    if start_tag:
        full_changelog = f"{repository_url}/compare/{start_tag}...{tag}"
    else:
        full_changelog = f"{repository_url}/commits/{tag}"
    blocks.append(f"**Full Changelog**: {full_changelog}")
    return "\n\n".join(blocks) + "\n"


def generate_notes(
    *,
    component: str,
    version: str,
    output: Path,
    reference: str = "HEAD",
    cwd: Path = Path("."),
) -> None:
    if component not in COMPONENT_TAG_PREFIXES:
        raise ChangelogError(f"unsupported component: {component}")
    start_tag = previous_tag(component, reference, cwd)
    notes = render_notes(
        component=component,
        version=version,
        titles=commit_titles(reference, start_tag, cwd),
        start_tag=start_tag,
    )
    output.write_text(notes, encoding="utf-8")
