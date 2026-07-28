#!/usr/bin/env python3
from __future__ import annotations

import subprocess
import tempfile
from pathlib import Path

from changelog import ChangelogError, generate_notes, parse_title, render_notes


def git(cwd: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True)


def commit(cwd: Path, title: str) -> None:
    marker = cwd / "history"
    content = marker.read_text() if marker.exists() else ""
    marker.write_text(content + title + "\n")
    git(cwd, "add", "history")
    git(cwd, "commit", "--quiet", "-m", title)


def expect_invalid(title: str) -> None:
    try:
        parse_title(title)
    except ChangelogError:
        return
    raise AssertionError(f"expected invalid title: {title}")


def test_accepts_release_internal_and_multi_scope_titles() -> None:
    title = parse_title("feat(server+cli)!: replace token contract (#42)")
    assert title.breaking
    assert title.scopes == ("server", "cli")
    assert title.number == 42
    parse_title("chore(deps-dev): bump pytest")


def test_rejects_ambiguous_or_malformed_titles() -> None:
    for title in (
        "fix: lose component",
        "feat(all+server): invalid all scope",
        "feat(server+server): repeated scope",
        "change(server): unknown type",
        "fix(website): unknown scope",
        "fix(server): Ends uppercase",
        "fix(server): ends with period.",
    ):
        expect_invalid(title)


def test_filters_components_and_renders_sections_and_links() -> None:
    notes = render_notes(
        component="server",
        version="0.0.2",
        titles=[
            "feat(server): add health endpoint (#10)",
            "fix(cli): preserve install directory (#11)",
            "feat(server+cli)!: replace diagnostics contract (#12)",
            "chore(repo): update automation (#13)",
            "fix: legacy unscoped title (#14)",
        ],
        start_tag="server-v0.0.1",
    )
    assert "## Breaking Changes" in notes
    assert "Replace diagnostics contract" in notes
    assert "Add health endpoint" in notes
    assert "Preserve install directory" not in notes
    assert "Legacy" not in notes
    assert "/pull/10" in notes
    assert "compare/server-v0.0.1...server-v0.0.2" in notes


def test_first_release_uses_commits_link_and_requires_entry() -> None:
    notes = render_notes(
        component="cli",
        version="0.0.2",
        titles=["feat(cli): add updater (#20)"],
        start_tag=None,
    )
    assert "commits/cli-v0.0.2" in notes
    try:
        render_notes(
            component="cli",
            version="0.0.2",
            titles=["chore(repo): initialize repository"],
            start_tag=None,
        )
    except ChangelogError:
        return
    raise AssertionError("an empty component changelog must fail")


def test_uses_previous_component_tag_and_first_parent_order() -> None:
    with tempfile.TemporaryDirectory() as directory:
        repository = Path(directory)
        git(repository, "init", "--quiet", "--initial-branch=main")
        git(repository, "config", "user.name", "Changelog Test")
        git(repository, "config", "user.email", "test@example.com")
        commit(repository, "feat(server): initial server (#1)")
        git(repository, "tag", "server-v0.0.1")
        commit(repository, "fix(python): fix Python client (#2)")
        commit(repository, "fix(server+cli): improve diagnostics (#3)")
        git(repository, "tag", "server-v0.0.2")
        output = repository / "notes.md"

        generate_notes(
            component="server",
            version="0.0.2",
            output=output,
            cwd=repository,
        )

        notes = output.read_text()
        assert "Improve diagnostics" in notes
        assert "Initial server" not in notes
        assert "Python client" not in notes


def main() -> None:
    tests = (
        test_accepts_release_internal_and_multi_scope_titles,
        test_rejects_ambiguous_or_malformed_titles,
        test_filters_components_and_renders_sections_and_links,
        test_first_release_uses_commits_link_and_requires_entry,
        test_uses_previous_component_tag_and_first_parent_order,
    )
    for test in tests:
        test()
    print(f"changelog tests passed ({len(tests)})")


if __name__ == "__main__":
    main()
