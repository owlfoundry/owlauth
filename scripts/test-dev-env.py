#!/usr/bin/env python3
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

SCRIPT = Path(__file__).with_name("check-dev-env.py")


def run_check(directory: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT)],
        cwd=directory,
        check=False,
        capture_output=True,
        text=True,
    )


def test_accepts_current_template(tmp_path: Path) -> None:
    template = "FIRST=value\nSECOND=other\n"
    (tmp_path / ".env.example").write_text(template, encoding="utf-8")
    (tmp_path / ".env").write_text(template, encoding="utf-8")

    result = run_check(tmp_path)

    assert result.returncode == 0
    assert result.stdout == ""
    assert result.stderr == ""


def test_reports_missing_and_empty_settings_without_values(tmp_path: Path) -> None:
    (tmp_path / ".env.example").write_text(
        "FIRST=public-template-value\nSECOND=other\nTHIRD=third\n",
        encoding="utf-8",
    )
    (tmp_path / ".env").write_text(
        "FIRST=private-local-value\nSECOND=\n",
        encoding="utf-8",
    )

    result = run_check(tmp_path)

    assert result.returncode == 1
    assert "Missing settings:\n  THIRD" in result.stderr
    assert "Empty settings:\n  SECOND" in result.stderr
    assert "private-local-value" not in result.stderr
    assert "public-template-value" not in result.stderr


def test_reports_shell_quoted_and_commented_empty_values(tmp_path: Path) -> None:
    (tmp_path / ".env.example").write_text(
        "FIRST=value\nSECOND=value\n",
        encoding="utf-8",
    )
    (tmp_path / ".env").write_text(
        'FIRST=""\nSECOND= # intentionally empty\n',
        encoding="utf-8",
    )

    result = run_check(tmp_path)

    assert result.returncode == 1
    assert "Empty settings:\n  FIRST\n  SECOND" in result.stderr


def test_rejects_obsolete_owlauth_settings_before_startup(tmp_path: Path) -> None:
    (tmp_path / ".env.example").write_text(
        "OWLAUTH_MODE=all\n",
        encoding="utf-8",
    )
    (tmp_path / ".env").write_text(
        "OWLAUTH_MODE=all\nOWLAUTH_PROJECTION_EMAIL_DIGEST_KEY=obsolete-secret-value\n",
        encoding="utf-8",
    )

    result = run_check(tmp_path)

    assert result.returncode == 1
    assert "Unknown or obsolete settings:" in result.stderr
    assert "OWLAUTH_PROJECTION_EMAIL_DIGEST_KEY" in result.stderr
    assert "obsolete-secret-value" not in result.stderr


def test_rejects_non_assignment_lines(tmp_path: Path) -> None:
    (tmp_path / ".env.example").write_text("FIRST=value\n", encoding="utf-8")
    (tmp_path / ".env").write_text("export FIRST=value\n", encoding="utf-8")

    result = run_check(tmp_path)

    assert result.returncode == 1
    assert "expected one KEY=value assignment" in result.stderr
