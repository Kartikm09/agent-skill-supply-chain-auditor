"""CLI integration tests for output generation and policy exit codes."""

from __future__ import annotations

from pathlib import Path

from skill_auditor.cli import main


def test_cli_writes_default_reports(fixture_root: Path, tmp_path: Path, capsys: object) -> None:
    exit_code = main(
        [
            "scan",
            str(fixture_root / "safe/minimal-skill"),
            "--output-dir",
            str(tmp_path),
        ]
    )
    assert exit_code == 0
    assert (tmp_path / "scan-report.json").is_file()
    assert (tmp_path / "scan-report.md").is_file()


def test_cli_policy_threshold_returns_one(fixture_root: Path, tmp_path: Path) -> None:
    exit_code = main(
        [
            "scan",
            str(fixture_root / "vulnerable/prompt-injection"),
            "--output-dir",
            str(tmp_path),
            "--fail-on",
            "high",
        ]
    )
    assert exit_code == 1


def test_cli_none_threshold_allows_sample_generation(fixture_root: Path, tmp_path: Path) -> None:
    exit_code = main(
        [
            "scan",
            str(fixture_root / "vulnerable/broad-mcp"),
            "--output-dir",
            str(tmp_path),
            "--format",
            "all",
            "--fail-on",
            "none",
        ]
    )
    assert exit_code == 0
    assert len(list(tmp_path.iterdir())) == 5


def test_cli_invalid_target_returns_two(tmp_path: Path, capsys: object) -> None:
    exit_code = main(["scan", str(tmp_path / "missing")])
    assert exit_code == 2
