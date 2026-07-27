"""Integration checks for generated evidence and public repository contracts."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from skill_auditor.rules import RULES
from skill_auditor.scanner import Auditor, scan_path


def test_all_repository_json_except_malformed_fixture_parses(repository_root: Path) -> None:
    excluded = repository_root / "fixtures/vulnerable/malformed-mcp/mcp-config.json"
    for path in repository_root.rglob("*"):
        if any(part in {".git", ".venv", ".cache"} for part in path.parts):
            continue
        if path.is_file() and path.suffix in {".json", ".sarif"} and path != excluded:
            json.loads(path.read_text(encoding="utf-8"))


def test_fixture_manifest_references_known_rules(fixture_root: Path) -> None:
    manifest = json.loads((fixture_root / "labels.json").read_text(encoding="utf-8"))
    labelled = {rule for fixture in manifest["fixtures"] for rule in fixture["expected_rules"]}
    assert labelled <= set(RULES)


def test_generated_sample_contains_no_raw_synthetic_token(repository_root: Path) -> None:
    token_fragment = "synthetic" + "portfoliofixture"
    for path in (repository_root / "reports/sample").iterdir():
        assert token_fragment not in path.read_text(encoding="utf-8")


def test_auditor_instance_can_be_reused_without_cross_scan_state(fixture_root: Path) -> None:
    auditor = Auditor()
    vulnerable = auditor.scan(fixture_root / "vulnerable/broad-mcp")
    safe = auditor.scan(fixture_root / "safe/minimal-skill")
    assert vulnerable.findings
    assert safe.findings == []


@pytest.mark.integration
def test_module_cli_runs_in_a_fresh_process(
    repository_root: Path, fixture_root: Path, tmp_path: Path
) -> None:
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(repository_root / "src")
    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "skill_auditor",
            "scan",
            str(fixture_root / "safe/minimal-skill"),
            "--output-dir",
            str(tmp_path),
        ],
        cwd=repository_root,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert completed.returncode == 0, completed.stderr
    assert "findings=0" in completed.stdout


def test_scan_id_changes_when_content_changes(tmp_path: Path) -> None:
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    skill = bundle / "SKILL.md"
    skill.write_text(
        "---\nname: changed-content\n"
        "description: A valid synthetic description for content hashing.\n"
        "source: https://example.invalid/changed\n---\nFirst\n",
        encoding="utf-8",
    )
    (bundle / "LICENSE").write_text("Apache-2.0\n", encoding="utf-8")
    first = scan_path(bundle).scan_id
    skill.write_text(skill.read_text(encoding="utf-8") + "Second\n", encoding="utf-8")
    assert scan_path(bundle).scan_id != first


def test_untrusted_metadata_is_redacted_from_inventory(tmp_path: Path) -> None:
    token = "ghp_" + "syntheticinventoryvalue00000000"
    api_key = "sk-" + "syntheticdescriptionvalue000000"
    userinfo = "user:" + "password"
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    (bundle / "SKILL.md").write_text(
        "---\n"
        "name: inventory-redaction\n"
        f"description: A synthetic description containing {api_key} for a redaction test.\n"
        f"source: https://{userinfo}@example.invalid/project?token={token}\n"
        "allowed-tools:\n"
        f"  - {token}\n"
        "---\n"
        "Static test body.\n",
        encoding="utf-8",
    )
    (bundle / "LICENSE").write_text("Apache-2.0\n", encoding="utf-8")
    (bundle / f"{token}.txt").write_text("safe content\n", encoding="utf-8")
    encoded = json.dumps(scan_path(bundle).to_dict())
    assert token not in encoded
    assert api_key not in encoded
    assert userinfo not in encoded
    assert "<redacted-value:" in encoded
