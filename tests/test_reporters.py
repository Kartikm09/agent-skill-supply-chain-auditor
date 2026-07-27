"""Reporter contract tests for every supported output format."""

from __future__ import annotations

import json
from pathlib import Path

from skill_auditor.reporters import (
    REPORT_FILENAMES,
    render_agent_sbom,
    render_json,
    render_markdown,
    render_permission_graph,
    render_sarif,
    write_reports,
)
from skill_auditor.scanner import scan_path


def test_json_report_has_versioned_contract(fixture_root: Path) -> None:
    report = json.loads(render_json(scan_path(fixture_root / "vulnerable/broad-mcp")))
    assert report["schema_version"] == "1.0.0"
    assert report["scanner"]["execution_model"] == "static-only"
    assert report["summary"]["finding_count"] == 4


def test_markdown_report_contains_remediation_and_boundary(fixture_root: Path) -> None:
    report = render_markdown(scan_path(fixture_root / "vulnerable/broad-mcp"))
    assert "## Findings" in report
    assert "**Remediation:**" in report
    assert "not a malware verdict" in report


def test_sarif_report_is_valid_and_uses_relative_uris(fixture_root: Path) -> None:
    report = json.loads(render_sarif(scan_path(fixture_root / "vulnerable/broad-mcp")))
    assert report["version"] == "2.1.0"
    run = report["runs"][0]
    assert len(run["results"]) == 4
    uris = [
        item["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        for item in run["results"]
    ]
    assert all(not uri.startswith("/") for uri in uris)


def test_agent_sbom_omits_environment_values(fixture_root: Path) -> None:
    report_text = render_agent_sbom(scan_path(fixture_root / "vulnerable/broad-mcp"))
    report = json.loads(report_text)
    assert report["bomFormat"] == "Agent-SBOM"
    assert report["mcpServers"][0]["environment_keys"] == ["ACCESS_TOKEN"]
    assert "syntheticportfoliofixture" not in report_text


def test_permission_graph_contains_declared_boundaries(fixture_root: Path) -> None:
    graph = render_permission_graph(scan_path(fixture_root / "safe/mcp-bundle"))
    assert graph.startswith("flowchart LR")
    assert "Human approval boundary" in graph
    assert "Tool: calendar.list_events" in graph
    assert "Environment key: CALENDAR_API_TOKEN" in graph


def test_write_reports_creates_all_outputs(fixture_root: Path, tmp_path: Path) -> None:
    result = scan_path(fixture_root / "safe/minimal-skill")
    written = write_reports(result, tmp_path, {"all"})
    assert set(written) == set(REPORT_FILENAMES)
    assert all(path.is_file() for path in written.values())


def test_report_outputs_are_byte_deterministic(fixture_root: Path) -> None:
    first = scan_path(fixture_root / "vulnerable/broad-mcp")
    second = scan_path(fixture_root / "vulnerable/broad-mcp")
    renderers = [
        render_json,
        render_markdown,
        render_sarif,
        render_agent_sbom,
        render_permission_graph,
    ]
    assert all(renderer(first) == renderer(second) for renderer in renderers)
