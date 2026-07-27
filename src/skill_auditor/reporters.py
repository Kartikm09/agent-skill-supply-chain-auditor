"""Deterministic JSON, Markdown, SARIF, Agent-SBOM, and graph reporters."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from .models import ScanResult, Severity
from .rules import RULES

REPORT_FILENAMES = {
    "json": "scan-report.json",
    "markdown": "scan-report.md",
    "sarif": "scan-report.sarif",
    "sbom": "agent-sbom.json",
    "graph": "permission-graph.mmd",
}


def _json_text(value: Any) -> str:
    return json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n"


def render_json(result: ScanResult) -> str:
    """Render the canonical scan report."""

    return _json_text(result.to_dict())


def render_markdown(result: ScanResult) -> str:
    """Render a reviewer-friendly report without machine-specific paths."""

    summary = result.summary
    lines = [
        "# Agent Skill Supply-Chain Audit",
        "",
        f"**Target:** `{result.target_name}`  ",
        f"**Scan ID:** `{result.scan_id}`  ",
        "**Execution model:** Static inspection only; scanned code was not executed.",
        "",
        "## Summary",
        "",
        "| Metric | Value |",
        "|---|---:|",
        f"| Findings | {summary['finding_count']} |",
        f"| Highest severity | {summary['highest_severity']} |",
        f"| Files inspected | {summary['files_inspected']} |",
        f"| Symlinks skipped | {summary['symlinks_skipped']} |",
        "",
        "| Critical | High | Medium | Low | Info |",
        "|---:|---:|---:|---:|---:|",
        "| {critical} | {high} | {medium} | {low} | {info} |".format(**summary["severity_counts"]),
        "",
        "## Findings",
        "",
    ]
    if not result.findings:
        lines.extend(
            [
                (
                    "No rules fired. This is not proof that the bundle is safe; "
                    "manual review remains required."
                ),
                "",
            ]
        )
    for finding in result.findings:
        location = finding.evidence.path
        if finding.evidence.line is not None:
            location += f":{finding.evidence.line}"
        lines.extend(
            [
                f"### {finding.rule_id}: {finding.title}",
                "",
                f"- **Severity:** {finding.severity.value}",
                f"- **Confidence:** {finding.confidence.value}",
                f"- **Location:** `{location}`",
                f"- **Finding ID:** `{finding.id}`",
                f"- **Message:** {finding.message}",
                f"- **Remediation:** {finding.remediation}",
                f"- **Evidence:** `{_escape_code(finding.evidence.snippet)}`",
                f"- **Evidence fingerprint:** `{finding.evidence.fingerprint}`",
                "",
            ]
        )
    lines.extend(
        [
            "## Inventory",
            "",
            f"- Declared skill: `{_display(result.inventory.get('skill'))}`",
            f"- MCP servers: {len(result.inventory.get('mcp_servers', []))}",
            f"- Declared permissions: {len(result.inventory.get('permissions', []))}",
            f"- Dependency references: {len(result.inventory.get('dependencies', []))}",
            f"- Provenance: `{_display(result.inventory.get('provenance'))}`",
            f"- License: `{_display(result.inventory.get('license'))}`",
            "",
            "## Review Boundary",
            "",
            (
                "This report is a deterministic static signal, not a malware verdict or "
                "hardened sandbox. It does not execute code, resolve dependencies, contact "
                "endpoints, or prove runtime behaviour."
            ),
            "",
        ]
    )
    return "\n".join(lines)


def _escape_code(value: str) -> str:
    return value.replace("`", "'")


def _display(value: Any) -> str:
    if value is None:
        return "not declared"
    if isinstance(value, dict):
        return str(value.get("name") or "declared")
    return str(value)


def render_sarif(result: ScanResult) -> str:
    """Render SARIF 2.1.0 suitable for GitHub code-scanning upload."""

    used_rule_ids = sorted({finding.rule_id for finding in result.findings})
    rules = []
    for rule_id in used_rule_ids:
        rule = RULES[rule_id]
        rules.append(
            {
                "id": rule.id,
                "name": re.sub(r"[^A-Za-z0-9]+", "", rule.title),
                "shortDescription": {"text": rule.title},
                "fullDescription": {"text": rule.description},
                "help": {"text": rule.remediation},
                "properties": {
                    "precision": rule.confidence.value,
                    "security-severity": _security_score(rule.severity),
                    "tags": list(rule.tags),
                },
            }
        )

    results = []
    for finding in result.findings:
        region = {"startLine": finding.evidence.line} if finding.evidence.line else None
        physical_location: dict[str, Any] = {
            "artifactLocation": {"uri": finding.evidence.path, "uriBaseId": "%SRCROOT%"}
        }
        if region:
            physical_location["region"] = region
        results.append(
            {
                "ruleId": finding.rule_id,
                "level": _sarif_level(finding.severity),
                "message": {"text": f"{finding.message} Remediation: {finding.remediation}"},
                "locations": [{"physicalLocation": physical_location}],
                "partialFingerprints": {"primaryLocationLineHash": finding.id},
                "properties": {
                    "confidence": finding.confidence.value,
                    "evidence": finding.evidence.snippet,
                    "evidenceFingerprint": finding.evidence.fingerprint,
                },
            }
        )

    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "agent-skill-supply-chain-auditor",
                        "version": result.scanner_version,
                        "informationUri": "https://github.com/Kartikm09/agent-skill-supply-chain-auditor",
                        "rules": rules,
                    }
                },
                "automationDetails": {"id": result.scan_id},
                "results": results,
            }
        ],
    }
    return _json_text(sarif)


def _sarif_level(severity: Severity) -> str:
    if severity in {Severity.CRITICAL, Severity.HIGH}:
        return "error"
    if severity is Severity.MEDIUM:
        return "warning"
    return "note"


def _security_score(severity: Severity) -> str:
    return {
        Severity.CRITICAL: "9.0",
        Severity.HIGH: "7.0",
        Severity.MEDIUM: "5.0",
        Severity.LOW: "3.0",
        Severity.INFO: "0.0",
    }[severity]


def render_agent_sbom(result: ScanResult) -> str:
    """Render a compact, deterministic Agent-SBOM inventory."""

    sbom = {
        "bomFormat": "Agent-SBOM",
        "specVersion": "1.0",
        "serialNumber": f"urn:sha256:{result.scan_id}",
        "metadata": {
            "component": {
                "type": "agent-skill-bundle",
                "name": result.target_name,
                "scanId": result.scan_id,
            },
            "tool": {
                "name": "agent-skill-supply-chain-auditor",
                "version": result.scanner_version,
                "executionModel": "static-only",
            },
        },
        "governance": {
            "provenance": result.inventory.get("provenance"),
            "license": result.inventory.get("license"),
        },
        "components": [
            {
                "type": "file",
                "name": record.path,
                "sizeBytes": record.size_bytes,
                "sha256": record.sha256,
                "inspectionStatus": "skipped" if record.kind == "symlink" else "inventoried",
            }
            for record in result.files
        ],
        "dependencies": result.inventory.get("dependencies", []),
        "capabilities": result.inventory.get("permissions", []),
        "mcpServers": result.inventory.get("mcp_servers", []),
    }
    return _json_text(sbom)


def render_permission_graph(result: ScanResult) -> str:
    """Render a Mermaid-compatible capability graph."""

    root_label = _mermaid_label(result.target_name)
    lines = [
        "flowchart LR",
        f'  bundle["{root_label}"]',
        '  reviewer["Human approval boundary"]',
        "  reviewer -. review .-> bundle",
    ]
    for index, permission in enumerate(result.inventory.get("permissions", []), start=1):
        label = _mermaid_label(str(permission.get("capability", "unknown")))
        lines.append(f'  permission_{index}["Tool: {label}"]')
        lines.append(f"  bundle --> permission_{index}")
    for index, server in enumerate(result.inventory.get("mcp_servers", []), start=1):
        label = _mermaid_label(str(server.get("name", "unnamed")))
        transport = _mermaid_label(str(server.get("transport", "unknown")))
        lines.append(f'  server_{index}["MCP: {label} ({transport})"]')
        lines.append(f"  bundle --> server_{index}")
        for env_index, env_key in enumerate(server.get("environment_keys", []), start=1):
            env_label = _mermaid_label(str(env_key))
            node = f"server_{index}_env_{env_index}"
            lines.append(f'  {node}["Environment key: {env_label}"]')
            lines.append(f"  {node} -. injected at runtime .-> server_{index}")
    if len(lines) == 4:
        lines.append('  none["No tool or MCP permissions declared"]')
        lines.append("  bundle --> none")
    return "\n".join(lines) + "\n"


def _mermaid_label(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9 _.:/@+-]", "_", value)[:80].replace('"', "'")


def write_reports(result: ScanResult, output_dir: Path, formats: set[str]) -> dict[str, Path]:
    """Write selected reports and return their paths."""

    output_dir.mkdir(parents=True, exist_ok=True)
    renderers = {
        "json": render_json,
        "markdown": render_markdown,
        "sarif": render_sarif,
        "sbom": render_agent_sbom,
        "graph": render_permission_graph,
    }
    selected = set(renderers) if "all" in formats else formats
    unknown = selected - set(renderers)
    if unknown:
        raise ValueError(f"unknown report formats: {', '.join(sorted(unknown))}")
    written: dict[str, Path] = {}
    for format_name in sorted(selected):
        path = output_dir / REPORT_FILENAMES[format_name]
        path.write_text(renderers[format_name](result), encoding="utf-8")
        written[format_name] = path
    return written
