#!/usr/bin/env python3
"""Assert that two scans of unchanged bytes render byte-identical reports."""

from __future__ import annotations

from pathlib import Path

from skill_auditor.reporters import (
    render_agent_sbom,
    render_json,
    render_markdown,
    render_permission_graph,
    render_sarif,
)
from skill_auditor.scanner import scan_path


def main() -> int:
    fixture = Path("fixtures/vulnerable/broad-mcp")
    first = scan_path(fixture)
    second = scan_path(fixture)
    renderers = (
        render_json,
        render_markdown,
        render_sarif,
        render_agent_sbom,
        render_permission_graph,
    )
    mismatches = [
        renderer.__name__ for renderer in renderers if renderer(first) != renderer(second)
    ]
    if mismatches:
        print(f"nondeterministic reporters: {', '.join(mismatches)}")
        return 1
    print(f"determinism: 5/5 reporters stable for scan {first.scan_id}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
