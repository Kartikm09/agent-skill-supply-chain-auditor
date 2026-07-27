"""Command-line interface for deterministic bundle inspection."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .models import SEVERITY_RANK, Severity
from .reporters import write_reports
from .scanner import ScanOptions, scan_path
from .version import __version__


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="skill-auditor",
        description="Statically inspect Agent Skill bundles and MCP JSON without executing them.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)
    scan = subparsers.add_parser("scan", help="scan one local bundle directory")
    scan.add_argument("target", type=Path, help="bundle directory to inspect")
    scan.add_argument("--output-dir", type=Path, default=Path("reports/local"))
    scan.add_argument(
        "--format",
        action="append",
        choices=["all", "json", "markdown", "sarif", "sbom", "graph"],
        default=None,
        dest="formats",
        help="repeat to select formats; defaults to json and markdown",
    )
    scan.add_argument(
        "--fail-on",
        choices=["none", "low", "medium", "high", "critical"],
        default="high",
        help="exit 1 when a finding meets this severity threshold",
    )
    scan.add_argument("--max-file-bytes", type=int, default=1_048_576)
    scan.add_argument("--max-total-bytes", type=int, default=20_971_520)
    scan.add_argument("--max-files", type=int, default=2_000)
    scan.add_argument("--max-depth", type=int, default=20)
    return parser


def _run_scan(args: argparse.Namespace) -> int:
    options = ScanOptions(
        max_file_bytes=args.max_file_bytes,
        max_total_bytes=args.max_total_bytes,
        max_files=args.max_files,
        max_depth=args.max_depth,
    )
    result = scan_path(args.target, options)
    formats = set(args.formats or ["json", "markdown"])
    written = write_reports(result, args.output_dir, formats)
    summary = result.summary
    print(
        f"scan_id={result.scan_id} findings={summary['finding_count']} "
        f"highest={summary['highest_severity']} files={summary['files_inspected']}"
    )
    for format_name, path in sorted(written.items()):
        print(f"{format_name}: {path}")
    if args.fail_on == "none":
        return 0
    threshold = SEVERITY_RANK[Severity(args.fail_on)]
    return int(any(SEVERITY_RANK[finding.severity] >= threshold for finding in result.findings))


def main(argv: list[str] | None = None) -> int:
    """CLI entry point. Usage failures return 2; policy findings return 1."""

    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "scan":
            return _run_scan(args)
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 2
