"""Minimal importable API example using a repository-owned synthetic fixture."""

from pathlib import Path

from skill_auditor import ScanOptions, scan_path

result = scan_path(
    Path("fixtures/safe/minimal-skill"),
    ScanOptions(max_files=100, max_total_bytes=2_000_000),
)

print(result.scan_id)
print(result.summary)
