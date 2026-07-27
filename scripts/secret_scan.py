#!/usr/bin/env python3
"""Fail when credential-shaped values appear outside explicit synthetic fixtures."""

from __future__ import annotations

from pathlib import Path

from skill_auditor.redaction import find_secret_matches

TEXT_SUFFIXES = {
    ".css",
    ".html",
    ".js",
    ".json",
    ".md",
    ".mmd",
    ".py",
    ".toml",
    ".txt",
    ".yaml",
    ".yml",
}
SKIP_PARTS = {".git", ".venv", ".cache", "__pycache__"}


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    problems: list[str] = []
    inspected = 0
    for path in sorted(root.rglob("*")):
        if not path.is_file() or any(part in SKIP_PARTS for part in path.parts):
            continue
        relative = path.relative_to(root)
        if relative.parts[:2] == ("fixtures", "vulnerable"):
            continue
        if path.suffix.lower() not in TEXT_SUFFIXES and path.name not in {"LICENSE", "Makefile"}:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        inspected += 1
        for line_number, line in enumerate(text.splitlines(), start=1):
            if find_secret_matches(line):
                problems.append(f"{relative.as_posix()}:{line_number}")
    if problems:
        print("credential-shaped values found outside synthetic fixtures:")
        print("\n".join(f"- {problem}" for problem in problems))
        return 1
    print(f"secret scan: {inspected} text files checked; no credential-shaped values found")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
