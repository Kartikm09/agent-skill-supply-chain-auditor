#!/usr/bin/env python3
"""Validate structured files and repository-local Markdown links."""

from __future__ import annotations

import json
import re
from pathlib import Path
from urllib.parse import unquote

LINK_PATTERN = re.compile(r"!?\[[^\]]*\]\(([^)]+)\)")
SKIP_PARTS = {".git", ".venv", ".cache", "__pycache__"}
INTENTIONALLY_INVALID = {"fixtures/vulnerable/malformed-mcp/mcp-config.json"}


def files_under(root: Path) -> list[Path]:
    return [
        path
        for path in sorted(root.rglob("*"))
        if path.is_file() and not any(part in SKIP_PARTS for part in path.parts)
    ]


def validate_json(root: Path, files: list[Path]) -> list[str]:
    problems: list[str] = []
    for path in files:
        relative = path.relative_to(root).as_posix()
        if path.suffix not in {".json", ".sarif"} or relative in INTENTIONALLY_INVALID:
            continue
        try:
            json.loads(path.read_text(encoding="utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            problems.append(f"{relative}: invalid structured JSON ({exc})")
    return problems


def validate_markdown_links(root: Path, files: list[Path]) -> list[str]:
    problems: list[str] = []
    for path in files:
        if path.suffix.lower() != ".md":
            continue
        text = path.read_text(encoding="utf-8")
        for raw_target in LINK_PATTERN.findall(text):
            target = raw_target.strip().strip("<>").split(maxsplit=1)[0]
            if target.startswith(("http://", "https://", "mailto:", "#")):
                continue
            target = unquote(target.split("#", 1)[0])
            if not target:
                continue
            resolved = (path.parent / target).resolve()
            if resolved != root and root not in resolved.parents:
                problems.append(f"{path.relative_to(root)}: link escapes repository ({raw_target})")
            elif not resolved.exists():
                problems.append(f"{path.relative_to(root)}: missing link target ({raw_target})")
    return problems


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    files = files_under(root)
    problems = validate_json(root, files) + validate_markdown_links(root, files)
    if problems:
        print("repository validation failed:")
        print("\n".join(f"- {problem}" for problem in problems))
        return 1
    json_count = sum(path.suffix in {".json", ".sarif"} for path in files)
    markdown_count = sum(path.suffix.lower() == ".md" for path in files)
    print(
        f"repository validation: {json_count} JSON/SARIF files and {markdown_count} Markdown files"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
