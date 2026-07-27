"""Strict parsers for untrusted Agent Skill frontmatter and MCP JSON."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class FrontmatterResult:
    metadata: dict[str, Any]
    body: str
    errors: tuple[str, ...]
    body_start_line: int


def _scalar(value: str) -> Any:
    value = value.strip()
    if not value:
        return ""
    if value in {"true", "false"}:
        return value == "true"
    if value in {"null", "~"}:
        return None
    if re.fullmatch(r"-?\d+", value):
        return int(value)
    if value.startswith("[") and value.endswith("]"):
        try:
            parsed = json.loads(value.replace("'", '"'))
            return parsed if isinstance(parsed, list) else value
        except json.JSONDecodeError:
            return [item.strip().strip("\"'") for item in value[1:-1].split(",") if item.strip()]
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
        return value[1:-1]
    return value


def _parse_frontmatter_lines(lines: list[str]) -> tuple[dict[str, Any], list[str]]:
    root: dict[str, Any] = {}
    errors: list[str] = []
    stack: list[tuple[int, dict[str, Any] | list[Any]]] = [(-1, root)]

    for offset, raw_line in enumerate(lines):
        index = offset + 2
        if not raw_line.strip() or raw_line.lstrip().startswith("#"):
            continue
        if "\t" in raw_line[: len(raw_line) - len(raw_line.lstrip())]:
            errors.append(f"line {index}: tabs are not accepted in metadata indentation")
            continue
        indent = len(raw_line) - len(raw_line.lstrip(" "))
        stripped = raw_line.strip()
        if re.search(r"(?:^|\s)(?:!!\S*|[&*][A-Za-z0-9_-]+)(?:\s|$)", stripped):
            errors.append(f"line {index}: YAML tags, anchors, and aliases are not accepted")
            continue

        while len(stack) > 1 and indent <= stack[-1][0]:
            stack.pop()
        parent = stack[-1][1]

        if stripped.startswith("- "):
            if not isinstance(parent, list):
                errors.append(f"line {index}: list item does not belong to a list field")
                continue
            parent.append(_scalar(stripped[2:]))
            continue

        if ":" not in stripped:
            errors.append(f"line {index}: expected a key and value separated by ':'")
            continue
        key, value = stripped.split(":", 1)
        key = key.strip()
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]*", key):
            errors.append(f"line {index}: invalid metadata key '{key}'")
            continue
        if not isinstance(parent, dict):
            errors.append(f"line {index}: mapping entry does not belong to an object")
            continue
        if key in parent:
            errors.append(f"line {index}: duplicate metadata key '{key}'")
            continue

        if value.strip():
            parent[key] = _scalar(value)
            continue

        next_container: dict[str, Any] | list[Any] = {}
        for following in lines[offset + 1 :]:
            if not following.strip() or following.lstrip().startswith("#"):
                continue
            following_indent = len(following) - len(following.lstrip(" "))
            if following_indent <= indent:
                break
            if following.strip().startswith("- "):
                next_container = []
            break
        parent[key] = next_container
        stack.append((indent, next_container))

    return root, errors


def parse_skill_frontmatter(text: str) -> FrontmatterResult:
    """Parse the conservative YAML subset used by Agent Skill metadata.

    The parser intentionally rejects executable tags, aliases, and complex YAML.
    """

    lines = text.splitlines()
    if not lines or lines[0].strip() != "---":
        return FrontmatterResult({}, text, ("missing opening frontmatter delimiter",), 1)
    closing = next(
        (index for index, line in enumerate(lines[1:], start=1) if line.strip() == "---"), None
    )
    if closing is None:
        return FrontmatterResult({}, text, ("missing closing frontmatter delimiter",), 1)
    metadata, errors = _parse_frontmatter_lines(lines[1:closing])
    body = "\n".join(lines[closing + 1 :])
    return FrontmatterResult(metadata, body, tuple(errors), closing + 2)


@dataclass(frozen=True, slots=True)
class McpParseResult:
    is_mcp: bool
    data: dict[str, Any] | None
    errors: tuple[str, ...]


def parse_mcp_json(text: str, filename: str) -> McpParseResult:
    """Parse MCP-like JSON while distinguishing unrelated JSON assets."""

    mcp_named = (
        filename.lower() in {"mcp.json", ".mcp.json", "mcp-config.json"}
        or "mcp" in filename.lower()
    )
    try:
        value = json.loads(text)
    except json.JSONDecodeError as exc:
        if mcp_named:
            return McpParseResult(
                True, None, (f"invalid JSON at line {exc.lineno}, column {exc.colno}",)
            )
        return McpParseResult(False, None, ())
    except RecursionError:
        if mcp_named:
            return McpParseResult(True, None, ("JSON nesting exceeds the parser limit",))
        return McpParseResult(False, None, ())
    if not isinstance(value, dict):
        return McpParseResult(
            mcp_named, None, ("MCP configuration root must be an object",) if mcp_named else ()
        )
    is_mcp = mcp_named or any(key in value for key in ("mcpServers", "servers"))
    if not is_mcp:
        return McpParseResult(False, None, ())
    errors: list[str] = []
    structure_error = _json_structure_error(value)
    if structure_error:
        errors.append(structure_error)
    servers = value.get("mcpServers", value.get("servers"))
    if not isinstance(servers, dict) or not servers:
        errors.append("MCP configuration requires a non-empty mcpServers object")
    else:
        for name, server in servers.items():
            if not isinstance(name, str) or not name.strip():
                errors.append("MCP server names must be non-empty strings")
            if not isinstance(server, dict):
                errors.append(f"MCP server '{name}' must be an object")
                continue
            command = server.get("command")
            url = server.get("url")
            if command is None and url is None:
                errors.append(f"MCP server '{name}' requires command or url")
            if command is not None and not isinstance(command, str):
                errors.append(f"MCP server '{name}' command must be a string")
            if "args" in server and not isinstance(server["args"], list):
                errors.append(f"MCP server '{name}' args must be an array")
            if "env" in server and not isinstance(server["env"], dict):
                errors.append(f"MCP server '{name}' env must be an object")
    return McpParseResult(True, value, tuple(errors))


def _json_structure_error(
    value: Any, *, max_depth: int = 64, max_nodes: int = 10_000
) -> str | None:
    stack: list[tuple[Any, int]] = [(value, 0)]
    nodes = 0
    while stack:
        current, depth = stack.pop()
        nodes += 1
        if nodes > max_nodes:
            return "MCP configuration exceeds the node-count limit"
        if depth > max_depth:
            return "MCP configuration exceeds the nesting limit"
        if isinstance(current, dict):
            stack.extend((child, depth + 1) for child in current.values())
        elif isinstance(current, list):
            stack.extend((child, depth + 1) for child in current)
    return None
