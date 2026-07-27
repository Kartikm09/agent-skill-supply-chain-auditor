"""Unit tests for strict, non-executing metadata parsers."""

from __future__ import annotations

from skill_auditor.parsers import parse_mcp_json, parse_skill_frontmatter


def test_frontmatter_parses_scalar_nested_and_list_values() -> None:
    result = parse_skill_frontmatter(
        "---\n"
        "name: reviewed-skill\n"
        "description: A long and useful description for a valid skill.\n"
        "metadata:\n"
        "  source: https://example.invalid/source\n"
        "allowed-tools:\n"
        "  - Read\n"
        "  - Search\n"
        "---\n"
        "Body\n"
    )
    assert result.errors == ()
    assert result.metadata["metadata"]["source"].endswith("/source")
    assert result.metadata["allowed-tools"] == ["Read", "Search"]
    assert result.body == "Body"


def test_frontmatter_reports_missing_delimiters() -> None:
    result = parse_skill_frontmatter("name: no-frontmatter\n")
    assert "missing opening" in result.errors[0]


def test_frontmatter_rejects_duplicate_keys() -> None:
    result = parse_skill_frontmatter("---\nname: first\nname: second\n---\n")
    assert any("duplicate" in error for error in result.errors)


def test_frontmatter_rejects_yaml_aliases_and_tags() -> None:
    result = parse_skill_frontmatter(
        "---\nname: &shared unsafe\ndescription: !!python/object x\n---\n"
    )
    assert len(result.errors) == 2


def test_mcp_parser_accepts_stdio_server() -> None:
    result = parse_mcp_json(
        '{"mcpServers":{"docs":{"command":"node","args":["server-1.0.0.js"]}}}',
        "mcp.json",
    )
    assert result.is_mcp
    assert result.errors == ()
    assert result.data is not None


def test_mcp_parser_ignores_unrelated_json() -> None:
    result = parse_mcp_json('{"name":"ordinary fixture"}', "data.json")
    assert not result.is_mcp
    assert result.errors == ()


def test_named_mcp_parser_reports_invalid_json() -> None:
    result = parse_mcp_json('{"mcpServers":', "mcp-config.json")
    assert result.is_mcp
    assert "invalid JSON" in result.errors[0]


def test_mcp_parser_validates_server_field_types() -> None:
    result = parse_mcp_json(
        '{"mcpServers":{"bad":{"command":4,"args":"no","env":[]}}}',
        "mcp.json",
    )
    assert len(result.errors) == 3


def test_mcp_parser_handles_excessive_nesting() -> None:
    nested = '{"mcpServers":{"deep":{"command":"node","metadata":' + "[" * 1_500
    nested += "0" + "]" * 1_500 + "}}}"
    result = parse_mcp_json(nested, "mcp.json")
    assert result.is_mcp
    assert result.errors == ("MCP configuration exceeds the nesting limit",)


def test_mcp_parser_applies_post_parse_nesting_budget() -> None:
    nested = '{"mcpServers":{"safe":{"command":"node","metadata":' + "[" * 70
    nested += "0" + "]" * 70 + "}}}"
    result = parse_mcp_json(nested, "mcp.json")
    assert "MCP configuration exceeds the nesting limit" in result.errors
