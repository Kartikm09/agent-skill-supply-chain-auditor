# Agent Skill Supply-Chain Audit

**Target:** `broad-mcp`  
**Scan ID:** `128822856c6c568905e70856959b1b3cbc5e9f891981976a75d06e694b25f14f`  
**Execution model:** Static inspection only; scanned code was not executed.

## Summary

| Metric | Value |
|---|---:|
| Findings | 4 |
| Highest severity | critical |
| Files inspected | 3 |
| Symlinks skipped | 0 |

| Critical | High | Medium | Low | Info |
|---:|---:|---:|---:|---:|
| 1 | 3 | 0 | 0 | 0 |

## Findings

### SEC001: Embedded secret-like value

- **Severity:** critical
- **Confidence:** high
- **Location:** `mcp.json:7`
- **Finding ID:** `c94de6fe392efa1b681a`
- **Message:** A credential-shaped value appears in bundle content.
- **Remediation:** Revoke any real credential, remove it from history, and reference an environment variable instead.
- **Evidence:** `"ACCESS_TOKEN": "<redacted-value:2b6975c74a4a>"`
- **Evidence fingerprint:** `2e76c4aefeff89e4`

### MCP001: Broad or wildcard tool permission

- **Severity:** high
- **Confidence:** high
- **Location:** `mcp.json:1`
- **Finding ID:** `5473827911f2280c13cf`
- **Message:** The configuration grants all tools or an equivalently broad capability.
- **Remediation:** Declare only the specific tools required for the documented workflow.
- **Evidence:** `permission field 'allowedTools' contains wildcard access`
- **Evidence fingerprint:** `15bc1575c100c371`

### MCP002: MCP server launches a general-purpose shell

- **Severity:** high
- **Confidence:** high
- **Location:** `mcp.json:1`
- **Finding ID:** `7cc4dddff7c0be8cbe79`
- **Message:** The MCP process uses a shell interpreter that can execute arbitrary command strings.
- **Remediation:** Launch a version-pinned server executable directly with fixed, reviewed arguments.
- **Evidence:** `server 'unsafe-shell' command is bash`
- **Evidence fingerprint:** `e794653437ddb4c9`

### PATH001: Unsafe path reference

- **Severity:** high
- **Confidence:** medium
- **Location:** `mcp.json:1`
- **Finding ID:** `bd273d3ee588b7dcdd06`
- **Message:** A declared path is absolute, traverses a parent directory, or targets a sensitive location.
- **Remediation:** Resolve paths against an allowed root and reject absolute or parent-traversal segments.
- **Evidence:** `server 'unsafe-shell' declares unsafe path in args`
- **Evidence fingerprint:** `80897c873ae86303`

## Inventory

- Declared skill: `overprivileged-mcp-demo`
- MCP servers: 1
- Declared permissions: 1
- Dependency references: 0
- Provenance: `https://example.invalid/fixtures/overprivileged-mcp-demo`
- License: `license`

## Review Boundary

This report is a deterministic static signal, not a malware verdict or hardened sandbox. It does not execute code, resolve dependencies, contact endpoints, or prove runtime behaviour.
