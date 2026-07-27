# Rule Catalogue

Rules are deterministic review signals. Severity estimates potential impact; confidence estimates how
directly the static evidence supports the signal. Neither field declares malicious intent.

| Rule | Severity | Confidence | Signal |
|---|---|---|---|
| `META001` | Medium | High | Missing/invalid frontmatter, required name, or meaningful description |
| `META002` | Low | High | Non-portable Agent Skill name |
| `INJ001` | High | Medium | Override, concealment, safeguard bypass, or exfiltration language |
| `SEC001` | Critical | High | Credential-shaped value or private-key marker |
| `CMD001` | Critical | High | Remote content piped directly to a shell |
| `CMD002` | High | High | Broad deletion, privilege expansion, weak permissions, or dynamic evaluation |
| `DEP001` | Medium | Medium | Floating package, action, container, or remote reference |
| `MCP001` | High | High | Wildcard or all-tools permission |
| `MCP002` | High | High | MCP server launches a general-purpose shell |
| `MCP003` | Medium | High | Invalid MCP JSON or server field types |
| `PATH001` | High | Medium | Parent traversal, absolute sensitive path, or unsafe declared root |
| `FSH001` | Medium | High | Symlink present; target is not followed |
| `FSH002` | Medium | High | File exceeds configured per-file inspection limit |
| `FSH003` | High | High | File count, total bytes, depth, or read budget prevents full inspection |
| `PROV001` | Medium | High | No source/repository/homepage field or `PROVENANCE.md` |
| `LIC001` | Medium | High | No root `LICENSE` or `COPYING` file |
| `NET001` | Medium | High | Non-loopback MCP endpoint uses plain HTTP |

## Evidence Rules

Every finding includes one relative location, one normalized snippet, a one-way evidence fingerprint,
and remediation. Known credential substrings are replaced before a finding is created. Messages never
echo the raw value.

## Matching Boundaries

### Natural-language instructions

`INJ001` uses a deliberately small phrase family rather than attempting semantic classification. It
looks for direct requests to ignore higher-priority instructions, disable safeguards, hide actions from
the user, exfiltrate protected values, or pretend approval exists. Quoted security training material can
therefore trigger it and should be reviewed in context.

### Commands

`CMD001` requires a `curl`/`wget` pipeline into a shell on the same line. `CMD002` covers a narrow set of
high-impact forms such as broad recursive deletion, privileged shell/file operations, mode `777`, and
dynamic expression evaluation. This is not a complete shell parser.

### Dependencies

`DEP001` recognizes common `pip`, `npm`, `npx`, GitHub Action branch, remote `main`/`latest`, and
container `latest` forms. A version string is evidence of pinning, not evidence that the dependency is
trustworthy. Lockfile resolution and digest verification are outside scope.

### MCP permissions

`MCP001` fires only on explicit wildcard-equivalent values in recognized permission fields. Reviewers
must still assess whether a specifically named tool is too powerful. `MCP002` flags shell interpreters
as MCP process commands; ordinary runtimes such as `node` are inventoried but not automatically unsafe.

### Filesystem and governance

The filesystem rules also describe inspection coverage. `FSH002` or `FSH003` means the report is
incomplete by design. A nested dependency license does not satisfy `LIC001`; the bundle itself needs a
root license.

## Adding a Rule

A rule change is complete only with:

1. a stable ID, title, severity, confidence, explanation, remediation, and tags;
2. an intentionally synthetic positive fixture;
3. a nearby negative test for a reasonable non-match;
4. an updated labelled manifest;
5. regenerated benchmark and sample evidence where affected; and
6. a documented false-positive and false-negative boundary.
