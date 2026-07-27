"""Rule catalogue and finding construction helpers."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass

from .models import Confidence, Evidence, Finding, Severity
from .redaction import redact_text


@dataclass(frozen=True, slots=True)
class RuleDefinition:
    id: str
    title: str
    severity: Severity
    confidence: Confidence
    description: str
    remediation: str
    tags: tuple[str, ...]


RULES: dict[str, RuleDefinition] = {
    "META001": RuleDefinition(
        "META001",
        "Missing or invalid Agent Skill metadata",
        Severity.MEDIUM,
        Confidence.HIGH,
        "The bundle lacks parseable SKILL.md frontmatter or required fields.",
        "Add strict frontmatter with a valid name and a meaningful description.",
        ("metadata", "integrity"),
    ),
    "META002": RuleDefinition(
        "META002",
        "Invalid Agent Skill name",
        Severity.LOW,
        Confidence.HIGH,
        "The declared skill name is not a portable lowercase slug.",
        "Use 1-64 lowercase letters, numbers, and single hyphens.",
        ("metadata",),
    ),
    "INJ001": RuleDefinition(
        "INJ001",
        "Suspicious instruction override or exfiltration language",
        Severity.HIGH,
        Confidence.MEDIUM,
        "Instructions attempt to suppress safeguards, deceive the user, or obtain protected data.",
        (
            "Remove override, concealment, and data-exfiltration instructions; require "
            "explicit user consent."
        ),
        ("prompt-injection", "social-engineering"),
    ),
    "SEC001": RuleDefinition(
        "SEC001",
        "Embedded secret-like value",
        Severity.CRITICAL,
        Confidence.HIGH,
        "A credential-shaped value appears in bundle content.",
        (
            "Revoke any real credential, remove it from history, and reference an environment "
            "variable instead."
        ),
        ("secret", "credential"),
    ),
    "CMD001": RuleDefinition(
        "CMD001",
        "Remote content piped into a shell",
        Severity.CRITICAL,
        Confidence.HIGH,
        "A command downloads remote content and executes it without an inspection boundary.",
        (
            "Download a version-pinned artifact, verify its digest, inspect it, and execute "
            "only with approval."
        ),
        ("shell", "supply-chain", "network"),
    ),
    "CMD002": RuleDefinition(
        "CMD002",
        "Destructive or privilege-expanding shell command",
        Severity.HIGH,
        Confidence.HIGH,
        (
            "A command can delete broadly, elevate privilege, weaken permissions, or "
            "evaluate dynamic text."
        ),
        (
            "Replace it with a least-privilege, path-bounded operation and require explicit "
            "confirmation."
        ),
        ("shell", "privilege"),
    ),
    "DEP001": RuleDefinition(
        "DEP001",
        "Unpinned dependency or remote reference",
        Severity.MEDIUM,
        Confidence.MEDIUM,
        "A dependency or remote artifact can change without a bundle revision.",
        "Pin an immutable version or commit and verify the downloaded artifact's digest.",
        ("dependency", "provenance"),
    ),
    "MCP001": RuleDefinition(
        "MCP001",
        "Broad or wildcard tool permission",
        Severity.HIGH,
        Confidence.HIGH,
        "The configuration grants all tools or an equivalently broad capability.",
        "Declare only the specific tools required for the documented workflow.",
        ("mcp", "permission", "least-privilege"),
    ),
    "MCP002": RuleDefinition(
        "MCP002",
        "MCP server launches a general-purpose shell",
        Severity.HIGH,
        Confidence.HIGH,
        "The MCP process uses a shell interpreter that can execute arbitrary command strings.",
        "Launch a version-pinned server executable directly with fixed, reviewed arguments.",
        ("mcp", "shell", "execution"),
    ),
    "MCP003": RuleDefinition(
        "MCP003",
        "Malformed MCP configuration",
        Severity.MEDIUM,
        Confidence.HIGH,
        "The MCP JSON structure is invalid or ambiguous.",
        "Correct the JSON and validate server command, URL, args, and env field types.",
        ("mcp", "configuration"),
    ),
    "PATH001": RuleDefinition(
        "PATH001",
        "Unsafe path reference",
        Severity.HIGH,
        Confidence.MEDIUM,
        (
            "A declared path is absolute, traverses a parent directory, or targets a "
            "sensitive location."
        ),
        "Resolve paths against an allowed root and reject absolute or parent-traversal segments.",
        ("filesystem", "path-traversal"),
    ),
    "FSH001": RuleDefinition(
        "FSH001",
        "Symbolic link present",
        Severity.MEDIUM,
        Confidence.HIGH,
        "The bundle contains a symbolic link that could escape its inspection root.",
        "Replace the symlink with an ordinary reviewed file or remove it from the bundle.",
        ("filesystem", "symlink"),
    ),
    "FSH002": RuleDefinition(
        "FSH002",
        "File exceeds inspection size limit",
        Severity.MEDIUM,
        Confidence.HIGH,
        "A file was not read because it exceeds the configured per-file limit.",
        (
            "Remove generated or binary payloads, or review the file separately under "
            "tighter controls."
        ),
        ("resource-limit", "availability"),
    ),
    "FSH003": RuleDefinition(
        "FSH003",
        "Bundle inspection resource limit reached",
        Severity.HIGH,
        Confidence.HIGH,
        "The file-count, byte-count, or directory-depth budget was exceeded.",
        "Reduce the bundle and inspect excluded content separately before trusting it.",
        ("resource-limit", "availability"),
    ),
    "PROV001": RuleDefinition(
        "PROV001",
        "Missing provenance declaration",
        Severity.MEDIUM,
        Confidence.HIGH,
        "The bundle does not identify an upstream source, repository, or provenance record.",
        "Add a source or repository field, and document origin plus review history.",
        ("provenance", "governance"),
    ),
    "LIC001": RuleDefinition(
        "LIC001",
        "Missing license",
        Severity.MEDIUM,
        Confidence.HIGH,
        "No root license file is present, so reuse rights are unclear.",
        "Add an explicit license after confirming the author has the right to grant it.",
        ("license", "governance"),
    ),
    "NET001": RuleDefinition(
        "NET001",
        "Unencrypted remote endpoint",
        Severity.MEDIUM,
        Confidence.HIGH,
        "An MCP endpoint uses plain HTTP outside a loopback address.",
        "Use HTTPS with certificate verification, or bind a local-only endpoint explicitly.",
        ("network", "mcp"),
    ),
}


PROMPT_INJECTION_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"(?i)ignore (?:all |any )?(?:previous|prior|system|developer) instructions?"),
    re.compile(r"(?i)(?:override|bypass|disable) (?:the )?(?:policy|safeguard|approval|security)"),
    re.compile(r"(?i)(?:do not|never) (?:tell|inform|show|alert) (?:the )?user"),
    re.compile(
        r"(?i)(?:upload|send|exfiltrate|transmit).{0,40}(?:secret|token|credential|private data)"
    ),
    re.compile(r"(?i)pretend (?:this|the action) (?:was|is) (?:approved|authorized)"),
)

REMOTE_PIPE_PATTERN = re.compile(
    r"(?i)(?:curl|wget)\b[^\n|;&]{0,240}(?:\||\|&)\s*(?:sudo\s+)?(?:ba)?sh\b"
)

DESTRUCTIVE_COMMAND_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"(?i)\brm\s+-[a-z]*r[a-z]*f[a-z]*\s+(?:/|~|\*|\$HOME)"),
    re.compile(r"(?i)\bsudo\s+(?:sh|bash|rm|chmod|chown|tee|install)\b"),
    re.compile(r"(?i)\bchmod\s+(?:-R\s+)?777\b"),
    re.compile(r"(?i)\b(?:eval|exec)\s+[\"'$({`]"),
    re.compile(r"(?i)\b(?:powershell|pwsh)\b.{0,100}\b(?:iex|invoke-expression)\b"),
)

UNPINNED_REFERENCE_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"(?i)\b(?:pip|pip3)\s+install\s+(?![^\n]*==)[A-Za-z0-9_.-]+"),
    re.compile(
        r"(?i)\b(?:npm\s+(?:install|i)|npx\s+-?y?)\s+(?:--\S+\s+)*[A-Za-z0-9_.@/-]+(?:\s|$)"
    ),
    re.compile(r"(?i)https?://\S+/(?:main|master|latest)(?:/|\b)"),
    re.compile(r"(?i)\buses:\s*[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+@(?:main|master|latest)\b"),
    re.compile(r"(?i)\b(?:image|docker)\s*[:=]\s*[A-Za-z0-9_./-]+:latest\b"),
)


def make_finding(
    rule_id: str,
    *,
    path: str,
    line: int | None,
    snippet: str,
    message: str | None = None,
    confidence: Confidence | None = None,
) -> Finding:
    """Create a stable finding with redacted evidence and ID."""

    rule = RULES[rule_id]
    safe_snippet = redact_text(snippet)
    evidence_fingerprint = hashlib.sha256(safe_snippet.encode("utf-8")).hexdigest()[:16]
    identity = f"{rule_id}\0{path}\0{line}\0{evidence_fingerprint}"
    finding_id = hashlib.sha256(identity.encode("utf-8")).hexdigest()[:20]
    return Finding(
        id=finding_id,
        rule_id=rule_id,
        title=rule.title,
        severity=rule.severity,
        confidence=confidence or rule.confidence,
        message=message or rule.description,
        remediation=rule.remediation,
        evidence=Evidence(
            path=path,
            line=line,
            snippet=safe_snippet,
            fingerprint=evidence_fingerprint,
        ),
        tags=rule.tags,
    )
