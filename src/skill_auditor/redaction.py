"""Secret detection and irreversible evidence redaction."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class SecretMatch:
    """Location and kind of a secret-like value."""

    start: int
    end: int
    kind: str
    value: str


TOKEN_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("private-key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("aws-access-key", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")),
    ("github-token", re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,255}\b")),
    ("openai-key", re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b")),
    ("slack-token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("url-credentials", re.compile(r"(?i)https?://([^\s/@:]+:[^\s/@]+)@")),
    (
        "assigned-secret",
        re.compile(
            r"(?i)\b(?:api[_-]?key|secret|token|password|passwd)\b\s*[:=]\s*"
            r"[\"']?([A-Za-z0-9_./+\-=]{12,})[\"']?"
        ),
    ),
)


def find_secret_matches(text: str) -> list[SecretMatch]:
    """Find non-overlapping secret-like values without retaining them in reports."""

    matches: list[SecretMatch] = []
    occupied: list[tuple[int, int]] = []
    for kind, pattern in TOKEN_PATTERNS:
        for match in pattern.finditer(text):
            start, end = match.span(1) if match.lastindex else match.span(0)
            if any(start < used_end and end > used_start for used_start, used_end in occupied):
                continue
            value = text[start:end]
            if value.startswith(("${", "{{", "<")):
                continue
            matches.append(SecretMatch(start=start, end=end, kind=kind, value=value))
            occupied.append((start, end))
    return sorted(matches, key=lambda item: (item.start, item.end))


def secret_fingerprint(value: str) -> str:
    """Create a short one-way correlation token for a secret-like value."""

    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()[:12]


def redact_text(text: str, *, limit: int = 240) -> str:
    """Redact known secret shapes and cap evidence length."""

    matches = find_secret_matches(text)
    redacted = text
    for match in reversed(matches):
        marker = f"<redacted-value:{secret_fingerprint(match.value)}>"
        redacted = redacted[: match.start] + marker + redacted[match.end :]
    compact = " ".join(redacted.strip().split())
    if len(compact) > limit:
        return compact[: limit - 3] + "..."
    return compact
