"""Deterministic domain models shared by scanning and reporting."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import StrEnum
from typing import Any


class Severity(StrEnum):
    """Finding impact, ordered separately through ``SEVERITY_RANK``."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Confidence(StrEnum):
    """How strongly the available static evidence supports a finding."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


SEVERITY_RANK = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


@dataclass(frozen=True, slots=True)
class Evidence:
    """A redacted, repository-relative observation supporting a finding."""

    path: str
    line: int | None
    snippet: str
    fingerprint: str


@dataclass(frozen=True, slots=True)
class Finding:
    """A policy-relevant static observation."""

    id: str
    rule_id: str
    title: str
    severity: Severity
    confidence: Confidence
    message: str
    remediation: str
    evidence: Evidence
    tags: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        """Return a stable JSON-ready representation."""

        value = asdict(self)
        value["severity"] = self.severity.value
        value["confidence"] = self.confidence.value
        value["tags"] = list(self.tags)
        return value


@dataclass(frozen=True, slots=True)
class FileRecord:
    """A content inventory entry; no absolute machine path is retained."""

    path: str
    kind: str
    size_bytes: int
    sha256: str | None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class ScanResult:
    """Complete deterministic result for one bundle."""

    schema_version: str
    scanner_version: str
    target_name: str
    scan_id: str
    findings: list[Finding]
    files: list[FileRecord]
    inventory: dict[str, Any]
    limits: dict[str, int]
    notices: list[str] = field(default_factory=list)

    @property
    def summary(self) -> dict[str, Any]:
        counts = {severity.value: 0 for severity in Severity}
        for finding in self.findings:
            counts[finding.severity.value] += 1
        highest = max(
            (finding.severity for finding in self.findings),
            key=lambda item: SEVERITY_RANK[item],
            default=Severity.INFO,
        )
        return {
            "finding_count": len(self.findings),
            "severity_counts": counts,
            "highest_severity": highest.value,
            "files_inspected": sum(record.kind == "file" for record in self.files),
            "symlinks_skipped": sum(record.kind == "symlink" for record in self.files),
        }

    def to_dict(self) -> dict[str, Any]:
        """Return a stable JSON-ready representation without wall-clock data."""

        return {
            "schema_version": self.schema_version,
            "scanner": {
                "name": "agent-skill-supply-chain-auditor",
                "version": self.scanner_version,
                "execution_model": "static-only",
            },
            "target": {"name": self.target_name, "scan_id": self.scan_id},
            "summary": self.summary,
            "findings": [finding.to_dict() for finding in self.findings],
            "inventory": self.inventory,
            "files": [record.to_dict() for record in self.files],
            "limits": self.limits,
            "notices": self.notices,
        }
