"""Bounded, non-executing scanner for untrusted skill bundles."""

from __future__ import annotations

import errno
import hashlib
import json
import os
import re
import stat
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from .models import SEVERITY_RANK, FileRecord, Finding, ScanResult
from .parsers import parse_mcp_json, parse_skill_frontmatter
from .redaction import find_secret_matches, redact_text
from .rules import (
    DESTRUCTIVE_COMMAND_PATTERNS,
    PROMPT_INJECTION_PATTERNS,
    REMOTE_PIPE_PATTERN,
    UNPINNED_REFERENCE_PATTERNS,
    make_finding,
)
from .version import __version__

TEXT_EXTENSIONS = {
    ".bash",
    ".cfg",
    ".conf",
    ".ini",
    ".js",
    ".json",
    ".md",
    ".mjs",
    ".ps1",
    ".py",
    ".sh",
    ".toml",
    ".ts",
    ".txt",
    ".yaml",
    ".yml",
}
TEXT_FILENAMES = {"Dockerfile", "Makefile", "SKILL.md", "LICENSE", "NOTICE"}
IGNORED_DIRECTORIES = {".git", ".venv", "__pycache__", ".pytest_cache", ".ruff_cache"}
LICENSE_FILENAMES = {"license", "license.md", "license.txt", "copying", "copying.md"}
SHELL_COMMANDS = {"bash", "sh", "zsh", "fish", "cmd", "cmd.exe", "powershell", "pwsh"}
SENSITIVE_PATH_PREFIXES = ("/etc/", "/root/", "/home/", "/users/", "~/.ssh", "~/.aws")


@dataclass(frozen=True, slots=True)
class ScanOptions:
    """Hard limits applied before any untrusted content is parsed."""

    max_file_bytes: int = 1_048_576
    max_total_bytes: int = 20_971_520
    max_files: int = 2_000
    max_depth: int = 20

    def validate(self) -> None:
        for name in ("max_file_bytes", "max_total_bytes", "max_files", "max_depth"):
            value = getattr(self, name)
            if value <= 0:
                raise ValueError(f"{name} must be greater than zero")


@dataclass(slots=True)
class _ContentFile:
    path: str
    text: str


class Auditor:
    """Inspect a bundle without importing, executing, or following its content."""

    def __init__(self, options: ScanOptions | None = None) -> None:
        self.options = options or ScanOptions()
        self.options.validate()
        self._reset_state()

    def _reset_state(self) -> None:
        self._findings: list[Finding] = []
        self._records: list[FileRecord] = []
        self._content: list[_ContentFile] = []
        self._total_bytes = 0
        self._limit_keys: set[str] = set()
        self._inventory: dict[str, Any] = {
            "skill": None,
            "mcp_servers": [],
            "permissions": [],
            "dependencies": [],
            "provenance": None,
            "license": None,
        }

    def scan(self, target: Path) -> ScanResult:
        """Scan ``target`` and return a deterministic result."""

        self._reset_state()
        target = Path(target)
        if target.is_symlink():
            raise ValueError("scan root must not be a symbolic link")
        if not target.exists() or not target.is_dir():
            raise ValueError("scan target must be an existing directory")

        self._walk(target, target, depth=0)
        self._inspect_content()
        self._inspect_governance()
        findings = self._deduplicate_and_sort(self._findings)
        records = sorted(self._records, key=lambda item: item.path)
        self._normalize_inventory()
        scan_id = self._scan_id(records)
        return ScanResult(
            schema_version="1.0.0",
            scanner_version=__version__,
            target_name=self._safe_path(target.name),
            scan_id=scan_id,
            findings=findings,
            files=records,
            inventory=self._inventory,
            limits={
                "max_file_bytes": self.options.max_file_bytes,
                "max_total_bytes": self.options.max_total_bytes,
                "max_files": self.options.max_files,
                "max_depth": self.options.max_depth,
            },
            notices=[
                "Static inspection only: no scanned code was imported or executed.",
                "A clean result does not prove that a bundle is safe.",
            ],
        )

    def _walk(self, root: Path, directory: Path, *, depth: int) -> None:
        if depth > self.options.max_depth:
            relative_directory = directory.relative_to(root).as_posix() or "."
            self._limit_finding("depth", self._safe_path(relative_directory))
            return
        try:
            entries = sorted(os.scandir(directory), key=lambda entry: entry.name.casefold())
        except OSError as exc:
            self._findings.append(
                make_finding(
                    "FSH003",
                    path=self._safe_path(directory.relative_to(root).as_posix() or "."),
                    line=None,
                    snippet=f"directory could not be read: {exc.__class__.__name__}",
                )
            )
            return

        for entry in entries:
            relative = self._safe_path((directory / entry.name).relative_to(root).as_posix())
            if entry.name in IGNORED_DIRECTORIES and entry.is_dir(follow_symlinks=False):
                continue
            if len(self._records) >= self.options.max_files:
                self._limit_finding("files", relative)
                return
            if entry.is_symlink():
                self._records.append(FileRecord(relative, "symlink", 0, None))
                self._findings.append(
                    make_finding(
                        "FSH001",
                        path=relative,
                        line=None,
                        snippet="symbolic link skipped without resolving its target",
                    )
                )
                continue
            if entry.is_dir(follow_symlinks=False):
                self._walk(root, Path(entry.path), depth=depth + 1)
                continue
            if not entry.is_file(follow_symlinks=False):
                self._records.append(FileRecord(relative, "special", 0, None))
                continue

            opened = self._read_regular_file(entry, relative)
            if opened is None:
                continue
            data, size = opened
            self._total_bytes += len(data)
            digest = hashlib.sha256(data).hexdigest()
            self._records.append(FileRecord(relative, "file", size, digest))
            if self._is_text_file(relative, data):
                try:
                    text = data.decode("utf-8")
                except UnicodeDecodeError:
                    continue
                self._content.append(_ContentFile(relative, text))

    def _read_regular_file(
        self, entry: os.DirEntry[str], relative: str
    ) -> tuple[bytes, int] | None:
        """Open one stable file descriptor without following a link."""

        try:
            before = os.lstat(entry.path)
            flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(entry.path, flags)
        except OSError as exc:
            if exc.errno == errno.ELOOP:
                self._records.append(FileRecord(relative, "symlink", 0, None))
                self._findings.append(
                    make_finding(
                        "FSH001",
                        path=relative,
                        line=None,
                        snippet="entry changed into a symlink before it could be opened",
                    )
                )
            else:
                self._limit_finding("read", relative)
            return None

        try:
            opened = os.fstat(descriptor)
            same_entry = (before.st_dev, before.st_ino) == (opened.st_dev, opened.st_ino)
            if not same_entry or not stat.S_ISREG(opened.st_mode):
                self._records.append(FileRecord(relative, "special", 0, None))
                self._findings.append(
                    make_finding(
                        "FSH001",
                        path=relative,
                        line=None,
                        snippet="entry identity changed during inspection; content was not read",
                    )
                )
                return None
            size = opened.st_size
            if size > self.options.max_file_bytes:
                self._records.append(FileRecord(relative, "file", size, None))
                self._findings.append(
                    make_finding(
                        "FSH002",
                        path=relative,
                        line=None,
                        snippet=f"file size {size} exceeds limit {self.options.max_file_bytes}",
                    )
                )
                return None
            if self._total_bytes + size > self.options.max_total_bytes:
                self._records.append(FileRecord(relative, "file", size, None))
                self._limit_finding("bytes", relative)
                return None

            chunks: list[bytes] = []
            remaining = self.options.max_file_bytes + 1
            while remaining:
                chunk = os.read(descriptor, min(65_536, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            data = b"".join(chunks)
            if len(data) > self.options.max_file_bytes:
                self._records.append(FileRecord(relative, "file", len(data), None))
                self._findings.append(
                    make_finding(
                        "FSH002",
                        path=relative,
                        line=None,
                        snippet="file grew beyond the inspection limit while being read",
                    )
                )
                return None
            if self._total_bytes + len(data) > self.options.max_total_bytes:
                self._records.append(FileRecord(relative, "file", len(data), None))
                self._limit_finding("bytes", relative)
                return None
            return data, len(data)
        finally:
            os.close(descriptor)

    def _limit_finding(self, key: str, path: str) -> None:
        if key in self._limit_keys:
            return
        self._limit_keys.add(key)
        self._findings.append(
            make_finding(
                "FSH003",
                path=path,
                line=None,
                snippet=f"inspection budget reached: {key}",
            )
        )

    @staticmethod
    def _is_text_file(path: str, data: bytes) -> bool:
        name = PurePosixPath(path).name
        suffix = PurePosixPath(path).suffix.lower()
        return (name in TEXT_FILENAMES or suffix in TEXT_EXTENSIONS) and b"\x00" not in data[:4096]

    def _inspect_content(self) -> None:
        for content in self._content:
            self._scan_lines(content)
            if PurePosixPath(content.path).name == "SKILL.md":
                self._inspect_skill(content)
            if PurePosixPath(content.path).suffix.lower() == ".json":
                self._inspect_mcp(content)

    def _scan_lines(self, content: _ContentFile) -> None:
        for line_number, line in enumerate(content.text.splitlines(), start=1):
            if find_secret_matches(line):
                self._findings.append(
                    make_finding("SEC001", path=content.path, line=line_number, snippet=line)
                )
            if any(pattern.search(line) for pattern in PROMPT_INJECTION_PATTERNS):
                self._findings.append(
                    make_finding("INJ001", path=content.path, line=line_number, snippet=line)
                )
            if REMOTE_PIPE_PATTERN.search(line):
                self._findings.append(
                    make_finding("CMD001", path=content.path, line=line_number, snippet=line)
                )
            if any(pattern.search(line) for pattern in DESTRUCTIVE_COMMAND_PATTERNS):
                self._findings.append(
                    make_finding("CMD002", path=content.path, line=line_number, snippet=line)
                )
            if self._is_unpinned_line(line):
                self._findings.append(
                    make_finding("DEP001", path=content.path, line=line_number, snippet=line)
                )
                self._inventory["dependencies"].append(
                    {
                        "reference": self._safe_reference(line),
                        "path": content.path,
                        "line": line_number,
                        "pinned": False,
                    }
                )

    @staticmethod
    def _is_unpinned_line(line: str) -> bool:
        if not any(pattern.search(line) for pattern in UNPINNED_REFERENCE_PATTERNS):
            return False
        stripped = line.strip()
        pip_match = re.search(r"(?i)\b(?:pip|pip3)\s+install\s+([^\s;&|]+)", stripped)
        if pip_match:
            package = pip_match.group(1)
            return not any(operator in package for operator in ("==", "~=", "@"))
        npm_match = re.search(
            r"(?i)\b(?:npm\s+(?:install|i)|npx\s+-?y?)\s+(?:--\S+\s+)*([^\s;&|]+)", stripped
        )
        if npm_match:
            package = npm_match.group(1)
            if package.startswith("@"):
                return package.count("@") < 2
            return "@" not in package
        return True

    @staticmethod
    def _safe_reference(line: str) -> str:
        value = " ".join(line.strip().split())
        return redact_text(value, limit=120)

    def _inspect_skill(self, content: _ContentFile) -> None:
        result = parse_skill_frontmatter(content.text)
        if result.errors:
            for error in result.errors:
                self._findings.append(
                    make_finding("META001", path=content.path, line=1, snippet=error)
                )
        metadata = result.metadata
        name = metadata.get("name")
        description = metadata.get("description")
        name_valid = isinstance(name, str) and bool(name)
        description_valid = isinstance(description, str) and len(description.strip()) >= 20
        if not name_valid:
            self._findings.append(
                make_finding(
                    "META001", path=content.path, line=1, snippet="required field 'name' is missing"
                )
            )
        elif not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", name) or len(name) > 64:
            self._findings.append(
                make_finding("META002", path=content.path, line=2, snippet=f"declared name: {name}")
            )
        if not description_valid:
            self._findings.append(
                make_finding(
                    "META001",
                    path=content.path,
                    line=1,
                    snippet="description must contain at least 20 characters",
                )
            )

        permissions = metadata.get("allowed-tools", metadata.get("allowed_tools", []))
        if isinstance(permissions, str):
            permissions = [item for item in re.split(r"[,\s]+", permissions) if item]
        if isinstance(permissions, list):
            for permission in permissions:
                if isinstance(permission, str):
                    self._inventory["permissions"].append(
                        {
                            "source": content.path,
                            "capability": redact_text(permission, limit=160),
                            "kind": "skill-tool",
                        }
                    )
                    if permission.casefold() in {"*", "all", "all-tools", "bash(*)", "shell(*)"}:
                        self._findings.append(
                            make_finding(
                                "MCP001",
                                path=content.path,
                                line=1,
                                snippet=f"allowed-tools includes {permission}",
                            )
                        )
        provenance = self._extract_provenance(metadata)
        if provenance:
            self._inventory["provenance"] = provenance
        self._inventory["skill"] = {
            "name": redact_text(name, limit=120) if isinstance(name, str) else None,
            "description": redact_text(description, limit=500)
            if isinstance(description, str)
            else None,
            "metadata_valid": not result.errors and name_valid and description_valid,
        }

    @classmethod
    def _extract_provenance(cls, metadata: dict[str, Any]) -> str | None:
        for key in ("source", "repository", "homepage"):
            if isinstance(metadata.get(key), str) and metadata[key].strip():
                return cls._safe_provenance(metadata[key].strip())
        nested = metadata.get("metadata")
        if isinstance(nested, dict):
            for key in ("source", "repository", "homepage"):
                if isinstance(nested.get(key), str) and nested[key].strip():
                    return cls._safe_provenance(nested[key].strip())
        return None

    @staticmethod
    def _safe_provenance(value: str) -> str:
        if value.startswith(("https://", "http://")):
            try:
                parsed = urlsplit(value)
                host = parsed.hostname or "invalid-host"
                if parsed.port:
                    host += f":{parsed.port}"
                return urlunsplit((parsed.scheme, host, parsed.path, "", ""))
            except ValueError:
                return "<invalid-provenance-url>"
        return redact_text(value, limit=500)

    def _inspect_mcp(self, content: _ContentFile) -> None:
        result = parse_mcp_json(content.text, PurePosixPath(content.path).name)
        if not result.is_mcp:
            return
        for error in result.errors:
            self._findings.append(make_finding("MCP003", path=content.path, line=1, snippet=error))
        if not result.data:
            return
        servers = result.data.get("mcpServers", result.data.get("servers", {}))
        if not isinstance(servers, dict):
            return
        for name, server in sorted(servers.items(), key=lambda item: str(item[0])):
            if not isinstance(server, dict):
                continue
            command = server.get("command")
            args = server.get("args", [])
            env = server.get("env", {})
            url = server.get("url")
            safe_name = redact_text(str(name), limit=120)
            server_record = {
                "name": safe_name,
                "transport": "remote" if isinstance(url, str) else "stdio",
                "command": redact_text(command, limit=160) if isinstance(command, str) else None,
                "argument_count": len(args) if isinstance(args, list) else 0,
                "environment_keys": sorted(redact_text(str(key), limit=120) for key in env)
                if isinstance(env, dict)
                else [],
                "url": self._safe_endpoint(url) if isinstance(url, str) else None,
                "source": content.path,
            }
            self._inventory["mcp_servers"].append(server_record)
            self._inspect_mcp_dependency(content.path, safe_name, command, args)
            if (
                isinstance(command, str)
                and PurePosixPath(command.casefold()).name in SHELL_COMMANDS
            ):
                self._findings.append(
                    make_finding(
                        "MCP002",
                        path=content.path,
                        line=1,
                        snippet=f"server '{safe_name}' command is {redact_text(command)}",
                    )
                )
            if (
                isinstance(url, str)
                and url.startswith("http://")
                and not re.match(r"http://(?:localhost|127\.0\.0\.1|\[::1\])(?::\d+)?(?:/|$)", url)
            ):
                self._findings.append(
                    make_finding(
                        "NET001",
                        path=content.path,
                        line=1,
                        snippet=f"server '{safe_name}' url is {self._safe_endpoint(url)}",
                    )
                )
            self._inspect_mcp_values(content.path, safe_name, server)

        self._inspect_permissions(content.path, result.data)

    def _inspect_mcp_values(self, path: str, server_name: str, server: dict[str, Any]) -> None:
        for key, value in self._flatten(server):
            if not isinstance(value, str):
                continue
            if key.casefold() in {"env", "environment"}:
                continue
            if self._unsafe_path(value):
                self._findings.append(
                    make_finding(
                        "PATH001",
                        path=path,
                        line=1,
                        snippet=f"server '{server_name}' declares unsafe path in {key}",
                    )
                )

    def _inspect_mcp_dependency(self, path: str, server_name: str, command: Any, args: Any) -> None:
        if not isinstance(command, str) or not isinstance(args, list):
            return
        command_name = PurePosixPath(command.casefold()).name
        if command_name not in {"npx", "uvx", "pipx"}:
            return
        candidate = next(
            (item for item in args if isinstance(item, str) and item and not item.startswith("-")),
            None,
        )
        if not candidate or candidate.startswith((".", "/")):
            return
        if command_name == "npx":
            pinned = self._npm_reference_is_pinned(candidate)
            ecosystem = "npm"
        else:
            pinned = "==" in candidate or "@" in candidate
            ecosystem = "python"
        safe_candidate = redact_text(candidate, limit=160)
        self._inventory["dependencies"].append(
            {
                "ecosystem": ecosystem,
                "reference": safe_candidate,
                "path": path,
                "line": 1,
                "pinned": pinned,
            }
        )
        if not pinned:
            self._findings.append(
                make_finding(
                    "DEP001",
                    path=path,
                    line=1,
                    snippet=f"server '{server_name}' launches unpinned {ecosystem} package",
                )
            )

    @staticmethod
    def _npm_reference_is_pinned(reference: str) -> bool:
        if reference.endswith("@latest"):
            return False
        if reference.startswith("@"):
            version_separator = reference.rfind("@")
            return version_separator > reference.find("/")
        return "@" in reference

    def _inspect_permissions(self, path: str, data: dict[str, Any]) -> None:
        permission_keys = {
            "allowedtools",
            "allowed_tools",
            "allow",
            "toolpermissions",
            "tool_permissions",
        }
        for key, value in self._flatten(data):
            if key.casefold().replace("-", "") not in {
                item.replace("_", "") for item in permission_keys
            }:
                continue
            values = value if isinstance(value, list) else [value]
            for permission in values:
                if not isinstance(permission, str):
                    continue
                self._inventory["permissions"].append(
                    {
                        "source": path,
                        "capability": redact_text(permission, limit=160),
                        "kind": "mcp-tool",
                    }
                )
                if permission.casefold() in {"*", "all", "all-tools", "**"}:
                    self._findings.append(
                        make_finding(
                            "MCP001",
                            path=path,
                            line=1,
                            snippet=f"permission field '{key}' contains wildcard access",
                        )
                    )

    @staticmethod
    def _flatten(value: Any, parent_key: str = "") -> Iterable[tuple[str, Any]]:
        stack: list[tuple[str, Any, int]] = [(parent_key, value, 0)]
        visited = 0
        while stack and visited < 10_000:
            key, current, depth = stack.pop()
            visited += 1
            if depth > 64:
                continue
            if isinstance(current, dict):
                children = [
                    (str(child_key), child, depth + 1) for child_key, child in current.items()
                ]
                stack.extend(reversed(children))
            elif isinstance(current, list):
                stack.extend((key, child, depth + 1) for child in reversed(current))
            else:
                yield key, current

    @staticmethod
    def _unsafe_path(value: str) -> bool:
        normalized = value.replace("\\", "/").casefold()
        if "../" in normalized or normalized == "..":
            return True
        return normalized.startswith(SENSITIVE_PATH_PREFIXES)

    @staticmethod
    def _safe_endpoint(value: str) -> str:
        try:
            parsed = urlsplit(value)
            if not parsed.scheme or not parsed.hostname:
                return "<invalid-endpoint>"
            host = parsed.hostname
            if parsed.port:
                host += f":{parsed.port}"
            return urlunsplit((parsed.scheme, host, "", "", ""))
        except ValueError:
            return "<invalid-endpoint>"

    @staticmethod
    def _safe_path(value: str) -> str:
        without_controls = "".join(
            character if character.isprintable() else "?" for character in value
        )
        return redact_text(without_controls, limit=512)

    def _inspect_governance(self) -> None:
        root_names = {
            PurePosixPath(record.path).name.casefold()
            for record in self._records
            if "/" not in record.path
        }
        has_skill = any(PurePosixPath(record.path).name == "SKILL.md" for record in self._records)
        has_mcp = bool(self._inventory["mcp_servers"])
        if not has_skill and not has_mcp:
            self._findings.append(
                make_finding(
                    "META001",
                    path=".",
                    line=None,
                    snippet="bundle contains neither SKILL.md nor a valid MCP server declaration",
                )
            )
        license_name = next(
            (name for name in sorted(root_names) if name in LICENSE_FILENAMES), None
        )
        if license_name:
            self._inventory["license"] = license_name
        else:
            self._findings.append(
                make_finding("LIC001", path=".", line=None, snippet="root license file not found")
            )
        if not self._inventory["provenance"]:
            provenance_file = next(
                (
                    record.path
                    for record in self._records
                    if PurePosixPath(record.path).name.casefold() == "provenance.md"
                ),
                None,
            )
            if provenance_file:
                self._inventory["provenance"] = provenance_file
            else:
                self._findings.append(
                    make_finding(
                        "PROV001", path=".", line=None, snippet="provenance declaration not found"
                    )
                )

    def _normalize_inventory(self) -> None:
        self._inventory["mcp_servers"] = sorted(
            self._inventory["mcp_servers"], key=lambda item: (item["name"], item["source"])
        )
        self._inventory["permissions"] = sorted(
            self._inventory["permissions"],
            key=lambda item: (item["kind"], item["capability"], item["source"]),
        )
        unique_dependencies = {
            (item["reference"], item["path"], item["line"]): item
            for item in self._inventory["dependencies"]
        }
        self._inventory["dependencies"] = [
            unique_dependencies[key] for key in sorted(unique_dependencies)
        ]

    @staticmethod
    def _deduplicate_and_sort(findings: list[Finding]) -> list[Finding]:
        unique = {finding.id: finding for finding in findings}
        return sorted(
            unique.values(),
            key=lambda finding: (
                -SEVERITY_RANK[finding.severity],
                finding.rule_id,
                finding.evidence.path,
                finding.evidence.line or 0,
                finding.id,
            ),
        )

    def _scan_id(self, records: list[FileRecord]) -> str:
        material = {
            "files": [record.to_dict() for record in records],
            "limits": {
                "max_file_bytes": self.options.max_file_bytes,
                "max_total_bytes": self.options.max_total_bytes,
                "max_files": self.options.max_files,
                "max_depth": self.options.max_depth,
            },
            "version": __version__,
        }
        encoded = json.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()


def scan_path(path: Path | str, options: ScanOptions | None = None) -> ScanResult:
    """Convenience API for importing applications."""

    return Auditor(options).scan(Path(path))
