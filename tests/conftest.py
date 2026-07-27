"""Shared paths and bundle helpers for synthetic tests."""

from __future__ import annotations

from pathlib import Path

import pytest


@pytest.fixture(scope="session")
def repository_root() -> Path:
    return Path(__file__).resolve().parents[1]


@pytest.fixture(scope="session")
def fixture_root(repository_root: Path) -> Path:
    return repository_root / "fixtures"


def write_valid_bundle(
    path: Path, *, body: str = "Read one user-selected file and stop.\n"
) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    (path / "SKILL.md").write_text(
        "---\n"
        "name: temporary-safe-skill\n"
        "description: A sufficiently detailed synthetic description for a scanner test.\n"
        "source: https://example.invalid/tests/temporary-safe-skill\n"
        "---\n\n"
        f"{body}",
        encoding="utf-8",
    )
    (path / "LICENSE").write_text("SPDX-License-Identifier: Apache-2.0\n", encoding="utf-8")
    return path
