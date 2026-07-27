"""Tests for transparent synthetic-corpus evaluation."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from skill_auditor.benchmark import evaluate_manifest, render_evaluation_markdown


@pytest.mark.integration
def test_labelled_fixture_benchmark_has_no_mismatches(fixture_root: Path) -> None:
    evaluation = evaluate_manifest(fixture_root / "labels.json")
    assert evaluation["dataset"]["fixture_count"] == 10
    assert evaluation["metrics"]["false_positives"] == 0
    assert evaluation["metrics"]["false_negatives"] == 0
    assert evaluation["metrics"]["precision"] == 1.0
    assert evaluation["metrics"]["recall"] == 1.0
    assert "synthetic corpus" in render_evaluation_markdown(evaluation)


@pytest.mark.negative
def test_manifest_path_traversal_is_rejected(tmp_path: Path) -> None:
    manifest = tmp_path / "labels.json"
    manifest.write_text(
        json.dumps(
            {
                "schema_version": "1.0.0",
                "fixtures": [{"id": "escape", "path": "../outside", "expected_rules": []}],
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="escapes manifest root"):
        evaluate_manifest(manifest)


def test_malformed_manifest_is_rejected(tmp_path: Path) -> None:
    manifest = tmp_path / "labels.json"
    manifest.write_text('{"schema_version":"0"}', encoding="utf-8")
    with pytest.raises(ValueError, match="unsupported"):
        evaluate_manifest(manifest)
