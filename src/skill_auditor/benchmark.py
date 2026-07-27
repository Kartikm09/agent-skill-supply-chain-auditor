"""Labelled synthetic-fixture evaluation for rule-level precision and recall."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .scanner import scan_path


@dataclass(frozen=True, slots=True)
class EvaluationMetrics:
    true_positives: int
    false_positives: int
    false_negatives: int
    precision: float
    recall: float
    f1: float

    def to_dict(self) -> dict[str, int | float]:
        return {
            "true_positives": self.true_positives,
            "false_positives": self.false_positives,
            "false_negatives": self.false_negatives,
            "precision": self.precision,
            "recall": self.recall,
            "f1": self.f1,
        }


def evaluate_manifest(manifest_path: Path) -> dict[str, Any]:
    """Evaluate rule presence against labelled, synthetic fixture directories."""

    manifest_path = manifest_path.resolve()
    data = json.loads(manifest_path.read_text(encoding="utf-8"))
    if data.get("schema_version") != "1.0.0" or not isinstance(data.get("fixtures"), list):
        raise ValueError("unsupported or malformed fixture manifest")
    fixture_root = manifest_path.parent.resolve()
    expected_pairs: set[tuple[str, str]] = set()
    predicted_pairs: set[tuple[str, str]] = set()
    fixture_results: list[dict[str, Any]] = []

    for entry in sorted(data["fixtures"], key=lambda item: item.get("id", "")):
        fixture_id = entry.get("id")
        relative_path = entry.get("path")
        expected = entry.get("expected_rules")
        if (
            not isinstance(fixture_id, str)
            or not isinstance(relative_path, str)
            or not isinstance(expected, list)
        ):
            raise ValueError("each fixture requires id, path, and expected_rules")
        fixture_path = (fixture_root / relative_path).resolve()
        if fixture_path != fixture_root and fixture_root not in fixture_path.parents:
            raise ValueError(f"fixture path escapes manifest root: {relative_path}")
        result = scan_path(fixture_path)
        predicted = sorted({finding.rule_id for finding in result.findings})
        expected_rules = sorted({str(rule_id) for rule_id in expected})
        expected_pairs.update((fixture_id, rule_id) for rule_id in expected_rules)
        predicted_pairs.update((fixture_id, rule_id) for rule_id in predicted)
        fixture_results.append(
            {
                "id": fixture_id,
                "path": relative_path,
                "expected_rules": expected_rules,
                "predicted_rules": predicted,
                "unexpected_rules": sorted(set(predicted) - set(expected_rules)),
                "missed_rules": sorted(set(expected_rules) - set(predicted)),
                "scan_id": result.scan_id,
            }
        )

    true_positives = len(expected_pairs & predicted_pairs)
    false_positives = len(predicted_pairs - expected_pairs)
    false_negatives = len(expected_pairs - predicted_pairs)
    precision = _divide(true_positives, true_positives + false_positives)
    recall = _divide(true_positives, true_positives + false_negatives)
    f1 = _divide(2 * precision * recall, precision + recall)
    metrics = EvaluationMetrics(
        true_positives,
        false_positives,
        false_negatives,
        precision,
        recall,
        f1,
    )
    return {
        "schema_version": "1.0.0",
        "dataset": {
            "name": data.get("name", "synthetic-labelled-fixtures"),
            "fixture_count": len(fixture_results),
            "label_unit": "unique rule ID per fixture",
            "synthetic": True,
        },
        "metrics": metrics.to_dict(),
        "fixtures": fixture_results,
        "limitations": [
            (
                "Metrics describe this small synthetic corpus only and do not estimate "
                "field performance."
            ),
            "Rule-level scoring does not measure duplicate finding quality or runtime behaviour.",
            (
                "The corpus was authored with the rules and should be supplemented by "
                "independent datasets."
            ),
        ],
    }


def _divide(numerator: float, denominator: float) -> float:
    return round(numerator / denominator, 4) if denominator else 0.0


def render_evaluation_markdown(evaluation: dict[str, Any]) -> str:
    """Render transparent benchmark results and per-fixture errors."""

    metrics = evaluation["metrics"]
    lines = [
        "# Synthetic Fixture Evaluation",
        "",
        "> This benchmark uses only labelled synthetic bundles. It is not a claim about detection "
        "performance on unknown real-world repositories.",
        "",
        "## Metrics",
        "",
        "| Fixture count | TP | FP | FN | Precision | Recall | F1 |",
        "|---:|---:|---:|---:|---:|---:|---:|",
        (
            f"| {evaluation['dataset']['fixture_count']} | {metrics['true_positives']} | "
            f"{metrics['false_positives']} | {metrics['false_negatives']} | "
            f"{metrics['precision']:.4f} | {metrics['recall']:.4f} | {metrics['f1']:.4f} |"
        ),
        "",
        "The scoring unit is one unique rule ID per fixture.",
        "",
        "## Fixture Results",
        "",
        "| Fixture | Expected | Predicted | Unexpected | Missed |",
        "|---|---|---|---|---|",
    ]
    for fixture in evaluation["fixtures"]:
        lines.append(
            "| {id} | {expected} | {predicted} | {unexpected} | {missed} |".format(
                id=fixture["id"],
                expected=_join(fixture["expected_rules"]),
                predicted=_join(fixture["predicted_rules"]),
                unexpected=_join(fixture["unexpected_rules"]),
                missed=_join(fixture["missed_rules"]),
            )
        )
    lines.extend(["", "## Limitations", ""])
    lines.extend(f"- {item}" for item in evaluation["limitations"])
    lines.append("")
    return "\n".join(lines)


def _join(items: list[str]) -> str:
    return ", ".join(f"`{item}`" for item in items) if items else "None"
