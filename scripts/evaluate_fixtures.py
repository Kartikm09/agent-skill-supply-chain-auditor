#!/usr/bin/env python3
"""Evaluate the scanner against the repository's labelled synthetic corpus."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from skill_auditor.benchmark import evaluate_manifest, render_evaluation_markdown


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()

    evaluation = evaluate_manifest(args.manifest)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    json_path = args.output_dir / "benchmark-results.json"
    markdown_path = args.output_dir / "benchmark-results.md"
    json_path.write_text(
        json.dumps(evaluation, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
        encoding="utf-8",
    )
    markdown_path.write_text(render_evaluation_markdown(evaluation), encoding="utf-8")
    metrics = evaluation["metrics"]
    print(
        "fixtures={fixture_count} tp={true_positives} fp={false_positives} "
        "fn={false_negatives} precision={precision:.4f} recall={recall:.4f} f1={f1:.4f}".format(
            fixture_count=evaluation["dataset"]["fixture_count"], **metrics
        )
    )
    return int(metrics["false_positives"] > 0 or metrics["false_negatives"] > 0)


if __name__ == "__main__":
    raise SystemExit(main())
