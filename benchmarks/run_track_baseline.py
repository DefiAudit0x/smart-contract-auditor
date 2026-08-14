#!/usr/bin/env python3
"""Produce a machine-readable comparison across isolated evaluation tracks."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
BENCHMARK_ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from benchmarks.run_benchmark import run_benchmark
from benchmarks.run_extended_benchmark import run_extended_benchmark
from benchmarks.real_world.run_negative_controls import run as run_real_world_negative_controls


def _read_json(path: Path | None) -> dict[str, Any] | None:
    if path is None or not path.is_file():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def _candidate_summary() -> dict[str, Any]:
    registry_path = BENCHMARK_ROOT / "real_world" / "registry.json"
    adjudication_dir = BENCHMARK_ROOT / "real_world" / "adjudications"
    registry = json.loads(registry_path.read_text(encoding="utf-8"))
    records = [
        json.loads(path.read_text(encoding="utf-8"))
        for path in sorted(adjudication_dir.glob("rw-*.json"))
        if not path.name.endswith("-pipeline.json")
    ]
    admitted = sum(record["review_status"] == "admitted" for record in records)
    quarantined = sum(record["review_status"] == "quarantined" for record in records)
    return {
        "candidate_count": len(registry["cases"]),
        "adjudication_record_count": len(records),
        "admitted_count": admitted,
        "quarantined_count": quarantined,
        "included_in_metrics": False,
        "reason": "Candidates lack complete source mapping and independent adjudication; no Ground Truth is inferred from analyzer or LLM output.",
    }


def build_report(llm_report_path: Path | None = None) -> dict[str, Any]:
    primary = run_benchmark()
    extended = run_extended_benchmark()
    real_world_negative_controls = run_real_world_negative_controls()
    llm_report = _read_json(llm_report_path)
    return {
        "schema_version": 1,
        "comparison_policy": {
            "primary_metrics_scope": "primary benchmark only",
            "supplementary_tracks_do_not_change_primary_metrics": True,
            "real_world_candidates_require_independent_adjudication": True,
        },
        "tracks": {
            "synthetic_primary": {
                "case_count": len(primary["cases"]),
                "totals": primary["totals"],
                "metrics": primary["metrics"],
                "comparator_totals": primary["comparator_totals"],
                "poc_totals": primary["poc_totals"],
            },
            "synthetic_supplementary": {
                "controls": extended["controls"],
                "variants": extended["variants"],
            },
            "real_world_negative_controls": real_world_negative_controls,
            "real_world_candidates": _candidate_summary(),
        },
        "llm_comparison": llm_report,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Compare isolated benchmark tracks")
    parser.add_argument("--llm-report", type=Path, default=None)
    parser.add_argument("--json-out", type=Path, default=None)
    args = parser.parse_args()
    report = build_report(args.llm_report)
    rendered = json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    print(rendered, end="")
    if args.json_out:
        args.json_out.write_text(rendered, encoding="utf-8")
    primary = report["tracks"]["synthetic_primary"]
    real_world_nc = report["tracks"]["real_world_negative_controls"]["metrics"]
    failed = (
        primary["totals"]["false_positives"]
        or primary["totals"]["false_negatives"]
        or primary["comparator_totals"].get("Rejected", 0)
        or primary["comparator_totals"].get("Inconclusive", 0)
        or real_world_nc["false_positive_checks"]
    )
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
