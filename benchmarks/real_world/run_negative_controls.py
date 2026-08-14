#!/usr/bin/env python3
"""Run the real-world-inspired negative-control track without touching primary metrics."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from analyzers.solidity_analyzer import SolidityAnalyzer


ROOT = Path(__file__).resolve().parents[2]
CONTROL_ROOT = ROOT / "benchmarks" / "real_world" / "negative_controls"
MANIFEST_PATH = CONTROL_ROOT / "manifest.json"


def run() -> dict:
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    results = []
    total_checks = 0
    false_positive_checks = 0

    for control in manifest["controls"]:
        path = CONTROL_ROOT / control["file"]
        source = path.read_text(encoding="utf-8")
        findings = SolidityAnalyzer().analyze_file(path.name, source)
        observed = sorted({finding.agent_name for finding in findings})
        expected_absent = set(control["expected_absent_detectors"])
        unexpected = sorted(set(observed) & expected_absent)
        checks = len(expected_absent)
        total_checks += checks
        false_positive_checks += len(unexpected)
        results.append(
            {
                "id": control["id"],
                "file": control["file"],
                "expected_clean": control["expected_clean"],
                "observed_detectors": observed,
                "expected_absent_detectors": sorted(expected_absent),
                "contextual_findings_allowed": sorted(control.get("contextual_findings_allowed", [])),
                "unexpected_detectors": unexpected,
                "status": "passed" if not unexpected else "failed",
            }
        )

    return {
        "schema_version": 1,
        "track": manifest["track"],
        "metric_role": manifest["metric_role"],
        "primary_benchmark_affected": False,
        "controls": results,
        "metrics": {
            "controls": len(results),
            "absence_checks": total_checks,
            "false_positive_checks": false_positive_checks,
            "false_positive_rate": (false_positive_checks / total_checks) if total_checks else 0.0,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=None)
    args = parser.parse_args()
    report = run()
    rendered = json.dumps(report, indent=2, ensure_ascii=False) + "\n"
    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    return 0 if report["metrics"]["false_positive_checks"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
