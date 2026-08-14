"""Evaluate negative controls and attack variants without altering primary benchmark totals."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
CORPUS_ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from analyzers.solidity_analyzer import SolidityAnalyzer
from verification.comparator import ComparisonStatus, compare_finding
from verification.poc import PocStatus, run_foundry_poc


CONTROL_MANIFEST = CORPUS_ROOT / "negative_controls" / "manifest.json"
VARIANT_MANIFEST = CORPUS_ROOT / "attack_variants" / "manifest.json"


def _load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _analyze(path: Path) -> tuple[set[str], list[Any]]:
    findings = SolidityAnalyzer().analyze_file(
        path.name,
        path.read_text(encoding="utf-8"),
    )
    return {finding.agent_name for finding in findings}, findings


def evaluate_controls() -> dict[str, Any]:
    manifest = _load(CONTROL_MANIFEST)
    cases = []
    expected_checks = 0
    false_positives = 0
    for control in manifest["controls"]:
        path = CORPUS_ROOT / "negative_controls" / control["file"]
        observed, _ = _analyze(path)
        expected = set(control["expected_absent_detectors"])
        unexpected = sorted(observed & expected)
        expected_checks += len(expected)
        false_positives += len(unexpected)
        cases.append({
            "file": control["file"],
            "category": control["category"],
            "expected_absent_detectors": sorted(expected),
            "observed_detectors": sorted(observed),
            "false_positives": unexpected,
        })
    return {
        "case_count": len(cases),
        "expected_absence_checks": expected_checks,
        "false_positives": false_positives,
        "fp_rate": false_positives / expected_checks if expected_checks else None,
        "cases": cases,
    }


def evaluate_variants() -> dict[str, Any]:
    manifest = _load(VARIANT_MANIFEST)
    cases = []
    true_positives = 0
    false_negatives = 0
    comparator_counts = {status.value: 0 for status in ComparisonStatus}
    poc_counts = {status.value: 0 for status in PocStatus}
    expected_total = 0
    for variant in manifest["variants"]:
        source_path = CORPUS_ROOT / "attack_variants" / variant["source"]
        poc_path = CORPUS_ROOT / "attack_variants" / variant["poc_file"]
        source = source_path.read_text(encoding="utf-8")
        expected = set(variant["expected_detectors"])
        observed, findings = _analyze(source_path)
        tp = sorted(expected & observed)
        fn = sorted(expected - observed)
        comparisons = []
        matched_detectors: set[str] = set()
        for finding in findings:
            if finding.agent_name in expected and finding.agent_name not in matched_detectors:
                result = compare_finding(finding, source)
                matched_detectors.add(finding.agent_name)
                comparisons.append({
                    "detector": finding.agent_name,
                    "status": result.status.value,
                    "reason": result.reason,
                })
                comparator_counts[result.status.value] += 1
        poc = run_foundry_poc(poc_path, ROOT)
        poc_counts[poc.status.value] += 1
        true_positives += len(tp)
        false_negatives += len(fn)
        expected_total += len(expected)
        cases.append({
            "name": variant["name"],
            "expected_detectors": sorted(expected),
            "observed_detectors": sorted(observed),
            "true_positives": tp,
            "false_negatives": fn,
            "comparisons": comparisons,
            "poc": {"status": poc.status.value, "reason": poc.reason},
        })
    return {
        "case_count": len(cases),
        "expected_detector_support": expected_total,
        "true_positives": true_positives,
        "false_negatives": false_negatives,
        "recall": true_positives / (true_positives + false_negatives) if expected_total else None,
        "comparator": comparator_counts,
        "poc": poc_counts,
        "cases": cases,
    }


def run_extended_benchmark() -> dict[str, Any]:
    return {
        "controls": evaluate_controls(),
        "variants": evaluate_variants(),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Evaluate extended benchmark controls and variants")
    parser.add_argument("--json-out", type=Path, help="Write the report to a JSON file")
    args = parser.parse_args()
    report = run_extended_benchmark()
    rendered = json.dumps(report, indent=2, sort_keys=True)
    print(rendered)
    if args.json_out:
        args.json_out.write_text(rendered + "\n", encoding="utf-8")
    failed = (
        report["controls"]["false_positives"]
        or report["variants"]["false_negatives"]
        or report["variants"]["comparator"][ComparisonStatus.REJECTED.value]
        or report["variants"]["comparator"][ComparisonStatus.INCONCLUSIVE.value]
        or report["variants"]["poc"][PocStatus.FAILED.value]
        or report["variants"]["poc"][PocStatus.INCONCLUSIVE.value]
    )
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
