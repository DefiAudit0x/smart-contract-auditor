"""Run the deterministic Solidity ground-truth benchmark."""

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

from analyzers.solidity_analyzer import SolidityAnalyzer
from verification.comparator import ComparisonStatus, compare_finding
from verification.invariants import (
    InvariantStatus,
    evaluate_invariants,
    summarize_invariants,
)
from verification.poc import PocStatus, run_foundry_poc


REQUIRED_METADATA_FIELDS = {
    "vulnerability",
    "location",
    "severity",
    "category",
    "invariant_id",
    "poc_file",
    "poc_mode",
    "expected_detectors",
    "expected_clean",
}


def discover_cases() -> list[Path]:
    """Return benchmark case directories in stable order."""
    return sorted(
        path
        for path in BENCHMARK_ROOT.iterdir()
        if path.is_dir() and (path / "metadata.json").is_file()
    )


def load_metadata(case_dir: Path) -> dict[str, Any]:
    """Load and minimally validate one case metadata file."""
    metadata_path = case_dir / "metadata.json"
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    missing = REQUIRED_METADATA_FIELDS - metadata.keys()
    if missing:
        missing_text = ", ".join(sorted(missing))
        raise ValueError(f"{metadata_path}: missing fields: {missing_text}")
    if not isinstance(metadata["expected_detectors"], list):
        raise ValueError(f"{metadata_path}: expected_detectors must be a list")
    if not isinstance(metadata["expected_clean"], bool):
        raise ValueError(f"{metadata_path}: expected_clean must be boolean")
    if not isinstance(metadata["poc_file"], str) or not metadata["poc_file"]:
        raise ValueError(f"{metadata_path}: poc_file must be a non-empty string")
    if not (case_dir / metadata["poc_file"]).is_file():
        raise ValueError(f"{metadata_path}: PoC file does not exist")
    if metadata["poc_mode"] not in {"exploit", "negative_control"}:
        raise ValueError(f"{metadata_path}: unsupported poc_mode")
    return metadata


def analyze_contract(path: Path) -> tuple[set[str], list[Any]]:
    """Analyze one Solidity file with a fresh analyzer instance."""
    analyzer = SolidityAnalyzer()
    findings = analyzer.analyze_file(path.name, path.read_text(encoding="utf-8"))
    return {finding.agent_name for finding in findings}, findings


def _serialize_invariant(result: Any) -> dict[str, Any]:
    return {
        "invariant_id": result.invariant_id,
        "description": result.description,
        "status": result.status.value,
        "reason": result.reason,
        "evidence": [
            {
                "kind": item.kind,
                "location": item.location,
                "excerpt": item.excerpt,
            }
            for item in result.evidence
        ],
    }


def _serialize_comparison(result: Any) -> dict[str, Any]:
    return {
        "detector": result.hypothesis.detector,
        "function": result.hypothesis.function,
        "status": result.status.value,
        "reason": result.reason,
        "evidence": [
            {
                "kind": item.kind,
                "location": item.location,
                "excerpt": item.excerpt,
            }
            for item in result.evidence
        ],
    }


def evaluate_case(case_dir: Path) -> dict[str, Any]:
    """Compute detector-level metrics and comparator results for one case."""
    metadata = load_metadata(case_dir)
    expected = set(metadata["expected_detectors"])
    vulnerable_path = case_dir / "vulnerable.sol"
    fixed_path = case_dir / "fixed.sol"
    vulnerable_source = vulnerable_path.read_text(encoding="utf-8")
    vulnerable_names, vulnerable_findings = analyze_contract(vulnerable_path)
    fixed_names, fixed_findings = analyze_contract(fixed_path)

    true_positives = sorted(expected & vulnerable_names)
    false_negatives = sorted(expected - vulnerable_names)
    false_positives = sorted(expected & fixed_names) if metadata["expected_clean"] else []
    comparisons = [
        compare_finding(finding, vulnerable_source)
        for finding in vulnerable_findings
        if finding.agent_name in expected
    ]
    comparison_payload = [_serialize_comparison(result) for result in comparisons]
    invariant_id = metadata["invariant_id"]
    vulnerable_invariants = evaluate_invariants(vulnerable_source, [invariant_id])
    fixed_invariants = evaluate_invariants(fixed_path.read_text(encoding="utf-8"), [invariant_id])
    poc_result = run_foundry_poc(case_dir / metadata["poc_file"], ROOT)

    return {
        "case": case_dir.name,
        "metadata": metadata,
        "expected_detectors": sorted(expected),
        "vulnerable_detectors": sorted(vulnerable_names),
        "fixed_detectors": sorted(fixed_names),
        "true_positives": true_positives,
        "false_positives": false_positives,
        "false_negatives": false_negatives,
        "vulnerable_finding_count": len(vulnerable_findings),
        "fixed_finding_count": len(fixed_findings),
        "comparisons": comparison_payload,
        "comparison_statuses": {
            status.value: sum(
                item.status == status for item in comparisons
            )
            for status in ComparisonStatus
        },
        "invariant_id": invariant_id,
        "invariant_results": {
            "vulnerable": [_serialize_invariant(item) for item in vulnerable_invariants],
            "fixed": [_serialize_invariant(item) for item in fixed_invariants],
        },
        "invariant_statuses": {
            "vulnerable": summarize_invariants(vulnerable_invariants),
            "fixed": summarize_invariants(fixed_invariants),
        },
        "poc": {
            "file": metadata["poc_file"],
            "mode": metadata["poc_mode"],
            "status": poc_result.status.value,
            "reason": poc_result.reason,
        },
    }


def run_benchmark() -> dict[str, Any]:
    """Evaluate every case and return machine-readable results."""
    cases = [evaluate_case(case_dir) for case_dir in discover_cases()]
    totals = {
        "true_positives": sum(len(case["true_positives"]) for case in cases),
        "false_positives": sum(len(case["false_positives"]) for case in cases),
        "false_negatives": sum(len(case["false_negatives"]) for case in cases),
    }
    comparator_totals = {
        status.value: sum(
            case["comparison_statuses"][status.value]
            for case in cases
        )
        for status in ComparisonStatus
    }
    invariant_totals = {
        side: {
            status.value: sum(
                case["invariant_statuses"][side][status.value]
                for case in cases
            )
            for status in InvariantStatus
        }
        for side in ("vulnerable", "fixed")
    }
    poc_totals = {
        status.value: sum(case["poc"]["status"] == status.value for case in cases)
        for status in PocStatus
    }
    return {
        "cases": cases,
        "totals": totals,
        "comparator_totals": comparator_totals,
        "invariant_totals": invariant_totals,
        "poc_totals": poc_totals,
    }


def _format_names(names: list[str]) -> str:
    return ", ".join(names) if names else "-"


def print_report(report: dict[str, Any]) -> None:
    """Print a concise human-readable benchmark report."""
    print("Solidity Ground Truth Benchmark")
    print("=" * 34)
    for case in report["cases"]:
        print(f"\n[{case['case']}]")
        print(f"  TP: {_format_names(case['true_positives'])}")
        print(f"  FP: {_format_names(case['false_positives'])}")
        print(f"  FN: {_format_names(case['false_negatives'])}")
        print(f"  vulnerable findings: {case['vulnerable_finding_count']}")
        print(f"  fixed findings: {case['fixed_finding_count']}")
        print(f"  comparator: {case['comparison_statuses']}")
        print(f"  invariants vulnerable: {case['invariant_statuses']['vulnerable']}")
        print(f"  invariants fixed: {case['invariant_statuses']['fixed']}")
        print(f"  poc: {case['poc']['status']} ({case['poc']['reason']})")
    print("\nTotals")
    print("------")
    for metric, value in report["totals"].items():
        print(f"{metric}: {value}")
    print("comparator_statuses:")
    for status, value in report["comparator_totals"].items():
        print(f"  {status}: {value}")
    print("invariant_statuses:")
    for side, values in report["invariant_totals"].items():
        print(f"  {side}: {values}")
    print("poc_statuses:")
    for status, value in report["poc_totals"].items():
        print(f"  {status}: {value}")


def main(require_poc: bool = False) -> int:
    report = run_benchmark()
    print_report(report)
    comparator_failed = (
        report["comparator_totals"][ComparisonStatus.REJECTED.value]
        or report["comparator_totals"][ComparisonStatus.INCONCLUSIVE.value]
    )
    invariant_failed = any(
        case["invariant_statuses"]["vulnerable"][InvariantStatus.VIOLATED.value] != 1
        or case["invariant_statuses"]["fixed"][InvariantStatus.SATISFIED.value] != 1
        for case in report["cases"]
    )
    poc_failed = report["poc_totals"][PocStatus.FAILED.value]
    poc_inconclusive = report["poc_totals"][PocStatus.INCONCLUSIVE.value]
    return 1 if (
        report["totals"]["false_positives"]
        or report["totals"]["false_negatives"]
        or comparator_failed
        or invariant_failed
        or poc_failed
        or (require_poc and poc_inconclusive)
    ) else 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run the Solidity ground-truth benchmark")
    parser.add_argument(
        "--require-poc",
        action="store_true",
        help="Fail when Foundry is unavailable instead of reporting PoC as Inconclusive",
    )
    raise SystemExit(main(require_poc=parser.parse_args().require_poc))
