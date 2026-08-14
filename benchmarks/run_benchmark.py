"""Run the deterministic Solidity ground-truth benchmark."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
BENCHMARK_ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from analyzers.solidity_analyzer import SolidityAnalyzer


REQUIRED_METADATA_FIELDS = {
    "vulnerability",
    "location",
    "severity",
    "category",
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
    return metadata


def analyze_contract(path: Path) -> tuple[set[str], list[Any]]:
    """Analyze one Solidity file with a fresh analyzer instance."""
    analyzer = SolidityAnalyzer()
    findings = analyzer.analyze_file(path.name, path.read_text(encoding="utf-8"))
    return {finding.agent_name for finding in findings}, findings


def evaluate_case(case_dir: Path) -> dict[str, Any]:
    """Compute detector-level TP, FP, and FN for one benchmark pair."""
    metadata = load_metadata(case_dir)
    expected = set(metadata["expected_detectors"])
    vulnerable_names, vulnerable_findings = analyze_contract(case_dir / "vulnerable.sol")
    fixed_names, fixed_findings = analyze_contract(case_dir / "fixed.sol")

    true_positives = sorted(expected & vulnerable_names)
    false_negatives = sorted(expected - vulnerable_names)
    false_positives = sorted(expected & fixed_names) if metadata["expected_clean"] else []

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
    }


def run_benchmark() -> dict[str, Any]:
    """Evaluate every case and return machine-readable results."""
    cases = [evaluate_case(case_dir) for case_dir in discover_cases()]
    totals = {
        "true_positives": sum(len(case["true_positives"]) for case in cases),
        "false_positives": sum(len(case["false_positives"]) for case in cases),
        "false_negatives": sum(len(case["false_negatives"]) for case in cases),
    }
    return {"cases": cases, "totals": totals}


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
    print("\nTotals")
    print("------")
    for metric, value in report["totals"].items():
        print(f"{metric}: {value}")


def main() -> int:
    report = run_benchmark()
    print_report(report)
    return 1 if (
        report["totals"]["false_positives"]
        or report["totals"]["false_negatives"]
    ) else 0


if __name__ == "__main__":
    raise SystemExit(main())
