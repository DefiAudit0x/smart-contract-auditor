"""Deterministic regression tests for the Solidity ground-truth benchmark."""

from pathlib import Path

import pytest

from benchmarks.run_benchmark import (
    REQUIRED_METADATA_FIELDS,
    discover_cases,
    evaluate_case,
    run_benchmark,
)


CASES = discover_cases()


@pytest.mark.parametrize(
    "case_dir",
    CASES,
    ids=[case_dir.name for case_dir in CASES],
)
def test_benchmark_case_has_expected_detector_without_fixed_false_positive(case_dir: Path):
    result = evaluate_case(case_dir)
    assert not result["false_negatives"], (
        f"{result['case']} false negatives: {result['false_negatives']}; "
        f"detected={result['vulnerable_detectors']}; "
        f"expected={result['expected_detectors']}; "
        f"TP={result['true_positives']}, FP={result['false_positives']}, "
        f"FN={result['false_negatives']}"
    )
    assert not result["false_positives"], (
        f"{result['case']} false positives on fixed.sol: {result['false_positives']}; "
        f"TP={result['true_positives']}, FP={result['false_positives']}, "
        f"FN={result['false_negatives']}"
    )


def test_benchmark_metadata_schema_is_complete():
    assert CASES, "No benchmark cases discovered"
    for case_dir in CASES:
        metadata = evaluate_case(case_dir)["metadata"]
        assert REQUIRED_METADATA_FIELDS <= metadata.keys()
        assert metadata["expected_detectors"]
        assert metadata["expected_clean"] is True
        assert (case_dir / "vulnerable.sol").is_file()
        assert (case_dir / "fixed.sol").is_file()


def test_benchmark_comparator_statuses_are_confirmed():
    report = run_benchmark()
    assert report["comparator_totals"] == {
        "Confirmed": len(report["cases"]),
        "Rejected": 0,
        "Inconclusive": 0,
    }
    for case in report["cases"]:
        assert case["comparison_statuses"] == {
            "Confirmed": 1,
            "Rejected": 0,
            "Inconclusive": 0,
        }


def test_benchmark_invariant_statuses_are_expected():
    report = run_benchmark()
    assert report["invariant_totals"] == {
        "vulnerable": {
            "Satisfied": 0,
            "Violated": len(report["cases"]),
            "Inconclusive": 0,
        },
        "fixed": {
            "Satisfied": len(report["cases"]),
            "Violated": 0,
            "Inconclusive": 0,
        },
    }
    for case in report["cases"]:
        assert case["invariant_statuses"]["vulnerable"] == {
            "Satisfied": 0,
            "Violated": 1,
            "Inconclusive": 0,
        }
        assert case["invariant_statuses"]["fixed"] == {
            "Satisfied": 1,
            "Violated": 0,
            "Inconclusive": 0,
        }


def test_benchmark_totals_are_clean():
    report = run_benchmark()
    assert report["totals"] == {
        "true_positives": sum(
            len(case["expected_detectors"])
            for case in report["cases"]
        ),
        "false_positives": 0,
        "false_negatives": 0,
    }
