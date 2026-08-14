"""Metrics regression tests for the ground-truth benchmark."""

from benchmarks.run_benchmark import run_benchmark
from verification.metrics import calculate_metrics


def test_detector_metrics_are_exact_for_current_ground_truth():
    report = run_benchmark()
    detector = calculate_metrics(report["cases"])["detector"]
    case_count = len(report["cases"])
    expected_support = sum(len(case["expected_detectors"]) for case in report["cases"])
    assert case_count == 10
    assert detector == {
        "case_count": case_count,
        "expected_support": expected_support,
        "true_positives": expected_support,
        "false_positives": 0,
        "false_negatives": 0,
        "true_negatives": expected_support,
        "precision": 1.0,
        "recall": 1.0,
        "f1": 1.0,
        "fp_rate": 0.0,
        "fn_rate": 0.0,
    }


def test_metrics_are_exact_for_each_detector():
    report = run_benchmark()
    metrics = calculate_metrics(report["cases"])
    expected = {
        detector
        for case in report["cases"]
        for detector in case["expected_detectors"]
    }
    assert set(metrics["per_detector"]) == expected
    for detector_metrics in metrics["per_detector"].values():
        assert detector_metrics["expected_support"] >= 1
        assert detector_metrics["true_positives"] == detector_metrics["expected_support"]
        assert detector_metrics["false_positives"] == 0
        assert detector_metrics["false_negatives"] == 0
        assert detector_metrics["precision"] == 1.0
        assert detector_metrics["recall"] == 1.0
        assert detector_metrics["f1"] == 1.0


def test_metrics_keep_comparator_inconclusive_separate():
    report = run_benchmark()
    metrics = calculate_metrics(report["cases"])
    assert metrics["comparator"] == {
        "Confirmed": len(report["cases"]),
        "Rejected": 0,
        "Inconclusive": 0,
        "total": len(report["cases"]),
        "confirmation_rate": 1.0,
    }


def test_metrics_separate_invariant_sides_and_poc_modes():
    report = run_benchmark()
    metrics = calculate_metrics(report["cases"])
    assert metrics["invariants"] == {
        "vulnerable": {"Satisfied": 0, "Violated": len(report["cases"]), "Inconclusive": 0},
        "fixed": {"Satisfied": len(report["cases"]), "Violated": 0, "Inconclusive": 0},
        "vulnerable_violation_rate": 1.0,
        "fixed_satisfaction_rate": 1.0,
    }
    poc = metrics["poc"]
    assert poc["total"] == len(report["cases"])
    assert set(poc["by_mode"]) == {"exploit", "negative_control"}
    assert sum(values["Passed"] + values["Failed"] + values["Inconclusive"] for values in poc["by_mode"].values()) == len(report["cases"])
    assert poc["inconclusive"] == 0 or poc["inconclusive"] == len(report["cases"])
