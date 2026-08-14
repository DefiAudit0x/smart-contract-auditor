"""Metrics regression tests for the ground-truth benchmark."""

from benchmarks.run_benchmark import run_benchmark
from verification.metrics import calculate_metrics


def test_detector_metrics_are_exact_for_current_ground_truth():
    report = run_benchmark()
    detector = calculate_metrics(report["cases"])["detector"]
    assert detector == {
        "case_count": 5,
        "expected_support": 5,
        "true_positives": 5,
        "false_positives": 0,
        "false_negatives": 0,
        "true_negatives": 5,
        "precision": 1.0,
        "recall": 1.0,
        "f1": 1.0,
        "fp_rate": 0.0,
        "fn_rate": 0.0,
    }


def test_metrics_keep_comparator_inconclusive_separate():
    report = run_benchmark()
    metrics = calculate_metrics(report["cases"])
    assert metrics["comparator"] == {
        "Confirmed": 5,
        "Rejected": 0,
        "Inconclusive": 0,
        "total": 5,
        "confirmation_rate": 1.0,
    }


def test_metrics_separate_invariant_sides_and_poc_modes():
    report = run_benchmark()
    metrics = calculate_metrics(report["cases"])
    assert metrics["invariants"] == {
        "vulnerable": {"Satisfied": 0, "Violated": 5, "Inconclusive": 0},
        "fixed": {"Satisfied": 5, "Violated": 0, "Inconclusive": 0},
        "vulnerable_violation_rate": 1.0,
        "fixed_satisfaction_rate": 1.0,
    }
    poc = metrics["poc"]
    assert poc["total"] == 5
    assert set(poc["by_mode"]) == {"exploit", "negative_control"}
    assert sum(values["Passed"] + values["Failed"] + values["Inconclusive"] for values in poc["by_mode"].values()) == 5
    assert poc["inconclusive"] == 0 or poc["inconclusive"] == 5
