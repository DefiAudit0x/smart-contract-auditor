"""Deterministic benchmark metrics with explicit inconclusive accounting."""

from __future__ import annotations

from typing import Any



def _rate(numerator: int, denominator: int) -> float | None:
    if denominator == 0:
        return None
    return round(numerator / denominator, 6)


def _f1(precision: float | None, recall: float | None) -> float | None:
    if precision is None or recall is None or precision + recall == 0:
        return None
    return round(2 * precision * recall / (precision + recall), 6)


def _status_counts(cases: list[dict[str, Any]], side: str) -> dict[str, int]:
    statuses = {"Satisfied": 0, "Violated": 0, "Inconclusive": 0}
    for case in cases:
        for status, count in case["invariant_statuses"][side].items():
            statuses[status] = statuses.get(status, 0) + count
    return statuses


def _poc_metrics(cases: list[dict[str, Any]]) -> dict[str, Any]:
    modes = {
        "exploit": {"Passed": 0, "Failed": 0, "Inconclusive": 0},
        "negative_control": {"Passed": 0, "Failed": 0, "Inconclusive": 0},
    }
    for case in cases:
        poc = case["poc"]
        mode = poc["mode"]
        status = poc["status"]
        if mode not in modes:
            modes[mode] = {"Passed": 0, "Failed": 0, "Inconclusive": 0}
        modes[mode][status] = modes[mode].get(status, 0) + 1

    all_results = [case["poc"] for case in cases]
    executable = sum(item["status"] in {"Passed", "Failed"} for item in all_results)
    runtime_coverage = _rate(executable, len(all_results))
    for mode, values in modes.items():
        values["evaluated"] = values["Passed"] + values["Failed"]
        values["rate"] = _rate(values["Passed"], values["evaluated"])
    return {
        "by_mode": modes,
        "total": len(all_results),
        "runtime_evaluated": executable,
        "inconclusive": sum(item["status"] == "Inconclusive" for item in all_results),
        "runtime_coverage": runtime_coverage,
    }


def _per_detector_metrics(cases: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Return ground-truth metrics grouped by expected detector name."""
    detector_names = sorted({
        detector
        for case in cases
        for detector in (
            case["expected_detectors"]
            + case["true_positives"]
            + case["false_positives"]
            + case["false_negatives"]
        )
    })
    results: dict[str, dict[str, Any]] = {}
    for detector in detector_names:
        expected_support = sum(detector in case["expected_detectors"] for case in cases)
        true_positives = sum(detector in case["true_positives"] for case in cases)
        false_positives = sum(detector in case["false_positives"] for case in cases)
        false_negatives = sum(detector in case["false_negatives"] for case in cases)
        true_negatives = sum(
            detector in case["expected_detectors"]
            for case in cases
            if case["metadata"].get("expected_clean") is True
        ) - false_positives
        precision = _rate(true_positives, true_positives + false_positives)
        recall = _rate(true_positives, true_positives + false_negatives)
        results[detector] = {
            "case_count": expected_support,
            "expected_support": expected_support,
            "true_positives": true_positives,
            "false_positives": false_positives,
            "false_negatives": false_negatives,
            "true_negatives": true_negatives,
            "precision": precision,
            "recall": recall,
            "f1": _f1(precision, recall),
            "fp_rate": _rate(false_positives, false_positives + true_negatives),
            "fn_rate": _rate(false_negatives, false_negatives + true_positives),
        }
    return results


def calculate_metrics(cases: list[dict[str, Any]]) -> dict[str, Any]:
    """Calculate all benchmark metrics from runner case records."""
    true_positives = sum(len(case["true_positives"]) for case in cases)
    false_positives = sum(len(case["false_positives"]) for case in cases)
    false_negatives = sum(len(case["false_negatives"]) for case in cases)
    expected_support = sum(len(case["expected_detectors"]) for case in cases)
    true_negatives = sum(
        len(case["expected_detectors"])
        for case in cases
        if case["metadata"].get("expected_clean") is True
    ) - false_positives
    precision = _rate(true_positives, true_positives + false_positives)
    recall = _rate(true_positives, true_positives + false_negatives)

    comparator = {
        status: sum(case["comparison_statuses"].get(status, 0) for case in cases)
        for status in ("Confirmed", "Rejected", "Inconclusive")
    }
    comparator["total"] = sum(comparator.values())
    comparator["confirmation_rate"] = _rate(comparator["Confirmed"], comparator["total"])

    invariant_vulnerable = _status_counts(cases, "vulnerable")
    invariant_fixed = _status_counts(cases, "fixed")

    return {
        "per_detector": _per_detector_metrics(cases),
        "detector": {
            "case_count": len(cases),
            "expected_support": expected_support,
            "true_positives": true_positives,
            "false_positives": false_positives,
            "false_negatives": false_negatives,
            "true_negatives": true_negatives,
            "precision": precision,
            "recall": recall,
            "f1": _f1(precision, recall),
            "fp_rate": _rate(false_positives, false_positives + true_negatives),
            "fn_rate": _rate(false_negatives, false_negatives + true_positives),
        },
        "comparator": comparator,
        "invariants": {
            "vulnerable": invariant_vulnerable,
            "fixed": invariant_fixed,
            "vulnerable_violation_rate": _rate(
                invariant_vulnerable["Violated"],
                sum(invariant_vulnerable.values()),
            ),
            "fixed_satisfaction_rate": _rate(
                invariant_fixed["Satisfied"],
                sum(invariant_fixed.values()),
            ),
        },
        "poc": _poc_metrics(cases),
    }


__all__ = ["calculate_metrics"]
