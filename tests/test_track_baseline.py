"""Offline isolation checks for the cross-track baseline report."""

from benchmarks.run_track_baseline import _candidate_summary
from benchmarks.real_world.run_negative_controls import run as run_real_world_negative_controls


def test_candidate_summary_is_quarantined_and_metric_neutral():
    summary = _candidate_summary()
    assert summary["candidate_count"] == 10
    assert summary["adjudication_record_count"] == 10
    assert summary["admitted_count"] == 0
    assert summary["quarantined_count"] == 10
    assert summary["included_in_metrics"] is False


def test_real_world_negative_control_track_is_separate():
    report = run_real_world_negative_controls()
    assert report["track"] == "real_world_negative_controls"
    assert report["primary_benchmark_affected"] is False
    assert report["metrics"]["false_positive_rate"] == 0.0
