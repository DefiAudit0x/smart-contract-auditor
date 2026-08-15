"""Regression checks for the measurement-only cross-detector compatibility audit."""

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
REPORT = ROOT / "benchmarks" / "historical_compatibility" / "cross_detector" / "metadata" / "cross_detector_compatibility_measurement.json"
DETECTORS = (
    "Selfdestruct",
    "block.timestamp Usage (AST)",
    "DELEGATECALL Usage (AST)",
)
VERSIONS = ("solidity_04", "solidity_05", "solidity_06", "solidity_07", "solidity_08")


def _rows():
    report = json.loads(REPORT.read_text(encoding="utf-8"))
    rows = {
        (row["detector"], row["version_family"], row["raw_source"]["form"]): row
        for row in report["rows"]
    }
    return report, rows


def test_cross_detector_measurement_is_separate_and_complete():
    report, rows = _rows()
    assert report["measurement_only"] is True
    assert report["production_changes"] == []
    assert report["row_count"] == 45
    assert len(rows) == 45
    assert tuple(report["detectors"]) == DETECTORS
    assert report["forms"] == ["canonical", "legacy", "fixed"]


def test_all_canonical_forms_have_historical_compiler_and_comparator_evidence():
    _, rows = _rows()
    for detector in DETECTORS:
        for version in VERSIONS:
            row = rows[(detector, version, "canonical")]
            assert row["historical_compiler"]["status"] == "compiled"
            assert row["comparator"]["status"] == "Confirmed"
            assert row["raw_source"]["expected_semantic_signal"] is True


def test_ast_only_detectors_show_current_compiler_boundary():
    _, rows = _rows()
    for detector in ("block.timestamp Usage (AST)", "DELEGATECALL Usage (AST)"):
        for version in VERSIONS[:-1]:
            row = rows[(detector, version, "canonical")]
            assert row["historical_compiler"]["status"] == "compiled"
            assert row["normalized_ast"]["status"] == "compile_failed"
            assert row["current_detector"]["target_hit"] is False
        current = rows[(detector, "solidity_08", "canonical")]
        assert current["normalized_ast"]["status"] == "normalized"
        assert current["current_detector"]["target_hit"] is True


def test_selfdestruct_text_fallback_differs_from_ast_only_detectors():
    _, rows = _rows()
    for version in VERSIONS:
        row = rows[("Selfdestruct", version, "canonical")]
        assert row["current_detector"]["target_hit"] is True
        assert row["comparator"]["status"] == "Confirmed"
    for detector in ("block.timestamp Usage (AST)", "DELEGATECALL Usage (AST)"):
        for version in VERSIONS[:-1]:
            assert rows[(detector, version, "canonical")]["current_detector"]["target_hit"] is False


def test_legacy_forms_measure_vocabulary_and_compiler_boundaries():
    _, rows = _rows()
    expected_compiled = {
        "Selfdestruct": {"solidity_04"},
        "block.timestamp Usage (AST)": {"solidity_04", "solidity_05", "solidity_06"},
        "DELEGATECALL Usage (AST)": {"solidity_04"},
    }
    for detector in DETECTORS:
        for version in VERSIONS:
            row = rows[(detector, version, "legacy")]
            if version in expected_compiled[detector]:
                assert row["historical_compiler"]["status"] == "compiled"
            else:
                assert row["historical_compiler"]["status"] == "compile_failed"
            assert row["current_detector"]["target_hit"] is False
            assert row["comparator"]["status"] == "Rejected"


def test_fixed_controls_are_compiled_and_target_clean():
    _, rows = _rows()
    for detector in DETECTORS:
        for version in VERSIONS:
            row = rows[(detector, version, "fixed")]
            assert row["historical_compiler"]["status"] == "compiled"
            assert row["current_detector"]["target_hit"] is False
            assert row["comparator"]["status"] == "Rejected"
