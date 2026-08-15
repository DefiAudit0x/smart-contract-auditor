"""Regression checks for the measurement-only Selfdestruct compatibility track."""

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
REPORT = ROOT / "benchmarks" / "historical_compatibility" / "metadata" / "selfdestruct_compatibility_measurement.json"


def _rows():
    report = json.loads(REPORT.read_text(encoding="utf-8"))
    return report, {(row["version_family"], row["fixture"]): row for row in report["rows"]}


def test_historical_measurement_is_separate_and_complete():
    report, rows = _rows()
    assert report["measurement_only"] is True
    assert report["production_changes"] == []
    assert len(rows) == 25
    assert report["current_analyzer_solc"] == "0.8.25"


def test_selfdestruct_spelling_hits_across_version_families():
    _, rows = _rows()
    for version in ("solidity_04", "solidity_05", "solidity_06", "solidity_07", "solidity_08"):
        for fixture in ("selfdestruct.sol", "assembly_selfdestruct.sol"):
            row = rows[(version, fixture)]
            assert row["historical_compiler"]["status"] == "compiled"
            assert row["current_analyzer"]["selfdestruct_detector"] is True
            assert row["current_comparator"]["status"] == "Confirmed"


def test_legacy_suicide_is_a_measured_miss_without_a_detector_change():
    _, rows = _rows()
    legacy = rows[("solidity_04", "suicide.sol")]
    assert legacy["historical_compiler"]["status"] == "compiled"
    assert legacy["historical_compiler"]["raw_ast_keywords"] == ["suicide"]
    assert legacy["current_analyzer"]["selfdestruct_detector"] is False
    assert legacy["current_comparator"]["status"] == "Rejected"

    for version in ("solidity_05", "solidity_06", "solidity_07", "solidity_08"):
        row = rows[(version, "suicide.sol")]
        assert row["historical_compiler"]["status"] == "compile_failed"
        assert row["current_analyzer"]["selfdestruct_detector"] is False
        assert row["current_comparator"]["status"] == "Rejected"


def test_fixed_controls_remain_clean():
    _, rows = _rows()
    for version in ("solidity_04", "solidity_05", "solidity_06", "solidity_07", "solidity_08"):
        row = rows[(version, "fixed.sol")]
        assert row["historical_compiler"]["status"] == "compiled"
        assert row["current_analyzer"]["selfdestruct_detector"] is False
        assert row["current_comparator"]["status"] == "Rejected"
