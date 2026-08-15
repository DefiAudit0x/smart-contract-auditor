"""Regression checks for the read-only compiler/AST boundary investigation."""

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
REPORT = ROOT / "benchmarks" / "historical_compatibility" / "architecture_boundary" / "metadata" / "compiler_ast_boundary_experiment.json"


def _rows():
    report = json.loads(REPORT.read_text(encoding="utf-8"))
    return report, {row["label"]: row for row in report["rows"]}


def test_boundary_investigation_is_read_only():
    report, rows = _rows()
    assert report["read_only_architecture_investigation"] is True
    assert report["production_changes"] == []
    assert report["current_normalizer_compiler"] == "0.8.25"
    assert len(rows) == 5


def test_parity_0410_reaches_raw_ast_but_old_normalizer_container_is_incompatible():
    _, rows = _rows()
    row = rows["parity_suicide_solc_0_4_10"]
    assert row["historical_raw_ast"]["status"] == "compiled"
    assert "suicide" in row["historical_raw_ast"]["raw_ast_tokens"]
    assert row["current_pipeline_compile_to_ast"]["status"] == "compile_failed_under_current_path"
    assert row["normalizer_on_historical_raw_ast"]["status"] == "incompatible_normalizer_container"
    assert row["normalizer_on_historical_raw_ast"]["output_types"] == ["dict"]
    assert row["normalizer_on_historical_raw_ast"]["contract_count"] == 0


def test_minimal_0411_isolates_old_raw_ast_normalizer_boundary():
    _, rows = _rows()
    row = rows["minimal_suicide_solc_0_4_11"]
    assert row["historical_raw_ast"]["status"] == "compiled"
    assert row["historical_raw_ast"]["raw_ast_tokens"] == ["suicide"]
    assert row["normalizer_on_historical_raw_ast"]["status"] == "incompatible_normalizer_container"
    assert row["normalizer_on_historical_raw_ast"]["contract_count"] == 0


def test_exact_parity_0411_is_source_compiler_specific_and_modern_control_normalizes():
    _, rows = _rows()
    parity_0411 = rows["parity_suicide_solc_0_4_11"]
    assert parity_0411["historical_raw_ast"]["status"] == "compile_failed"
    assert parity_0411["normalizer_on_historical_raw_ast"]["status"] == "not_run"

    modern = rows["modern_selfdestruct_solc_0_8_25"]
    assert modern["historical_raw_ast"]["status"] == "compiled"
    assert modern["normalizer_on_historical_raw_ast"]["status"] == "normalized_from_historical_raw_ast"
    assert modern["normalizer_on_historical_raw_ast"]["contract_count"] == 1
    assert modern["normalizer_on_historical_raw_ast"]["signals"]["uses_selfdestruct"] is True
    assert modern["current_pipeline_compile_to_ast"]["status"] == "normalized_under_current_path"
