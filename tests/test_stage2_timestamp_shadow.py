from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

from benchmarks.historical_compatibility.stage2_timestamp_shadow import ROOT, run
from benchmarks.historical_compatibility.canonical_ast_poc.canonical import AnalysisStatus
from benchmarks.historical_compatibility.canonical_ast_poc.compiler import compile_source
from benchmarks.historical_compatibility.canonical_ast_poc.modern_ast_adapter import adapt_modern


def _case(payload, name):
    return next(item for item in payload["cases"] if item["case"] == name)


def test_stage2_modern_parity_and_fixed_control():
    payload = run()
    vulnerable = _case(payload, "modern-vulnerable")
    fixed = _case(payload, "modern-fixed")
    assert vulnerable["compiler_status"] == "Compiled"
    assert vulnerable["production"]["finding_count"] == 1
    assert vulnerable["canonical"]["status"] == "AnalysisSucceededWithFindings"
    assert vulnerable["canonical"]["finding_count"] == 1
    assert vulnerable["canonical"]["findings"][0]["function_name"] == "readTime"
    assert vulnerable["canonical"]["comparator_results"][0]["status"] == "Confirmed"
    assert fixed["production"]["finding_count"] == 0
    assert fixed["canonical"]["status"] == "AnalysisSucceededNoFindings"
    assert fixed["canonical"]["finding_count"] == 0


def test_stage2_historical_now_is_semantic_divergence_not_alias_repair():
    payload = run()
    historical = _case(payload, "historical-vulnerable-now")
    fixed = _case(payload, "historical-fixed")
    assert historical["compiler_status"] == "Compiled"
    assert historical["canonical"]["status"] == "AnalysisSucceededWithFindings"
    assert historical["canonical"]["finding_count"] == 1
    assert historical["canonical"]["findings"][0]["function_name"] == "readTime"
    assert historical["canonical"]["comparator_results"][0]["status"] == "Rejected"
    assert fixed["canonical"]["status"] == "AnalysisSucceededNoFindings"
    assert fixed["canonical"]["finding_count"] == 0


def test_stage2_negative_controls_remain_clean():
    payload = run()
    for version in ("0.4.10", "0.8.25"):
        case = _case(payload, f"negative-controls-{version}")
        assert case["compiler_status"] == "Compiled"
        assert case["canonical"]["status"] == "AnalysisSucceededNoFindings"
        assert case["canonical"]["finding_count"] == 0
        assert case["production"]["finding_count"] == 0


def test_stage2_imported_source_is_attributed_and_entry_is_clean():
    payload = run()
    imported = _case(payload, "imported-source-vulnerable")
    assert imported["compiler_status"] == "Compiled"
    assert imported["imported"]["status"] == "AnalysisSucceededWithFindings"
    assert imported["imported"]["finding_count"] == 1
    assert imported["imported"]["analyzed_source_id"] == "Lib.sol"
    provenance = imported["imported"]["finding_provenance"][0]
    assert provenance["source_id"] == "Lib.sol"
    assert provenance["canonical_expression_id"].startswith("Lib.sol:")
    assert provenance["source_range"]
    assert imported["imported"]["comparator_results"][0]["status"] == "Confirmed"
    assert imported["entry_control"]["status"] == "AnalysisSucceededNoFindings"
    assert imported["entry_control"]["finding_count"] == 0


def test_stage2_invalid_ast_never_becomes_zero_findings():
    source = (ROOT / "modern_0_8_25.sol").read_text(encoding="utf-8")
    compiled = compile_source(source, "0.8.25", "invalid.sol")
    assert compiled.status == AnalysisStatus.COMPILED
    invalid = replace(compiled, raw_ast={"schema": "standard-json-source-units-v1", "source_units": {}})
    program, metadata = adapt_modern(invalid)
    assert program is None
    assert metadata["status"] == "ASTNormalizationFailed"


def test_stage2_machine_readable_artifact_is_written():
    payload = run()
    artifact = ROOT.parent / "metadata" / "stage2_timestamp_shadow_results.json"
    assert artifact.exists()
    loaded = json.loads(artifact.read_text(encoding="utf-8"))
    assert loaded["status"] == "Passed"
    assert loaded["scope"] == "isolated-compatibility-poc"
    assert loaded["invariants"]["production_analyzer_modified"] is False
    assert loaded["invariants"]["comparator_modified"] is False
    assert len(loaded["cases"]) == len(payload["cases"])
