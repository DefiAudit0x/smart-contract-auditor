from pathlib import Path

import pytest

from benchmarks.historical_compatibility.architecture_boundary.provenance_retention import (
    RetentionError,
    RetentionPolicy,
    persist_analysis_bundle,
    verify_bundle,
)
from benchmarks.historical_compatibility.canonical_ast_poc.canonical import (
    AnalysisStatus,
    CompilerProvenance,
    CompilerResult,
)


FIXTURE_ROOT = Path(__file__).parents[1] / "canonical_ast_poc" / "fixtures"


def _compiled_fixture():
    from benchmarks.historical_compatibility.canonical_ast_poc.compiler import compile_sources
    from benchmarks.historical_compatibility.canonical_ast_poc.modern_ast_adapter import adapt_modern

    sources = {
        "Lib.sol": (FIXTURE_ROOT / "imported_lib_0_8_25.sol").read_text(encoding="utf-8"),
        "Main.sol": (FIXTURE_ROOT / "imported_main_0_8_25.sol").read_text(encoding="utf-8"),
    }
    compiled = compile_sources(sources, "0.8.25", "Main.sol")
    assert compiled.status == AnalysisStatus.COMPILED
    program, metadata = adapt_modern(compiled)
    assert program is not None, metadata
    payload = {
        "status": AnalysisStatus.ANALYSIS_SUCCEEDED_WITH_FINDINGS.value,
        "finding_count": 1,
        "findings": [{"source_id": "Lib.sol", "kind": "selfdestruct"}],
        "finding_provenance": [{"source_id": "Lib.sol", "canonical_expression_id": "Lib.sol:4"}],
        "comparator_results": [{"status": "Confirmed", "source_id": "Lib.sol"}],
        "source_id": "Lib.sol",
    }
    return compiled, program, payload


def test_gate3_rejects_compiled_result_without_raw_ast(tmp_path):
    compiled, program, payload = _compiled_fixture()
    broken = CompilerResult(
        status=AnalysisStatus.COMPILED,
        provenance=compiled.provenance,
        source=compiled.source,
        raw_ast=None,
        sources=compiled.sources,
    )
    with pytest.raises(RetentionError):
        persist_analysis_bundle(broken, program, payload, tmp_path)


def test_gate3_rejects_compiled_result_without_provenance(tmp_path):
    compiled, program, payload = _compiled_fixture()
    broken = CompilerResult(
        status=AnalysisStatus.COMPILED,
        provenance=None,
        source=compiled.source,
        raw_ast=compiled.raw_ast,
        sources=compiled.sources,
    )
    with pytest.raises(RetentionError):
        persist_analysis_bundle(broken, program, payload, tmp_path)


def test_gate3_replay_detects_raw_ast_tamper(tmp_path):
    compiled, program, payload = _compiled_fixture()
    manifest = persist_analysis_bundle(compiled, program, payload, tmp_path, RetentionPolicy())
    bundle_root = tmp_path / "bundles" / manifest["bundle_id"]
    raw_path = bundle_root / manifest["raw_ast"]["artifact_path"]
    original = raw_path.read_bytes()
    raw_path.write_bytes(original + b"\n")
    result = verify_bundle(tmp_path, manifest["bundle_id"])
    assert result["status"] == "ReplayVerificationFailed"
    assert any("raw AST hash mismatch" in item for item in result["diagnostics"])


def test_gate3_replay_detects_canonical_summary_tamper(tmp_path):
    compiled, program, payload = _compiled_fixture()
    manifest = persist_analysis_bundle(compiled, program, payload, tmp_path, RetentionPolicy())
    bundle_root = tmp_path / "bundles" / manifest["bundle_id"]
    canonical_path = bundle_root / manifest["canonical_ast"]["artifact"]
    original = canonical_path.read_text(encoding="utf-8")
    canonical_path.write_text(original.replace("canonical_ast_version", "tampered_field", 1), encoding="utf-8")
    result = verify_bundle(tmp_path, manifest["bundle_id"])
    assert result["status"] == "ReplayVerificationFailed"
    assert any("canonical AST hash mismatch" in item for item in result["diagnostics"])


def test_gate3_replay_detects_analysis_payload_tamper(tmp_path):
    compiled, program, payload = _compiled_fixture()
    manifest = persist_analysis_bundle(compiled, program, payload, tmp_path, RetentionPolicy())
    bundle_root = tmp_path / "bundles" / manifest["bundle_id"]
    analysis_path = bundle_root / manifest["analysis_artifact"]["path"]
    original = analysis_path.read_text(encoding="utf-8")
    analysis_path.write_text(original.replace('"finding_count": 1', '"finding_count": 2', 1), encoding="utf-8")
    result = verify_bundle(tmp_path, manifest["bundle_id"])
    assert result["status"] == "ReplayVerificationFailed"
    assert any("analysis payload hash mismatch" in item for item in result["diagnostics"])


def test_gate3_failure_provenance_is_explicit_and_source_bound():
    from benchmarks.historical_compatibility.architecture_boundary.provenance_retention import failure_provenance

    result = failure_provenance(
        AnalysisStatus.AST_NORMALIZATION_FAILED.value,
        ["missing contract container"],
        sources={"Lib.sol": "contract Lib {}"},
        compiler_provenance=CompilerProvenance(
            compiler_version="0.8.25",
            compiler_build="poc",
            compiler_binary_hash="binary",
            source_sha256="source",
            raw_ast_sha256="raw",
            ast_format="solc-json-ast",
            source_id="Lib.sol",
        ),
        adapter_version="modern-adapter-v1",
        canonical_ast_version="canonical-ast-poc-v2",
        detector_version="selfdestruct-v1",
    )
    assert result["status"] == AnalysisStatus.AST_NORMALIZATION_FAILED.value
    assert result["source_manifest"][0]["source_id"] == "Lib.sol"
    assert result["compiler_provenance"]["compiler_version"] == "0.8.25"
    assert result["failure_evidence_policy"] == "explicit-status-plus-provenance-v1"
