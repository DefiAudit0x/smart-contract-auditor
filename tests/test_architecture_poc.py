from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from benchmarks.historical_compatibility.canonical_ast_poc.canonical import AnalysisStatus
from benchmarks.historical_compatibility.canonical_ast_poc.compiler import compile_source, compile_sources
from benchmarks.historical_compatibility.canonical_ast_poc.detector_bridge import make_detector_input, run_detector
from benchmarks.historical_compatibility.canonical_ast_poc.legacy_ast_adapter import adapt_legacy
from benchmarks.historical_compatibility.canonical_ast_poc.modern_ast_adapter import adapt_modern


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "benchmarks" / "historical_compatibility" / "canonical_ast_poc" / "fixtures"
FAMILIES = ("Selfdestruct", "block.timestamp", "DELEGATECALL")


def _load(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def _adapt(version: str, source: str):
    compiled = compile_source(source, version)
    assert compiled.status == AnalysisStatus.COMPILED
    return compiled, (adapt_legacy(compiled) if version == "0.4.10" else adapt_modern(compiled))


def _run_detector(program, family: str, source: str, filename: str):
    source_id = program.provenance.source_id or filename
    detector_input = make_detector_input(program, source_id, source)
    return run_detector(detector_input, family, filename)


def _semantic_presence(program, family: str) -> bool:
    for contract in program.contracts:
        for function in contract.functions:
            if family == "Selfdestruct" and function.uses_selfdestruct:
                return True
            if family == "block.timestamp" and function.uses_block_timestamp:
                return True
            if family == "DELEGATECALL" and "delegatecall" in function.call_kinds:
                return True
    return False


@pytest.mark.parametrize(
    ("version", "fixture"),
    (("0.4.10", "historical_0_4_10.sol"), ("0.8.25", "modern_0_8_25.sol")),
)
def test_historical_and_modern_adapters_produce_same_semantic_contract(version, fixture):
    source = _load(fixture)
    compiled, (program, metadata) = _adapt(version, source)
    assert metadata["status"] == "CanonicalASTReady"
    assert program is not None
    assert program.function_count == 3
    assert all(_semantic_presence(program, family) for family in FAMILIES)
    assert program.provenance.compiler_version == version
    assert program.provenance.raw_ast_sha256


def test_fixed_controls_remain_clean_on_both_adapters():
    for version, fixture in (("0.4.10", "fixed_0_4_10.sol"), ("0.8.25", "fixed_0_8_25.sol")):
        source = _load(fixture)
        _, (program, metadata) = _adapt(version, source)
        assert metadata["status"] == "CanonicalASTReady"
        assert program is not None
        for family in FAMILIES:
            assert not _semantic_presence(program, family)
            result = _run_detector(program, family, source, fixture)
            assert result["finding_count"] == 0
            assert result["status"] == "AnalysisSucceededNoFindings"


def test_no_compiler_guess_or_silent_fallback():
    source = _load("historical_0_4_10.sol")
    result = compile_source(source, "0.3.0")
    assert result.status == AnalysisStatus.UNSUPPORTED_COMPILER
    program, metadata = adapt_legacy(result)
    assert program is None
    assert metadata["status"] == AnalysisStatus.UNSUPPORTED_COMPILER.value


def test_invalid_ast_container_is_explicit_normalization_failure():
    source = _load("historical_0_4_10.sol")
    compiled = compile_source(source, "0.4.10")
    broken = replace(compiled, raw_ast={"children": [{"name": "NotAContract"}]})
    program, metadata = adapt_legacy(broken)
    assert program is None
    assert metadata["status"] == AnalysisStatus.AST_NORMALIZATION_FAILED.value
    assert metadata["diagnostics"]
    assert metadata["provenance"]["raw_ast_sha256"]


def test_existing_detectors_are_compiler_agnostic_and_comparator_is_unchanged():
    outputs = {}
    for version, fixture in (("0.4.10", "historical_0_4_10.sol"), ("0.8.25", "modern_0_8_25.sol")):
        source = _load(fixture)
        _, (program, _) = _adapt(version, source)
        outputs[version] = {
            family: _run_detector(program, family, source, fixture)
            for family in FAMILIES
        }

    for family in FAMILIES:
        historical = outputs["0.4.10"][family]
        modern = outputs["0.8.25"][family]
        assert historical["finding_count"] == modern["finding_count"] == 1
        assert historical["status"] == modern["status"] == "AnalysisSucceededWithFindings"
        assert historical["detector_compiler_knowledge"] is False
        assert modern["detector_compiler_knowledge"] is False
        assert historical["findings"][0]["agent_name"] == modern["findings"][0]["agent_name"]
        assert historical["comparator_results"][0]["status"].value == "Rejected"
        assert modern["comparator_results"][0]["status"].value == "Confirmed"
        assert historical["comparator_implementation_changed"] is False
        assert modern["comparator_implementation_changed"] is False
        assert historical["finding_provenance"][0]["canonical_expression_id"]
        assert modern["finding_provenance"][0]["raw_ast_hash"]


def test_context_negative_controls_are_clean_on_both_schema_paths():
    for version, fixture in (("0.4.10", "negative_0_4_10.sol"), ("0.8.25", "negative_0_8_25.sol")):
        source = _load(fixture)
        _, (program, metadata) = _adapt(version, source)
        assert metadata["status"] == "CanonicalASTReady"
        for family in FAMILIES:
            result = _run_detector(program, family, source, fixture)
            assert not _semantic_presence(program, family)
            assert result["status"] == "AnalysisSucceededNoFindings"
            assert result["finding_count"] == 0


def test_adapters_reject_cross_format_raw_ast():
    historical_source = _load("historical_0_4_10.sol")
    modern_source = _load("modern_0_8_25.sol")
    historical = compile_source(historical_source, "0.4.10")
    modern = compile_source(modern_source, "0.8.25")
    modern_raw_with_legacy_metadata = replace(
        historical,
        raw_ast=modern.raw_ast,
        provenance=replace(historical.provenance, raw_ast_sha256=modern.provenance.raw_ast_sha256),
    )
    legacy_raw_with_modern_metadata = replace(
        modern,
        raw_ast=historical.raw_ast,
        provenance=replace(modern.provenance, raw_ast_sha256=historical.provenance.raw_ast_sha256),
    )
    assert adapt_legacy(legacy_raw_with_modern_metadata)[1]["status"] == AnalysisStatus.UNSUPPORTED_AST_VERSION.value
    assert adapt_modern(modern_raw_with_legacy_metadata)[1]["status"] == AnalysisStatus.UNSUPPORTED_AST_VERSION.value


def test_structural_loss_for_constructor_fallback_receive_is_rejected():
    source = "pragma solidity ^0.8.25; contract C { constructor() {} fallback() external {} receive() external payable {} }"
    compiled = compile_source(source, "0.8.25")
    broken = replace(
        compiled,
        raw_ast={
            "nodeType": "SourceUnit",
            "nodes": [{"nodeType": "ContractDefinition", "name": "C", "contractKind": "contract", "nodes": []}],
        },
    )
    program, metadata = adapt_modern(broken)
    assert program is None
    assert metadata["status"] == AnalysisStatus.AST_NORMALIZATION_FAILED.value


def test_status_matrix_is_explicit_end_to_end():
    source = _load("historical_0_4_10.sol")
    unsupported = compile_source(source, "0.3.0")
    assert adapt_legacy(unsupported)[1]["status"] == AnalysisStatus.UNSUPPORTED_COMPILER.value
    failed = compile_source('pragma solidity ^0.4.10; import "Missing.sol"; contract C {}', "0.4.10")
    assert adapt_legacy(failed)[1]["status"] == AnalysisStatus.COMPILATION_FAILED.value
    unavailable = replace(unsupported, status=AnalysisStatus.AST_UNAVAILABLE, diagnostics=("missing AST",))
    assert adapt_legacy(unavailable)[1]["status"] == AnalysisStatus.AST_UNAVAILABLE.value
    compiled = compile_source(source, "0.4.10")
    unknown_format = replace(
        compiled,
        provenance=replace(compiled.provenance, ast_format="unknown", raw_ast_sha256="raw"),
    )
    assert adapt_legacy(unknown_format)[1]["status"] == AnalysisStatus.UNSUPPORTED_AST_VERSION.value
    unknown_node = replace(
        compile_source(_load("fixed_0_8_25.sol"), "0.8.25"),
        raw_ast={
            "nodeType": "SourceUnit",
            "nodes": [{"nodeType": "ContractDefinition", "name": "C", "contractKind": "contract", "nodes": [{"nodeType": "UnknownNode"}]}],
        },
    )
    assert adapt_modern(unknown_node)[1]["status"] == AnalysisStatus.INCONCLUSIVE.value
    _, (clean_program, _) = _adapt("0.8.25", _load("fixed_0_8_25.sol"))
    clean_result = _run_detector(clean_program, "Selfdestruct", _load("fixed_0_8_25.sol"), "fixed.sol")
    assert clean_result["status"] == AnalysisStatus.ANALYSIS_SUCCEEDED_NO_FINDINGS.value
    _, (vulnerable_program, _) = _adapt("0.8.25", _load("modern_0_8_25.sol"))
    vulnerable_result = _run_detector(vulnerable_program, "Selfdestruct", _load("modern_0_8_25.sol"), "modern.sol")
    assert vulnerable_result["status"] == AnalysisStatus.ANALYSIS_SUCCEEDED_WITH_FINDINGS.value


def test_finding_provenance_is_reversible_from_finding_to_expression():
    source = _load("modern_0_8_25.sol")
    _, (program, _) = _adapt("0.8.25", source)
    result = _run_detector(program, "Selfdestruct", source, "modern.sol")
    provenance = result["finding_provenance"][0]
    required = {
        "source_id",
        "source_manifest",
        "source_sha256",
        "compiler_version",
        "compiler_hash",
        "raw_ast_hash",
        "adapter_version",
        "canonical_ast_version",
        "detector_version",
        "comparator_version",
        "source_range",
        "evidence_kind",
        "canonical_expression_id",
    }
    assert required.issubset(provenance)
    assert provenance["canonical_expression_id"]
    assert provenance["source_range"]
    assert provenance["source_manifest"]


def test_multifile_slice_preserves_units_manifest_pragma_and_status():
    sources = {
        "Lib.sol": "pragma solidity ^0.8.25; library Lib { function value() internal pure returns (uint256) { return 1; } }",
        "Main.sol": "pragma solidity ^0.8.25; import \"Lib.sol\"; contract Main { function read() public pure returns (uint256) { return Lib.value(); } }",
    }
    compiled = compile_sources(sources, "0.8.25", "Main.sol")
    assert compiled.status == AnalysisStatus.COMPILED
    program, metadata = adapt_modern(compiled)
    assert metadata["status"] == "CanonicalASTReady"
    assert [unit.source_id for unit in program.source_units] == ["Lib.sol", "Main.sol"]
    assert {entry.source_id for entry in program.provenance.source_manifest} == set(sources)
    assert compiled.raw_ast["pragma_constraints"]["Lib.sol"] == ["^0.8.25"] or tuple(compiled.raw_ast["pragma_constraints"]["Lib.sol"]) == ("^0.8.25",)
    result = _run_detector(program, "Selfdestruct", sources["Main.sol"], "Main.sol")
    assert result["status"] == AnalysisStatus.ANALYSIS_SUCCEEDED_NO_FINDINGS.value
    assert result["finding_provenance"] == []
