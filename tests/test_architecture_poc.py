from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from benchmarks.historical_compatibility.canonical_ast_poc.canonical import AnalysisStatus
from benchmarks.historical_compatibility.canonical_ast_poc.compiler import compile_source
from benchmarks.historical_compatibility.canonical_ast_poc.detector_bridge import run_detector
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
            assert run_detector(program, family, source, fixture)["finding_count"] == 0


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
            family: run_detector(program, family, source, fixture)
            for family in FAMILIES
        }

    for family in FAMILIES:
        historical = outputs["0.4.10"][family]
        modern = outputs["0.8.25"][family]
        assert historical["finding_count"] == modern["finding_count"] == 1
        assert historical["detector_compiler_knowledge"] is False
        assert modern["detector_compiler_knowledge"] is False
        assert historical["findings"][0]["agent_name"] == modern["findings"][0]["agent_name"]
        assert historical["comparator_results"][0]["status"].value == "Rejected"
        assert modern["comparator_results"][0]["status"].value == "Confirmed"
        assert historical["comparator_implementation_changed"] is False
        assert modern["comparator_implementation_changed"] is False
