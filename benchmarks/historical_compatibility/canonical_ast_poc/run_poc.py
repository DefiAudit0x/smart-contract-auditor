from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path
from typing import Any, Callable

from .canonical import AnalysisStatus, CompilerProvenance, CompilerResult
from .compiler import compile_source, compile_sources
from .detector_bridge import make_detector_input, run_detector
from .legacy_ast_adapter import adapt_legacy
from .modern_ast_adapter import adapt_modern


POC_ROOT = Path(__file__).resolve().parent
FIXTURE_ROOT = POC_ROOT / "fixtures"
RESULT_PATH = POC_ROOT / "metadata" / "poc_results.json"
FAMILIES = ("Selfdestruct", "block.timestamp", "DELEGATECALL")

CASES = (
    ("historical", "0.4.10", "historical_0_4_10.sol", True),
    ("modern", "0.8.25", "modern_0_8_25.sol", True),
    ("historical_fixed", "0.4.10", "fixed_0_4_10.sol", False),
    ("modern_fixed", "0.8.25", "fixed_0_8_25.sol", False),
    ("historical_negative_context", "0.4.10", "negative_0_4_10.sol", False),
    ("modern_negative_context", "0.8.25", "negative_0_8_25.sol", False),
)

EXPECTED_ALIASES = {
    "historical": {"Selfdestruct": "suicide", "block.timestamp": "now", "DELEGATECALL": "callcode"},
    "modern": {"Selfdestruct": "selfdestruct", "block.timestamp": "timestamp", "DELEGATECALL": "delegatecall"},
}


def _adapter_for(version: str) -> Callable:
    return adapt_legacy if version == "0.4.10" else adapt_modern


def _canonical_semantics(program: Any) -> dict[str, dict[str, Any]]:
    semantics: dict[str, dict[str, Any]] = {}
    for family in FAMILIES:
        if family == "Selfdestruct":
            matches = [
                function.name
                for contract in program.contracts
                for function in contract.functions
                if function.uses_selfdestruct
            ]
        elif family == "block.timestamp":
            matches = [
                function.name
                for contract in program.contracts
                for function in contract.functions
                if function.uses_block_timestamp
            ]
        else:
            matches = [
                function.name
                for contract in program.contracts
                for function in contract.functions
                if "delegatecall" in function.call_kinds
            ]
        semantics[family] = {"present": bool(matches), "functions": matches}
    return semantics


def _run_family(
    program: Any,
    family: str,
    source: str,
    source_id: str,
    filename: str,
    source_texts: dict[str, str] | None = None,
) -> dict[str, Any]:
    detector_input = make_detector_input(program, source_id, source, source_texts)
    return run_detector(detector_input, family, filename)


def _assert_case(case_name: str, version: str, source: str, vulnerable: bool) -> dict[str, Any]:
    compiler_result = compile_source(source, version)
    assert compiler_result.status == AnalysisStatus.COMPILED, {
        "case": case_name,
        "status": compiler_result.status.value,
        "diagnostics": compiler_result.diagnostics,
    }
    program, adapter_metadata = _adapter_for(version)(compiler_result)
    assert program is not None, {"case": case_name, "adapter": adapter_metadata}
    assert adapter_metadata["status"] == "CanonicalASTReady"

    semantics = _canonical_semantics(program)
    for family in FAMILIES:
        assert semantics[family]["present"] is vulnerable, {
            "case": case_name,
            "family": family,
            "semantics": semantics[family],
            "expected": vulnerable,
        }

    detector_results: dict[str, Any] = {}
    expected_status = "AnalysisSucceededWithFindings" if vulnerable else "AnalysisSucceededNoFindings"
    for family in FAMILIES:
        detector_result = _run_family(program, family, source, compiler_result.provenance.source_id, f"fixtures/{case_name}.sol")
        assert detector_result["finding_count"] == int(vulnerable), {
            "case": case_name,
            "family": family,
            "detector_result": detector_result,
        }
        assert detector_result["status"] == expected_status
        if vulnerable:
            assert detector_result["finding_provenance"]
            assert detector_result["finding_provenance"][0]["canonical_expression_id"]
            assert detector_result["finding_provenance"][0]["raw_ast_hash"]
        else:
            assert detector_result["finding_provenance"] == []
        detector_results[family] = detector_result

    expected_aliases = EXPECTED_ALIASES.get(case_name, {})
    if expected_aliases:
        expression_arguments = [
            argument
            for contract in program.contracts
            for function in contract.functions
            for expression in function.expressions
            for argument in expression.arguments
        ]
        for family, alias in expected_aliases.items():
            assert alias in expression_arguments, {
                "case": case_name,
                "family": family,
                "expected_alias": alias,
                "arguments": expression_arguments,
            }

    return {
        "case": case_name,
        "track": "Compatibility",
        "compiler_status": compiler_result.status.value,
        "adapter_status": adapter_metadata["status"],
        "adapter_metadata": adapter_metadata,
        "canonical_semantics": semantics,
        "detectors": detector_results,
        "expected_findings": int(vulnerable),
    }


def _invalid_ast_case() -> dict[str, Any]:
    source = (FIXTURE_ROOT / "historical_0_4_10.sol").read_text(encoding="utf-8")
    compiled = compile_source(source, "0.4.10")
    broken = replace(compiled, raw_ast={"children": [{"name": "NotAContract"}]})
    program, metadata = adapt_legacy(broken)
    assert program is None
    assert metadata["status"] == AnalysisStatus.AST_NORMALIZATION_FAILED.value
    assert metadata["analysis_result"]["status"] == AnalysisStatus.AST_NORMALIZATION_FAILED.value
    return {
        "case": "invalid_ast_container",
        "track": "Compatibility",
        "compiler_status": compiled.status.value,
        "adapter_status": metadata["status"],
        "adapter_metadata": metadata,
        "detectors": {},
        "expected_findings": None,
    }


def _failure_state_cases() -> list[dict[str, Any]]:
    source = (FIXTURE_ROOT / "historical_0_4_10.sol").read_text(encoding="utf-8")
    unsupported = compile_source(source, "0.3.0")
    _, unsupported_metadata = adapt_legacy(unsupported)
    missing_import = compile_source('pragma solidity ^0.4.10; import "Missing.sol"; contract C {}', "0.4.10")
    _, compilation_metadata = adapt_legacy(missing_import)
    ast_unavailable = CompilerResult(AnalysisStatus.AST_UNAVAILABLE, unsupported.provenance, source, None, ("raw AST unavailable",), {"<stdin>": source})
    _, ast_unavailable_metadata = adapt_legacy(ast_unavailable)
    compiled_for_schema = compile_source(source, "0.4.10")
    unknown_format = replace(
        compiled_for_schema,
        status=AnalysisStatus.COMPILED,
        raw_ast={"nodeType": "SourceUnit", "nodes": []},
        provenance=replace(compiled_for_schema.provenance, ast_format="unknown", raw_ast_sha256="raw"),
    )
    _, unsupported_ast_metadata = adapt_legacy(unknown_format)
    unknown_node_result = replace(
        compile_source((FIXTURE_ROOT / "fixed_0_8_25.sol").read_text(encoding="utf-8"), "0.8.25"),
        raw_ast={
            "nodeType": "SourceUnit",
            "nodes": [{"nodeType": "ContractDefinition", "name": "C", "contractKind": "contract", "nodes": [{"nodeType": "UnknownNode"}]}],
        },
    )
    _, inconclusive_metadata = adapt_modern(unknown_node_result)
    return [
        {"case": "unsupported_compiler", "status": unsupported_metadata["status"], "analysis_result": unsupported_metadata["analysis_result"]},
        {"case": "compilation_failed", "status": compilation_metadata["status"], "analysis_result": compilation_metadata["analysis_result"]},
        {"case": "ast_unavailable", "status": ast_unavailable_metadata["status"], "analysis_result": ast_unavailable_metadata["analysis_result"]},
        {"case": "unsupported_ast_version", "status": unsupported_ast_metadata["status"], "analysis_result": unsupported_ast_metadata["analysis_result"]},
        {"case": "unknown_ast_node", "status": inconclusive_metadata["status"], "analysis_result": inconclusive_metadata["analysis_result"]},
    ]


def _multi_file_case() -> dict[str, Any]:
    sources = {
        "Lib.sol": "pragma solidity ^0.8.25; library Lib { function value() internal pure returns (uint256) { return 1; } }",
        "Main.sol": "pragma solidity ^0.8.25; import \"Lib.sol\"; contract Main { function read() public pure returns (uint256) { return Lib.value(); } }",
    }
    compiled = compile_sources(sources, "0.8.25", "Main.sol")
    assert compiled.status == AnalysisStatus.COMPILED, compiled.diagnostics
    program, metadata = adapt_modern(compiled)
    assert program is not None, metadata
    assert metadata["status"] == "CanonicalASTReady"
    assert [unit.source_id for unit in program.source_units] == ["Lib.sol", "Main.sol"]
    assert {entry.source_id for entry in program.provenance.source_manifest} == {"Lib.sol", "Main.sol"}
    detector = _run_family(program, "Selfdestruct", sources["Main.sol"], "Main.sol", "fixtures/Main.sol")
    assert detector["status"] == "AnalysisSucceededNoFindings"
    return {
        "case": "multi_file_import_graph",
        "track": "Compatibility",
        "compiler_status": compiled.status.value,
        "adapter_status": metadata["status"],
        "source_units": [unit.source_id for unit in program.source_units],
        "source_manifest": [entry.__dict__ for entry in program.provenance.source_manifest],
        "pragma_constraints": compiled.raw_ast["pragma_constraints"],
        "detector": detector,
    }


def _imported_source_semantic_case() -> dict[str, Any]:
    sources = {
        "Lib.sol": (FIXTURE_ROOT / "imported_lib_0_8_25.sol").read_text(encoding="utf-8"),
        "Main.sol": (FIXTURE_ROOT / "imported_main_0_8_25.sol").read_text(encoding="utf-8"),
    }
    compiled = compile_sources(sources, "0.8.25", "Main.sol")
    assert compiled.status == AnalysisStatus.COMPILED, compiled.diagnostics
    program, metadata = adapt_modern(compiled)
    assert program is not None, metadata
    assert metadata["status"] == "CanonicalASTReady"
    assert [unit.source_id for unit in program.source_units] == ["Lib.sol", "Main.sol"]

    imported_detector = _run_family(
        program,
        "Selfdestruct",
        sources["Lib.sol"],
        "Lib.sol",
        "Lib.sol",
        sources,
    )
    assert imported_detector["status"] == AnalysisStatus.ANALYSIS_SUCCEEDED_WITH_FINDINGS.value
    assert imported_detector["finding_count"] == 1
    assert imported_detector["analyzed_source_id"] == "Lib.sol"
    assert imported_detector["findings"][0]["file"] == "Lib.sol"
    assert imported_detector["finding_provenance"][0]["source_id"] == "Lib.sol"
    assert imported_detector["finding_provenance"][0]["source_range"]
    assert imported_detector["finding_provenance"][0]["canonical_expression_id"].startswith("Lib.sol:")
    assert imported_detector["comparator_results"][0]["status"].value == "Confirmed"
    assert imported_detector["comparator_results"][0]["evidence"]
    assert imported_detector["comparator_results"][0]["evidence"][0]["kind"] == "selfdestruct"
    assert imported_detector["comparator_results"][0]["evidence"][0]["location"].startswith("line ")

    entry_detector = _run_family(
        program,
        "Selfdestruct",
        sources["Main.sol"],
        "Main.sol",
        "Main.sol",
        sources,
    )
    assert entry_detector["status"] == AnalysisStatus.ANALYSIS_SUCCEEDED_NO_FINDINGS.value
    assert entry_detector["finding_count"] == 0

    return {
        "case": "multi_file_imported_semantic_detection",
        "track": "Compatibility",
        "compiler_status": compiled.status.value,
        "adapter_status": metadata["status"],
        "vulnerability_source_id": "Lib.sol",
        "entry_source_id": "Main.sol",
        "imported_detector": imported_detector,
        "entry_detector": entry_detector,
        "source_units": [unit.source_id for unit in program.source_units],
        "source_manifest": [entry.__dict__ for entry in program.provenance.source_manifest],
        "pragma_constraints": compiled.raw_ast["pragma_constraints"],
    }


def main() -> int:
    results: list[dict[str, Any]] = []
    for case_name, version, filename, vulnerable in CASES:
        source = (FIXTURE_ROOT / filename).read_text(encoding="utf-8")
        results.append(_assert_case(case_name, version, source, vulnerable))
    results.append(_invalid_ast_case())
    results.extend(_failure_state_cases())
    results.append(_multi_file_case())
    results.append(_imported_source_semantic_case())

    payload = {
        "schema_version": 2,
        "poc_scope": {
            "production_changes": [],
            "detector_families": list(FAMILIES),
            "context_safe_mapping": True,
            "strict_schema_ownership": True,
            "structural_completeness": True,
            "status_bearing_results": True,
            "provenance_propagation": True,
            "multi_file_slice": True,
            "imported_source_semantic_detection": True,
            "primary_benchmark_changed": False,
            "real_world_adjudications_changed": False,
            "comparator_changed": False,
            "parity_re_adjudicated": False,
        },
        "results": results,
    }
    RESULT_PATH.write_text(json.dumps(payload, indent=2, sort_keys=True, default=str) + "\n", encoding="utf-8")
    print(json.dumps(payload, indent=2, sort_keys=True, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
