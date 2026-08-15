from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path
from typing import Any, Callable

from .canonical import AnalysisStatus
from .compiler import compile_source
from .detector_bridge import run_detector
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


def _assert_case(case_name: str, version: str, source: str, vulnerable: bool) -> dict[str, Any]:
    compiler_result = compile_source(source, version)
    assert compiler_result.status == AnalysisStatus.COMPILED, {
        "case": case_name,
        "status": compiler_result.status.value,
        "diagnostics": compiler_result.diagnostics,
    }

    program, adapter_metadata = _adapter_for(version)(compiler_result)
    assert program is not None, {"case": case_name, "adapter": adapter_metadata}
    semantics = _canonical_semantics(program)
    for family in FAMILIES:
        assert semantics[family]["present"] is vulnerable, {
            "case": case_name,
            "family": family,
            "semantics": semantics[family],
            "expected": vulnerable,
        }

    detector_results: dict[str, Any] = {}
    for family in FAMILIES:
        detector_result = run_detector(program, family, source, f"fixtures/{case_name}.sol")
        assert detector_result["finding_count"] == int(vulnerable), {
            "case": case_name,
            "family": family,
            "detector_result": detector_result,
        }
        assert detector_result["detector_compiler_knowledge"] is False
        assert detector_result["comparator_implementation_changed"] is False
        detector_results[family] = detector_result

    expected_aliases = EXPECTED_ALIASES.get(case_name, {})
    if expected_aliases:
        for family, alias in expected_aliases.items():
            expression_arguments = [
                argument
                for contract in program.contracts
                for function in contract.functions
                for expression in function.expressions
                if expression.member in {"selfdestruct", "timestamp", "delegatecall"}
                for argument in expression.arguments
            ]
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
    assert metadata["diagnostics"]
    return {
        "case": "invalid_ast_container",
        "track": "Compatibility",
        "compiler_status": compiled.status.value,
        "adapter_status": metadata["status"],
        "adapter_metadata": metadata,
        "canonical_program": None,
        "detectors": {},
        "expected_findings": None,
    }


def main() -> int:
    results: list[dict[str, Any]] = []
    for case_name, version, filename, vulnerable in CASES:
        source = (FIXTURE_ROOT / filename).read_text(encoding="utf-8")
        results.append(_assert_case(case_name, version, source, vulnerable))
    results.append(_invalid_ast_case())

    payload = {
        "schema_version": 1,
        "poc_scope": {
            "production_changes": [],
            "detector_families": list(FAMILIES),
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
