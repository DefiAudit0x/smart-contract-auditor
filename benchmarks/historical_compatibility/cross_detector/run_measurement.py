from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import solcx
from solcx.exceptions import SolcError

from analyzers.solidity_analyzer import SolidityAnalyzer
from analyzers.solidity_ast import SOLC_VERSION, analyze_contracts, compile_to_ast
from verification.comparator import compare_finding

ROOT = Path(__file__).resolve().parent
VERSIONS = {
    "solidity_04": "0.4.11",
    "solidity_05": "0.5.17",
    "solidity_06": "0.6.12",
    "solidity_07": "0.7.6",
    "solidity_08": "0.8.25",
}

PROBES = {
    "Selfdestruct": {
        "canonical": "selfdestruct_canonical.sol",
        "legacy": "selfdestruct_legacy.sol",
        "fixed": "selfdestruct_fixed.sol",
        "function": "destroy",
        "normalized_fields": ["uses_selfdestruct"],
        "raw_ast_tokens": ["selfdestruct", "suicide"],
        "category": "Access Control",
        "severity": "Critical",
    },
    "block.timestamp Usage (AST)": {
        "canonical": "timestamp_canonical.sol",
        "legacy": "timestamp_legacy.sol",
        "fixed": "timestamp_fixed.sol",
        "function": "claim",
        "normalized_fields": ["uses_block_timestamp"],
        "raw_ast_tokens": ["timestamp", "now"],
        "category": "Timing",
        "severity": "Medium",
    },
    "DELEGATECALL Usage (AST)": {
        "canonical": "delegatecall_canonical.sol",
        "legacy": "delegatecall_legacy.sol",
        "fixed": "delegatecall_fixed.sol",
        "function": "execute",
        "normalized_fields": ["uses_delegatecall"],
        "raw_ast_tokens": ["delegatecall", "callcode"],
        "category": "Access Control",
        "severity": "High",
    },
}


def _collect_ast_tokens(value: Any, tokens: set[str]) -> None:
    if isinstance(value, dict):
        node_type = value.get("nodeType")
        if isinstance(node_type, str):
            for key in ("name", "memberName", "member_name"):
                item = value.get(key)
                if isinstance(item, str):
                    tokens.add(item.lower())
        for key in ("memberName", "member_name"):
            item = value.get(key)
            if isinstance(item, str):
                tokens.add(item.lower())
        attributes = value.get("attributes")
        if isinstance(attributes, dict):
            for key in ("value", "memberName", "member_name"):
                item = attributes.get(key)
                if isinstance(item, str):
                    tokens.add(item.lower())
        for child in value.values():
            _collect_ast_tokens(child, tokens)
    elif isinstance(value, list):
        for child in value:
            _collect_ast_tokens(child, tokens)


def _historical_compile(source: str, version: str, raw_ast_tokens: list[str]) -> dict[str, Any]:
    try:
        if version not in {str(item) for item in solcx.get_installed_solc_versions()}:
            solcx.install_solc(version, show_progress=False)
        compiled = solcx.compile_source(source, output_values=["ast"], solc_version=version)
        ast_tokens: set[str] = set()
        for artifact in compiled.values():
            _collect_ast_tokens(artifact.get("ast", {}), ast_tokens)
        return {
            "compiler": version,
            "status": "compiled",
            "error": None,
            "raw_ast_keywords": sorted(keyword for keyword in raw_ast_tokens if keyword.lower() in ast_tokens),
            "artifact_count": len(compiled),
        }
    except SolcError as exc:
        return {
            "compiler": version,
            "status": "compile_failed",
            "error": str(exc).splitlines()[-1][:400],
            "raw_ast_keywords": [],
        }
    except Exception as exc:
        return {
            "compiler": version,
            "status": "compile_failed",
            "error": f"{type(exc).__name__}: {exc}",
            "raw_ast_keywords": [],
        }


def _normalized_ast(source: str, fields: list[str]) -> dict[str, Any]:
    units = compile_to_ast(source)
    if not units:
        return {
            "status": "compile_failed",
            "compiler": SOLC_VERSION,
            "signals": {field: False for field in fields},
            "function_count": 0,
        }
    contracts = analyze_contracts(units)
    functions = [function for contract in contracts for function in contract.functions]
    return {
        "status": "normalized",
        "compiler": SOLC_VERSION,
        "signals": {
            field: any(bool(getattr(function, field, False)) for function in functions)
            for field in fields
        },
        "function_count": len(functions),
    }


def _current_detector(source: str, filename: str, detector: str) -> dict[str, Any]:
    analyzer = SolidityAnalyzer()
    findings = analyzer.analyze_file(filename, source)
    matches = [finding for finding in findings if finding.agent_name == detector]
    return {
        "detectors": sorted({finding.agent_name for finding in findings}),
        "target_hit": bool(matches),
        "matching_functions": sorted({finding.function_name for finding in matches}),
        "finding_count": len(findings),
        "analyzer_solc_version": SOLC_VERSION,
    }


def _comparator(source: str, filename: str, detector: str, function_name: str) -> dict[str, Any]:
    finding = {
        "agent_name": detector,
        "severity": "Critical",
        "category": "Compatibility",
        "file": filename,
        "function_name": function_name,
        "description": "Cross-detector compatibility probe",
    }
    result = compare_finding(finding, source)
    return {
        "status": result.status.value,
        "reason": result.reason,
        "evidence": [
            {"kind": item.kind, "location": item.location, "excerpt": item.excerpt}
            for item in result.evidence
        ],
    }


def run() -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    for version_family, compiler in VERSIONS.items():
        directory = ROOT / version_family
        for detector, probe in PROBES.items():
            for form in ("canonical", "legacy", "fixed"):
                filename = probe[form]
                path = directory / filename
                source = path.read_text(encoding="utf-8")
                rows.append({
                    "detector": detector,
                    "version_family": version_family,
                    "historical_compiler": _historical_compile(source, compiler, probe["raw_ast_tokens"]),
                    "raw_source": {
                        "fixture": filename,
                        "form": form,
                        "expected_semantic_signal": form != "fixed",
                    },
                    "normalized_ast": _normalized_ast(source, probe["normalized_fields"]),
                    "current_detector": _current_detector(source, filename, detector),
                    "comparator": _comparator(source, filename, detector, probe["function"]),
                })
    return {
        "schema_version": 1,
        "measurement_only": True,
        "production_changes": [],
        "current_analyzer_solc": SOLC_VERSION,
        "historical_compilers": VERSIONS,
        "detectors": list(PROBES),
        "forms": ["canonical", "legacy", "fixed"],
        "row_count": len(rows),
        "rows": rows,
    }


if __name__ == "__main__":
    output = ROOT / "metadata" / "cross_detector_compatibility_measurement.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(run(), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(output)
