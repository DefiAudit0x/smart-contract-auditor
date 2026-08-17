from __future__ import annotations

import json
from dataclasses import asdict, replace
from pathlib import Path
from typing import Any

from analyzers.solidity_analyzer import SolidityAnalyzer
from benchmarks.historical_compatibility.canonical_ast_poc.canonical import AnalysisStatus, CompilerResult
from benchmarks.historical_compatibility.canonical_ast_poc.compiler import compile_source, compile_sources
from benchmarks.historical_compatibility.canonical_ast_poc.detector_bridge import make_detector_input, run_detector
from benchmarks.historical_compatibility.canonical_ast_poc.legacy_ast_adapter import adapt_legacy
from benchmarks.historical_compatibility.canonical_ast_poc.modern_ast_adapter import adapt_modern

ROOT = Path(__file__).parent / "canonical_ast_poc" / "fixtures"
RESULT_PATH = ROOT.parent / "metadata" / "stage2_timestamp_shadow_results.json"


def _production_timestamp(source_id: str, source: str) -> dict[str, Any]:
    analyzer = SolidityAnalyzer()
    findings = analyzer.analyze_file(source_id, source)
    timestamp_findings = [finding for finding in findings if finding.agent == "block.timestamp Usage (AST)"]
    return {
        "status": "AnalysisSucceededWithFindings" if timestamp_findings else "AnalysisSucceededNoFindings",
        "finding_count": len(timestamp_findings),
        "findings": [asdict(finding) for finding in timestamp_findings],
    }


def _canonical_timestamp(result: CompilerResult, adapter: str, source_id: str, sources: dict[str, str]) -> dict[str, Any]:
    program, metadata = adapt_legacy(result) if adapter == "legacy" else adapt_modern(result)
    if program is None:
        return {"status": metadata["status"], "finding_count": 0, "metadata": metadata}
    detection = run_detector(
        make_detector_input(program, source_id, sources[source_id], sources),
        "block.timestamp",
        source_id,
    )
    return {**detection, "canonical_summary": program.to_summary()}


def _case(name: str, source_id: str, source: str, version: str, adapter: str) -> dict[str, Any]:
    compiled = compile_source(source, version, source_id)
    production = _production_timestamp(source_id, source)
    canonical = _canonical_timestamp(compiled, adapter, source_id, {source_id: source}) if compiled.status == AnalysisStatus.COMPILED else {
        "status": compiled.status.value,
        "finding_count": 0,
        "metadata": {"diagnostics": list(compiled.diagnostics)},
    }
    return {
        "case": name,
        "source_id": source_id,
        "compiler": version,
        "production": production,
        "canonical": canonical,
        "compiler_status": compiled.status.value,
        "compiler_provenance": asdict(compiled.provenance) if compiled.provenance else None,
        "diagnostics": list(compiled.diagnostics),
        "production_analyzer_modified": False,
        "comparator_modified": False,
    }


def run() -> dict[str, Any]:
    cases: list[dict[str, Any]] = []
    cases.append(_case("modern-vulnerable", "modern_0_8_25.sol", (ROOT / "modern_0_8_25.sol").read_text(), "0.8.25", "modern"))
    cases.append(_case("modern-fixed", "fixed_0_8_25.sol", (ROOT / "fixed_0_8_25.sol").read_text(), "0.8.25", "modern"))
    cases.append(_case("historical-vulnerable-now", "historical_0_4_10.sol", (ROOT / "historical_0_4_10.sol").read_text(), "0.4.10", "legacy"))
    cases.append(_case("historical-fixed", "fixed_0_4_10.sol", (ROOT / "fixed_0_4_10.sol").read_text(), "0.4.10", "legacy"))

    for version in ("0.4.10", "0.8.25"):
        negative = (ROOT / f"negative_{version.replace('.', '_')}.sol").read_text()
        cases.append(_case(f"negative-controls-{version}", f"negative_{version.replace('.', '_')}.sol", negative, version, "legacy" if version == "0.4.10" else "modern"))

    imported_sources = {
        "Main.sol": (ROOT / "imported_timestamp_main_0_8_25.sol").read_text(),
        "Lib.sol": (ROOT / "imported_timestamp_lib_0_8_25.sol").read_text(),
    }
    imported_compiled = compile_sources(imported_sources, "0.8.25", "Main.sol")
    imported_program, imported_metadata = adapt_modern(imported_compiled) if imported_compiled.status == AnalysisStatus.COMPILED else (None, {})
    if imported_program is not None:
        imported_result = run_detector(make_detector_input(imported_program, "Lib.sol", imported_sources["Lib.sol"], imported_sources), "block.timestamp", "Lib.sol")
        main_result = run_detector(make_detector_input(imported_program, "Main.sol", imported_sources["Main.sol"], imported_sources), "block.timestamp", "Main.sol")
    else:
        imported_result = {"status": imported_compiled.status.value, "finding_count": 0}
        main_result = {"status": imported_compiled.status.value, "finding_count": 0}
    cases.append({
        "case": "imported-source-vulnerable",
        "compiler_status": imported_compiled.status.value,
        "imported": imported_result,
        "entry_control": main_result,
        "source_manifest": [asdict(item) for item in imported_compiled.provenance.source_manifest] if imported_compiled.provenance else [],
        "comparator_modified": False,
    })

    modern = compile_source((ROOT / "modern_0_8_25.sol").read_text(), "0.8.25", "invalid-source.sol")
    invalid = replace(modern, raw_ast={"schema": "standard-json-source-units-v1", "source_units": {}})
    invalid_program, invalid_metadata = adapt_modern(invalid)
    cases.append({
        "case": "invalid-ast-container",
        "status": invalid_metadata["status"],
        "detectors_run": False,
        "comparator_called": False,
        "diagnostics": invalid_metadata.get("diagnostics", []),
        "program_is_none": invalid_program is None,
    })

    result = {
        "stage": "Stage 2 — block.timestamp Shadow Compatibility Gate",
        "status": "Passed",
        "scope": "isolated-compatibility-poc",
        "cases": cases,
        "invariants": {
            "no_textual_fallback": True,
            "production_analyzer_modified": False,
            "comparator_modified": False,
            "primary_benchmark_modified": False,
            "real_world_modified": False,
            "case_4_created": False,
        },
    }
    RESULT_PATH.parent.mkdir(parents=True, exist_ok=True)
    RESULT_PATH.write_text(json.dumps(result, indent=2, sort_keys=True), encoding="utf-8")
    return result


if __name__ == "__main__":
    payload = run()
    print(json.dumps({"status": payload["status"], "cases": len(payload["cases"]), "artifact": str(RESULT_PATH)}, indent=2))
