from __future__ import annotations

from dataclasses import asdict
from typing import Any

from analyzers.solidity_analyzer import SolidityAnalyzer
from analyzers.solidity_ast import ASTContract, ASTFunction
from verification.comparator import compare_finding

from .canonical import (
    AnalysisResult,
    AnalysisStatus,
    CANONICAL_AST_VERSION,
    CanonicalProgram,
    DetectorInput,
    FindingProvenance,
    SourceManifestEntry,
    SourceView,
)

POC_DETECTOR_VERSION = "canonical-poc-detector-bridge-v2"
POC_COMPARATOR_VERSION = "existing-comparator-unchanged"
_DETECTOR_NAMES = {
    "Selfdestruct": "_check_selfdestruct",
    "block.timestamp": "_check_block_timestamp",
    "DELEGATECALL": "_check_delegatecall",
}
_EXPRESSION_KINDS = {
    "Selfdestruct": "destructive_operation",
    "block.timestamp": "block_timestamp",
    "DELEGATECALL": "external_call",
}


def _to_detector_contracts(program: CanonicalProgram, source_id: str | None = None) -> list[ASTContract]:
    """Project only semantic fields needed by the detector from one source unit."""
    units = [unit for unit in program.source_units if source_id is None or unit.source_id == source_id]
    contracts: list[ASTContract] = []
    for canonical_contract in [contract for unit in units for contract in unit.contracts]:
        functions: list[ASTFunction] = []
        for canonical_function in canonical_contract.functions:
            functions.append(
                ASTFunction(
                    name=canonical_function.name,
                    visibility=canonical_function.visibility,
                    modifiers=list(canonical_function.modifiers),
                    uses_selfdestruct=canonical_function.uses_selfdestruct,
                    uses_block_timestamp=canonical_function.uses_block_timestamp,
                    uses_delegatecall="delegatecall" in canonical_function.call_kinds,
                )
            )
        contracts.append(
            ASTContract(
                name=canonical_contract.name,
                kind=canonical_contract.kind,
                functions=functions,
                uses_delegatecall=any(fn.uses_delegatecall for fn in functions),
                uses_selfdestruct=any(fn.uses_selfdestruct for fn in functions),
            )
        )
    return contracts


def make_detector_input(
    program: CanonicalProgram,
    source_id: str,
    source_text: str,
    source_texts: dict[str, str] | None = None,
) -> DetectorInput:
    manifest = program.provenance.source_manifest or (SourceManifestEntry(source_id, program.provenance.source_sha256),)
    source_hash = next((entry.source_sha256 for entry in manifest if entry.source_id == source_id), program.provenance.source_sha256)
    return DetectorInput(
        canonical_program=program,
        source_view=SourceView(source_id, source_text, source_hash, manifest, source_texts or {source_id: source_text}),
        detector_version=POC_DETECTOR_VERSION,
    )


def _finding_provenance(detector_input: DetectorInput, family: str, function_name: str) -> FindingProvenance:
    program = detector_input.canonical_program
    expression_kind = _EXPRESSION_KINDS[family]
    expression = None
    source_range = ""
    units = [unit for unit in program.source_units if unit.source_id == detector_input.source_view.source_id]
    for contract in [contract for unit in units for contract in unit.contracts]:
        for function in contract.functions:
            if function.name == function_name:
                expression = next((item for item in function.expressions if item.kind == expression_kind), None)
                source_range = expression.source_range if expression else function.source_range
                break
        if expression:
            break
    return FindingProvenance(
        source_id=detector_input.source_view.source_id,
        source_manifest=detector_input.source_view.source_manifest,
        source_sha256=detector_input.source_view.source_sha256,
        compiler_version=program.provenance.compiler_version,
        compiler_hash=program.provenance.compiler_binary_hash,
        raw_ast_hash=program.provenance.raw_ast_sha256,
        adapter_version=program.adapter_version,
        canonical_ast_version=CANONICAL_AST_VERSION,
        detector_version=detector_input.detector_version,
        comparator_version=POC_COMPARATOR_VERSION,
        source_range=source_range,
        evidence_kind=expression.kind if expression else "detector_finding",
        canonical_expression_id=expression.expression_id if expression else "",
    )


def run_detector(
    detector_input: DetectorInput,
    family: str,
    filename: str | None = None,
) -> dict[str, Any]:
    """Run one existing detector using a status-bearing Canonical DetectorInput."""
    if family not in _DETECTOR_NAMES:
        raise ValueError(f"Unsupported POC detector family: {family}")

    source = detector_input.source_view.source_text
    source_id = detector_input.source_view.source_id
    analyzer = SolidityAnalyzer()
    analyzer._contracts = _to_detector_contracts(detector_input.canonical_program, source_id)
    check = getattr(analyzer, _DETECTOR_NAMES[family])
    detector_source = "" if family == "Selfdestruct" else source
    findings = check(filename or source_id, detector_source)
    comparisons = [asdict(compare_finding(finding, source)) for finding in findings]
    finding_provenance = [
        _finding_provenance(detector_input, family, finding.function_name)
        for finding in findings
    ]
    status = AnalysisStatus.ANALYSIS_SUCCEEDED_WITH_FINDINGS if findings else AnalysisStatus.ANALYSIS_SUCCEEDED_NO_FINDINGS
    analysis = AnalysisResult(
        status=status,
        findings=findings,
        finding_provenance=finding_provenance,
        diagnostics=[],
        provenance=detector_input.canonical_program.provenance,
        adapter_version=detector_input.canonical_program.adapter_version,
        canonical_ast_version=CANONICAL_AST_VERSION,
        detector_version=detector_input.detector_version,
        comparator_version=POC_COMPARATOR_VERSION,
    )
    return {
        "family": family,
        "detector_method": _DETECTOR_NAMES[family],
        "status": analysis.status.value,
        "finding_count": len(findings),
        "findings": [asdict(finding) for finding in findings],
        "finding_provenance": [
            {
                **asdict(item),
                "source_manifest": [asdict(entry) for entry in item.source_manifest],
            }
            for item in finding_provenance
        ],
        "analysis_result": {
            "status": analysis.status.value,
            "diagnostics": analysis.diagnostics,
            "adapter_version": analysis.adapter_version,
            "canonical_ast_version": analysis.canonical_ast_version,
            "detector_version": analysis.detector_version,
            "comparator_version": analysis.comparator_version,
        },
        "comparator_results": comparisons,
        "detector_input_contract": "CanonicalProgram+SourceView+Provenance",
        "detector_source_policy": "canonical-ast-only",
        "analyzed_source_id": source_id,
        "source_text_ids": sorted(detector_input.source_view.source_texts),
        "detector_compiler_knowledge": False,
        "comparator_implementation_changed": False,
    }
