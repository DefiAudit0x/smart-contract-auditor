from __future__ import annotations

from dataclasses import asdict
from typing import Any

from analyzers.solidity_analyzer import SolidityAnalyzer
from analyzers.solidity_ast import ASTContract, ASTFunction
from verification.comparator import compare_finding

from .canonical import CanonicalProgram


_DETECTOR_NAMES = {
    "Selfdestruct": "_check_selfdestruct",
    "block.timestamp": "_check_block_timestamp",
    "DELEGATECALL": "_check_delegatecall",
}


def _to_detector_contracts(program: CanonicalProgram) -> list[ASTContract]:
    """Project only semantic fields needed by the existing detector methods."""
    contracts: list[ASTContract] = []
    for canonical_contract in program.contracts:
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


def run_detector(
    program: CanonicalProgram,
    family: str,
    source: str,
    filename: str,
) -> dict[str, Any]:
    """Run an existing detector against semantic projections of Canonical AST."""
    if family not in _DETECTOR_NAMES:
        raise ValueError(f"Unsupported POC detector family: {family}")

    analyzer = SolidityAnalyzer()
    analyzer._contracts = _to_detector_contracts(program)
    check = getattr(analyzer, _DETECTOR_NAMES[family])
    findings = check(filename, source)
    comparisons = [asdict(compare_finding(finding, source)) for finding in findings]

    return {
        "family": family,
        "detector_method": _DETECTOR_NAMES[family],
        "finding_count": len(findings),
        "findings": [asdict(finding) for finding in findings],
        "comparator_results": comparisons,
        "detector_compiler_knowledge": False,
        "comparator_implementation_changed": False,
    }
