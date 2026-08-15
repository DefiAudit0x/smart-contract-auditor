from __future__ import annotations

import re
from typing import Any, Iterable

from .canonical import (
    AnalysisStatus,
    CanonicalContract,
    CanonicalExpression,
    CanonicalFunction,
    CanonicalProgram,
    CompilerResult,
)

ADAPTER_VERSION = "canonical-poc-adapter-v1"


def _kind(node: dict[str, Any]) -> str:
    return str(node.get("nodeType") or node.get("name") or "")


def _attributes(node: dict[str, Any]) -> dict[str, Any]:
    attrs = node.get("attributes")
    return attrs if isinstance(attrs, dict) else {}


def _children(node: dict[str, Any]) -> list[dict[str, Any]]:
    children: list[dict[str, Any]] = []
    structural_keys = {"nodes", "children"}
    for key in structural_keys:
        value = node.get(key)
        if isinstance(value, list):
            children.extend(item for item in value if isinstance(item, dict))
    for key, value in node.items():
        if key in structural_keys:
            continue
        if isinstance(value, dict):
            children.append(value)
        elif isinstance(value, list):
            children.extend(item for item in value if isinstance(item, dict))
    return children


def _node_name(node: dict[str, Any]) -> str:
    attrs = _attributes(node)
    if node.get("nodeType"):
        return str(node.get("name") or "")
    return str(attrs.get("name") or "")


def _source_range(node: dict[str, Any]) -> str:
    return str(node.get("src") or _attributes(node).get("src") or "")


def _walk(node: dict[str, Any]) -> Iterable[dict[str, Any]]:
    yield node
    for child in _children(node):
        yield from _walk(child)


def _direct_tokens(node: dict[str, Any]) -> set[str]:
    attrs = _attributes(node)
    found: set[str] = set()
    for value in (
        node.get("name"),
        node.get("memberName"),
        node.get("member_name"),
        attrs.get("value"),
        attrs.get("member_name"),
        attrs.get("memberName"),
    ):
        if isinstance(value, str):
            found.add(value.lower())
    return found


def _expressions(function_node: dict[str, Any]) -> list[CanonicalExpression]:
    expressions: list[CanonicalExpression] = []
    expression_specs = (
        ({"selfdestruct", "suicide"}, "destructive_operation", "selfdestruct"),
        ({"timestamp", "now"}, "block_timestamp", "timestamp"),
        ({"delegatecall", "callcode"}, "external_call", "delegatecall"),
    )
    for aliases, kind, canonical_member in expression_specs:
        for node in _walk(function_node):
            node_tokens = _direct_tokens(node)
            matched = sorted(aliases.intersection(node_tokens))
            if matched:
                expressions.append(
                    CanonicalExpression(
                        kind=kind,
                        member=canonical_member,
                        arguments=tuple(matched),
                        source_range=_source_range(node),
                    )
                )
                break
    return expressions


def _contract_nodes(raw_ast: dict[str, Any]) -> list[dict[str, Any]]:
    return [node for node in _walk(raw_ast) if _kind(node) in {"ContractDefinition", "ContractDefinition"}]


def _function_nodes(contract_node: dict[str, Any]) -> list[dict[str, Any]]:
    return [node for node in _walk(contract_node) if _kind(node) == "FunctionDefinition"]


def _expected_source_structure(source: str) -> tuple[int, int]:
    contracts = len(re.findall(r"\b(?:contract|library|interface)\s+[A-Za-z_]\w*", source))
    functions = len(re.findall(r"\bfunction\s+[A-Za-z_]\w*\s*\(", source))
    return contracts, functions


def _failure(result: CompilerResult, adapter_name: str, diagnostic: str) -> tuple[None, dict[str, Any]]:
    return None, {
        "status": AnalysisStatus.AST_NORMALIZATION_FAILED.value,
        "adapter_version": ADAPTER_VERSION,
        "diagnostics": [diagnostic],
        "provenance": result.provenance.__dict__ if result.provenance else None,
    }


def adapt(result: CompilerResult, adapter_name: str) -> tuple[CanonicalProgram | None, dict[str, Any]]:
    if result.status != AnalysisStatus.COMPILED:
        return None, {
            "status": result.status.value,
            "adapter_version": ADAPTER_VERSION,
            "diagnostics": list(result.diagnostics),
            "provenance": result.provenance.__dict__ if result.provenance else None,
        }
    if not isinstance(result.raw_ast, dict):
        return _failure(result, adapter_name, "Compiled result did not contain a usable raw AST")

    raw_ast = result.raw_ast
    contracts: list[CanonicalContract] = []
    for contract_node in _contract_nodes(raw_ast):
        functions: list[CanonicalFunction] = []
        for function_node in _function_nodes(contract_node):
            functions.append(
                CanonicalFunction(
                    name=_node_name(function_node) or "<fallback>",
                    visibility=str(_attributes(function_node).get("visibility") or function_node.get("visibility") or "public"),
                    modifiers=[],
                    expressions=_expressions(function_node),
                    source_range=_source_range(function_node),
                )
            )
        contracts.append(
            CanonicalContract(
                name=_node_name(contract_node) or "<anonymous>",
                kind=str(_attributes(contract_node).get("contractKind") or contract_node.get("contractKind") or "contract"),
                functions=functions,
            )
        )

    expected_contracts, expected_functions = _expected_source_structure(result.source)
    normalized_functions = sum(len(contract.functions) for contract in contracts)
    if not contracts:
        return _failure(result, adapter_name, f"{adapter_name} adapter produced zero contracts; expected at least {expected_contracts}")
    if len(contracts) < expected_contracts:
        return _failure(result, adapter_name, f"Structural validation failed: normalized contracts={len(contracts)}, expected={expected_contracts}")
    if normalized_functions < expected_functions:
        return _failure(result, adapter_name, f"Structural validation failed: normalized functions={normalized_functions}, expected={expected_functions}")

    program = CanonicalProgram(
        contracts=contracts,
        provenance=result.provenance,
        adapter_version=ADAPTER_VERSION,
        diagnostics=result.diagnostics,
    )
    return program, {
        "status": "CanonicalASTReady",
        "adapter_name": adapter_name,
        "adapter_version": ADAPTER_VERSION,
        "diagnostics": list(result.diagnostics),
        "summary": program.to_summary(),
    }
