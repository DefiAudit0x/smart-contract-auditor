from __future__ import annotations

import re
from dataclasses import asdict
from typing import Any, Iterable

from .canonical import (
    AnalysisStatus,
    CANONICAL_AST_VERSION,
    CanonicalContract,
    CanonicalExpression,
    CanonicalFunction,
    CanonicalProgram,
    CanonicalSourceUnit,
    CompilerResult,
)

ADAPTER_VERSION = "canonical-poc-adapter-v2"

_LEGACY_KNOWN_CONTRACT_CHILDREN = {
    "FunctionDefinition",
    "ModifierDefinition",
    "VariableDeclaration",
    "EventDefinition",
    "StructDefinition",
    "EnumDefinition",
}
_MODERN_KNOWN_CONTRACT_CHILDREN = {
    "FunctionDefinition",
    "ModifierDefinition",
    "VariableDeclaration",
    "EventDefinition",
    "StructDefinition",
    "EnumDefinition",
}
_MODERN_STRUCTURAL_KEYS = (
    "nodes",
    "body",
    "statements",
    "expression",
    "initialValue",
    "arguments",
    "parameters",
    "returnParameters",
    "baseContracts",
    "modifiers",
    "modifierName",
    "typeName",
    "components",
)


def _legacy_children(node: dict[str, Any]) -> list[dict[str, Any]]:
    value = node.get("children")
    return [item for item in value if isinstance(item, dict)] if isinstance(value, list) else []


def _modern_children(node: dict[str, Any]) -> list[dict[str, Any]]:
    children: list[dict[str, Any]] = []
    for key in _MODERN_STRUCTURAL_KEYS:
        value = node.get(key)
        if isinstance(value, dict):
            children.append(value)
        elif isinstance(value, list):
            children.extend(item for item in value if isinstance(item, dict))
    return children


def _walk(node: dict[str, Any], flavor: str) -> Iterable[dict[str, Any]]:
    yield node
    children = _legacy_children(node) if flavor == "legacy" else _modern_children(node)
    for child in children:
        yield from _walk(child, flavor)


def _kind(node: dict[str, Any], flavor: str) -> str:
    return str(node.get("name") if flavor == "legacy" else node.get("nodeType") or "")


def _attributes(node: dict[str, Any]) -> dict[str, Any]:
    value = node.get("attributes")
    return value if isinstance(value, dict) else {}


def _node_name(node: dict[str, Any], flavor: str) -> str:
    if flavor == "legacy":
        return str(_attributes(node).get("name") or "")
    return str(node.get("name") or "")


def _source_range(node: dict[str, Any]) -> str:
    value = node.get("src") or _attributes(node).get("src") or ""
    return str(value)


def _token(node: dict[str, Any], flavor: str) -> str:
    if flavor == "legacy":
        return str(_attributes(node).get("value") or "").lower()
    return str(node.get("name") or "").lower()


def _member(node: dict[str, Any], flavor: str) -> str:
    if flavor == "legacy":
        return str(_attributes(node).get("member_name") or "").lower()
    return str(node.get("memberName") or "").lower()


def _expression_id(source_id: str, node: dict[str, Any], index: int) -> str:
    return f"{source_id}:{node.get('id', _source_range(node) or index)}"


def _source_range_valid(value: str) -> bool:
    return bool(re.fullmatch(r"\d+:\d+:-?\d+", value))


def _source_declaration_shape(source: str) -> dict[str, int]:
    masked = re.sub(r"//[^\n]*|/\*[\s\S]*?\*/|\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'", " ", source)
    tokens = re.findall(r"\b(contract|library|interface|function|constructor|fallback|receive|modifier)\b", masked)
    return {
        "contracts": sum(token in {"contract", "library", "interface"} for token in tokens),
        "function_like": sum(token in {"function", "constructor", "fallback", "receive"} for token in tokens),
        "modifiers": tokens.count("modifier"),
    }


def _provenance_dict(result: CompilerResult) -> dict[str, Any] | None:
    if result.provenance is None:
        return None
    payload = asdict(result.provenance)
    payload["source_manifest"] = [asdict(entry) for entry in result.provenance.source_manifest]
    return payload


def _failure(result: CompilerResult, adapter_name: str, status: AnalysisStatus, diagnostic: str) -> tuple[None, dict[str, Any]]:
    return None, {
        "status": status.value,
        "adapter_version": ADAPTER_VERSION,
        "canonical_ast_version": CANONICAL_AST_VERSION,
        "diagnostics": [diagnostic],
        "provenance": _provenance_dict(result),
        "analysis_result": {
            "status": status.value,
            "findings": [],
            "diagnostics": [diagnostic],
            "provenance": _provenance_dict(result),
        },
    }


def _validate_provenance(result: CompilerResult, adapter_name: str) -> tuple[None, dict[str, Any]] | None:
    provenance = result.provenance
    if provenance is None:
        return _failure(result, adapter_name, AnalysisStatus.AST_NORMALIZATION_FAILED, "Compiled result is missing required compiler provenance")
    required = {
        "compiler_version": provenance.compiler_version,
        "compiler_binary_hash": provenance.compiler_binary_hash,
        "source_sha256": provenance.source_sha256,
        "raw_ast_sha256": provenance.raw_ast_sha256,
        "ast_format": provenance.ast_format,
    }
    missing = [name for name, value in required.items() if not value]
    if missing:
        return _failure(result, adapter_name, AnalysisStatus.AST_NORMALIZATION_FAILED, f"Compiler provenance is incomplete: {', '.join(missing)}")
    return None


def _validate_schema(raw_ast: dict[str, Any], flavor: str, ast_format: str, adapter_name: str, result: CompilerResult) -> tuple[tuple[str, dict[str, Any]], ...] | tuple[None, dict[str, Any]]:
    if flavor == "legacy":
        if ast_format != "ast-json" or "nodeType" in raw_ast or "schema" in raw_ast or "source_units" in raw_ast:
            return _failure(result, adapter_name, AnalysisStatus.UNSUPPORTED_AST_VERSION, "Legacy adapter received a non-legacy AST schema")
        if raw_ast.get("name") != "SourceUnit" or not isinstance(raw_ast.get("children"), list):
            return _failure(result, adapter_name, AnalysisStatus.AST_NORMALIZATION_FAILED, "Legacy AST container is malformed")
        return ((result.provenance.source_id or "<stdin>", raw_ast),)

    if ast_format == "standard-json-modern-ast":
        if raw_ast.get("schema") != "standard-json-source-units-v1" or not isinstance(raw_ast.get("source_units"), dict):
            return _failure(result, adapter_name, AnalysisStatus.UNSUPPORTED_AST_VERSION, "Modern multi-file adapter received an invalid source-unit wrapper")
        units = []
        for source_id, unit in raw_ast["source_units"].items():
            if not isinstance(unit, dict) or unit.get("nodeType") != "SourceUnit" or not isinstance(unit.get("nodes"), list):
                return _failure(result, adapter_name, AnalysisStatus.UNSUPPORTED_AST_VERSION, f"Modern source unit has invalid schema: {source_id}")
            units.append((source_id, unit))
        return tuple(units)

    if ast_format == "ast-compact-json":
        if "children" in raw_ast or raw_ast.get("name") == "SourceUnit":
            return _failure(result, adapter_name, AnalysisStatus.UNSUPPORTED_AST_VERSION, "Modern adapter received a legacy AST schema")
        if raw_ast.get("nodeType") != "SourceUnit" or not isinstance(raw_ast.get("nodes"), list):
            return _failure(result, adapter_name, AnalysisStatus.AST_NORMALIZATION_FAILED, "Modern AST container is malformed")
        return ((result.provenance.source_id or "<stdin>", raw_ast),)

    return _failure(result, adapter_name, AnalysisStatus.UNSUPPORTED_AST_VERSION, "Modern adapter received a non-modern AST schema")


def _legacy_function_symbols(contract_node: dict[str, Any], function_node: dict[str, Any]) -> set[str]:
    symbols: set[str] = set()
    for node in _walk(function_node, "legacy"):
        if _kind(node, "legacy") == "VariableDeclaration":
            name = _node_name(node, "legacy")
            if name:
                symbols.add(name.lower())
    return symbols


def _modern_function_symbols(contract_node: dict[str, Any], function_node: dict[str, Any]) -> set[str]:
    symbols: set[str] = set()
    for node in _walk(function_node, "modern"):
        if _kind(node, "modern") == "VariableDeclaration":
            name = _node_name(node, "modern")
            if name:
                symbols.add(name.lower())
    return symbols


def _legacy_expressions(contract_node: dict[str, Any], function_node: dict[str, Any], source_id: str) -> list[CanonicalExpression]:
    symbols = _legacy_function_symbols(contract_node, function_node)
    expressions: list[CanonicalExpression] = []
    index = 0
    for node in _walk(function_node, "legacy"):
        kind = _kind(node, "legacy")
        if kind == "FunctionCall":
            children = _legacy_children(node)
            callee = children[0] if children else None
            if isinstance(callee, dict) and _kind(callee, "legacy") == "Identifier" and _token(callee, "legacy") == "suicide" and "suicide" not in symbols:
                expressions.append(CanonicalExpression("destructive_operation", "selfdestruct", ("suicide",), _source_range(callee), _expression_id(source_id, callee, index)))
                index += 1
            elif isinstance(callee, dict) and _kind(callee, "legacy") == "MemberAccess" and _member(callee, "legacy") == "callcode":
                expressions.append(CanonicalExpression("external_call", "delegatecall", ("callcode",), _source_range(callee), _expression_id(source_id, callee, index)))
                index += 1
        elif kind == "Identifier" and _token(node, "legacy") == "now" and "now" not in symbols:
            expressions.append(CanonicalExpression("block_timestamp", "timestamp", ("now",), _source_range(node), _expression_id(source_id, node, index)))
            index += 1
    return expressions


def _modern_expressions(contract_node: dict[str, Any], function_node: dict[str, Any], source_id: str) -> list[CanonicalExpression]:
    symbols = _modern_function_symbols(contract_node, function_node)
    expressions: list[CanonicalExpression] = []
    index = 0
    for node in _walk(function_node, "modern"):
        kind = _kind(node, "modern")
        if kind == "FunctionCall":
            callee = node.get("expression")
            if isinstance(callee, dict) and _kind(callee, "modern") == "Identifier" and _token(callee, "modern") == "selfdestruct" and "selfdestruct" not in symbols:
                expressions.append(CanonicalExpression("destructive_operation", "selfdestruct", ("selfdestruct",), _source_range(callee), _expression_id(source_id, callee, index)))
                index += 1
            elif isinstance(callee, dict) and _kind(callee, "modern") == "MemberAccess" and _member(callee, "modern") == "delegatecall":
                expressions.append(CanonicalExpression("external_call", "delegatecall", ("delegatecall",), _source_range(callee), _expression_id(source_id, callee, index)))
                index += 1
        elif kind == "MemberAccess" and _member(node, "modern") == "timestamp":
            receiver = node.get("expression")
            type_descriptions = receiver.get("typeDescriptions", {}) if isinstance(receiver, dict) else {}
            if (
                isinstance(receiver, dict)
                and _kind(receiver, "modern") == "Identifier"
                and _token(receiver, "modern") == "block"
                and type_descriptions.get("typeIdentifier") == "t_magic_block"
            ):
                expressions.append(CanonicalExpression("block_timestamp", "timestamp", ("timestamp",), _source_range(node), _expression_id(source_id, node, index)))
                index += 1
    return expressions


def _direct_contract_nodes(unit: dict[str, Any], flavor: str) -> list[dict[str, Any]]:
    children = _legacy_children(unit) if flavor == "legacy" else _modern_children(unit)
    return [node for node in children if _kind(node, flavor) == "ContractDefinition"]


def _contract_children(contract_node: dict[str, Any], flavor: str) -> list[dict[str, Any]]:
    return _legacy_children(contract_node) if flavor == "legacy" else _modern_children(contract_node)


def _function_like(node: dict[str, Any], flavor: str) -> bool:
    return _kind(node, flavor) == "FunctionDefinition"


def _normalize_unit(source_id: str, unit: dict[str, Any], flavor: str) -> tuple[CanonicalSourceUnit, set[str], set[str]]:
    contracts: list[CanonicalContract] = []
    unknown_nodes: set[str] = set()
    skipped_nodes: set[str] = set()
    for contract_node in _direct_contract_nodes(unit, flavor):
        functions: list[CanonicalFunction] = []
        modifiers: list[str] = []
        state_variables: list[str] = []
        for child in _contract_children(contract_node, flavor):
            child_kind = _kind(child, flavor)
            if _function_like(child, flavor):
                function_kind = str(child.get("kind") or _attributes(child).get("kind") or "function")
                expressions = (
                    _legacy_expressions(contract_node, child, source_id)
                    if flavor == "legacy"
                    else _modern_expressions(contract_node, child, source_id)
                )
                functions.append(
                    CanonicalFunction(
                        name=_node_name(child, flavor) or f"<{function_kind}>",
                        kind=function_kind,
                        visibility=str(child.get("visibility") or _attributes(child).get("visibility") or "public"),
                        state_mutability=str(child.get("stateMutability") or _attributes(child).get("stateMutability") or "nonpayable"),
                        expressions=expressions,
                        source_range=_source_range(child),
                    )
                )
            elif child_kind == "ModifierDefinition":
                modifiers.append(_node_name(child, flavor) or "<modifier>")
            elif child_kind == "VariableDeclaration":
                state_variables.append(_node_name(child, flavor))
            elif child_kind in (_LEGACY_KNOWN_CONTRACT_CHILDREN if flavor == "legacy" else _MODERN_KNOWN_CONTRACT_CHILDREN):
                skipped_nodes.add(child_kind or "<skipped>")
            else:
                unknown_nodes.add(child_kind or "<unknown>")
        contracts.append(
            CanonicalContract(
                name=_node_name(contract_node, flavor) or "<anonymous>",
                kind=str(contract_node.get("contractKind") or _attributes(contract_node).get("contractKind") or "contract"),
                functions=functions,
                modifiers=modifiers,
                state_variables=state_variables,
                source_range=_source_range(contract_node),
            )
        )
    return CanonicalSourceUnit(source_id=source_id, contracts=contracts, source_range=_source_range(unit)), unknown_nodes, skipped_nodes


def adapt(result: CompilerResult, adapter_name: str, flavor: str) -> tuple[CanonicalProgram | None, dict[str, Any]]:
    if result.status != AnalysisStatus.COMPILED:
        return None, {
            "status": result.status.value,
            "adapter_version": ADAPTER_VERSION,
            "canonical_ast_version": CANONICAL_AST_VERSION,
            "diagnostics": list(result.diagnostics),
            "provenance": _provenance_dict(result),
            "analysis_result": {
                "status": result.status.value,
                "findings": [],
                "diagnostics": list(result.diagnostics),
                "provenance": _provenance_dict(result),
            },
        }
    provenance_error = _validate_provenance(result, adapter_name)
    if provenance_error:
        return provenance_error
    if not isinstance(result.raw_ast, dict):
        return _failure(result, adapter_name, AnalysisStatus.AST_NORMALIZATION_FAILED, "Compiled result did not contain a usable raw AST")

    schema_result = _validate_schema(result.raw_ast, flavor, result.provenance.ast_format, adapter_name, result)
    if schema_result and all(isinstance(item, tuple) and len(item) == 2 for item in schema_result):
        source_units = schema_result
    else:
        return schema_result  # type: ignore[return-value]

    normalized_units: list[CanonicalSourceUnit] = []
    unknown_nodes: set[str] = set()
    skipped_nodes: set[str] = set()
    for source_id, unit in source_units:
        canonical_unit, unit_unknown, unit_skipped = _normalize_unit(source_id, unit, flavor)
        normalized_units.append(canonical_unit)
        unknown_nodes.update(unit_unknown)
        skipped_nodes.update(unit_skipped)

    expected_sources = set(result.sources) if result.sources else {result.provenance.source_id or "<stdin>"}
    actual_sources = {unit.source_id for unit in normalized_units}
    expected_contracts = sum(_source_declaration_shape(source)["contracts"] for source in result.sources.values()) if result.sources else _source_declaration_shape(result.source)["contracts"]
    expected_function_like = sum(_source_declaration_shape(source)["function_like"] for source in result.sources.values()) if result.sources else _source_declaration_shape(result.source)["function_like"]
    expected_modifiers = sum(_source_declaration_shape(source)["modifiers"] for source in result.sources.values()) if result.sources else _source_declaration_shape(result.source)["modifiers"]
    actual_contracts = sum(len(unit.contracts) for unit in normalized_units)
    actual_function_like = sum(len(contract.functions) for unit in normalized_units for contract in unit.contracts)
    actual_modifiers = sum(len(contract.modifiers) for unit in normalized_units for contract in unit.contracts)

    if unknown_nodes:
        return _failure(result, adapter_name, AnalysisStatus.INCONCLUSIVE, f"Adapter encountered unknown contract nodes: {', '.join(sorted(unknown_nodes))}")
    if actual_sources != expected_sources:
        return _failure(result, adapter_name, AnalysisStatus.AST_NORMALIZATION_FAILED, f"Structural validation failed: source units={sorted(actual_sources)}, expected={sorted(expected_sources)}")
    if actual_contracts < expected_contracts:
        return _failure(result, adapter_name, AnalysisStatus.AST_NORMALIZATION_FAILED, f"Structural validation failed: contracts={actual_contracts}, expected={expected_contracts}")
    if actual_function_like < expected_function_like:
        return _failure(result, adapter_name, AnalysisStatus.AST_NORMALIZATION_FAILED, f"Structural validation failed: function-like nodes={actual_function_like}, expected={expected_function_like}")
    if actual_modifiers < expected_modifiers:
        return _failure(result, adapter_name, AnalysisStatus.AST_NORMALIZATION_FAILED, f"Structural validation failed: modifiers={actual_modifiers}, expected={expected_modifiers}")

    for unit in normalized_units:
        if not _source_range_valid(unit.source_range) and unit.source_range:
            return _failure(result, adapter_name, AnalysisStatus.AST_NORMALIZATION_FAILED, f"Invalid source-unit range in {unit.source_id}: {unit.source_range}")
        for contract in unit.contracts:
            if contract.source_range and not _source_range_valid(contract.source_range):
                return _failure(result, adapter_name, AnalysisStatus.AST_NORMALIZATION_FAILED, f"Invalid contract range in {unit.source_id}: {contract.source_range}")
            for function in contract.functions:
                if function.source_range and not _source_range_valid(function.source_range):
                    return _failure(result, adapter_name, AnalysisStatus.AST_NORMALIZATION_FAILED, f"Invalid function range in {unit.source_id}: {function.source_range}")

    program = CanonicalProgram(
        source_units=normalized_units,
        provenance=result.provenance,
        adapter_version=ADAPTER_VERSION,
        diagnostics=result.diagnostics,
        unknown_nodes=tuple(sorted(unknown_nodes)),
        skipped_nodes=tuple(sorted(skipped_nodes)),
    )
    metadata = {
        "status": "CanonicalASTReady",
        "adapter_name": adapter_name,
        "adapter_version": ADAPTER_VERSION,
        "canonical_ast_version": CANONICAL_AST_VERSION,
        "diagnostics": list(result.diagnostics),
        "unknown_nodes": sorted(unknown_nodes),
        "skipped_nodes": sorted(skipped_nodes),
        "summary": program.to_summary(),
    }
    return program, metadata
