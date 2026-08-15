from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class AnalysisStatus(str, Enum):
    COMPILED = "Compiled"
    AST_NORMALIZATION_FAILED = "ASTNormalizationFailed"
    AST_UNAVAILABLE = "ASTUnavailable"
    UNSUPPORTED_AST_VERSION = "UnsupportedASTVersion"
    UNSUPPORTED_COMPILER = "UnsupportedCompiler"
    COMPILATION_FAILED = "CompilationFailed"
    INCONCLUSIVE = "Inconclusive"
    ANALYSIS_SUCCEEDED_NO_FINDINGS = "AnalysisSucceededNoFindings"
    ANALYSIS_SUCCEEDED_WITH_FINDINGS = "AnalysisSucceededWithFindings"


@dataclass(frozen=True)
class CompilerProvenance:
    compiler_version: str
    compiler_build: str
    compiler_binary_hash: str
    source_sha256: str
    raw_ast_sha256: str
    ast_format: str


@dataclass(frozen=True)
class CompilerResult:
    status: AnalysisStatus
    provenance: CompilerProvenance | None
    source: str
    raw_ast: Any | None
    diagnostics: tuple[str, ...] = ()


@dataclass(frozen=True)
class CanonicalExpression:
    kind: str
    member: str = ""
    arguments: tuple[str, ...] = ()
    source_range: str = ""


@dataclass
class CanonicalFunction:
    name: str
    visibility: str = "public"
    modifiers: list[str] = field(default_factory=list)
    expressions: list[CanonicalExpression] = field(default_factory=list)
    source_range: str = ""

    @property
    def uses_selfdestruct(self) -> bool:
        return any(expression.kind == "destructive_operation" for expression in self.expressions)

    @property
    def uses_block_timestamp(self) -> bool:
        return any(expression.kind == "block_timestamp" for expression in self.expressions)

    @property
    def call_kinds(self) -> tuple[str, ...]:
        return tuple(expression.member for expression in self.expressions if expression.kind == "external_call")


@dataclass
class CanonicalContract:
    name: str
    kind: str = "contract"
    functions: list[CanonicalFunction] = field(default_factory=list)


@dataclass
class CanonicalProgram:
    contracts: list[CanonicalContract]
    provenance: CompilerProvenance
    adapter_version: str
    diagnostics: tuple[str, ...] = ()

    @property
    def function_count(self) -> int:
        return sum(len(contract.functions) for contract in self.contracts)

    def to_summary(self) -> dict[str, Any]:
        return {
            "contract_count": len(self.contracts),
            "function_count": self.function_count,
            "adapter_version": self.adapter_version,
            "provenance": {
                "compiler_version": self.provenance.compiler_version,
                "compiler_build": self.provenance.compiler_build,
                "compiler_binary_hash": self.provenance.compiler_binary_hash,
                "source_sha256": self.provenance.source_sha256,
                "raw_ast_sha256": self.provenance.raw_ast_sha256,
                "ast_format": self.provenance.ast_format,
            },
            "contracts": [
                {
                    "name": contract.name,
                    "functions": [
                        {
                            "name": function.name,
                            "uses_selfdestruct": function.uses_selfdestruct,
                            "uses_block_timestamp": function.uses_block_timestamp,
                            "call_kinds": list(function.call_kinds),
                            "expressions": [
                                {
                                    "kind": expression.kind,
                                    "member": expression.member,
                                    "source_range": expression.source_range,
                                }
                                for expression in function.expressions
                            ],
                        }
                        for function in contract.functions
                    ],
                }
                for contract in self.contracts
            ],
        }
