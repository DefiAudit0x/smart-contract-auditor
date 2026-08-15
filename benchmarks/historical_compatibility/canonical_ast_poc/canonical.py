from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


CANONICAL_AST_VERSION = "canonical-ast-poc-v2"


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
class SourceManifestEntry:
    source_id: str
    source_sha256: str


@dataclass(frozen=True)
class CompilerProvenance:
    compiler_version: str
    compiler_build: str
    compiler_binary_hash: str
    source_sha256: str
    raw_ast_sha256: str
    ast_format: str
    source_id: str = ""
    source_manifest: tuple[SourceManifestEntry, ...] = ()
    compiler_settings_sha256: str = ""


@dataclass(frozen=True)
class CompilerResult:
    status: AnalysisStatus
    provenance: CompilerProvenance | None
    source: str
    raw_ast: Any | None
    diagnostics: tuple[str, ...] = ()
    sources: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class CanonicalExpression:
    kind: str
    member: str = ""
    arguments: tuple[str, ...] = ()
    source_range: str = ""
    expression_id: str = ""


@dataclass
class CanonicalFunction:
    name: str
    kind: str = "function"
    visibility: str = "public"
    state_mutability: str = "nonpayable"
    modifiers: list[str] = field(default_factory=list)
    parameters: list[str] = field(default_factory=list)
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
    modifiers: list[str] = field(default_factory=list)
    state_variables: list[str] = field(default_factory=list)
    source_range: str = ""


@dataclass
class CanonicalSourceUnit:
    source_id: str
    contracts: list[CanonicalContract] = field(default_factory=list)
    source_range: str = ""


@dataclass
class CanonicalProgram:
    source_units: list[CanonicalSourceUnit]
    provenance: CompilerProvenance
    adapter_version: str
    diagnostics: tuple[str, ...] = ()
    unknown_nodes: tuple[str, ...] = ()
    skipped_nodes: tuple[str, ...] = ()

    @property
    def contracts(self) -> list[CanonicalContract]:
        return [contract for unit in self.source_units for contract in unit.contracts]

    @property
    def function_count(self) -> int:
        return sum(len(contract.functions) for contract in self.contracts)

    def to_summary(self) -> dict[str, Any]:
        return {
            "canonical_ast_version": CANONICAL_AST_VERSION,
            "contract_count": len(self.contracts),
            "function_count": self.function_count,
            "adapter_version": self.adapter_version,
            "unknown_nodes": list(self.unknown_nodes),
            "skipped_nodes": list(self.skipped_nodes),
            "provenance": {
                **asdict(self.provenance),
                "source_manifest": [asdict(entry) for entry in self.provenance.source_manifest],
            },
            "source_units": [
                {
                    "source_id": unit.source_id,
                    "source_range": unit.source_range,
                    "contracts": [
                        {
                            "name": contract.name,
                            "kind": contract.kind,
                            "source_range": contract.source_range,
                            "functions": [
                                {
                                    "name": function.name,
                                    "kind": function.kind,
                                    "uses_selfdestruct": function.uses_selfdestruct,
                                    "uses_block_timestamp": function.uses_block_timestamp,
                                    "call_kinds": list(function.call_kinds),
                                    "source_range": function.source_range,
                                    "expressions": [asdict(expression) for expression in function.expressions],
                                }
                                for function in contract.functions
                            ],
                        }
                        for contract in unit.contracts
                    ],
                }
                for unit in self.source_units
            ],
        }


@dataclass(frozen=True)
class SourceView:
    source_id: str
    source_text: str
    source_sha256: str
    source_manifest: tuple[SourceManifestEntry, ...]


@dataclass(frozen=True)
class DetectorInput:
    canonical_program: CanonicalProgram
    source_view: SourceView
    detector_version: str


@dataclass(frozen=True)
class FindingProvenance:
    source_id: str
    source_manifest: tuple[SourceManifestEntry, ...]
    source_sha256: str
    compiler_version: str
    compiler_hash: str
    raw_ast_hash: str
    adapter_version: str
    canonical_ast_version: str
    detector_version: str
    comparator_version: str
    source_range: str
    evidence_kind: str
    canonical_expression_id: str


@dataclass
class AnalysisResult:
    status: AnalysisStatus
    findings: list[Any] = field(default_factory=list)
    finding_provenance: list[FindingProvenance] = field(default_factory=list)
    diagnostics: list[str] = field(default_factory=list)
    provenance: CompilerProvenance | None = None
    adapter_version: str = ""
    canonical_ast_version: str = CANONICAL_AST_VERSION
    detector_version: str = ""
    comparator_version: str = ""
    comparator_results: list[Any] = field(default_factory=list)
