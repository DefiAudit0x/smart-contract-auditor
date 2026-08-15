from __future__ import annotations

from .adapters import adapt
from .canonical import AnalysisStatus, CompilerResult


def adapt_modern(result: CompilerResult):
    if result.provenance and result.provenance.ast_format != "ast-compact-json":
        return None, {
            "status": AnalysisStatus.UNSUPPORTED_AST_VERSION.value,
            "adapter_version": "canonical-poc-adapter-v1",
            "diagnostics": ["Modern adapter received a non-modern ast format"],
            "provenance": result.provenance.__dict__,
        }
    return adapt(result, "modern")
