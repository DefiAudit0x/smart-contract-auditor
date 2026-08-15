from __future__ import annotations

from .adapters import adapt
from .canonical import AnalysisStatus, CompilerResult


def adapt_legacy(result: CompilerResult):
    if result.provenance and result.provenance.ast_format != "ast-json":
        return None, {
            "status": AnalysisStatus.UNSUPPORTED_AST_VERSION.value,
            "adapter_version": "canonical-poc-adapter-v1",
            "diagnostics": ["Legacy adapter received a non-legacy ast format"],
            "provenance": result.provenance.__dict__,
        }
    return adapt(result, "legacy")
