"""Resolved compiler-to-runner bridge for the isolated compatibility POC.

This module closes the Gate 2 orchestration gap without changing production
compiler invocation. A successful resolution is the only source of truth for
the compiler version passed to the runner, and the resulting CompilerResult is
checked against the selected candidate before it can be treated as usable.
"""

from __future__ import annotations

from .canonical import AnalysisStatus, CompilerResult
from .compiler import compile_source, compile_sources
from .compiler_resolution_policy import (
    CompilerCandidate,
    CompilerResolutionRequest,
    CompilerResolutionResult,
    ResolutionStatus,
    resolve_compiler,
)


def _require_selected(resolution: CompilerResolutionResult) -> str:
    if resolution.status != ResolutionStatus.RESOLVED or resolution.selected is None:
        raise ValueError(f"Compiler resolution is not usable: {resolution.status.value}")
    return resolution.selected.version


def compile_resolved_source(
    request: CompilerResolutionRequest,
    candidates: tuple[CompilerCandidate, ...],
) -> tuple[CompilerResolutionResult, CompilerResult]:
    """Resolve first, then compile with exactly the selected candidate."""
    resolution = resolve_compiler(request, candidates)
    version = _require_selected(resolution)
    result = compile_source(request.sources[request.entry_source_id], version, request.entry_source_id)
    if result.provenance is None or result.provenance.compiler_version != version:
        raise AssertionError("CompilerResult version does not match the resolved compiler candidate")
    if result.status != AnalysisStatus.COMPILED and result.raw_ast is not None:
        raise AssertionError("A failed compilation result must not expose a raw AST")
    return resolution, result


def compile_resolved_sources(
    request: CompilerResolutionRequest,
    candidates: tuple[CompilerCandidate, ...],
) -> tuple[CompilerResolutionResult, CompilerResult]:
    """Resolve first, then compile the complete source map with that version."""
    resolution = resolve_compiler(request, candidates)
    version = _require_selected(resolution)
    result = compile_sources(request.sources, version, request.entry_source_id)
    if result.provenance is None or result.provenance.compiler_version != version:
        raise AssertionError("CompilerResult version does not match the resolved compiler candidate")
    if result.status != AnalysisStatus.COMPILED and result.raw_ast is not None:
        raise AssertionError("A failed compilation result must not expose a raw AST")
    return resolution, result
