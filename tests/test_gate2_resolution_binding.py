from benchmarks.historical_compatibility.architecture_boundary.run_gate2 import (
    CANDIDATES,
    _compile_after_resolution,
)
from benchmarks.historical_compatibility.canonical_ast_poc.canonical import AnalysisStatus
from benchmarks.historical_compatibility.canonical_ast_poc.compiler_resolution_policy import (
    CompilerResolutionRequest,
    ResolutionStatus,
    resolve_compiler,
)


def test_gate2_compilation_is_bound_to_selected_resolution():
    sources = {
        "Main.sol": "pragma solidity ^0.8.25; contract Main {}",
    }
    request = CompilerResolutionRequest(sources, "Main.sol", verified_version="0.8.25")
    resolution = resolve_compiler(request, CANDIDATES)
    assert resolution.status == ResolutionStatus.RESOLVED
    compiled = _compile_after_resolution(request, resolution)
    assert compiled.status == AnalysisStatus.COMPILED
    assert compiled.provenance is not None
    assert compiled.provenance.compiler_version == resolution.selected.version


def test_gate2_compilation_failure_cannot_expose_raw_ast():
    sources = {
        "Broken.sol": "pragma solidity ^0.8.25; contract Broken { function { } }",
    }
    request = CompilerResolutionRequest(sources, "Broken.sol", explicit_version="0.8.25")
    resolution = resolve_compiler(request, CANDIDATES)
    assert resolution.status == ResolutionStatus.RESOLVED
    compiled = _compile_after_resolution(request, resolution)
    assert compiled.status == AnalysisStatus.COMPILATION_FAILED
    assert compiled.raw_ast is None
    assert compiled.provenance is not None
    assert compiled.provenance.compiler_version == resolution.selected.version
