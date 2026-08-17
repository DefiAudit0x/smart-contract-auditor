from benchmarks.historical_compatibility.canonical_ast_poc.canonical import AnalysisStatus
from benchmarks.historical_compatibility.canonical_ast_poc.compiler_resolution_policy import (
    CompilerCandidate,
    CompilerResolutionRequest,
    ResolutionStatus,
)
from benchmarks.historical_compatibility.canonical_ast_poc.resolved_compiler_runner import (
    compile_resolved_source,
    compile_resolved_sources,
)


CANDIDATES = (
    CompilerCandidate("0.4.10", "/solc/0.4.10", True, "legacy"),
    CompilerCandidate("0.8.25", "/solc/0.8.25", True, "025"),
)


def test_gate2_resolution_selected_version_drives_single_file_compilation():
    request = CompilerResolutionRequest(
        {"Main.sol": "pragma solidity ^0.8.25; contract Main {}"},
        "Main.sol",
        explicit_version="0.8.25",
    )
    resolution, compiled = compile_resolved_source(request, CANDIDATES)
    assert resolution.status == ResolutionStatus.RESOLVED
    assert resolution.selected.version == "0.8.25"
    assert compiled.status == AnalysisStatus.COMPILED
    assert compiled.provenance.compiler_version == resolution.selected.version
    assert compiled.raw_ast is not None


def test_gate2_resolution_selected_version_drives_multi_file_compilation():
    sources = {
        "Lib.sol": "pragma solidity ^0.8.25; library Lib { function value() internal pure returns (uint256) { return 1; } }",
        "Main.sol": "pragma solidity ^0.8.25; import \"Lib.sol\"; contract Main { function read() public pure returns (uint256) { return Lib.value(); } }",
    }
    request = CompilerResolutionRequest(sources, "Main.sol", verified_version="0.8.25")
    resolution, compiled = compile_resolved_sources(request, CANDIDATES)
    assert resolution.status == ResolutionStatus.RESOLVED
    assert compiled.status == AnalysisStatus.COMPILED
    assert compiled.provenance.compiler_version == resolution.selected.version
    assert sorted(compiled.raw_ast["source_units"]) == ["Lib.sol", "Main.sol"]


def test_gate2_compilation_failure_is_fail_closed_before_ast_normalization():
    request = CompilerResolutionRequest(
        {"Broken.sol": "pragma solidity ^0.8.25; contract Broken { function { } }"},
        "Broken.sol",
        explicit_version="0.8.25",
    )
    resolution, compiled = compile_resolved_source(request, CANDIDATES)
    assert resolution.status == ResolutionStatus.RESOLVED
    assert compiled.status == AnalysisStatus.COMPILATION_FAILED
    assert compiled.raw_ast is None
    assert compiled.provenance.compiler_version == resolution.selected.version
    assert compiled.diagnostics
