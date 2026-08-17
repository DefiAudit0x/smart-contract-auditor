"""Run the isolated Gate 2 compiler-resolution policy matrix."""

from __future__ import annotations

import json
from pathlib import Path

from ..canonical_ast_poc.compiler import compile_source, compile_sources
from ..canonical_ast_poc.compiler_resolution_policy import (
    CompilerCandidate,
    CompilerResolutionRequest,
    ResolutionStatus,
    resolve_compiler,
)


RESULT_PATH = Path(__file__).with_name("metadata") / "gate2_compiler_resolution_results.json"


CANDIDATES = (
    CompilerCandidate("0.4.10", str(Path.home() / ".solcx" / "solc-v0.4.10"), True, "legacy-binary-hash"),
    CompilerCandidate("0.8.24", "/poc/solc-v0.8.24", True, "candidate-0.8.24"),
    CompilerCandidate("0.8.25", str(Path.home() / ".solcx" / "solc-v0.8.25"), True, "modern-binary-hash"),
    CompilerCandidate("0.8.26", "/poc/solc-v0.8.26", True, "candidate-0.8.26"),
    CompilerCandidate("0.6.12", "/poc/solc-v0.6.12", False, "", support_status="registered-but-unavailable"),
)


def _resolution_case(name: str, request: CompilerResolutionRequest) -> dict[str, object]:
    result = resolve_compiler(request, CANDIDATES)
    return {
        "case": name,
        "kind": "resolution",
        "request": {
            "entry_source_id": request.entry_source_id,
            "explicit_version": request.explicit_version,
            "verified_version": request.verified_version,
            "allow_highest_compatible": request.allow_highest_compatible,
            "sources": request.sources,
        },
        "result": result.to_dict(),
    }


def _compile_after_resolution(
    request: CompilerResolutionRequest,
    resolution,
):
    """Compile only with the compiler selected by the resolution result."""
    assert resolution.status == ResolutionStatus.RESOLVED
    assert resolution.selected is not None
    version = resolution.selected.version
    if len(request.sources) == 1:
        source = request.sources[request.entry_source_id]
        compiled = compile_source(source, version, request.entry_source_id)
    else:
        compiled = compile_sources(request.sources, version, request.entry_source_id)
    if compiled.provenance is not None:
        assert compiled.provenance.compiler_version == version
    return compiled


def _compile_failure_case() -> dict[str, object]:
    source = "pragma solidity ^0.8.25; contract Broken { function { } }"
    request = CompilerResolutionRequest({"Broken.sol": source}, "Broken.sol", explicit_version="0.8.25")
    resolution = resolve_compiler(request, CANDIDATES)
    compiled = _compile_after_resolution(request, resolution)
    assert compiled.status.value == "CompilationFailed"
    assert compiled.raw_ast is None
    assert compiled.provenance is not None
    assert compiled.provenance.compiler_version == resolution.selected.version
    return {
        "case": "compiler_available_compilation_fails",
        "kind": "resolution_then_compilation",
        "resolution": resolution.to_dict(),
        "compilation": {
            "status": compiled.status.value,
            "raw_ast_present": compiled.raw_ast is not None,
            "diagnostics": list(compiled.diagnostics),
            "compiler_version": compiled.provenance.compiler_version,
            "compiler_hash": compiled.provenance.compiler_binary_hash,
            "bound_to_selected_version": compiled.provenance.compiler_version == resolution.selected.version,
        },
    }


def _multi_file_success_case() -> dict[str, object]:
    sources = {
        "Lib.sol": "pragma solidity ^0.8.25; library Lib { function value() internal pure returns (uint256) { return 1; } }",
        "Main.sol": "pragma solidity ^0.8.25; import \"Lib.sol\"; contract Main { function read() public pure returns (uint256) { return Lib.value(); } }",
    }
    request = CompilerResolutionRequest(sources, "Main.sol", verified_version="0.8.25")
    resolution = resolve_compiler(request, CANDIDATES)
    compiled = _compile_after_resolution(request, resolution)
    assert compiled.status.value == "Compiled"
    assert compiled.provenance is not None
    assert compiled.provenance.compiler_version == resolution.selected.version
    assert sorted(compiled.raw_ast["source_units"]) == ["Lib.sol", "Main.sol"]
    return {
        "case": "multi_file_same_pragma",
        "kind": "resolution_then_compilation",
        "resolution": resolution.to_dict(),
        "compilation": {
            "status": compiled.status.value,
            "compiler_version": compiled.provenance.compiler_version,
            "selected_version": resolution.selected.version,
            "bound_to_selected_version": compiled.provenance.compiler_version == resolution.selected.version,
            "source_units": sorted(compiled.raw_ast["source_units"]),
            "source_manifest": [entry.__dict__ for entry in compiled.provenance.source_manifest],
        },
    }


def main() -> int:
    results = [
        _resolution_case(
            "single_file_0_8_x_explicit",
            CompilerResolutionRequest({"Main.sol": "pragma solidity ^0.8.25; contract Main {}"}, "Main.sol", explicit_version="0.8.25"),
        ),
        _resolution_case(
            "single_file_0_4_x_explicit",
            CompilerResolutionRequest({"Legacy.sol": "pragma solidity ^0.4.10; contract Legacy {}"}, "Legacy.sol", explicit_version="0.4.10"),
        ),
        _resolution_case(
            "two_files_same_pragma",
            CompilerResolutionRequest(
                {"A.sol": "pragma solidity ^0.8.25; contract A {}", "B.sol": "pragma solidity ^0.8.25; contract B {}"},
                "A.sol",
                verified_version="0.8.25",
            ),
        ),
        _resolution_case(
            "partially_compatible_explicit_highest_policy",
            CompilerResolutionRequest(
                {"A.sol": "pragma solidity >=0.8.0 <0.8.27; contract A {}"},
                "A.sol",
                allow_highest_compatible=True,
            ),
        ),
        _resolution_case(
            "partially_compatible_without_explicit_policy",
            CompilerResolutionRequest(
                {"A.sol": "pragma solidity >=0.8.0 <0.8.27; contract A {}"},
                "A.sol",
            ),
        ),
        _resolution_case(
            "conflicting_pragmas",
            CompilerResolutionRequest(
                {"A.sol": "pragma solidity ^0.8.25; contract A {}", "B.sol": "pragma solidity ^0.4.10; contract B {}"},
                "A.sol",
            ),
        ),
        _resolution_case(
            "compiler_not_available",
            CompilerResolutionRequest(
                {"Legacy.sol": "pragma solidity ^0.6.12; contract Legacy {}"},
                "Legacy.sol",
                explicit_version="0.6.12",
            ),
        ),
        _resolution_case(
            "no_pragma_requires_policy",
            CompilerResolutionRequest({"NoPragma.sol": "contract NoPragma {}"}, "NoPragma.sol"),
        ),
        _resolution_case(
            "explicit_version_violates_pragma",
            CompilerResolutionRequest(
                {"Main.sol": "pragma solidity ^0.8.25; contract Main {}"},
                "Main.sol",
                explicit_version="0.4.10",
            ),
        ),
        _resolution_case(
            "verified_explicit_conflict",
            CompilerResolutionRequest(
                {"Main.sol": "pragma solidity ^0.8.25; contract Main {}"},
                "Main.sol",
                explicit_version="0.8.26",
                verified_version="0.8.25",
            ),
        ),
        _resolution_case(
            "verified_explicit_agreement",
            CompilerResolutionRequest(
                {"Main.sol": "pragma solidity ^0.8.25; contract Main {}"},
                "Main.sol",
                explicit_version="0.8.25",
                verified_version="0.8.25",
            ),
        ),
        _multi_file_success_case(),
        _compile_failure_case(),
    ]
    payload = {
        "schema_version": 2,
        "gate": "Gate2",
        "policy_version": "gate2-policy-v1",
        "no_compiler_guess": True,
        "no_silent_fallback": True,
        "resolution_compilation_binding": True,
        "compilation_failure_raw_ast_forbidden": True,
        "production_resolver_changed": False,
        "results": results,
    }
    RESULT_PATH.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
