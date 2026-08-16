import json
from pathlib import Path

from benchmarks.historical_compatibility.architecture_boundary.provenance_retention import (
    RetentionError,
    RetentionPolicy,
    failure_provenance,
    persist_analysis_bundle,
    verify_bundle,
)
from benchmarks.historical_compatibility.canonical_ast_poc.canonical import AnalysisStatus
from benchmarks.historical_compatibility.canonical_ast_poc.compiler import compile_source, compile_sources
from benchmarks.historical_compatibility.canonical_ast_poc.compiler_resolution_policy import (
    CompilerCandidate,
    CompilerResolutionRequest,
    ResolutionStatus,
    resolve_compiler,
)
from benchmarks.historical_compatibility.canonical_ast_poc.detector_bridge import make_detector_input, run_detector
from benchmarks.historical_compatibility.canonical_ast_poc.modern_ast_adapter import adapt_modern


CANDIDATES = (
    CompilerCandidate("0.4.10", "/solc/0.4.10", True, "legacy"),
    CompilerCandidate("0.8.24", "/solc/0.8.24", True, "024"),
    CompilerCandidate("0.8.25", "/solc/0.8.25", True, "025"),
    CompilerCandidate("0.8.26", "/solc/0.8.26", True, "026"),
    CompilerCandidate("0.6.12", "/solc/0.6.12", False, "", support_status="unavailable"),
)


GATE1_FIXTURE_ROOT = Path(__file__).parents[1] / "benchmarks" / "historical_compatibility" / "canonical_ast_poc" / "fixtures"


def test_gate2_explicit_version_is_deterministic_and_pragma_checked():
    request = CompilerResolutionRequest(
        {"Main.sol": "pragma solidity ^0.8.25; contract Main {}"},
        "Main.sol",
        explicit_version="0.8.25",
    )
    result = resolve_compiler(request, CANDIDATES)
    assert result.status == ResolutionStatus.RESOLVED
    assert result.selected.version == "0.8.25"
    assert result.selection_reason == "explicit-version"

    conflict = resolve_compiler(
        CompilerResolutionRequest(
            {"Main.sol": "pragma solidity ^0.8.25; contract Main {}"},
            "Main.sol",
            explicit_version="0.4.10",
        ),
        CANDIDATES,
    )
    assert conflict.status == ResolutionStatus.PRAGMA_CONFLICT
    assert conflict.selected is None
    assert conflict.compatible_candidates == ()

    precedence_conflict = resolve_compiler(
        CompilerResolutionRequest(
            {"Main.sol": "pragma solidity ^0.8.25; contract Main {}"},
            "Main.sol",
            explicit_version="0.8.26",
            verified_version="0.8.25",
        ),
        CANDIDATES,
    )
    assert precedence_conflict.status == ResolutionStatus.VERSION_CONFLICT
    assert precedence_conflict.selected is None
    assert precedence_conflict.compatible_candidates == ()
    assert precedence_conflict.selection_reason == "explicit-verified-conflict"
    assert "no precedence" in precedence_conflict.diagnostics[0]

    agreement = resolve_compiler(
        CompilerResolutionRequest(
            {"Main.sol": "pragma solidity ^0.8.25; contract Main {}"},
            "Main.sol",
            explicit_version="0.8.25",
            verified_version="0.8.25",
        ),
        CANDIDATES,
    )
    assert agreement.status == ResolutionStatus.RESOLVED
    assert agreement.selection_reason == "explicit-and-verified-agree"


def test_gate2_multiple_candidates_are_not_guessed_without_explicit_policy():
    request = CompilerResolutionRequest(
        {"Main.sol": "pragma solidity >=0.8.0 <0.8.27; contract Main {}"},
        "Main.sol",
    )
    result = resolve_compiler(request, CANDIDATES)
    assert result.status == ResolutionStatus.AMBIGUOUS_CANDIDATES
    assert result.selected is None
    assert "0.8.25" in result.compatible_candidates
    assert "0.8.26" in result.compatible_candidates

    explicit_policy = CompilerResolutionRequest(
        request.sources,
        request.entry_source_id,
        allow_highest_compatible=True,
    )
    selected = resolve_compiler(explicit_policy, CANDIDATES)
    assert selected.status == ResolutionStatus.RESOLVED
    assert selected.selected.version == "0.8.26"
    assert selected.selection_reason == "highest-compatible-explicit-policy"


def test_gate2_failure_boundaries_are_explicit_and_source_set_hash_is_stable():
    no_pragma = resolve_compiler(
        CompilerResolutionRequest({"Main.sol": "contract Main {}"}, "Main.sol"),
        CANDIDATES,
    )
    assert no_pragma.status == ResolutionStatus.NO_PRAGMA_POLICY

    unavailable = resolve_compiler(
        CompilerResolutionRequest(
            {"Legacy.sol": "pragma solidity ^0.6.12; contract Legacy {}"},
            "Legacy.sol",
            explicit_version="0.6.12",
        ),
        CANDIDATES,
    )
    assert unavailable.status == ResolutionStatus.UNSUPPORTED_COMPILER

    conflicting = resolve_compiler(
        CompilerResolutionRequest(
            {"A.sol": "pragma solidity ^0.8.25; contract A {}", "B.sol": "pragma solidity ^0.4.10; contract B {}"},
            "A.sol",
        ),
        CANDIDATES,
    )
    assert conflicting.status == ResolutionStatus.PRAGMA_CONFLICT

    request_a = CompilerResolutionRequest({"A.sol": "pragma solidity ^0.8.25; contract A {}"}, "A.sol")
    request_b = CompilerResolutionRequest({"A.sol": "pragma solidity ^0.8.25; contract A {}"}, "A.sol")
    assert request_a.source_set_sha256 == request_b.source_set_sha256

    broken = compile_source("pragma solidity ^0.8.25; contract Broken { function { } }", "0.8.25", "Broken.sol")
    assert broken.status == AnalysisStatus.COMPILATION_FAILED


def test_gate2_multi_file_compilation_requires_resolution_then_compiles():
    sources = {
        "Lib.sol": "pragma solidity ^0.8.25; library Lib { function value() internal pure returns (uint256) { return 1; } }",
        "Main.sol": "pragma solidity ^0.8.25; import \"Lib.sol\"; contract Main { function read() public pure returns (uint256) { return Lib.value(); } }",
    }
    request = CompilerResolutionRequest(sources, "Main.sol", verified_version="0.8.25")
    result = resolve_compiler(request, CANDIDATES)
    assert result.status == ResolutionStatus.RESOLVED
    compiled = compile_sources(sources, "0.8.25", "Main.sol")
    assert compiled.status == AnalysisStatus.COMPILED
    assert sorted(compiled.raw_ast["source_units"]) == ["Lib.sol", "Main.sol"]


def test_gate3_persists_provenance_and_verifies_replay(tmp_path):
    sources = {
        "Lib.sol": (GATE1_FIXTURE_ROOT / "imported_lib_0_8_25.sol").read_text(encoding="utf-8"),
        "Main.sol": (GATE1_FIXTURE_ROOT / "imported_main_0_8_25.sol").read_text(encoding="utf-8"),
    }
    compiled = compile_sources(sources, "0.8.25", "Main.sol")
    assert compiled.status == AnalysisStatus.COMPILED
    program, metadata = adapt_modern(compiled)
    assert metadata["status"] == "CanonicalASTReady"
    detector = run_detector(
        make_detector_input(program, "Lib.sol", sources["Lib.sol"], sources),
        "Selfdestruct",
        "Lib.sol",
    )
    payload = {
        "status": detector["status"],
        "finding_count": detector["finding_count"],
        "findings": detector["findings"],
        "finding_provenance": detector["finding_provenance"],
        "comparator_results": detector["comparator_results"],
        "source_id": "Lib.sol",
    }
    manifest = persist_analysis_bundle(compiled, program, payload, tmp_path, RetentionPolicy(retention_days=7))
    assert manifest["retention_policy"]["raw_ast_mode"] == "persisted-content-addressed"
    assert manifest["compiler_provenance"]["compiler_version"] == "0.8.25"
    assert manifest["raw_ast"]["sha256"] == compiled.provenance.raw_ast_sha256
    assert manifest["analysis"]["source_id"] == "Lib.sol"
    assert manifest["verification"]["status"] == "ReplayVerified"
    assert verify_bundle(tmp_path, manifest["bundle_id"])["status"] == "ReplayVerified"

    source_artifact = tmp_path / "bundles" / manifest["bundle_id"] / manifest["source_manifest"][0]["artifact_path"]
    original = source_artifact.read_bytes()
    source_artifact.write_bytes(original + b"tampered")
    assert verify_bundle(tmp_path, manifest["bundle_id"])["status"] == "ReplayVerificationFailed"
    source_artifact.write_bytes(original)
    assert verify_bundle(tmp_path, manifest["bundle_id"])["status"] == "ReplayVerified"


def _build_gate3_bundle(tmp_path):
    sources = {
        "Lib.sol": (GATE1_FIXTURE_ROOT / "imported_lib_0_8_25.sol").read_text(encoding="utf-8"),
        "Main.sol": (GATE1_FIXTURE_ROOT / "imported_main_0_8_25.sol").read_text(encoding="utf-8"),
    }
    compiled = compile_sources(sources, "0.8.25", "Main.sol")
    assert compiled.status == AnalysisStatus.COMPILED
    program, _ = adapt_modern(compiled)
    detector = run_detector(
        make_detector_input(program, "Lib.sol", sources["Lib.sol"], sources),
        "Selfdestruct",
        "Lib.sol",
    )
    payload = {
        "status": detector["status"],
        "finding_count": detector["finding_count"],
        "findings": detector["findings"],
        "finding_provenance": detector["finding_provenance"],
        "comparator_results": detector["comparator_results"],
        "source_id": "Lib.sol",
    }
    manifest = persist_analysis_bundle(compiled, program, payload, tmp_path, RetentionPolicy(retention_days=7))
    return sources, compiled, program, payload, manifest


def test_gate3_finding_provenance_chain_is_complete(tmp_path):
    sources, compiled, _, _, manifest = _build_gate3_bundle(tmp_path)
    provenance = manifest["analysis"]["finding_provenance"][0]
    assert provenance["source_id"] == "Lib.sol"
    assert provenance["canonical_expression_id"].startswith("Lib.sol:")
    assert provenance["source_range"]
    assert provenance["source_sha256"] == next(
        item.source_sha256 for item in compiled.provenance.source_manifest if item.source_id == "Lib.sol"
    )
    assert provenance["raw_ast_hash"] == compiled.provenance.raw_ast_sha256
    assert provenance["compiler_version"] == "0.8.25"
    assert provenance["compiler_hash"] == compiled.provenance.compiler_binary_hash
    assert provenance["adapter_version"] == manifest["canonical_ast"]["adapter_version"]
    assert provenance["canonical_ast_version"] == manifest["canonical_ast"]["version"]
    assert provenance["source_id"] in [entry["source_id"] for entry in manifest["source_manifest"]]
    assert sources["Lib.sol"]


def test_gate3_tamper_matrix_detects_each_material_artifact(tmp_path):
    _, _, _, _, manifest = _build_gate3_bundle(tmp_path)
    root = tmp_path / "bundles" / manifest["bundle_id"]
    manifest_path = root / "manifest.json"
    original_manifest = manifest_path.read_text(encoding="utf-8")
    targets = {
        "source": root / manifest["source_manifest"][0]["artifact_path"],
        "raw_ast": root / manifest["raw_ast"]["artifact_path"],
        "canonical_ast": root / manifest["canonical_ast"]["artifact"],
        "analysis_payload": root / manifest["analysis_artifact"]["path"],
    }
    for name, path in targets.items():
        original = path.read_bytes()
        path.write_bytes(original + f"\n// {name} tamper\n".encode("utf-8"))
        assert verify_bundle(tmp_path, manifest["bundle_id"])["status"] == "ReplayVerificationFailed", name
        path.write_bytes(original)
        assert verify_bundle(tmp_path, manifest["bundle_id"])["status"] == "ReplayVerified", name

    for name, mutation in (
        ("manifest", lambda value: value.update({"compiler_provenance": {"compiler_version": "0.0.0"}})),
        ("compiler_metadata", lambda value: value["bundle_identity"].update({"compiler_binary_hash": "tampered"})),
        ("adapter_version", lambda value: value["bundle_identity"].update({"adapter_version": "tampered"})),
        ("finding_provenance", lambda value: value["analysis"].update({"finding_provenance": [{"source_id": "Main.sol"}]})),
    ):
        value = json.loads(original_manifest)
        mutation(value)
        manifest_path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        assert verify_bundle(tmp_path, manifest["bundle_id"])["status"] == "ReplayVerificationFailed", name
        manifest_path.write_text(original_manifest, encoding="utf-8")
        assert verify_bundle(tmp_path, manifest["bundle_id"])["status"] == "ReplayVerified", name


def test_gate3_failure_provenance_is_explicit_and_json_safe():
    statuses = (
        "CompilationFailed",
        "ASTUnavailable",
        "UnsupportedCompiler",
        "UnsupportedASTVersion",
        "ASTNormalizationFailed",
        "Inconclusive",
    )
    for status in statuses:
        evidence = failure_provenance(
            status,
            [f"diagnostic for {status}"],
            sources={"Lib.sol": "pragma solidity ^0.8.25; contract Lib {}"},
            compiler_provenance={"compiler_version": "0.8.25"},
            adapter_version="adapter-v2",
            canonical_ast_version="canonical-ast-poc-v2",
            detector_version="detector-v1",
        )
        assert evidence["status"] == status
        assert evidence["diagnostics"]
        assert evidence["source_set_sha256"]
        assert evidence["source_manifest"][0]["source_id"] == "Lib.sol"
        json.dumps(evidence)


def test_gate3_retention_semantics_reject_unknown_policy(tmp_path):
    sources = {
        "Lib.sol": (GATE1_FIXTURE_ROOT / "imported_lib_0_8_25.sol").read_text(encoding="utf-8"),
        "Main.sol": (GATE1_FIXTURE_ROOT / "imported_main_0_8_25.sol").read_text(encoding="utf-8"),
    }
    compiled = compile_sources(sources, "0.8.25", "Main.sol")
    assert compiled.status == AnalysisStatus.COMPILED
    program, _ = adapt_modern(compiled)
    payload = {"status": "AnalysisSucceededNoFindings", "finding_count": 0, "findings": []}
    try:
        persist_analysis_bundle(
            compiled,
            program,
            payload,
            tmp_path,
            RetentionPolicy(retention_semantics="Unknown"),
        )
    except RetentionError as exc:
        assert "Unknown retention semantics" in str(exc)
    else:
        raise AssertionError("unknown retention semantics must fail explicitly")
    assert sources["Lib.sol"]
