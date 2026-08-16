"""Run the isolated Gate 3 provenance/raw-AST retention matrix."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

from ..canonical_ast_poc.canonical import AnalysisStatus
from ..canonical_ast_poc.compiler import compile_sources
from ..canonical_ast_poc.detector_bridge import make_detector_input, run_detector
from ..canonical_ast_poc.modern_ast_adapter import adapt_modern
from .provenance_retention import RetentionPolicy, persist_analysis_bundle, verify_bundle


BASE_DIR = Path(__file__).parent
FIXTURE_ROOT = BASE_DIR.parent / "canonical_ast_poc" / "fixtures"
RESULT_PATH = BASE_DIR / "metadata" / "gate3_provenance_retention_results.json"
ARTIFACT_ROOT = BASE_DIR / "metadata" / "gate3_artifacts"


def main() -> int:
    sources = {
        "Lib.sol": (FIXTURE_ROOT / "imported_lib_0_8_25.sol").read_text(encoding="utf-8"),
        "Main.sol": (FIXTURE_ROOT / "imported_main_0_8_25.sol").read_text(encoding="utf-8"),
    }
    compiled = compile_sources(sources, "0.8.25", "Main.sol")
    assert compiled.status == AnalysisStatus.COMPILED, compiled.diagnostics
    program, adapter_metadata = adapt_modern(compiled)
    assert program is not None, adapter_metadata
    detector = run_detector(
        make_detector_input(program, "Lib.sol", sources["Lib.sol"], sources),
        "Selfdestruct",
        "Lib.sol",
    )
    assert detector["status"] == AnalysisStatus.ANALYSIS_SUCCEEDED_WITH_FINDINGS.value
    analysis_payload = {
        "status": detector["status"],
        "finding_count": detector["finding_count"],
        "findings": detector["findings"],
        "finding_provenance": detector["finding_provenance"],
        "comparator_results": detector["comparator_results"],
        "source_id": "Lib.sol",
    }

    if ARTIFACT_ROOT.exists():
        shutil.rmtree(ARTIFACT_ROOT)
    ARTIFACT_ROOT.mkdir(parents=True, exist_ok=True)
    manifest = persist_analysis_bundle(
        compiled,
        program,
        analysis_payload,
        ARTIFACT_ROOT,
        RetentionPolicy(),
    )
    bundle_id = manifest["bundle_id"]
    bundle_root = ARTIFACT_ROOT / "bundles" / bundle_id
    source_artifact = bundle_root / manifest["source_manifest"][0]["artifact_path"]
    original_source = source_artifact.read_bytes()
    source_artifact.write_bytes(original_source + b"\n// tamper probe\n")
    tampered_verification = verify_bundle(ARTIFACT_ROOT, bundle_id)
    source_artifact.write_bytes(original_source)
    final_verification = verify_bundle(ARTIFACT_ROOT, bundle_id)

    assert manifest["replay_status"] == "ReplayVerified"
    assert tampered_verification["status"] == "ReplayVerificationFailed"
    assert final_verification["status"] == "ReplayVerified"
    assert manifest["raw_ast"]["sha256"] == compiled.provenance.raw_ast_sha256
    assert manifest["source_manifest"]
    assert manifest["analysis"]["source_id"] == "Lib.sol"

    payload = {
        "schema_version": 1,
        "gate": "Gate3",
        "policy": manifest["retention_policy"],
        "production_storage_changed": False,
        "bundle": {
            "bundle_id": bundle_id,
            "manifest_path": str(bundle_root / "manifest.json"),
            "source_artifacts": [entry["artifact_path"] for entry in manifest["source_manifest"]],
            "raw_ast_artifact": manifest["raw_ast"]["artifact_path"],
            "canonical_summary_artifact": manifest["canonical_ast"]["artifact"],
            "source_set_sha256": manifest["source_set_sha256"],
            "raw_ast_sha256": manifest["raw_ast"]["sha256"],
            "compiler_version": manifest["compiler_provenance"]["compiler_version"],
            "compiler_binary_hash": manifest["compiler_provenance"]["compiler_binary_hash"],
            "compiler_settings_sha256": manifest["compiler_provenance"]["compiler_settings_sha256"],
            "adapter_version": manifest["canonical_ast"]["adapter_version"],
            "canonical_ast_version": manifest["canonical_ast"]["version"],
            "analysis_source_id": manifest["analysis"]["source_id"],
            "analysis_finding_count": manifest["analysis"]["finding_count"],
        },
        "verification": {
            "initial": manifest["verification"],
            "tampered": tampered_verification,
            "restored": final_verification,
        },
    }
    RESULT_PATH.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
