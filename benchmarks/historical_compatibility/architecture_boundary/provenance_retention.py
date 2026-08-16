"""Isolated Gate 3 provenance and artifact-retention contract.

The module persists a replayable, content-addressed evidence bundle. It is
intentionally not wired into production reporting or storage.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, is_dataclass
from enum import Enum
from pathlib import Path
from typing import Any

from ..canonical_ast_poc.canonical import CanonicalProgram, CompilerResult


@dataclass(frozen=True)
class RetentionPolicy:
    policy_version: str = "gate3-retention-v2"
    raw_ast_mode: str = "persisted-content-addressed"
    source_mode: str = "persisted-content-addressed"
    canonical_summary_mode: str = "persisted-content-addressed"
    finding_mode: str = "persisted-with-provenance"
    retention_days: int = 2555
    replay_guarantee: str = "hash-verified-artifact-replay"
    retention_semantics: str = "Persisted+Replayable"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class RetentionError(ValueError):
    """Raised when an evidence bundle cannot meet the Gate 3 contract."""


def _jsonable(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if is_dataclass(value):
        return _jsonable(asdict(value))
    if isinstance(value, dict):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(item) for item in value]
    return value


def _canonical_json(value: Any) -> bytes:
    return json.dumps(_jsonable(value), sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _source_set_hash(sources: dict[str, str]) -> str:
    return _sha256_bytes(_canonical_json({key: sources[key] for key in sorted(sources)}))


def _bundle_id(identity: dict[str, Any]) -> str:
    return _sha256_bytes(_canonical_json(identity))


def failure_provenance(
    status: str,
    diagnostics: list[str] | tuple[str, ...],
    *,
    sources: dict[str, str] | None = None,
    compiler_provenance: Any | None = None,
    adapter_version: str = "",
    canonical_ast_version: str = "",
    detector_version: str = "",
) -> dict[str, Any]:
    """Build a JSON-safe explanation for a failed or inconclusive stage."""
    normalized_sources = sources or {}
    source_manifest = [
        {"source_id": source_id, "source_sha256": _sha256_bytes(content.encode("utf-8"))}
        for source_id, content in sorted(normalized_sources.items())
    ]
    provenance = _jsonable(compiler_provenance) if compiler_provenance is not None else None
    return {
        "status": status,
        "diagnostics": list(diagnostics),
        "source_set_sha256": _source_set_hash(normalized_sources) if normalized_sources else "",
        "source_manifest": source_manifest,
        "compiler_provenance": provenance,
        "adapter_version": adapter_version,
        "canonical_ast_version": canonical_ast_version,
        "detector_version": detector_version,
        "failure_evidence_policy": "explicit-status-plus-provenance-v1",
    }


def _build_identity(
    result: CompilerResult,
    program: CanonicalProgram,
    analysis_payload: Any,
    policy: RetentionPolicy,
    canonical_summary_sha256: str,
    analysis_payload_sha256: str,
) -> dict[str, Any]:
    if result.provenance is None or result.raw_ast is None:
        raise RetentionError("A compiled result with raw AST and provenance is required")
    return {
        "source_set_sha256": _source_set_hash(result.sources),
        "compiler_version": result.provenance.compiler_version,
        "compiler_build": result.provenance.compiler_build,
        "compiler_binary_hash": result.provenance.compiler_binary_hash,
        "compiler_settings_sha256": result.provenance.compiler_settings_sha256,
        "raw_ast_sha256": result.provenance.raw_ast_sha256,
        "adapter_version": program.adapter_version,
        "canonical_ast_version": program.to_summary()["canonical_ast_version"],
        "canonical_summary_sha256": canonical_summary_sha256,
        "analysis_payload_sha256": analysis_payload_sha256,
        "retention_policy": policy.to_dict(),
        "analysis_payload": analysis_payload,
    }


def persist_analysis_bundle(
    result: CompilerResult,
    program: CanonicalProgram,
    analysis_payload: Any,
    artifact_root: Path,
    policy: RetentionPolicy = RetentionPolicy(),
) -> dict[str, Any]:
    """Persist replayable artifacts and the complete finding provenance chain."""
    if result.status.value != "Compiled" or result.provenance is None or result.raw_ast is None:
        raise RetentionError("Only a fully compiled result can produce a replayable bundle")
    if not result.sources:
        raise RetentionError("Source content is required for replayable retention")
    if not result.provenance.raw_ast_sha256:
        raise RetentionError("Raw AST hash is required for replayable retention")
    if policy.retention_semantics not in {"Persisted", "Replayable", "Persisted+Replayable", "Replay-limited"}:
        raise RetentionError(f"Unknown retention semantics: {policy.retention_semantics}")
    if policy.retention_semantics == "Replay-limited" and policy.replay_guarantee != "hash-verified-artifact-replay":
        raise RetentionError("Replay-limited retention must declare its replay guarantee")

    canonical_summary = _jsonable(program.to_summary())
    analysis_json = _jsonable(analysis_payload)
    canonical_summary_bytes = _canonical_json(canonical_summary)
    analysis_payload_bytes = _canonical_json(analysis_json)
    canonical_summary_hash = _sha256_bytes(canonical_summary_bytes)
    analysis_payload_hash = _sha256_bytes(analysis_payload_bytes)
    identity = _build_identity(
        result, program, analysis_json, policy, canonical_summary_hash, analysis_payload_hash
    )
    bundle_id = _bundle_id(identity)
    bundle_root = artifact_root / "bundles" / bundle_id
    source_root = bundle_root / "sources"
    raw_ast_root = bundle_root / "raw_ast"
    source_root.mkdir(parents=True, exist_ok=True)
    raw_ast_root.mkdir(parents=True, exist_ok=True)

    source_entries = []
    for source_id in sorted(result.sources):
        content_bytes = result.sources[source_id].encode("utf-8")
        content_hash = _sha256_bytes(content_bytes)
        relative_path = Path("sources") / f"{content_hash}.sol"
        (bundle_root / relative_path).write_bytes(content_bytes)
        source_entries.append(
            {
                "source_id": source_id,
                "content_sha256": content_hash,
                "artifact_path": str(relative_path),
                "byte_length": len(content_bytes),
            }
        )

    raw_ast_bytes = _canonical_json(result.raw_ast)
    raw_ast_hash = _sha256_bytes(raw_ast_bytes)
    if raw_ast_hash != result.provenance.raw_ast_sha256:
        raise RetentionError(
            f"Raw AST hash mismatch: provenance={result.provenance.raw_ast_sha256}, computed={raw_ast_hash}"
        )
    raw_ast_path = Path("raw_ast") / f"{raw_ast_hash}.json"
    (bundle_root / raw_ast_path).write_bytes(raw_ast_bytes + b"\n")
    canonical_path = Path("canonical_summary.json")
    analysis_path = Path("analysis_payload.json")
    (bundle_root / canonical_path).write_bytes(canonical_summary_bytes + b"\n")
    (bundle_root / analysis_path).write_bytes(analysis_payload_bytes + b"\n")

    manifest = {
        "schema_version": 2,
        "bundle_id": bundle_id,
        "bundle_identity": identity,
        "retention_policy": policy.to_dict(),
        "replay_status": "ReplayVerifiedPendingVerification",
        "source_set_sha256": _source_set_hash(result.sources),
        "source_manifest": source_entries,
        "compiler_provenance": _jsonable(result.provenance),
        "raw_ast": {
            "sha256": raw_ast_hash,
            "artifact_path": str(raw_ast_path),
            "format": result.provenance.ast_format,
        },
        "canonical_ast": {
            "version": canonical_summary["canonical_ast_version"],
            "adapter_version": program.adapter_version,
            "artifact": str(canonical_path),
            "sha256": canonical_summary_hash,
        },
        "analysis": analysis_json,
        "analysis_artifact": {
            "path": str(analysis_path),
            "sha256": analysis_payload_hash,
        },
    }
    (bundle_root / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    verification = verify_bundle(artifact_root, bundle_id)
    manifest["replay_status"] = verification["status"]
    manifest["verification"] = verification
    (bundle_root / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return manifest


def verify_bundle(artifact_root: Path, bundle_id: str) -> dict[str, Any]:
    """Verify the complete content-addressed bundle and provenance chain."""
    bundle_root = artifact_root / "bundles" / bundle_id
    manifest_path = bundle_root / "manifest.json"
    if not manifest_path.exists():
        return {"status": "ReplayVerificationFailed", "diagnostics": ["manifest.json is missing"]}
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return {"status": "ReplayVerificationFailed", "diagnostics": [f"manifest unreadable: {exc}"]}
    diagnostics: list[str] = []
    if manifest.get("bundle_id") != bundle_id:
        diagnostics.append("bundle id mismatch")

    identity = manifest.get("bundle_identity")
    if not isinstance(identity, dict) or _bundle_id(identity) != bundle_id:
        diagnostics.append("bundle identity hash mismatch")
    else:
        compiler = manifest.get("compiler_provenance", {})
        if identity.get("source_set_sha256") != manifest.get("source_set_sha256"):
            diagnostics.append("bundle identity source-set mismatch")
        if identity.get("compiler_version") != compiler.get("compiler_version"):
            diagnostics.append("compiler version provenance mismatch")
        if identity.get("compiler_build") != compiler.get("compiler_build"):
            diagnostics.append("compiler build provenance mismatch")
        if identity.get("compiler_binary_hash") != compiler.get("compiler_binary_hash"):
            diagnostics.append("compiler binary provenance mismatch")
        if identity.get("compiler_settings_sha256") != compiler.get("compiler_settings_sha256"):
            diagnostics.append("compiler settings provenance mismatch")

    source_hashes = []
    for entry in manifest.get("source_manifest", []):
        path = bundle_root / entry.get("artifact_path", "")
        if not path.exists():
            diagnostics.append(f"missing source artifact: {entry.get('source_id', '<unknown>')}")
            continue
        raw = path.read_bytes()
        actual = _sha256_bytes(raw)
        source_hashes.append((entry["source_id"], raw.decode("utf-8")))
        if actual != entry.get("content_sha256"):
            diagnostics.append(f"source hash mismatch: {entry.get('source_id', '<unknown>')}")
    if _source_set_hash(dict(source_hashes)) != manifest.get("source_set_sha256"):
        diagnostics.append("source set hash mismatch")

    raw_ast = manifest.get("raw_ast", {})
    raw_ast_path = bundle_root / raw_ast.get("artifact_path", "")
    if not raw_ast_path.exists():
        diagnostics.append("missing raw AST artifact")
    else:
        try:
            raw_ast_value = json.loads(raw_ast_path.read_text(encoding="utf-8"))
            if _sha256_bytes(_canonical_json(raw_ast_value)) != raw_ast.get("sha256"):
                diagnostics.append("raw AST hash mismatch")
        except (OSError, json.JSONDecodeError) as exc:
            diagnostics.append(f"raw AST unreadable: {exc}")

    canonical = manifest.get("canonical_ast", {})
    canonical_path = bundle_root / canonical.get("artifact", "")
    if not canonical_path.exists():
        diagnostics.append("missing canonical AST artifact")
    else:
        try:
            canonical_value = json.loads(canonical_path.read_text(encoding="utf-8"))
            canonical_hash = _sha256_bytes(_canonical_json(canonical_value))
            if canonical_hash != canonical.get("sha256"):
                diagnostics.append("canonical AST hash mismatch")
            if identity and identity.get("canonical_summary_sha256") != canonical_hash:
                diagnostics.append("bundle identity canonical AST mismatch")
            if identity and identity.get("adapter_version") != canonical.get("adapter_version"):
                diagnostics.append("adapter version provenance mismatch")
        except (OSError, json.JSONDecodeError) as exc:
            diagnostics.append(f"canonical AST unreadable: {exc}")

    analysis_artifact = manifest.get("analysis_artifact", {})
    analysis_path = bundle_root / analysis_artifact.get("path", "")
    if not analysis_path.exists():
        diagnostics.append("missing analysis payload artifact")
    else:
        try:
            analysis_value = json.loads(analysis_path.read_text(encoding="utf-8"))
            analysis_hash = _sha256_bytes(_canonical_json(analysis_value))
            if analysis_hash != analysis_artifact.get("sha256"):
                diagnostics.append("analysis payload hash mismatch")
            if _canonical_json(manifest.get("analysis", {})) != _canonical_json(analysis_value):
                diagnostics.append("manifest analysis payload mismatch")
            if identity and identity.get("analysis_payload_sha256") != analysis_hash:
                diagnostics.append("bundle identity analysis payload mismatch")
        except (OSError, json.JSONDecodeError) as exc:
            diagnostics.append(f"analysis payload unreadable: {exc}")

    status = "ReplayVerified" if not diagnostics else "ReplayVerificationFailed"
    return {"status": status, "bundle_id": bundle_id, "diagnostics": diagnostics}
