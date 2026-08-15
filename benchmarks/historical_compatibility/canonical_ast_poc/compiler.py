from __future__ import annotations

import hashlib
import json
import re
import subprocess
from pathlib import Path
from typing import Any

from .canonical import AnalysisStatus, CompilerProvenance, CompilerResult, SourceManifestEntry


CANONICAL_COMPILER_SUPPORTED = {"0.4.10", "0.8.25"}
SOLC_BINARIES = {
    "0.4.10": Path.home() / ".solcx" / "solc-v0.4.10",
    "0.8.25": Path.home() / ".solcx" / "solc-v0.8.25",
}


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_text(value: str) -> str:
    return _sha256_bytes(value.encode("utf-8"))


def _canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _compiler_build(binary: Path) -> str:
    completed = subprocess.run(
        [str(binary), "--version"],
        check=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout.strip()


def _extract_json_ast(stdout: str) -> Any:
    start = stdout.find("{")
    if start < 0:
        raise ValueError("solc output did not contain a JSON AST object")
    decoder = json.JSONDecoder()
    value, _ = decoder.raw_decode(stdout[start:])
    return value


def _manifest(sources: dict[str, str]) -> tuple[SourceManifestEntry, ...]:
    return tuple(
        SourceManifestEntry(source_id=source_id, source_sha256=_sha256_text(sources[source_id]))
        for source_id in sorted(sources)
    )


def _source_set_hash(sources: dict[str, str]) -> str:
    return _sha256_bytes(_canonical_json({source_id: sources[source_id] for source_id in sorted(sources)}))


def _base_provenance(
    version: str,
    build: str,
    binary_hash: str,
    source_sha256: str,
    source_id: str,
    source_manifest: tuple[SourceManifestEntry, ...],
    ast_format: str,
    raw_ast_sha256: str = "",
    compiler_settings_sha256: str = "",
) -> CompilerProvenance:
    return CompilerProvenance(
        compiler_version=version,
        compiler_build=build,
        compiler_binary_hash=binary_hash,
        source_sha256=source_sha256,
        raw_ast_sha256=raw_ast_sha256,
        ast_format=ast_format,
        source_id=source_id,
        source_manifest=source_manifest,
        compiler_settings_sha256=compiler_settings_sha256,
    )


def _unsupported_result(source: str, version: str, source_id: str) -> CompilerResult:
    sources = {source_id: source}
    manifest = _manifest(sources)
    provenance = _base_provenance(
        version=version,
        build="",
        binary_hash="",
        source_sha256=_sha256_text(source),
        source_id=source_id,
        source_manifest=manifest,
        ast_format="unavailable",
    )
    return CompilerResult(
        status=AnalysisStatus.UNSUPPORTED_COMPILER,
        provenance=provenance,
        source=source,
        raw_ast=None,
        diagnostics=(f"No compiler binary is registered for requested version {version}",),
        sources=sources,
    )


def compile_source(source: str, version: str, source_id: str = "<stdin>") -> CompilerResult:
    """Compile one source using only the explicitly requested compiler version."""
    source_hash = _sha256_text(source)
    sources = {source_id: source}
    manifest = _manifest(sources)
    binary = SOLC_BINARIES.get(version)
    if binary is None or version not in CANONICAL_COMPILER_SUPPORTED:
        return _unsupported_result(source, version, source_id)
    if not binary.exists():
        return CompilerResult(
            status=AnalysisStatus.UNSUPPORTED_COMPILER,
            provenance=_base_provenance(version, "", "", source_hash, source_id, manifest, "unavailable"),
            source=source,
            raw_ast=None,
            diagnostics=(f"Requested compiler binary does not exist: {binary}",),
            sources=sources,
        )

    build = ""
    binary_hash = ""
    ast_format = "ast-json" if version == "0.4.10" else "ast-compact-json"
    try:
        build = _compiler_build(binary)
        binary_hash = _sha256_bytes(binary.read_bytes())
        ast_flag = "--ast-json" if version == "0.4.10" else "--ast-compact-json"
        completed = subprocess.run(
            [str(binary), ast_flag, "-"],
            input=source,
            check=False,
            capture_output=True,
            text=True,
        )
        provenance = _base_provenance(version, build, binary_hash, source_hash, source_id, manifest, ast_format)
        if completed.returncode != 0:
            diagnostics = tuple(line for line in completed.stderr.splitlines() if line.strip())
            return CompilerResult(
                status=AnalysisStatus.COMPILATION_FAILED,
                provenance=provenance,
                source=source,
                raw_ast=None,
                diagnostics=diagnostics or ("solc returned a non-zero exit code",),
                sources=sources,
            )

        raw_ast = _extract_json_ast(completed.stdout.strip())
        raw_hash = _sha256_bytes(_canonical_json(raw_ast))
        provenance = _base_provenance(
            version,
            build,
            binary_hash,
            source_hash,
            source_id,
            manifest,
            ast_format,
            raw_hash,
        )
        return CompilerResult(
            status=AnalysisStatus.COMPILED,
            provenance=provenance,
            source=source,
            raw_ast=raw_ast,
            sources=sources,
        )
    except json.JSONDecodeError as exc:
        return CompilerResult(
            status=AnalysisStatus.AST_UNAVAILABLE,
            provenance=_base_provenance(version, build, binary_hash, source_hash, source_id, manifest, ast_format),
            source=source,
            raw_ast=None,
            diagnostics=(f"solc output was not valid JSON: {exc}",),
            sources=sources,
        )
    except Exception as exc:
        return CompilerResult(
            status=AnalysisStatus.COMPILATION_FAILED,
            provenance=_base_provenance(version, build, binary_hash, source_hash, source_id, manifest, ast_format),
            source=source,
            raw_ast=None,
            diagnostics=(f"Compilation runner error: {exc}",),
            sources=sources,
        )


def _pragma_constraints(sources: dict[str, str]) -> dict[str, tuple[str, ...]]:
    return {
        source_id: tuple(re.findall(r"pragma\s+solidity\s+([^;]+);", source, flags=re.IGNORECASE))
        for source_id, source in sorted(sources.items())
    }


def compile_sources(
    sources: dict[str, str],
    version: str,
    entry_source_id: str,
) -> CompilerResult:
    """Compile a complete source map with solc standard-json and preserve source units."""
    if version != "0.8.25":
        source = sources.get(entry_source_id, "")
        return _unsupported_result(source, version, entry_source_id)
    if not sources or entry_source_id not in sources:
        return CompilerResult(
            status=AnalysisStatus.COMPILATION_FAILED,
            provenance=None,
            source=sources.get(entry_source_id, ""),
            raw_ast=None,
            diagnostics=("A non-empty source map and an entry source id are required",),
            sources=sources,
        )

    binary = SOLC_BINARIES[version]
    manifest = _manifest(sources)
    source_hash = _source_set_hash(sources)
    settings = {"outputSelection": {"*": {"": ["ast"]}}}
    settings_hash = _sha256_bytes(_canonical_json(settings))
    standard_input = {
        "language": "Solidity",
        "sources": {source_id: {"content": sources[source_id]} for source_id in sorted(sources)},
        "settings": settings,
    }
    source_view = sources[entry_source_id]
    build = ""
    binary_hash = ""
    ast_format = "standard-json-modern-ast"
    try:
        build = _compiler_build(binary)
        binary_hash = _sha256_bytes(binary.read_bytes())
        completed = subprocess.run(
            [str(binary), "--standard-json"],
            input=json.dumps(standard_input, sort_keys=True),
            check=False,
            capture_output=True,
            text=True,
        )
        provenance = _base_provenance(version, build, binary_hash, source_hash, entry_source_id, manifest, ast_format, compiler_settings_sha256=settings_hash)
        diagnostics: tuple[str, ...] = ()
        if completed.stderr.strip():
            diagnostics = tuple(line for line in completed.stderr.splitlines() if line.strip())
        if completed.returncode != 0:
            return CompilerResult(
                status=AnalysisStatus.COMPILATION_FAILED,
                provenance=provenance,
                source=source_view,
                raw_ast=None,
                diagnostics=diagnostics or ("solc standard-json returned a non-zero exit code",),
                sources=sources,
            )

        payload = json.loads(completed.stdout)
        structured_diagnostics = tuple(
            str(item.get("formattedMessage") or item.get("message") or item)
            for item in payload.get("errors", [])
        )
        errors = [item for item in payload.get("errors", []) if item.get("severity") == "error"]
        if errors:
            return CompilerResult(
                status=AnalysisStatus.COMPILATION_FAILED,
                provenance=provenance,
                source=source_view,
                raw_ast=None,
                diagnostics=structured_diagnostics or diagnostics or ("standard-json compilation failed",),
                sources=sources,
            )

        source_units = {
            source_id: item.get("ast")
            for source_id, item in payload.get("sources", {}).items()
            if isinstance(item, dict) and isinstance(item.get("ast"), dict)
        }
        if set(source_units) != set(sources):
            return CompilerResult(
                status=AnalysisStatus.AST_UNAVAILABLE,
                provenance=provenance,
                source=source_view,
                raw_ast=None,
                diagnostics=structured_diagnostics or ("standard-json did not return an AST for every source unit",),
                sources=sources,
            )

        raw_ast = {
            "schema": "standard-json-source-units-v1",
            "entry_source_id": entry_source_id,
            "pragma_constraints": _pragma_constraints(sources),
            "source_units": source_units,
        }
        raw_hash = _sha256_bytes(_canonical_json(raw_ast))
        provenance = _base_provenance(
            version,
            build,
            binary_hash,
            source_hash,
            entry_source_id,
            manifest,
            ast_format,
            raw_hash,
            settings_hash,
        )
        return CompilerResult(
            status=AnalysisStatus.COMPILED,
            provenance=provenance,
            source=source_view,
            raw_ast=raw_ast,
            diagnostics=structured_diagnostics or diagnostics,
            sources=sources,
        )
    except json.JSONDecodeError as exc:
        return CompilerResult(
            status=AnalysisStatus.AST_UNAVAILABLE,
            provenance=_base_provenance(version, build, binary_hash, source_hash, entry_source_id, manifest, ast_format, compiler_settings_sha256=settings_hash),
            source=source_view,
            raw_ast=None,
            diagnostics=(f"solc standard-json output was not valid JSON: {exc}",),
            sources=sources,
        )
    except Exception as exc:
        return CompilerResult(
            status=AnalysisStatus.COMPILATION_FAILED,
            provenance=_base_provenance(version, build, binary_hash, source_hash, entry_source_id, manifest, ast_format, compiler_settings_sha256=settings_hash),
            source=source_view,
            raw_ast=None,
            diagnostics=(f"Multi-file compilation runner error: {exc}",),
            sources=sources,
        )
