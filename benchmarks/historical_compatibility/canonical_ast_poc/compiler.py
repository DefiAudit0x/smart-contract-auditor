from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path
from typing import Any

from .canonical import AnalysisStatus, CompilerProvenance, CompilerResult


REPO_ROOT = Path(__file__).resolve().parents[3]
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


def compile_source(source: str, version: str) -> CompilerResult:
    """Compile only with the explicitly requested compiler version."""
    source_hash = _sha256_text(source)
    binary = SOLC_BINARIES.get(version)
    if binary is None:
        return CompilerResult(
            status=AnalysisStatus.UNSUPPORTED_COMPILER,
            provenance=None,
            source=source,
            raw_ast=None,
            diagnostics=(f"No compiler binary is registered for requested version {version}",),
        )
    if not binary.exists():
        return CompilerResult(
            status=AnalysisStatus.UNSUPPORTED_COMPILER,
            provenance=None,
            source=source,
            raw_ast=None,
            diagnostics=(f"Requested compiler binary does not exist: {binary}",),
        )

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
        if completed.returncode != 0:
            diagnostics = tuple(line for line in completed.stderr.splitlines() if line.strip())
            provenance = CompilerProvenance(
                compiler_version=version,
                compiler_build=build,
                compiler_binary_hash=binary_hash,
                source_sha256=source_hash,
                raw_ast_sha256="",
                ast_format="ast-json" if version == "0.4.10" else "ast-compact-json",
            )
            return CompilerResult(
                status=AnalysisStatus.COMPILATION_FAILED,
                provenance=provenance,
                source=source,
                raw_ast=None,
                diagnostics=diagnostics or ("solc returned a non-zero exit code",),
            )

        payload = completed.stdout.strip()
        raw_ast = _extract_json_ast(payload)

        raw_hash = _sha256_bytes(_canonical_json(raw_ast))
        provenance = CompilerProvenance(
            compiler_version=version,
            compiler_build=build,
            compiler_binary_hash=binary_hash,
            source_sha256=source_hash,
            raw_ast_sha256=raw_hash,
            ast_format="ast-json" if version == "0.4.10" else "ast-compact-json",
        )
        return CompilerResult(
            status=AnalysisStatus.COMPILED,
            provenance=provenance,
            source=source,
            raw_ast=raw_ast,
        )
    except json.JSONDecodeError as exc:
        return CompilerResult(
            status=AnalysisStatus.AST_UNAVAILABLE,
            provenance=None,
            source=source,
            raw_ast=None,
            diagnostics=(f"solc output was not valid JSON: {exc}",),
        )
    except Exception as exc:
        return CompilerResult(
            status=AnalysisStatus.COMPILATION_FAILED,
            provenance=None,
            source=source,
            raw_ast=None,
            diagnostics=(f"Compilation runner error: {exc}",),
        )
