from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path
from typing import Any

import solcx
from solcx.exceptions import SolcError
from solcast import from_ast

from analyzers.solidity_ast import SOLC_VERSION, analyze_contracts, compile_to_ast

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "architecture_boundary" / "metadata"
PARITY_SOURCE = ROOT.parent / "real_world" / "source_snapshots" / "parity" / "WalletLibrary.sol"
MODERN_SOURCE = ROOT / "modern_selfdestruct.sol"
MINIMAL_SOURCE = ROOT / "architecture_boundary" / "minimal_suicide_0_4_11.sol"


def _tokens(value: Any, found: set[str]) -> None:
    if isinstance(value, dict):
        for key in ("memberName", "member_name"):
            item = value.get(key)
            if isinstance(item, str):
                found.add(item.lower())
        attrs = value.get("attributes")
        if isinstance(attrs, dict):
            item = attrs.get("value")
            if isinstance(item, str):
                found.add(item.lower())
        if isinstance(value.get("nodeType"), str):
            for key in ("name", "memberName"):
                item = value.get(key)
                if isinstance(item, str):
                    found.add(item.lower())
        for child in value.values():
            _tokens(child, found)
    elif isinstance(value, list):
        for child in value:
            _tokens(child, found)


def _extract_asts(compiled: dict[str, Any]) -> list[dict[str, Any]]:
    sources = compiled.get("sources")
    if isinstance(sources, dict):
        return [entry.get("AST") for entry in sources.values() if isinstance(entry, dict) and entry.get("AST")]
    artifacts = compiled.get("contracts") if isinstance(compiled.get("contracts"), dict) else compiled
    return [artifact.get("ast", {}) for artifact in artifacts.values() if isinstance(artifact, dict) and artifact.get("ast")]


def compile_raw(source: str, version: str) -> dict[str, Any]:
    try:
        if version in {"0.4.10", "0.4.11"}:
            binary = f"/home/ubuntu/.solcx/solc-v{version}"
            process = subprocess.run(
                [binary, "--combined-json", "ast", "-"],
                input=source,
                text=True,
                capture_output=True,
                check=False,
            )
            if process.returncode != 0:
                return {
                    "status": "compile_failed",
                    "compiler": version,
                    "error": process.stderr.splitlines()[-1][:500] if process.stderr else f"exit {process.returncode}",
                    "ast_objects": [],
                }
            compiled = json.loads(process.stdout)
        else:
            compiled = solcx.compile_source(source, output_values=["ast"], solc_version=version)
        asts = _extract_asts(compiled)
        found: set[str] = set()
        _tokens(asts, found)
        return {
            "status": "compiled",
            "compiler": version,
            "artifact_count": len(asts),
            "raw_ast_tokens": sorted(token for token in found if token in {"suicide", "selfdestruct", "delegatecall"}),
            "ast_objects": asts,
        }
    except SolcError as exc:
        return {
            "status": "compile_failed",
            "compiler": version,
            "error": str(exc).splitlines()[-1][:500],
            "ast_objects": [],
        }
    except Exception as exc:
        return {
            "status": "compile_failed",
            "compiler": version,
            "error": f"{type(exc).__name__}: {exc}",
            "ast_objects": [],
        }


def normalize_historical_ast(raw: dict[str, Any]) -> dict[str, Any]:
    if raw["status"] != "compiled":
        return {"status": "not_run", "error": "raw AST unavailable"}
    try:
        converted = [from_ast(ast) for ast in raw["ast_objects"]]
        if any(isinstance(item, dict) for item in converted):
            return {
                "status": "incompatible_normalizer_container",
                "output_types": [type(item).__name__ for item in converted],
                "dict_keys": [sorted(item.keys()) for item in converted if isinstance(item, dict)],
                "contract_count": 0,
                "function_count": 0,
            }
        contracts = []
        for unit in converted:
            contracts.extend(analyze_contracts(unit))
        functions = [function for contract in contracts for function in contract.functions]
        return {
            "status": "normalized_from_historical_raw_ast",
            "contract_count": len(contracts),
            "function_count": len(functions),
            "signals": {
                "uses_selfdestruct": any(function.uses_selfdestruct for function in functions),
                "uses_delegatecall": any(function.uses_delegatecall for function in functions),
                "uses_block_timestamp": any(function.uses_block_timestamp for function in functions),
            },
        }
    except Exception as exc:
        return {
            "status": "normalization_failed",
            "error": f"{type(exc).__name__}: {exc}",
        }


def current_pipeline_normalizer(source: str) -> dict[str, Any]:
    try:
        units = compile_to_ast(source)
        if not units:
            return {"status": "compile_failed_under_current_path", "compiler": SOLC_VERSION}
        contracts = analyze_contracts(units)
        functions = [function for contract in contracts for function in contract.functions]
        return {
            "status": "normalized_under_current_path",
            "compiler": SOLC_VERSION,
            "contract_count": len(contracts),
            "function_count": len(functions),
            "signals": {
                "uses_selfdestruct": any(function.uses_selfdestruct for function in functions),
                "uses_delegatecall": any(function.uses_delegatecall for function in functions),
                "uses_block_timestamp": any(function.uses_block_timestamp for function in functions),
            },
        }
    except Exception as exc:
        return {
            "status": "normalization_failed_under_current_path",
            "compiler": SOLC_VERSION,
            "error": f"{type(exc).__name__}: {exc}",
        }


def row(label: str, source_path: Path, source: str, historical_version: str | None) -> dict[str, Any]:
    raw = compile_raw(source, historical_version) if historical_version else {"status": "not_run"}
    normalized_historical = normalize_historical_ast(raw) if historical_version else {"status": "not_run"}
    current = current_pipeline_normalizer(source)
    return {
        "label": label,
        "source": str(source_path.relative_to(ROOT.parent.parent)),
        "source_sha256": hashlib.sha256(source.encode("utf-8")).hexdigest(),
        "historical_raw_ast": {key: value for key, value in raw.items() if key != "ast_objects"},
        "normalizer_on_historical_raw_ast": normalized_historical,
        "current_pipeline_compile_to_ast": current,
    }


parity_source = PARITY_SOURCE.read_text(encoding="utf-8")
modern_source = MODERN_SOURCE.read_text(encoding="utf-8")
minimal_source = MINIMAL_SOURCE.read_text(encoding="utf-8")
report = {
    "schema_version": 1,
    "read_only_architecture_investigation": True,
    "production_changes": [],
    "current_normalizer_compiler": SOLC_VERSION,
    "rows": [
        row("parity_suicide_solc_0_4_10", PARITY_SOURCE, parity_source, "0.4.10"),
        row("parity_suicide_solc_0_4_11", PARITY_SOURCE, parity_source, "0.4.11"),
        row("minimal_suicide_solc_0_4_11", MINIMAL_SOURCE, minimal_source, "0.4.11"),
        row("parity_suicide_current_0_8_25_path", PARITY_SOURCE, parity_source, None),
        row("modern_selfdestruct_solc_0_8_25", MODERN_SOURCE, modern_source, "0.8.25"),
    ],
}
OUT.mkdir(parents=True, exist_ok=True)
(OUT / "compiler_ast_boundary_experiment.json").write_text(
    json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
)
print(OUT / "compiler_ast_boundary_experiment.json")
