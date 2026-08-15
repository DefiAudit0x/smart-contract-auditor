from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import solcx
from solcx.exceptions import SolcError

from analyzers.solidity_analyzer import SolidityAnalyzer
from analyzers.solidity_ast import SOLC_VERSION
from verification.comparator import compare_finding

ROOT = Path(__file__).resolve().parent
VERSION_MAP = {
    "solidity_04": "0.4.11",
    "solidity_05": "0.5.17",
    "solidity_06": "0.6.12",
    "solidity_07": "0.7.6",
    "solidity_08": "0.8.25",
}


def _install(version: str) -> str | None:
    if version not in {str(item) for item in solcx.get_installed_solc_versions()}:
        try:
            solcx.install_solc(version, show_progress=False)
        except Exception as exc:
            return f"{type(exc).__name__}: {exc}"
    return None


def _walk_ast(value: Any, matches: list[str]) -> None:
    if isinstance(value, dict):
        name = value.get("name")
        member_name = value.get("memberName")
        attributes = value.get("attributes")
        attribute_value = attributes.get("value") if isinstance(attributes, dict) else None
        if isinstance(name, str) and name.lower() in {"selfdestruct", "suicide"}:
            matches.append(name.lower())
        if isinstance(member_name, str) and member_name.lower() in {"selfdestruct", "suicide"}:
            matches.append(member_name.lower())
        if isinstance(attribute_value, str) and attribute_value.lower() in {"selfdestruct", "suicide"}:
            matches.append(attribute_value.lower())
        for child in value.values():
            _walk_ast(child, matches)
    elif isinstance(value, list):
        for child in value:
            _walk_ast(child, matches)


def _historical_compile(source: str, version: str) -> dict[str, Any]:
    install_error = _install(version)
    if install_error:
        return {
            "compiler": version,
            "status": "compiler_unavailable",
            "error": install_error,
            "ast_keywords": [],
            "raw_ast_keywords": [],
        }
    try:
        compiled = solcx.compile_source(source, output_values=["ast"], solc_version=version)
        ast_keywords: list[str] = []
        for artifact in compiled.values():
            _walk_ast(artifact.get("ast", {}), ast_keywords)
        serialized_ast = json.dumps(compiled, sort_keys=True).lower()
        raw_ast_keywords = sorted({keyword for keyword in ("selfdestruct", "suicide") if keyword in serialized_ast})
        return {
            "compiler": version,
            "status": "compiled",
            "error": None,
            "ast_keywords": sorted(set(ast_keywords)),
            "raw_ast_keywords": raw_ast_keywords,
            "artifact_count": len(compiled),
        }
    except SolcError as exc:
        return {
            "compiler": version,
            "status": "compile_failed",
            "error": str(exc).splitlines()[-1][:400],
            "ast_keywords": [],
            "raw_ast_keywords": [],
        }
    except Exception as exc:
        return {
            "compiler": version,
            "status": "compile_failed",
            "error": f"{type(exc).__name__}: {exc}",
            "ast_keywords": [],
            "raw_ast_keywords": [],
        }


def _current_analyzer(path: Path) -> dict[str, Any]:
    source = path.read_text(encoding="utf-8")
    analyzer = SolidityAnalyzer()
    findings = analyzer.analyze_file(path.name, source)
    detectors = sorted({finding.agent_name for finding in findings})
    selfdestruct_findings = [finding for finding in findings if finding.agent_name == "Selfdestruct"]
    return {
        "analyzer_solc_version": SOLC_VERSION,
        "detectors": detectors,
        "selfdestruct_detector": bool(selfdestruct_findings),
        "finding_count": len(findings),
        "compiler_compatibility": not bool(re.search(r"pragma\s+solidity\s+\^?0\.[0-7]", source)),
    }


def _comparator(path: Path) -> dict[str, Any]:
    source = path.read_text(encoding="utf-8")
    finding = {
        "agent_name": "Selfdestruct",
        "severity": "Critical",
        "category": "Access Control",
        "file": path.name,
        "function_name": "destroy",
        "description": "Historical compatibility probe",
    }
    result = compare_finding(finding, source)
    return {
        "status": result.status.value,
        "reason": result.reason,
        "evidence": [
            {"kind": item.kind, "location": item.location, "excerpt": item.excerpt}
            for item in result.evidence
        ],
    }


def run() -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    for directory_name, compiler in VERSION_MAP.items():
        directory = ROOT / directory_name
        for path in sorted(directory.glob("*.sol")):
            historical = _historical_compile(path.read_text(encoding="utf-8"), compiler)
            analyzer = _current_analyzer(path)
            comparator = _comparator(path)
            rows.append({
                "version_family": directory_name,
                "fixture": path.name,
                "source": str(path.relative_to(ROOT)),
                "historical_compiler": historical,
                "current_analyzer": analyzer,
                "current_comparator": comparator,
            })
    return {
        "schema_version": 1,
        "measurement_only": True,
        "production_changes": [],
        "current_analyzer_solc": SOLC_VERSION,
        "compiler_matrix": list(VERSION_MAP.values()),
        "rows": rows,
    }


if __name__ == "__main__":
    output_path = ROOT / "metadata" / "selfdestruct_compatibility_measurement.json"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    report = run()
    output_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(output_path)
