from __future__ import annotations

import argparse
import json
from dataclasses import asdict
from pathlib import Path
from typing import Any

from analyzers.solidity_analyzer import SolidityAnalyzer

from .canonical_ast_poc.canonical import AnalysisStatus
from .canonical_ast_poc.compiler import compile_source
from .canonical_ast_poc.detector_bridge import make_detector_input, run_detector
from .canonical_ast_poc.legacy_ast_adapter import adapt_legacy
from .canonical_ast_poc.modern_ast_adapter import adapt_modern


SUPPORTED = {"0.4.10": adapt_legacy, "0.8.25": adapt_modern}


def _baseline(source_id: str, source: str) -> dict[str, Any]:
    analyzer = SolidityAnalyzer()
    findings = analyzer.analyze_file(source_id, source)
    selfdestruct = [item for item in findings if item.agent_name == "Selfdestruct"]
    return {
        "status": "AnalysisSucceededWithFindings" if selfdestruct else "AnalysisSucceededNoFindings",
        "finding_count": len(selfdestruct),
        "findings": [asdict(item) for item in selfdestruct],
        "agent_errors": list(analyzer._agent_errors),
        "path": "existing-production-analyzer",
    }


def _canonical(source_id: str, source: str, compiler_version: str) -> dict[str, Any]:
    adapter = SUPPORTED.get(compiler_version)
    if adapter is None:
        raise ValueError(f"Unsupported Stage 1 compiler version: {compiler_version}")

    compiled = compile_source(source, compiler_version, source_id)
    result: dict[str, Any] = {
        "compiler_status": compiled.status.value,
        "compiler_version": compiler_version,
        "diagnostics": list(compiled.diagnostics),
        "path": "canonical-ast-shadow",
    }
    if compiled.status != AnalysisStatus.COMPILED:
        result["status"] = compiled.status.value
        result["finding_count"] = 0
        return result

    program, metadata = adapter(compiled)
    result["canonical_status"] = metadata["status"]
    if metadata["status"] != "CanonicalASTReady":
        result["status"] = metadata["status"]
        result["finding_count"] = 0
        return result

    detector_input = make_detector_input(program, source_id, source, {source_id: source})
    detection = run_detector(detector_input, "Selfdestruct", source_id)
    result.update(
        {
            "status": detection["status"],
            "finding_count": detection["finding_count"],
            "findings": detection["findings"],
            "finding_provenance": detection["finding_provenance"],
            "comparator_results": detection["comparator_results"],
            "detector_input_contract": detection["detector_input_contract"],
        }
    )
    return result


def run_shadow(source_id: str, source: str, compiler_version: str) -> dict[str, Any]:
    """Run production and canonical Selfdestruct paths without changing production decisions."""
    baseline = _baseline(source_id, source)
    canonical = _canonical(source_id, source, compiler_version)
    baseline_count = baseline["finding_count"]
    canonical_count = canonical.get("finding_count", 0)
    return {
        "mode": "shadow-only",
        "decision_effect": "none",
        "detector_family": "Selfdestruct",
        "source_id": source_id,
        "compiler_version": compiler_version,
        "baseline": baseline,
        "canonical": canonical,
        "comparison": {
            "baseline_finding_count": baseline_count,
            "canonical_finding_count": canonical_count,
            "finding_count_equal": baseline_count == canonical_count,
            "divergence": baseline_count != canonical_count,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Run Stage 1 Selfdestruct shadow comparison")
    parser.add_argument("source", type=Path)
    parser.add_argument("--compiler-version", required=True, choices=sorted(SUPPORTED))
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    source = args.source.read_text(encoding="utf-8")
    result = run_shadow(args.source.name, source, args.compiler_version)
    payload = json.dumps(result, indent=2, sort_keys=True)
    if args.output:
        args.output.write_text(payload + "\n", encoding="utf-8")
    else:
        print(payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
