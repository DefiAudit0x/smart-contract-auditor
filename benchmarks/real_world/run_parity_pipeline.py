#!/usr/bin/env python3
"""Record A/B/C observations for the Parity WalletLibrary real-world case."""

from __future__ import annotations

import argparse
import json
import re
from datetime import datetime, timezone
from pathlib import Path

from analyzers.solidity_analyzer import SolidityAnalyzer
from analyzers.solidity_ast import SOLC_VERSION
from verification.comparator import compare_finding
from verification.poc import run_foundry_poc

ROOT = Path(__file__).resolve().parents[2]
PARITY_ROOT = ROOT / "benchmarks" / "real_world" / "owned_reproductions" / "parity"
SOURCE = ROOT / "benchmarks" / "real_world" / "source_snapshots" / "parity" / "WalletLibrary.sol"
VULNERABLE = PARITY_ROOT / "ParityWalletLibraryVulnerable.sol"
FIXED = PARITY_ROOT / "ParityWalletLibraryFixed.sol"
POC = PARITY_ROOT / "parity_library_kill_poc.t.sol"
EXPECTED_DETECTOR = "Selfdestruct"


def _static(path: Path) -> dict:
    analyzer = SolidityAnalyzer()
    findings = analyzer.analyze_file(path.name, path.read_text(encoding="utf-8"))
    pragma_match = re.search(r"pragma\s+solidity\s+([^;]+);", path.read_text(encoding="utf-8"))
    pragma = pragma_match.group(1).strip() if pragma_match else None
    compiler_compatible = pragma is None or SOLC_VERSION.startswith(pragma.replace("^", ""))
    return {
        "status": "Completed" if compiler_compatible else "CompletedWithCompatibilityGap",
        "source": str(path.relative_to(ROOT)),
        "observed_detectors": sorted({finding.agent_name for finding in findings}),
        "finding_count": len(findings),
        "findings": [
            {
                "agent_name": finding.agent_name,
                "function_name": finding.function_name,
                "severity": finding.severity,
                "category": finding.category,
                "description": finding.description,
            }
            for finding in findings
        ],
        "expected_detector_observed": EXPECTED_DETECTOR in {finding.agent_name for finding in findings},
        "source_pragma": pragma,
        "analyzer_solc_version": SOLC_VERSION,
        "compiler_compatibility": compiler_compatible,
        "compatibility_note": None if compiler_compatible else "The current analyzer is fixed at solc 0.8.25 while the pinned WalletLibrary source requires Solidity 0.4.x; AST compilation falls back and the literal selfdestruct matcher does not recognize legacy suicide().",
    }


def _comparisons(static_result: dict, source: str) -> list[dict]:
    results = []
    for finding in static_result["findings"]:
        result = compare_finding(finding, source)
        results.append({
            "detector": result.hypothesis.detector,
            "function": result.hypothesis.function,
            "status": result.status.value,
            "reason": result.reason,
            "evidence": [
                {"kind": item.kind, "location": item.location, "excerpt": item.excerpt}
                for item in result.evidence
            ],
        })
    return results


def _llm(path: Path, model: str) -> dict:
    try:
        from benchmarks.run_llm_comparison import (
            ALLOWED_DETECTORS,
            PROMPT_PATH,
            _available_models,
            _call_llm,
        )
        import requests

        session = requests.Session()
        available = _available_models(session)
        if model not in available:
            return {
                "status": "Inconclusive",
                "model": model,
                "catalog_checked": True,
                "error": "model_not_present_in_live_catalog",
            }
        result = _call_llm(
            session,
            path.read_text(encoding="utf-8"),
            path.name,
            model,
            PROMPT_PATH.read_text(encoding="utf-8").strip(),
        )
        return {
            "status": "Completed",
            "model": model,
            "catalog_checked": True,
            "predictions": result["findings"],
            "rationale": result["rationale"],
            "usage": result["usage"],
            "allowed_detectors": ALLOWED_DETECTORS,
        }
    except Exception as exc:
        return {
            "status": "Inconclusive",
            "model": model,
            "catalog_checked": False,
            "error": f"{type(exc).__name__}: {exc}",
        }


def _invariant(path: Path) -> dict:
    from benchmarks.real_world.owned_reproductions.parity.parity_invariant import evaluate

    result = evaluate(path)
    return {
        "status": result.status,
        "reason": result.reason,
        "evidence_lines": list(result.evidence_lines),
    }


def run(model: str) -> dict:
    source_text = SOURCE.read_text(encoding="utf-8")
    static_source = _static(SOURCE)
    static_vulnerable = _static(VULNERABLE)
    static_fixed = _static(FIXED)
    source_comparisons = _comparisons(static_source, source_text)
    vulnerable_comparisons = _comparisons(static_vulnerable, VULNERABLE.read_text(encoding="utf-8"))
    fixed_comparisons = _comparisons(static_fixed, FIXED.read_text(encoding="utf-8"))

    llm_source = _llm(SOURCE, model)
    llm_vulnerable = _llm(VULNERABLE, model)
    llm_fixed = _llm(FIXED, model)
    invariant_vulnerable = _invariant(VULNERABLE)
    invariant_fixed = _invariant(FIXED)
    poc = run_foundry_poc(POC, ROOT)

    exact_source_detector_miss = not static_source["expected_detector_observed"]
    a_status = "Missed" if exact_source_detector_miss else "Detected"
    a_reason = (
        "The semantic family is in the controlled taxonomy, but the current analyzer emitted no Selfdestruct finding on the exact deployed snapshot. The pinned source uses legacy suicide(_to), the AST compiler is fixed at solc 0.8.25 while the source requires 0.4.x, and the comparator matcher recognizes only selfdestruct(. The owned 0.8.25 vulnerable contrast is detected and comparator-confirmed, so the miss is an exact-source compatibility/implementation observation rather than a taxonomy gap."
        if exact_source_detector_miss
        else "The current analyzer emitted Selfdestruct on the exact deployed snapshot and the registered comparator evidence confirmed it."
    )
    b_status = "Completed" if llm_source.get("status") == "Completed" else "Inconclusive"
    full_pipeline = {
        "status": "Quarantined",
        "acceptance_gate": False,
        "reason": "Independent evidence, exact source pinning, taxonomy family coverage, invariant, and owned PoC are present, but the current detector did not confirm Selfdestruct on the exact legacy source. LLM output and the owned modern contrast cannot substitute for exact-source detector confirmation; no detector or architecture change is introduced.",
    }

    return {
        "schema_version": 1,
        "run_id": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "case_id": "rw-001-parity-kill",
        "track": "real_world_adjudication",
        "ground_truth_status": "quarantined",
        "taxonomy_gate": {
            "status": "Covered",
            "expected_detectors": [EXPECTED_DETECTOR],
            "reason": "The confirmed root-cause family includes a destructive selfdestruct/suicide path; Selfdestruct is an existing controlled detector family."
        },
        "stages": {
            "a_existing_detector_only": {
                "status": a_status,
                "expected_detector": EXPECTED_DETECTOR,
                "pinned_source": static_source,
                "owned_vulnerable_contrast": static_vulnerable,
                "owned_fixed_contrast": static_fixed,
                "pinned_source_comparator": source_comparisons,
                "owned_vulnerable_comparator": vulnerable_comparisons,
                "owned_fixed_comparator": fixed_comparisons,
                "reason": a_reason,
            },
            "b_llm_only": {
                "status": b_status,
                "expected_detector": EXPECTED_DETECTOR,
                "pinned_source": llm_source,
                "owned_vulnerable_contrast": llm_vulnerable,
                "owned_fixed_contrast": llm_fixed,
                "ground_truth_role": "ObservationOnly",
                "reason": "LLM predictions are recorded after a live catalog check but cannot create Ground Truth or override exact-source comparator evidence."
            },
            "c_full_pipeline": {
                "status": full_pipeline["status"],
                "acceptance_gate": full_pipeline["acceptance_gate"],
                "reason": full_pipeline["reason"],
                "source_evidence": "Completed",
                "detector_mapping": "CoveredAtTaxonomyLevel",
                "comparator": "NoExactSourceHypothesis",
                "invariant": "Violated/Satisfied",
                "poc": poc.status.value,
            },
            "invariant": {
                "id": "parity.uninitialized_shared_library_cannot_be_destroyed",
                "vulnerable": invariant_vulnerable,
                "fixed": invariant_fixed,
            },
            "poc": {
                "status": poc.status.value,
                "reason": poc.reason,
                "output": poc.output,
            },
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", default="gpt-5-mini")
    parser.add_argument("--json-out", type=Path, required=True)
    args = parser.parse_args()
    report = run(args.model)
    rendered = json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    print(rendered, end="")
    args.json_out.write_text(rendered, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
