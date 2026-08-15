#!/usr/bin/env python3
"""Record stage-by-stage observations for the quarantined BonqDAO candidate."""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

from analyzers.solidity_analyzer import SolidityAnalyzer
from benchmarks.real_world.owned_reproductions.bonqdao.bonqdao_invariant import evaluate as evaluate_bonq_invariant
from verification.poc import run_foundry_poc

ROOT = Path(__file__).resolve().parents[2]
BONQ_ROOT = ROOT / "benchmarks" / "real_world" / "owned_reproductions" / "bonqdao"
VULNERABLE = BONQ_ROOT / "BonqTellorVulnerable.sol"
FIXED = BONQ_ROOT / "BonqTellorFixed.sol"
POC = BONQ_ROOT / "bonqdao_dispute_window_poc.t.sol"


def _static(path: Path) -> dict:
    findings = SolidityAnalyzer().analyze_file(path.name, path.read_text(encoding="utf-8"))
    return {
        "status": "Completed",
        "source": str(path.relative_to(ROOT)),
        "observed_detectors": sorted({finding.agent_name for finding in findings}),
        "finding_count": len(findings),
    }


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


def run(model: str) -> dict:
    static_vulnerable = _static(VULNERABLE)
    static_fixed = _static(FIXED)
    llm_vulnerable = _llm(VULNERABLE, model)
    llm_fixed = _llm(FIXED, model)
    vulnerable_invariant = evaluate_bonq_invariant(VULNERABLE)
    fixed_invariant = evaluate_bonq_invariant(FIXED)
    poc = run_foundry_poc(POC, ROOT)

    comparator = {
        "status": "NotApplicable",
        "expected_detectors": [],
        "reason": "The existing detector taxonomy has no semantically valid oracle-manipulation or dispute-window detector for this case.",
    }
    static_plus_llm = {
        "status": "ObservationalOnly",
        "reason": "Static and LLM observations are retained for transparency but cannot create Ground Truth or override the Taxonomy Coverage Gate.",
        "static_vulnerable": static_vulnerable["observed_detectors"],
        "llm_vulnerable": llm_vulnerable.get("predictions", []),
    }
    full_pipeline = {
        "status": "Quarantined",
        "acceptance_gate": False,
        "reason": "The source, on-chain evidence, owned invariant, and executable PoC establish the incident mechanism, but oracle manipulation / spot-price consumption without a dispute window is not covered by the current detector taxonomy; no existing detector is forced.",
    }
    return {
        "schema_version": 1,
        "run_id": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "case_id": "rw-004-bonqdao",
        "track": "real_world_adjudication",
        "ground_truth_status": "quarantined",
        "stages": {
            "static": {"vulnerable": static_vulnerable, "fixed": static_fixed},
            "llm": {"vulnerable": llm_vulnerable, "fixed": llm_fixed},
            "static_plus_llm": static_plus_llm,
            "comparator": comparator,
            "invariant": {
                "id": "bonq.oracle_price_requires_dispute_window",
                "vulnerable": {
                    "status": vulnerable_invariant.status,
                    "reason": vulnerable_invariant.reason,
                    "evidence_lines": list(vulnerable_invariant.evidence_lines),
                },
                "fixed": {
                    "status": fixed_invariant.status,
                    "reason": fixed_invariant.reason,
                    "evidence_lines": list(fixed_invariant.evidence_lines),
                },
            },
            "poc": {
                "status": poc.status.value,
                "reason": poc.reason,
                "output": poc.output,
            },
            "full_pipeline": full_pipeline,
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
