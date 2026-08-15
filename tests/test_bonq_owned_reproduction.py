"""Offline and Foundry checks for the owned BonqDAO adjudication reproduction."""

from pathlib import Path

from benchmarks.real_world.owned_reproductions.bonqdao.bonqdao_invariant import evaluate
from verification.poc import PocStatus, run_foundry_poc


ROOT = Path(__file__).resolve().parents[1]
BONQ_ROOT = ROOT / "benchmarks" / "real_world" / "owned_reproductions" / "bonqdao"
VULNERABLE = BONQ_ROOT / "BonqTellorVulnerable.sol"
FIXED = BONQ_ROOT / "BonqTellorFixed.sol"
POC = BONQ_ROOT / "bonqdao_dispute_window_poc.t.sol"


def test_bonq_invariant_contrast_is_explicit():
    vulnerable = evaluate(VULNERABLE)
    fixed = evaluate(FIXED)
    assert vulnerable.status == "Violated"
    assert fixed.status == "Satisfied"
    assert vulnerable.evidence_lines
    assert fixed.evidence_lines


def test_bonq_owned_poc_passes():
    result = run_foundry_poc(POC, ROOT)
    assert result.status is PocStatus.PASSED, result.reason
