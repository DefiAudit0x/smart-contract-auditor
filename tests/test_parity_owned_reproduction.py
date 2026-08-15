"""Offline and Foundry checks for the owned Parity WalletLibrary reproduction."""

from pathlib import Path

from benchmarks.real_world.owned_reproductions.parity.parity_invariant import evaluate
from verification.poc import PocStatus, run_foundry_poc


ROOT = Path(__file__).resolve().parents[1]
PARITY_ROOT = ROOT / "benchmarks" / "real_world" / "owned_reproductions" / "parity"
VULNERABLE = PARITY_ROOT / "ParityWalletLibraryVulnerable.sol"
FIXED = PARITY_ROOT / "ParityWalletLibraryFixed.sol"
POC = PARITY_ROOT / "parity_library_kill_poc.t.sol"


def test_parity_invariant_contrast_is_explicit():
    vulnerable = evaluate(VULNERABLE)
    fixed = evaluate(FIXED)
    assert vulnerable.status == "Violated"
    assert fixed.status == "Satisfied"
    assert vulnerable.evidence_lines
    assert fixed.evidence_lines


def test_parity_owned_poc_passes():
    result = run_foundry_poc(POC, ROOT)
    assert result.status is PocStatus.PASSED, result.reason
