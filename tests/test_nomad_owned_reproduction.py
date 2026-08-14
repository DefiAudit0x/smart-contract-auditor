"""Offline and Foundry checks for the owned Nomad adjudication reproduction."""

from pathlib import Path

from benchmarks.real_world.owned_reproductions.nomad.nomad_invariant import evaluate
from verification.poc import PocStatus, run_foundry_poc


ROOT = Path(__file__).resolve().parents[1]
NOMAD_ROOT = ROOT / "benchmarks" / "real_world" / "owned_reproductions" / "nomad"
VULNERABLE = NOMAD_ROOT / "NomadReplicaVulnerable.sol"
FIXED = NOMAD_ROOT / "NomadReplicaFixed.sol"
POC = NOMAD_ROOT / "nomad_zero_root_poc.t.sol"


def test_nomad_invariant_contrast_is_explicit():
    vulnerable = evaluate(VULNERABLE)
    fixed = evaluate(FIXED)
    assert vulnerable.status == "Violated"
    assert fixed.status == "Satisfied"
    assert vulnerable.evidence_lines
    assert fixed.evidence_lines


def test_nomad_owned_poc_passes():
    result = run_foundry_poc(POC, ROOT)
    assert result.status is PocStatus.PASSED, result.reason
