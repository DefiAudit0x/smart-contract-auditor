"""Tests for deterministic source-level security invariants."""

import pytest

from benchmarks.run_benchmark import discover_cases, load_metadata
from verification.invariants import InvariantStatus, evaluate_invariants, summarize_invariants


@pytest.mark.parametrize("case_dir", discover_cases(), ids=lambda path: path.name)
def test_vulnerable_contract_violates_declared_invariant(case_dir):
    metadata = load_metadata(case_dir)
    source = (case_dir / "vulnerable.sol").read_text(encoding="utf-8")
    results = evaluate_invariants(source, [metadata["invariant_id"]])
    assert len(results) == 1
    assert results[0].status is InvariantStatus.VIOLATED
    assert results[0].evidence
    assert results[0].evidence[0].location.startswith("line ")


@pytest.mark.parametrize("case_dir", discover_cases(), ids=lambda path: path.name)
def test_fixed_contract_satisfies_declared_invariant(case_dir):
    metadata = load_metadata(case_dir)
    source = (case_dir / "fixed.sol").read_text(encoding="utf-8")
    results = evaluate_invariants(source, [metadata["invariant_id"]])
    assert len(results) == 1
    assert results[0].status is InvariantStatus.SATISFIED
    assert results[0].evidence == ()


def test_unknown_invariant_is_inconclusive():
    results = evaluate_invariants("contract C {}", ["unknown.invariant"])
    assert results[0].status is InvariantStatus.INCONCLUSIVE
    assert results[0].evidence == ()


def test_invalid_source_is_inconclusive():
    results = evaluate_invariants("not solidity", ["no_selfdestruct"])
    assert results[0].status is InvariantStatus.INCONCLUSIVE


def test_summary_is_stable():
    results = evaluate_invariants("contract C {}", ["no_selfdestruct", "unknown.invariant"])
    assert summarize_invariants(results) == {
        "Satisfied": 1,
        "Violated": 0,
        "Inconclusive": 1,
    }
