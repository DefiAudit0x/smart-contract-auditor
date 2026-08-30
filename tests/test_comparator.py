"""Tests for deterministic Hypothesis → Verification → Evidence comparison."""

import pytest

from benchmarks.run_benchmark import discover_cases, evaluate_case
from verification.comparator import ComparisonStatus, compare_finding


@pytest.mark.parametrize(
    "detector,source",
    [
        (
            "Reentrancy (AST)",
            'contract C { function withdraw() external { msg.sender.call{value: 1}(""); } }',
        ),
        (
            "DELEGATECALL Usage (AST)",
            "contract C { function run(address target, bytes calldata data) external { target.delegatecall(data); } }",
        ),
        (
            "Selfdestruct",
            "contract C { function destroy() external { selfdestruct(payable(msg.sender)); } }",
        ),
        (
            "Public Mint/Burn",
            "contract C { function mint(address to, uint256 amount) public { amount; to; } }",
        ),
        (
            "tx.origin Auth (AST)",
            "contract C { function check() external view { require(tx.origin == msg.sender); } }",
        ),
    ],
)
def test_known_pattern_is_confirmed(detector, source):
    finding = {
        "agent_name": detector,
        "severity": "High",
        "category": "Test",
        "file": "C.sol",
        "function_name": "withdraw" if detector == "Reentrancy (AST)" else "",
        "description": "test finding",
    }
    result = compare_finding(finding, source)
    assert result.status is ComparisonStatus.CONFIRMED
    assert result.verification.supported is True
    assert result.evidence
    assert result.evidence[0].location.startswith("line ")


def test_known_pattern_without_evidence_is_rejected():
    finding = {
        "agent_name": "tx.origin Auth (AST)",
        "severity": "High",
        "category": "Access Control",
        "file": "C.sol",
        "function_name": "check",
        "description": "test finding",
    }
    result = compare_finding(finding, "contract C { function check() external view { return; } }")
    assert result.status is ComparisonStatus.REJECTED
    # M24 remediation: 'supported' now honestly reflects the evidence.
    # It used to be True in both branches, which made the field useless.
    assert result.verification.supported is False
    assert result.evidence == ()


def test_unknown_detector_is_inconclusive():
    finding = {
        "agent_name": "Future Detector",
        "severity": "Medium",
        "category": "Unknown",
        "file": "C.sol",
        "function_name": "check",
        "description": "test finding",
    }
    result = compare_finding(finding, "contract C { function check() external view { return; } }")
    assert result.status is ComparisonStatus.INCONCLUSIVE
    assert result.verification.supported is False
    assert result.evidence == ()


@pytest.mark.parametrize("case_dir", discover_cases(), ids=lambda path: path.name)
def test_benchmark_expected_findings_are_confirmed(case_dir):
    result = evaluate_case(case_dir)
    statuses = [item["status"] for item in result["comparisons"]]
    assert statuses, f"No comparator results for {case_dir.name}"
    assert set(statuses) == {ComparisonStatus.CONFIRMED.value}, result
    assert result["comparison_statuses"][ComparisonStatus.REJECTED.value] == 0
    assert result["comparison_statuses"][ComparisonStatus.INCONCLUSIVE.value] == 0
