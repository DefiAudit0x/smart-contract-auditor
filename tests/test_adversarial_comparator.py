"""Adversarial false-positive tests for deterministic comparator rules."""

import pytest

from verification.comparator import ComparisonStatus, compare_finding


@pytest.mark.parametrize(
    "detector,source",
    [
        (
            "Reentrancy (AST)",
            'contract C { /* .call{value: 1}() */ function f() external {} }',
        ),
        (
            "Flash Loan Attack Vector",
            'contract FlashLoanWord { string public note = "flashLoan"; }',
        ),
        (
            "Storage Collision (Delegatecall)",
            "contract DelegatecallWord { mapping(address => uint256) public values; }",
        ),
        (
            "Unchecked Transfer",
            'contract C { string public note = ".send("; }',
        ),
        (
            "Unbounded Loop (AST)",
            'contract C { string public note = "for("; }',
        ),
        (
            "block.timestamp Usage (AST)",
            'contract C { string public note = "block.timestamp"; }',
        ),
    ],
)
def test_keyword_only_source_is_rejected(detector, source):
    finding = {
        "agent_name": detector,
        "severity": "High",
        "category": "Adversarial",
        "file": "C.sol",
        "function_name": "",
        "description": "keyword-only test finding",
    }
    result = compare_finding(finding, source)
    assert result.status is ComparisonStatus.REJECTED
    assert result.evidence == ()


def test_public_state_identifier_is_not_public_mint():
    finding = {
        "agent_name": "Public Mint/Burn",
        "severity": "High",
        "category": "Adversarial",
        "file": "C.sol",
        "function_name": "",
        "description": "identifier-only test finding",
    }
    source = "contract MintCounter { uint256 public mintCount; }"
    result = compare_finding(finding, source)
    assert result.status is ComparisonStatus.REJECTED
    assert result.evidence == ()
