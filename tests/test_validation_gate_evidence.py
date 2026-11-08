"""Regression tests for issues #28 (F-18) and #27 (F-17).

Solc-free by design: gate_validator works on report text + source
text only, so these tests run without a compiler or LLM credentials.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import gate_validator
from gate_validator import (
    _has_code_evidence,
    mark_unverified,
    validate_finding,
    validate_report,
)

VAULT_CODE = """
contract Vault {
    mapping(address => uint256) public balances;
    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }
    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount, "insufficient");
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "call failed");
        balances[msg.sender] -= amount;
    }
}
"""

SAFE_CODE = """
contract SafeVault {
    mapping(address => uint256) public balances;
    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }
}
"""

ONLY_OWNER_CODE = """
contract OwnedVault {
    mapping(address => uint256) public balances;
    function adminWithdraw(uint256 amount) public onlyOwner {
        balances[msg.sender] -= amount;
    }
}
"""


def _passing_finding():
    return {
        "name": "Reentrancy in withdraw",
        "severity": "Critical",
        "description": (
            "Setup: attacker deposits funds, then calls withdraw(). "
            "First attacker calls withdraw() with amount, then the call "
            "to msg.sender.call( re-enters withdraw before balances is "
            "updated, then attacker drains balances. This is direct theft "
            "and loss of funds: steal drain loss."
        ),
        "fix": "Apply checks-effects-interactions and nonReentrant.",
        "poc": "withdraw() then re-enter withdraw()",
        "impact": "direct theft",
    }


def _prose_only_finding():
    # Convincing exploit wording, but about a function that does not
    # exist in SAFE_CODE — no code path at all.
    return {
        "name": "Reentrancy attack exploit",
        "severity": "Critical",
        "description": (
            "Setup: attacker prepares an attack, then calls function "
            "claimReward in step 1, then exploits the contract in step 2, "
            "then drains the contract via msg.sender.call(. This is direct "
            "theft and loss of funds: steal drain loss. Attack exploit sequence."
        ),
        "fix": "Fix the vulnerability.",
        "poc": "claimReward() attack exploit",
        "impact": "direct theft",
    }


def _report_text(finding):
    return (
        "### Vulnerability List\n"
        f"- **Name**: {finding['name']}\n"
        f"- **Severity**: {finding['severity']}\n"
        f"- **Description**: {finding['description']}\n"
        f"- **Fix**: {finding['fix']}\n"
        f"- **PoC**: {finding['poc']}\n"
        f"- **Impact**: {finding['impact']}\n"
    )


# --- Issue #28: code evidence, not wording alone ---

def test_plausible_prose_without_code_path_is_rejected():
    passed, _sev, reason = validate_finding(_prose_only_finding(), SAFE_CODE)
    assert passed is False
    assert "No code evidence" in reason


def test_prose_with_no_function_name_is_rejected_for_critical():
    finding = {
        "name": "Critical vulnerability attack",
        "severity": "Critical",
        "description": (
            "Setup: attacker first attacks, then exploits, then steals. "
            "This is direct theft and loss of funds: steal drain loss. "
            "Attack exploit sequence with transaction and swap."
        ),
        "fix": "Fix it.",
        "impact": "direct theft",
    }
    passed, _sev, reason = validate_finding(finding, VAULT_CODE)
    assert passed is False
    assert "No code evidence" in reason


def test_finding_with_real_code_evidence_passes():
    passed, new_sev, reason = validate_finding(_passing_finding(), VAULT_CODE)
    assert passed is True, reason
    assert new_sev is None


def test_code_evidence_helper_rejects_only_owner_function():
    finding = {
        "name": "Reentrancy in adminWithdraw",
        "severity": "Critical",
        "description": "adminWithdraw() with amount drains balances",
    }
    ok, reason = _has_code_evidence(finding, ONLY_OWNER_CODE)
    assert ok is False
    assert "reachable" in reason


def test_code_evidence_helper_accepts_reachable_state_transition():
    ok, reason = _has_code_evidence(_passing_finding(), VAULT_CODE)
    assert ok is True, reason


def test_medium_finding_naming_missing_function_is_rejected():
    finding = {
        "name": "Reentrancy in claimReward",
        "severity": "Medium",
        "description": (
            "First attacker calls function claimReward, then exploits it, "
            "then drains funds via msg.sender.call(."
        ),
    }
    passed, _sev, reason = validate_finding(finding, SAFE_CODE)
    assert passed is False
    assert "No code evidence" in reason


# --- Issue #27: fail closed ---

class _RaisingKB:
    def __bool__(self):
        return True

    def __iter__(self):
        raise RuntimeError("KB exploded")


def test_validator_exception_returns_unverified_not_validated():
    report = _report_text(_passing_finding())
    result = validate_report(report, VAULT_CODE, kb_patterns=_RaisingKB())
    assert "UNVERIFIED" in result
    assert _passing_finding()["name"] in result
    # The banner must come first; the original finding must not be
    # presented as a cleaned, validated finding on its own.
    assert result.startswith("### Validation Warning")


def test_monkeypatched_validator_exception_returns_unverified(monkeypatch):
    def _boom(*_args, **_kwargs):
        raise RuntimeError("validator exploded")

    monkeypatch.setattr(gate_validator, "validate_finding", _boom)
    report = _report_text(_passing_finding())
    result = validate_report(report, VAULT_CODE)
    assert "UNVERIFIED" in result
    assert result.startswith("### Validation Warning")


def test_mark_unverified_is_idempotent():
    report = _report_text(_passing_finding())
    once = mark_unverified(report, "test")
    twice = mark_unverified(once, "test")
    assert once == twice
    assert "UNVERIFIED" in once


# --- Normal behaviour is preserved ---

def test_valid_report_passes_without_unverified_banner():
    report = _report_text(_passing_finding())
    result = validate_report(report, VAULT_CODE)
    assert "UNVERIFIED" not in result
    assert "Reentrancy in withdraw" in result


def test_alternate_finding_markers_are_preserved_by_validation():
    report = (
        "### Vulnerability List\n"
        "* **Name**: Reentrancy in withdraw\n"
        "* **Severity**: Critical\n"
        "* **Description**: Setup: an attacker deposits funds, then calls withdraw() with an amount. "
        "First the attacker calls withdraw(), then msg.sender.call( permits re-entry before balances changes. "
        "This causes direct theft and loss of funds: steal, drain, loss.\n"
        "* **Fix**: Apply checks-effects-interactions.\n"
        "* **PoC**: First call withdraw(), then re-enter through msg.sender.call(.\n"
        "* **Impact**: direct theft\n"
        "1. **Name**: Unauthorized withdrawal in withdraw\n"
        "1. **Severity**: Critical\n"
        "1. **Description**: Setup: an attacker deposits funds, then calls withdraw() with an amount. "
        "First the attacker calls withdraw(), then msg.sender.call( permits re-entry before balances changes. "
        "This causes direct theft and loss of funds: steal, drain, loss.\n"
        "1. **Fix**: Apply checks-effects-interactions.\n"
        "1. **PoC**: First call withdraw(), then re-enter through msg.sender.call(.\n"
        "1. **Impact**: direct theft\n"
    )

    result = validate_report(report, VAULT_CODE)

    assert "UNVERIFIED" not in result
    assert "* **Name**: Reentrancy in withdraw" in result
    assert "1. **Name**: Unauthorized withdrawal in withdraw" in result
    for body in (
        "* **Description**:", "* **Fix**:", "* **PoC**:", "* **Impact**:",
        "1. **Description**:", "1. **Fix**:", "1. **PoC**:", "1. **Impact**:",
    ):
        assert body in result


def test_alternate_marker_is_preserved_when_severity_is_downgraded(monkeypatch):
    report = (
        "### Vulnerability List\n"
        "* **Name**: Reentrancy in withdraw\n"
        "* **Severity**: Critical\n"
        "* **Description**: Test description.\n"
    )
    monkeypatch.setattr(
        gate_validator, "validate_finding",
        lambda *_args, **_kwargs: (True, "High", "test downgrade"),
    )

    result = validate_report(report, VAULT_CODE)

    assert "* **Severity**: High" in result


def test_all_rejected_report_keeps_unverified_banner():
    report = _report_text(_prose_only_finding())
    result = validate_report(report, SAFE_CODE)
    assert "UNVERIFIED" in result
    assert "Reentrancy attack exploit" in result


def test_unparseable_finding_format_is_marked_unverified():
    report = "## Findings\n- Vulnerability: Reentrancy in withdraw\n  Severity: High\n"
    result = validate_report(report, SAFE_CODE)
    assert result.startswith("### Validation Warning")
    assert "UNVERIFIED" in result
    assert report in result


def test_recognized_empty_report_does_not_get_unverified_banner():
    report = "## Findings\nNo vulnerabilities found.\n"
    result = validate_report(report, SAFE_CODE)
    assert result == report
