"""Regression tests for the remaining Priority 1 full-audit gate hardening.

Covers ONLY the full-audit (7-Question Gate / self_critique) path, not
Mini-Review: Mini-Review's Confirmed definition is unchanged, and none
of these tests touch it.

Toolchain-independent by design: gate_validator works on report text +
source text only, and self_critique is tested with a monkeypatched LLM
call, never a real model, docker, or forge invocation (cf. the PR #45
CI lesson: tests must never depend on the real environment's toolchain).
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import gate_validator
from gate_validator import (
    _gate_q1b_code_evidence,
    _has_code_evidence,
    validate_finding,
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


def _genuine_finding():
    # Names the function AND concrete artefacts actually in its body:
    # the state variable `balances` and the `.call(` pattern.
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


def _weak_finding():
    # Previously passing: names a real function (withdraw) whose body
    # contains a write and an external call, but claims NO concrete
    # artefact from that body — no state variable, no call pattern,
    # no called function.  Only the function name plus generic
    # exploit prose ("transaction", "drains funds").  Deliberately
    # avoids the words "balances", ".call(", "transfer", "send" so
    # the only thing tying it to the code is the function name.
    return {
        "name": "Reentrancy in withdraw",
        "severity": "Critical",
        "description": (
            "Setup: attacker deposits funds, then calls withdraw() with "
            "amount. First attacker calls withdraw(), then a transaction "
            "repeats withdraw before the state update, then attacker "
            "drains funds. This is direct theft and loss of funds: "
            "steal drain loss."
        ),
        "fix": "Fix the vulnerability.",
        "poc": "withdraw() then repeat withdraw()",
        "impact": "direct theft",
    }


# --- (a) Tied artefact required, not just named function + any write ---

def test_weak_evidence_finding_now_rejected():
    ok, reason = _has_code_evidence(_weak_finding(), VAULT_CODE)
    assert ok is False
    assert "artefact" in reason


def test_weak_evidence_finding_rejected_end_to_end():
    passed, _sev, reason = validate_finding(_weak_finding(), VAULT_CODE)
    assert passed is False
    assert "No code evidence" in reason


def test_genuine_evidenced_finding_still_passes():
    ok, reason = _has_code_evidence(_genuine_finding(), VAULT_CODE)
    assert ok is True, reason
    passed, new_sev, reason = validate_finding(_genuine_finding(), VAULT_CODE)
    assert passed is True, reason
    assert new_sev is None


def test_call_pattern_alone_is_a_sufficient_tied_artefact():
    # Names withdraw and the .call( pattern, but never mentions the
    # state variable: the call-pattern artefact alone must pass.
    finding = {
        "name": "Reentrancy in withdraw",
        "severity": "Critical",
        "description": (
            "Setup: attacker deposits funds, then calls withdraw(). "
            "First attacker calls withdraw(), then msg.sender.call( "
            "re-enters withdraw, then attacker drains funds. This is "
            "direct theft and loss of funds: steal drain loss."
        ),
        "fix": "Fix it.",
        "poc": "withdraw()",
        "impact": "direct theft",
    }
    ok, reason = _has_code_evidence(finding, VAULT_CODE)
    assert ok is True, reason


# --- (a) Hallucination check is no longer waived by a real name ---

def test_real_plus_hallucinated_function_is_rejected():
    finding = _genuine_finding()
    finding = dict(finding)
    finding["description"] = finding["description"] + (
        " The attacker then calls claimReward() to finish the exploit."
    )
    finding["poc"] = "withdraw() then claimReward()"
    ok, reason = _has_code_evidence(finding, VAULT_CODE)
    assert ok is False
    assert "claimReward" in reason
    assert "not present in the analyzed code" in reason


def test_method_call_is_not_a_hallucinated_function():
    # msg.sender.call( in the genuine finding must not count as a
    # hallucinated "call" function — it is a method call, and the
    # genuine finding passes (see test_genuine_evidenced_finding_*
    # above).  This test pins the method exclusion directly.
    assert _has_code_evidence(_genuine_finding(), VAULT_CODE)[0] is True


# --- (b) Q1b for Medium/Low: hallucinated location + claimed variable ---

def test_medium_backtick_variable_not_in_code_is_hard_reject():
    # Old behaviour: Medium/Low passed Q1b here, because the only hard
    # reject was a hallucinated FUNCTION and `ghostBalances` is a
    # variable claim in backticks, not a function call.
    finding = {
        "name": "Reentrancy in deposit",
        "severity": "Medium",
        "description": (
            "First attacker calls deposit, then a transaction exploits "
            "the `ghostBalances` mapping, then drains funds via "
            "msg.sender.call(."
        ),
    }
    passed, _sev, reason = validate_finding(finding, SAFE_CODE)
    assert passed is False
    assert "ghostBalances" in reason


def test_medium_indexed_assignment_variable_not_in_code_is_hard_reject():
    finding = {
        "name": "Reentrancy in deposit",
        "severity": "Medium",
        "description": (
            "First attacker calls deposit, then a transaction exploits "
            "ghostBalances[msg.sender] -= amount, then drains funds via "
            "msg.sender.call(."
        ),
    }
    passed, _sev, reason = validate_finding(finding, SAFE_CODE)
    assert passed is False
    assert "ghostBalances" in reason


def test_medium_real_backtick_variable_passes_q1b():
    finding = {
        "name": "Reentrancy in deposit",
        "severity": "Medium",
        "description": (
            "First attacker calls deposit, then a transaction exploits "
            "the `balances` mapping, then drains funds via msg.sender.call(."
        ),
    }
    passed, _reason = _gate_q1b_code_evidence(finding, SAFE_CODE)
    assert passed is True


def test_medium_weak_evidence_without_claimed_identifier_still_triage():
    # The new variable check must not over-reject Medium/Low: a weak
    # finding that claims NO code identifier in code syntax (no
    # backticks, no assignment target) still passes Q1b as triage —
    # only Critical/High are hard-rejected for missing artefacts.
    finding = _weak_finding()
    finding = dict(finding, severity="Medium")
    passed, _reason = _gate_q1b_code_evidence(finding, VAULT_CODE)
    assert passed is True


# --- (a) self_critique fails closed on exception ---

def test_self_critique_exception_returns_unverified_not_bare_report(monkeypatch):
    import agents.validation as validation

    def _boom(*_args, **_kwargs):
        raise RuntimeError("model exploded")

    monkeypatch.setattr(validation, "call_model_with_fallback", _boom)
    report = "### Vulnerability List\n- **Name**: Reentrancy in withdraw\n"
    result = validation.self_critique(report, VAULT_CODE)
    assert result != report
    assert result.startswith("### Validation Warning")
    assert "UNVERIFIED" in result
    assert "Reentrancy in withdraw" in result


def test_self_critique_success_path_unchanged(monkeypatch):
    import agents.validation as validation

    monkeypatch.setattr(
        validation, "call_model_with_fallback", lambda _prompt: "cleaned report"
    )
    result = validation.self_critique("original", VAULT_CODE)
    assert result == "cleaned report"
    assert "UNVERIFIED" not in result
