"""Non-LLM template PoC wiring tests for Mini-Review.

Every test here is toolchain-independent: template building is pure
string work, and execution attempts are faked by monkeypatching
``mini_review.attempt_poc`` (which generate_mini_review reaches via
globals()). No test depends on a real docker or forge binary — the
lesson of PR #45 run 149, where tests that assumed an absent
toolchain failed on CI runners that have both.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import mini_review as mr

LAB_VAULT = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract VulnerableVault {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) external {
        require(amount > 0, "zero amount");
        require(balances[msg.sender] >= amount, "insufficient balance");
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");
        balances[msg.sender] = 0;
    }

    receive() external payable {}
}
"""

CEI_VAULT = LAB_VAULT.replace(
    """        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");
        balances[msg.sender] = 0;""",
    """        balances[msg.sender] = 0;
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");""",
)

NO_DEPOSIT_VAULT = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Vault {
    mapping(address => uint256) public balances;

    function withdraw(uint256 amount) public {
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "fail");
        balances[msg.sender] -= amount;
    }
}
"""

OLD_VAULT = """
pragma solidity ^0.4.15;

contract Reentrance {
    mapping (address => uint) userBalance;

    function addToBalance() payable {
        userBalance[msg.sender] += msg.value;
    }

    function withdrawBalance() {
        if (!(msg.sender.call.value(userBalance[msg.sender])())) {
            throw;
        }
        userBalance[msg.sender] = 0;
    }
}
"""

GUARDED_VAULT = LAB_VAULT.replace(
    "function withdraw(uint256 amount) external {",
    "function withdraw(uint256 amount) external nonReentrant {",
)

LAB_FINDING = {
    "name": "Reentrancy",
    "severity": "Critical",
    "description": (
        "Reentrancy in withdraw(): callback-capable call followed by "
        "a write to 'balances'."
    ),
}


def test_template_built_for_lab_vault_shape():
    poc, reason = mr._template_poc_for_finding(LAB_VAULT, LAB_FINDING)
    assert reason == ""
    assert poc is not None
    assert 'import "forge-std/Test.sol";' in poc
    assert 'import "../src/Victim.sol";' in poc
    assert "VulnerableVault" in poc
    assert "MiniReviewAttacker" in poc
    assert "victim.deposit{value: msg.value}()" in poc
    assert "victim.withdraw(amount)" in poc
    assert "assertGe(address(attacker).balance, 2 ether" in poc
    assert "assertGe(attacker.reentries(), 1" in poc
    # No dangerous cheatcodes in the template.
    for bad in ("vm.ffi", "vm.broadcast", "vm.writeFile", "vm.readFile"):
        assert bad not in poc


def test_template_declines_cei_fixed_victim():
    # A CEI-fixed victim has no call-before-write, so the builder
    # declines it instead of executing a PoC against it.
    poc, reason = mr._template_poc_for_finding(CEI_VAULT, LAB_FINDING)
    assert poc is None
    assert "no state write after the external call" in reason


def test_template_declines_no_deposit():
    poc, reason = mr._template_poc_for_finding(
        NO_DEPOSIT_VAULT,
        {
            "name": "Reentrancy",
            "severity": "Critical",
            "description": "Reentrancy in withdraw(): call before write.",
        },
    )
    assert poc is None
    assert "deposit" in reason


def test_template_declines_pre_08_pragma():
    poc, reason = mr._template_poc_for_finding(
        OLD_VAULT,
        {
            "name": "Reentrancy",
            "severity": "Critical",
            "description": "Reentrancy in withdrawBalance(): call before write.",
        },
    )
    assert poc is None
    assert "<0.8" in reason


def test_template_declines_guarded_function():
    poc, reason = mr._template_poc_for_finding(GUARDED_VAULT, LAB_FINDING)
    assert poc is None
    assert "guarded" in reason


def test_template_declines_unknown_function():
    poc, reason = mr._template_poc_for_finding(
        LAB_VAULT,
        {
            "name": "Reentrancy",
            "severity": "Critical",
            "description": "Reentrancy in nosuch(): call before write.",
        },
    )
    assert poc is None
    assert "not found" in reason


def test_generate_attempt_poc_template_passed(monkeypatch):
    # The wiring feeds the built template file to attempt_poc and
    # records its passed result verbatim; the finding stays Confirmed.
    seen = {}

    def fake_attempt(poc_path, victim_code="", use_docker=True):
        seen["path"] = poc_path
        seen["text"] = Path(poc_path).read_text(encoding="utf-8")
        return {"status": "passed", "output": "FAKE-PASS-1"}

    monkeypatch.setattr(mr, "attempt_poc", fake_attempt)
    report = mr.generate_mini_review(
        LAB_VAULT, file_path="Vault.sol", commit="abc",
        findings=[dict(LAB_FINDING)], attempt_poc=True,
    )
    assert "MiniReviewAttacker" in seen["text"]
    assert "victim.withdraw(amount)" in seen["text"]
    assert "- **Confirmed findings**: 1" in report
    assert "- **PoC result**: passed — FAKE-PASS-1" in report


def test_generate_attempt_poc_template_failed_downgrades(monkeypatch):
    # A failed template execution downgrades a reentrancy Confirmed
    # finding, exactly as a failed supplied PoC does.
    monkeypatch.setattr(
        mr, "attempt_poc",
        lambda poc_path, victim_code="", use_docker=True: {
            "status": "failed", "output": "FAKE-FAIL-1",
        },
    )
    report = mr.generate_mini_review(
        LAB_VAULT, file_path="Vault.sol", commit="abc",
        findings=[dict(LAB_FINDING)], attempt_poc=True,
    )
    assert "- **Confirmed findings**: 0" in report
    assert "- **PoC result**: failed — FAKE-FAIL-1" in report


def test_generate_attempt_poc_template_could_not_run_keeps_confirmed(monkeypatch):
    # A could-not-run template attempt (e.g. no toolchain in the
    # real attempt path) never downgrades a Confirmed finding.
    monkeypatch.setattr(
        mr, "attempt_poc",
        lambda poc_path, victim_code="", use_docker=True: {
            "status": "could-not-run", "error": "FAKE-NOTOOLCHAIN-1",
        },
    )
    report = mr.generate_mini_review(
        LAB_VAULT, file_path="Vault.sol", commit="abc",
        findings=[dict(LAB_FINDING)], attempt_poc=True,
    )
    assert "- **Confirmed findings**: 1" in report
    assert "- **PoC result**: could-not-run — FAKE-NOTOOLCHAIN-1" in report


def test_generate_attempt_poc_declined_template_records_reason():
    # No fake attempt here: the builder declines the no-deposit
    # vault, so generate records could-not-run with the shape
    # reason and the finding is not Confirmed on PoC grounds alone
    # (triage still marks it Confirmed by code evidence, which is
    # the reentrancy rule; the PoC line must say could-not-run).
    report = mr.generate_mini_review(
        NO_DEPOSIT_VAULT, file_path="Vault.sol", commit="abc",
        findings=[{
            "name": "Reentrancy",
            "severity": "Critical",
            "description": "Reentrancy in withdraw(): call before write.",
        }],
        attempt_poc=True,
    )
    assert "no PoC template for this finding shape" in report
    assert "deposit" in report


def test_generate_attempt_poc_non_reentrancy_without_poc_path():
    # Non-reentrancy without a supplied PoC gets could-not-run with
    # the "no PoC supplied" reason and stays a hypothesis, never a
    # Confirmed finding.
    report = mr.generate_mini_review(
        LAB_VAULT, file_path="Vault.sol", commit="abc",
        findings=[{
            "name": "Access Control",
            "severity": "Critical",
            "description": "Access Control in withdraw()",
        }],
        attempt_poc=True,
    )
    assert "- **Confirmed findings**: 0" in report
    assert "no PoC supplied" in report
    assert "- **Unverified LLM hypotheses (not findings)**: 1" in report


def test_generate_poc_use_docker_flag_reaches_attempt(monkeypatch):
    # poc_use_docker=False reaches the attempt call (used by the
    # CLI --poc-local flag); per-finding poc_use_docker still wins
    # when present, as in the pre-existing poc_path behaviour.
    seen = {}

    def fake_attempt(poc_path, victim_code="", use_docker=True):
        seen["use_docker"] = use_docker
        return {"status": "could-not-run", "error": "FAKE-LOCAL-1"}

    monkeypatch.setattr(mr, "attempt_poc", fake_attempt)
    mr.generate_mini_review(
        LAB_VAULT, file_path="Vault.sol", commit="abc",
        findings=[dict(LAB_FINDING)], attempt_poc=True,
        poc_use_docker=False,
    )
    assert seen["use_docker"] is False


def test_generate_template_attempt_failure_is_could_not_run_not_crash(monkeypatch):
    # A failure inside the template attempt itself must not crash
    # the report; it records could-not-run and the finding keeps
    # its code-evidence bucket.
    def boom(source, finding):
        raise RuntimeError("FAKE-BUILDER-BOOM")

    monkeypatch.setattr(mr, "_template_poc_for_finding", boom)
    report = mr.generate_mini_review(
        LAB_VAULT, file_path="Vault.sol", commit="abc",
        findings=[dict(LAB_FINDING)], attempt_poc=True,
    )
    assert "- **Confirmed findings**: 1" in report
    assert "template PoC attempt failed" in report
    assert "FAKE-BUILDER-BOOM" in report


def test_generate_without_attempt_poc_unchanged():
    # Opt-in preserved: without attempt_poc=True, a reentrancy
    # Confirmed finding still says "not attempted", exactly as
    # before this change.
    report = mr.generate_mini_review(
        LAB_VAULT, file_path="Vault.sol", commit="abc",
        findings=[dict(LAB_FINDING)],
    )
    assert "- **Confirmed findings**: 1" in report
    assert "- **PoC result**: not attempted" in report
