"""Fix 2 tests: separate code-proven from LLM hypothesis in Mini-Review.

- Confirmed section = code-evidence + Critical only.
- Guard notes live only in the appendix, explicitly "not findings".
- A non-reentrancy finding without Q1b + a verified Foundry PoC is
  labelled "unverified LLM hypothesis", never a finding -- even when
  Q1b passes or when it carries prose "poc" text (unexecuted text is
  not a PoC run).
- A supplied structured poc_result is recorded verbatim, and only a
  passed result upgrades a Q1b-passing non-reentrancy finding to
  Confirmed. Automatic PoC execution is NOT claimed: attempt_poc()
  returns could-not-run when the toolchain is absent. The
  could-not-run tests simulate an absent toolchain with monkeypatch:
  CI runners have docker and Foundry installed, so these tests must
  never depend on the real environment's toolchain.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import mini_review as mr

VULN_SOURCE = """
contract Vault {
    mapping(address => uint256) public balances;
    function withdraw(uint256 amount) public {
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "fail");
        balances[msg.sender] -= amount;
    }
    function ping(address target) public {
        (bool ok, ) = target.call("");
        require(ok, "fail");
    }
}
"""

COMMIT = "a6ad6111f33761f01b591c8e9c96ae6b8e900d11"

# Non-reentrancy finding whose Q1b check passes (names withdraw(),
# which is public, unguarded, and writes state) but which has no PoC.
ACCESS_Q1B_ONLY = {
    "name": "Access Control",
    "severity": "High",
    "description": (
        "Access control in withdraw(): attacker drains funds, "
        "first call withdraw then drain"
    ),
}


def _section(report, heading):
    """Text of one report section (up to the next ## heading)."""
    start = report.index(heading)
    rest = report[start + len(heading):]
    for marker in (
        "\n## Unverified LLM hypotheses",
        "\n## Other items",
        "\n## Appendix:",
        "\n## Method and limits",
    ):
        if marker in rest:
            rest = rest[: rest.index(marker)]
    return rest


def test_confirmed_count_equals_critical_and_guard_notes_only_in_appendix():
    report = mr.generate_mini_review(
        VULN_SOURCE, file_path="Vault.sol", commit=COMMIT,
        findings=[
            {"name": "Reentrancy", "severity": "Critical",
             "description": "Reentrancy in withdraw()"},
            {"name": "External Call Without Recognized Guard",
             "severity": "Medium",
             "description": "External call in ping() with no recognized guard"},
        ],
    )
    assert "- **Confirmed findings**: 1" in report
    assert "- **Critical**: 1" in report
    confirmed = _section(report, "## Confirmed findings")
    assert "Reentrancy" in confirmed
    assert "External Call Without Recognized Guard" not in confirmed
    assert "Guard note only" not in confirmed
    # Guard-note items appear only after the appendix heading (the
    # summary count line before it is a count, not an item listing).
    before_appendix, appendix = report.split("## Appendix: Guard notes (not findings)")
    assert "External Call Without Recognized Guard" not in before_appendix
    assert "External Call Without Recognized Guard" in appendix
    assert "NOT findings" in appendix
    # The old single Findings section is gone: nothing may hide a
    # guard note under a generic findings heading.
    assert "\n## Findings\n" not in report


def test_non_reentrancy_without_poc_is_unverified_llm_hypothesis():
    report = mr.generate_mini_review(
        VULN_SOURCE, file_path="Vault.sol", commit=COMMIT,
        findings=[dict(ACCESS_Q1B_ONLY)],
    )
    assert "- **Confirmed findings**: 0" in report
    confirmed = _section(report, "## Confirmed findings")
    assert "Access Control" not in confirmed
    assert "No confirmed findings" in confirmed
    hypotheses = _section(report, "## Unverified LLM hypotheses")
    assert "Access Control" in hypotheses
    assert "unverified LLM hypothesis" in hypotheses
    assert "not a finding" in hypotheses
    triaged = mr.triage_findings([dict(ACCESS_Q1B_ONLY)], VULN_SOURCE)
    assert triaged[0]["evidence_status"] == "Unverified LLM hypothesis"
    assert triaged[0]["q1b_passed"] is True  # Q1b alone is not enough
    assert triaged[0]["poc_status"] == "not attempted"


def test_non_reentrancy_prose_poc_text_is_not_a_verified_poc():
    finding = dict(ACCESS_Q1B_ONLY)
    finding["poc"] = "Foundry test: call withdraw, drain funds"
    report = mr.generate_mini_review(
        VULN_SOURCE, file_path="Vault.sol", commit=COMMIT, findings=[finding]
    )
    assert "- **Confirmed findings**: 0" in report
    assert "unverified LLM hypothesis" in report
    triaged = mr.triage_findings([finding], VULN_SOURCE)
    assert triaged[0]["evidence_status"] == "Unverified LLM hypothesis"


def test_non_reentrancy_without_q1b_is_unverified_llm_hypothesis():
    finding = {
        "name": "Flash Loan Attack",
        "severity": "Critical",
        "description": "Flash loan in borrowFunds(): attacker drains the pool",
    }
    report = mr.generate_mini_review(
        VULN_SOURCE, file_path="Vault.sol", commit=COMMIT, findings=[finding]
    )
    assert "- **Confirmed findings**: 0" in report
    assert "unverified LLM hypothesis" in report


def test_verified_poc_result_recorded_verbatim_and_confirms():
    finding = dict(ACCESS_Q1B_ONLY)
    finding["severity"] = "Critical"
    finding["poc_result"] = {
        "status": "PROVED",
        "output": "EXPLOIT-VERBATIM-123: attacker balance 2 ETH, vault 0",
    }
    report = mr.generate_mini_review(
        VULN_SOURCE, file_path="Vault.sol", commit=COMMIT, findings=[finding]
    )
    assert "- **Confirmed findings**: 1" in report
    confirmed = _section(report, "## Confirmed findings")
    assert "Access Control" in confirmed
    assert "EXPLOIT-VERBATIM-123: attacker balance 2 ETH, vault 0" in confirmed
    assert "- **PoC result**: passed" in confirmed
    assert "## Unverified LLM hypotheses" not in report


def test_failed_poc_result_recorded_verbatim_and_not_confirmed():
    finding = dict(ACCESS_Q1B_ONLY)
    finding["severity"] = "Critical"
    finding["poc_result"] = {
        "status": "DISPROVED",
        "output": "FAIL-VERBATIM-456: 0 passed, 1 failed",
    }
    report = mr.generate_mini_review(
        VULN_SOURCE, file_path="Vault.sol", commit=COMMIT, findings=[finding]
    )
    assert "- **Confirmed findings**: 0" in report
    hypotheses = _section(report, "## Unverified LLM hypotheses")
    assert "FAIL-VERBATIM-456: 0 passed, 1 failed" in hypotheses
    assert "- **PoC result**: failed" in hypotheses


def test_failed_poc_downgrades_reentrancy_confirmed():
    finding = {
        "name": "Reentrancy", "severity": "Critical",
        "description": "Reentrancy in withdraw()",
        "poc_result": {"status": "DISPROVED", "output": "exploit did not reproduce"},
    }
    report = mr.generate_mini_review(
        VULN_SOURCE, file_path="Vault.sol", commit=COMMIT, findings=[finding]
    )
    assert "- **Confirmed findings**: 0" in report
    assert "exploit did not reproduce" in report


def test_non_critical_verified_poc_is_not_a_confirmed_finding():
    finding = dict(ACCESS_Q1B_ONLY)  # High, Q1b passes, PoC passed
    finding["poc_result"] = {"status": "passed", "output": "proved on High"}
    report = mr.generate_mini_review(
        VULN_SOURCE, file_path="Vault.sol", commit=COMMIT, findings=[finding]
    )
    assert "- **Confirmed findings**: 0" in report
    confirmed = _section(report, "## Confirmed findings")
    assert "Access Control" not in confirmed
    assert "## Other items (not Confirmed findings)" in report


def test_reentrancy_critical_without_poc_still_confirmed():
    # Reentrancy is the exception: its code evidence (PR #34) is the
    # proof, and a PoC is recorded as "not attempted", not invented.
    report = mr.generate_mini_review(
        VULN_SOURCE, file_path="Vault.sol", commit=COMMIT,
        findings=[{"name": "Reentrancy", "severity": "Critical",
                   "description": "Reentrancy in withdraw()"}],
    )
    assert "- **Confirmed findings**: 1" in report
    assert "- **PoC result**: not attempted" in report


def test_attempt_poc_without_toolchain_is_could_not_run_not_a_pass(tmp_path, monkeypatch):
    poc = tmp_path / "PoC.t.sol"
    poc.write_text("// SPDX-License-Identifier: MIT\npragma solidity ^0.8.0;\n")
    # Simulate a missing toolchain deterministically: CI runners have
    # docker and forge, so this test must not depend on the real
    # environment. A missing toolchain must never be reported as a
    # pass or a failure of the exploit.
    monkeypatch.setattr("shutil.which", lambda name: None)
    result = mr.attempt_poc(str(poc), victim_code=VULN_SOURCE, use_docker=True)
    assert result["status"] == "could-not-run"
    assert "Docker not found" in result["error"]
    result_local = mr.attempt_poc(
        str(poc), victim_code=VULN_SOURCE, use_docker=False
    )
    assert result_local["status"] == "could-not-run"
    assert "forge not installed" in result_local["error"]


def test_attempt_poc_via_generate_records_could_not_run(tmp_path, monkeypatch):
    poc = tmp_path / "PoC.t.sol"
    poc.write_text("// SPDX-License-Identifier: MIT\npragma solidity ^0.8.0;\n")
    # Same deterministic simulation as above: do not depend on the
    # real CI/local toolchain for the could-not-run wording.
    monkeypatch.setattr("shutil.which", lambda name: None)
    report = mr.generate_mini_review(
        VULN_SOURCE, file_path="Vault.sol", commit=COMMIT,
        findings=[{"name": "Reentrancy", "severity": "Critical",
                   "description": "Reentrancy in withdraw()",
                   "poc_path": str(poc)}],
        attempt_poc=True,
    )
    assert "- **PoC result**: could-not-run" in report
    assert "Docker not found" in report


def test_poc_results_parameter_records_verbatim():
    report = mr.generate_mini_review(
        VULN_SOURCE, file_path="Vault.sol", commit=COMMIT,
        findings=[dict(ACCESS_Q1B_ONLY, severity="Critical")],
        poc_results=[{"status": "passed", "output": "PARAM-VERBATIM-789"}],
    )
    assert "- **Confirmed findings**: 1" in report
    assert "PARAM-VERBATIM-789" in report
