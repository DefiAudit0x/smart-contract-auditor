"""Regression tests for the Mini-Review generator (mini_review.py).

Solc-free by design: the generator reuses only the solc-free evidence
helpers (reentrancy_evidence, gate_validator Q1b, cvss_scorer).
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import pytest

import mini_review as mr

VULN_SOURCE = """
contract Vault {
    mapping(address => uint256) public balances;
    function withdraw(uint256 amount) public {
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "fail");
        balances[msg.sender] -= amount;
    }
}
"""

GUARDED_SOURCE = """
contract Vault {
    mapping(address => uint256) public balances;
    function withdraw(uint256 amount) public nonReentrant {
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "fail");
        balances[msg.sender] -= amount;
    }
}
"""

GUARD_NOTE_SOURCE = """
contract Vault {
    mapping(address => uint256) public balances;
    function ping(address target) public {
        (bool ok, ) = target.call("");
        require(ok, "fail");
    }
}
"""

COMMIT = "a6ad6111f33761f01b591c8e9c96ae6b8e900d11"


def _finding(name, severity, description, **extra):
    finding = {"name": name, "severity": severity, "description": description}
    finding.update(extra)
    return finding


class TestConfirmedReentrancy:
    def test_confirmed_reentrancy_is_confirmed_not_just_critical_label(self):
        report = mr.generate_mini_review(
            VULN_SOURCE, file_path="Vault.sol", commit=COMMIT,
            findings=[_finding(
                "Reentrancy", "Critical",
                "Reentrancy in withdraw(): attacker re-enters and drains funds",
                poc="Foundry test: withdraw, re-enter, withdraw again",
            )],
        )
        assert "Confirmed by code evidence / PoC" in report
        assert "- **Severity**: Critical" in report
        assert COMMIT in report

    def test_confirmed_reentrancy_without_poc_is_still_confirmed(self):
        triaged = mr.triage_findings(
            [_finding("Reentrancy", "Critical", "Reentrancy in withdraw()")],
            VULN_SOURCE,
        )
        assert triaged[0]["evidence_status"] == "Confirmed by code evidence"

    def test_auto_findings_generate_confirmed_reentrancy(self):
        report = mr.generate_mini_review(
            VULN_SOURCE, file_path="Vault.sol", commit=COMMIT
        )
        assert "### 1. Reentrancy" in report
        assert "Confirmed by code evidence" in report


class TestGuardNote:
    def test_guarded_function_is_not_confirmed_reentrancy(self):
        report = mr.generate_mini_review(
            GUARDED_SOURCE, file_path="Vault.sol", commit=COMMIT,
            findings=[_finding(
                "Reentrancy", "Critical", "Reentrancy in withdraw()",
            )],
        )
        # The guarded finding must not be presented as Confirmed.
        assert "Confirmed by code evidence" not in report
        assert "Guard note only" in report

    def test_guard_note_finding_stays_guard_note(self):
        triaged = mr.triage_findings(
            [_finding(
                "External Call Without Recognized Guard", "Medium",
                "External call in ping() with no recognized guard",
            )],
            GUARD_NOTE_SOURCE,
        )
        assert triaged[0]["evidence_status"] == "Guard note only"

    def test_guarded_source_generates_no_auto_finding(self):
        report = mr.generate_mini_review(
            GUARDED_SOURCE, file_path="Vault.sol", commit=COMMIT
        )
        assert "No findings to report" in report


class TestUnverified:
    def test_validation_failure_produces_unverified_banner(self):
        report = mr.generate_mini_review(
            VULN_SOURCE, file_path="Vault.sol", commit=COMMIT,
            findings=[_finding("Reentrancy", "Critical", "Reentrancy in withdraw()")],
            validation_failed=True,
        )
        assert "UNVERIFIED" in report
        assert "Validation Warning" in report

    def test_unverified_finding_flags_the_report(self):
        report = mr.generate_mini_review(
            VULN_SOURCE, file_path="Vault.sol", commit=COMMIT,
            findings=[_finding(
                "Reentrancy", "Critical", "Reentrancy in withdraw()",
                validation_error="gate raised",
            )],
        )
        assert "UNVERIFIED" in report
        assert "- **Evidence**: Unverified" in report


class TestCvssProvenance:
    def test_fallback_cvss_is_labelled_not_official(self):
        report = mr.generate_mini_review(
            VULN_SOURCE, file_path="Vault.sol", commit=COMMIT,
            findings=[_finding(
                "Reentrancy", "Critical", "Reentrancy in withdraw()",
            )],
        )
        assert "fallback_estimate" in report
        assert "not official" in report
        # A fallback must never read as a bare official score.
        assert "— assessed (method: official" not in report

    def test_explicit_cvss_attributes_are_assessed(self):
        triaged = mr.triage_findings(
            [_finding(
                "Reentrancy", "Critical", "Reentrancy in withdraw()",
                cvss_attributes={
                    "AV": "N", "AC": "L", "AT": "N", "PR": "N",
                    "UI": "N", "VC": "H", "VI": "H", "VA": "H",
                },
            )],
            VULN_SOURCE,
        )
        cvss = triaged[0]["cvss"]
        assert cvss["status"] == "assessed"
        assert cvss["vector"] == (
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
        )

    def test_missing_cvss_attributes_are_not_assessed(self):
        triaged = mr.triage_findings(
            [_finding(
                "Reentrancy", "Critical", "Reentrancy in withdraw()",
                cvss_attributes={"AV": "N", "AC": "L"},
            )],
            VULN_SOURCE,
        )
        assert triaged[0]["cvss"]["status"] == "not_assessed"
        assert triaged[0]["cvss"]["score"] is None


class TestScopeAndCommit:
    def test_missing_commit_is_recorded_not_invented(self):
        report = mr.generate_mini_review(
            VULN_SOURCE, file_path="Vault.sol",
            findings=[_finding("Reentrancy", "Critical", "Reentrancy in withdraw()")],
        )
        assert "- **Commit**: not provided" in report
        # No 40-hex hash should appear anywhere in the report.
        import re
        assert not re.search(r"\b[0-9a-f]{40}\b", report)

    def test_commit_is_recorded_verbatim(self):
        report = mr.generate_mini_review(
            VULN_SOURCE, file_path="Vault.sol", commit=COMMIT,
            findings=[],
        )
        assert f"- **Commit**: {COMMIT}" in report

    def test_scope_lists_out_of_scope(self):
        report = mr.generate_mini_review(
            VULN_SOURCE, file_path="Vault.sol", commit=COMMIT, findings=[]
        )
        assert "Out of scope" in report
        assert "every other file" in report

    def test_location_comes_from_source_not_invented(self):
        report = mr.generate_mini_review(
            VULN_SOURCE, file_path="Vault.sol", commit=COMMIT,
            findings=[_finding("Reentrancy", "Critical", "Reentrancy in withdraw()")],
        )
        # withdraw() is on line 4 of VULN_SOURCE (after the leading blank line).
        assert "- **Location**: Vault.sol:4" in report

    def test_summary_counts_by_severity_and_evidence(self):
        # Fix 2: only the Critical Confirmed finding counts in the
        # summary findings count. The Medium item names withdraw(),
        # which is code-confirmed reentrancy, so triage marks it
        # Confirmed but its severity is not Critical: it lands in
        # "Other items (not Confirmed findings)", not in Confirmed
        # findings and not in the guard-note appendix.
        report = mr.generate_mini_review(
            VULN_SOURCE, file_path="Vault.sol", commit=COMMIT,
            findings=[
                _finding("Reentrancy", "Critical", "Reentrancy in withdraw()"),
                _finding("External Call Without Recognized Guard", "Medium",
                         "External call in withdraw() with no recognized guard"),
            ],
        )
        assert "- **Confirmed findings**: 1" in report
        assert "- **Critical**: 1" in report
        assert "- **Other items (not Confirmed findings)**: 1" in report
        confirmed = report.split("## Confirmed findings")[1].split("## Other items")[0]
        assert "External Call Without Recognized Guard" not in confirmed

    def test_from_file_reads_file_and_commit(self, tmp_path):
        path = tmp_path / "Vault.sol"
        path.write_text(VULN_SOURCE)
        report = mr.generate_mini_review_from_file(
            str(path), commit=COMMIT
        )
        assert str(path) in report
        assert COMMIT in report
        assert "Confirmed by code evidence" in report
