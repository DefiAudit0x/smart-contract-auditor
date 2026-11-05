"""Priority 4: pre-scan failures visible in the report + honest CVSS rendering.

Toolchain-free by design: pre-scan tasks are mocked (never the real
environment's toolchain, per the PR #45 CI lesson), CVSS needs no
compiler, and the pipeline path mocks the LLM/validation/gate steps.
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import pytest

import agents.pre_scan as ps
import cvss_scorer as cvss
import hackerone_report as h1


def _ok_task(code):
    return "### Pre-Scan: ok\n- something found"


def _boom_task(code):
    raise RuntimeError("simulated scanner crash")


@pytest.fixture(autouse=True)
def _no_registration(monkeypatch):
    # Learned-pattern registration touches the real pattern store;
    # these tests are about task-failure plumbing, not registration.
    monkeypatch.setattr(ps, "_register_learned_classes", lambda: None)


class TestPreScanFailures:
    def test_failed_task_appears_with_name_and_reason(self, monkeypatch):
        monkeypatch.setattr(ps, "_SCAN_TASKS", [
            ("ok_task", _ok_task),
            ("boom_task", _boom_task),
        ])
        text, failures = ps.run_pre_scan_with_failures("contract C {}")
        assert len(failures) == 1
        assert failures[0]["task"] == "boom_task"
        assert "simulated scanner crash" in failures[0]["error"]
        # The failure is in the returned text, not only in a log line.
        assert "boom_task" in text
        assert "simulated scanner crash" in text
        assert "INCOMPLETE" in text
        assert "complete coverage" in text
        # The surviving task still ran: the audit is not aborted.
        assert "something found" in text

    def test_run_pre_scan_string_carries_failure_section(self, monkeypatch):
        monkeypatch.setattr(ps, "_SCAN_TASKS", [
            ("boom_task", _boom_task),
        ])
        text = ps.run_pre_scan("contract C {}")
        assert "Failed pre-scan task: boom_task" in text
        assert "simulated scanner crash" in text

    def test_fully_successful_pre_scan_has_no_failure_entry(self, monkeypatch):
        monkeypatch.setattr(ps, "_SCAN_TASKS", [
            ("ok_task", _ok_task),
            ("quiet_task", lambda c: ""),
        ])
        text, failures = ps.run_pre_scan_with_failures("contract C {}")
        assert failures == []
        assert "Failed pre-scan task" not in text
        assert "INCOMPLETE" not in text
        assert ps.format_pre_scan_failures(failures) == ""
        assert ps.format_pre_scan_failures([]) == ""

    def test_failure_section_lists_every_failed_task(self):
        section = ps.format_pre_scan_failures([
            {"task": "mcp", "error": "ValueError: bad output"},
            {"task": "sbom", "error": "Timeout"},
        ])
        assert "Failed pre-scan task: mcp — ValueError: bad output" in section
        assert "Failed pre-scan task: sbom — Timeout" in section
        assert "2 of 9" in section


class TestPipelinePreScanSection:
    @pytest.fixture(autouse=True)
    def _mock_pipeline(self, monkeypatch):
        import agents.pipeline as pl
        monkeypatch.setattr(pl, "call_model_with_fallback",
                            lambda *a, **k: "# Audit\n" + "finding text\n" * 10)
        monkeypatch.setattr(pl, "validate_report",
                            lambda report, code, lang: report)
        monkeypatch.setattr(pl, "_has_gate", False)
        monkeypatch.setattr(pl, "cvss_score_report", lambda report: {"findings": []})
        monkeypatch.setattr(pl, "KB_AUTO_LEARN", False)
        return pl

    def test_pipeline_report_carries_failed_task(self, monkeypatch, _mock_pipeline):
        import agents.pipeline as pl
        monkeypatch.setattr(pl, "run_pre_scan_with_failures",
                            lambda code: ("pre-scan ctx", [
                                {"task": "mcp", "error": "RuntimeError: boom"}]))
        result = pl.analyze_code("contract C {}")
        assert "Failed pre-scan task: mcp" in result
        assert "RuntimeError: boom" in result
        assert "INCOMPLETE" in result

    def test_pipeline_report_has_no_failure_entry_on_success(
            self, monkeypatch, _mock_pipeline):
        import agents.pipeline as pl
        monkeypatch.setattr(pl, "run_pre_scan_with_failures",
                            lambda code: ("pre-scan ctx", []))
        result = pl.analyze_code("contract C {}")
        assert "Failed pre-scan task" not in result


def _report(name, severity, description, extra=""):
    return (
        f"- **Name**: {name}\n"
        f"- **Severity**: {severity}\n"
        f"- **Description**: {description}\n"
        f"{extra}"
    )


class TestCvssRendering:
    def test_fallback_estimate_labelled_as_estimate(self):
        scored = cvss.score_report(_report(
            "Withdraw", "High", "reentrancy drains funds"))
        entry = scored["findings"][0]
        assert entry["status"] == "fallback_estimate"
        rendered = cvss.format_finding_score(entry)
        assert "estimate" in rendered
        assert "not an attribute assessment" in rendered
        # Must not read as an official assessment: the estimate label
        # is on the same line (house style, as in mini_review), and the
        # assessed-with-official-method wording must never appear.
        assert "— estimate" in rendered
        assert "— assessed (method: official" not in rendered

    def test_genuinely_computed_score_still_renders_normally(self):
        attrs = "AV:N, AC:L, AT:N, PR:N, UI:N, VC:H, VI:H, VA:H"
        scored = cvss.score_report(_report(
            "Reentrancy", "Critical", "withdraw drains funds",
            f"- **CVSS Attributes**: {attrs}\n"))
        entry = scored["findings"][0]
        assert entry["status"] == "assessed"
        rendered = cvss.format_finding_score(entry)
        assert f"{entry['cvss_score']}/10" in rendered
        assert "assessed" in rendered
        assert "estimate" not in rendered or "internal estimate" in rendered

    def test_not_assessed_has_no_numeric_score(self):
        scored = cvss.score_report(_report(
            "Withdraw", "High", "reentrancy drains funds",
            "- **CVSS Attributes**: AV:N, PR:N\n"))
        entry = scored["findings"][0]
        assert entry["status"] == "not_assessed"
        assert entry["cvss_score"] is None
        assert cvss.format_finding_score(entry).startswith(
            "Not assessed — no score")
        assert scored["overall_score"] is None
        assert scored["overall_status"] == "not_assessed"
        assert cvss.format_overall_score(scored) == "Not assessed — no score"
        assert "0.0" not in cvss.format_overall_score(scored)

    def test_empty_report_overall_is_not_zero_safe(self):
        scored = cvss.score_report("")
        assert scored["overall_score"] is None
        assert scored["overall_status"] == "not_assessed"
        assert cvss.format_overall_score(scored) == "Not assessed — no score"

    def test_estimate_only_overall_labelled_estimate(self):
        scored = cvss.score_report(_report(
            "Withdraw", "High", "reentrancy drains funds"))
        assert scored["overall_basis"] == "estimate"
        assert "estimate" in cvss.format_overall_score(scored)

    def test_assessed_overall_not_labelled_estimate(self):
        attrs = "AV:N, AC:L, AT:N, PR:N, UI:N, VC:H, VI:H, VA:H"
        scored = cvss.score_report(_report(
            "Reentrancy", "Critical", "withdraw drains funds",
            f"- **CVSS Attributes**: {attrs}\n"))
        assert scored["overall_basis"] == "assessed"
        assert "estimate" not in cvss.format_overall_score(scored)

    def test_cvss_explanation_none_score_has_no_number(self):
        text = cvss.cvss_explanation(None, "Not Assessed", "")
        assert "Not assessed — no score" in text
        assert "0.0" not in text


class TestHackerOneRendering:
    def test_fallback_report_labels_estimate(self):
        report = h1.generate_h1_report(_report(
            "Withdraw", "High", "reentrancy drains funds"))
        assert "estimate" in report
        assert "— estimate" in report

    def test_not_assessed_report_has_no_zero_score_or_none_vector(self):
        report = h1.generate_h1_report(_report(
            "Withdraw", "High", "reentrancy drains funds",
            "- **CVSS Attributes**: AV:N, PR:N\n"))
        assert "Not assessed — no score" in report
        assert "0.0/10" not in report
        assert "`None`" not in report

    def test_not_assessed_short_report_has_no_zero_score(self):
        report = h1.generate_h1_short(_report(
            "Withdraw", "High", "reentrancy drains funds",
            "- **CVSS Attributes**: AV:N, PR:N\n"))
        assert "Not assessed — no score" in report
        assert "0.0/10" not in report
