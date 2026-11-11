"""Priority 3: silent truncation must be surfaced, skipped external
tools must be reported as SKIPPED — never silently omitted.

Every test here is toolchain-independent (the PR #45 lesson): tool
availability is faked by monkeypatching ``tool_available`` /
``shutil.which`` / the runner functions, never by asserting what this
VM or a CI runner really has installed.  LLM calls are faked too, so
no test needs an API key, docker, forge, solc, or a network call.
"""

import re
import sys
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import agents.pipeline as pipeline
import agents.pattern_learner as pattern_learner
import agents.truncation as truncation
import external_analyzers as ext
import mcp_integration as mcp
import telegram_bot as tg

MOCK_REPORT = "## Report\n\n### Finding: test\n- **Severity:** High\n"


# ─── Shared helper ──────────────────────────────────────────────────

class TestTruncationHelper:
    def test_no_notice_when_nothing_cut(self):
        assert truncation.truncation_notice("x", 100, 100) is None
        assert truncation.truncation_notice("x", 50, 100) is None
        assert truncation.scope_notices_section([]) == ""
        assert truncation.skipped_tools_section([]) == ""

    def test_notice_carries_exact_lengths(self):
        notice = truncation.truncation_notice("pipeline", 5000, 3000)
        assert "original 5000 chars" in notice
        assert "analysed 3000 chars" in notice
        assert "2000 chars were NOT analysed" in notice

    def test_append_is_idempotent(self):
        once = truncation.append_scope_notices(
            MOCK_REPORT, ["- pipeline: input truncated — original 9 chars, analysed 3 chars (6 chars were NOT analysed)."]
        )
        assert truncation.TRUNCATION_SECTION_HEADING in once
        assert truncation.append_scope_notices(once, ["- other: x"]) == once

    def test_skipped_section_names_tool_and_reason(self):
        section = truncation.skipped_tools_section(
            [("slither", "not installed")]
        )
        assert "slither: SKIPPED" in section
        assert "not installed" in section
        # A tool that ran and found nothing must never be listed here.
        assert truncation.skipped_tools_section([]) == ""


# ─── Pipeline: analyze_code ─────────────────────────────────────────

def _patch_pipeline(monkeypatch, validate=None):
    monkeypatch.setattr(pipeline, "call_model_with_fallback", lambda *a, **k: MOCK_REPORT)
    monkeypatch.setattr(pipeline, "validate_report", validate or (lambda r, c, lang="english": r))
    monkeypatch.setattr(pipeline, "_has_gate", False)
    monkeypatch.setattr(pipeline, "KB_AUTO_LEARN", False)
    monkeypatch.setattr(pipeline, "run_pre_scan", lambda code: "")


def _long_contract():
    # gemma-2-27b context is 8192, so truncate_code caps at 4096 chars.
    return (
        "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.0;\n"
        "contract A {\n" + "    uint256 private dummy;\n" * 400 + "}\n"
    )


class TestAnalyzeCodeTruncation:
    def test_short_code_has_no_scope_section(self, monkeypatch):
        _patch_pipeline(monkeypatch)
        result = pipeline.analyze_code("contract A { uint x; }")
        assert truncation.TRUNCATION_SECTION_HEADING not in result

    def test_long_code_reports_pipeline_and_validator_cuts(self, monkeypatch):
        _patch_pipeline(monkeypatch)
        code = _long_contract()
        assert len(code) > 4096
        truncated = pipeline.truncate_code(code, "gemma-2-27b")
        # The prompt footer states the analysed length; the report
        # notice must agree with it exactly.
        footer = re.search(r"-> (\d+) chars", truncated)
        assert footer is not None
        analysed = int(footer.group(1))
        result = pipeline.analyze_code(code, model_key="gemma-2-27b")
        assert truncation.TRUNCATION_SECTION_HEADING in result
        assert f"pipeline truncate_code: input truncated — original {len(code)} chars, analysed {analysed} chars" in result
        # The validator sees the (already truncated) code, capped at 3000.
        assert f"second-pass validator: input truncated — original {len(truncated)} chars, analysed 3000 chars" in result

    def test_validator_failure_still_reports_pipeline_cut(self, monkeypatch):
        def _boom(report, code, lang="english"):
            raise RuntimeError("validator down")
        _patch_pipeline(monkeypatch, validate=_boom)
        code = _long_contract()
        result = pipeline.analyze_code(code, model_key="gemma-2-27b")
        assert "### Validation Warning" in result
        assert "pipeline truncate_code" in result
        # A failed validator saw nothing, so no validator-cut claim.
        assert "second-pass validator" not in result


# ─── Pipeline: chunked_audit ────────────────────────────────────────

class TestChunkedAuditTruncation:
    def test_long_function_chunks_are_noticed(self, monkeypatch):
        monkeypatch.setattr(pipeline, "call_model_with_fallback", lambda *a, **k: "chunk ok")
        body = "    uint256 a;\n" * 400  # ~6400 chars per function
        code = (
            "contract A {\n"
            f"    function f() public {{\n{body}    }}\n"
            f"    function g() public {{\n{body}    }}\n"
            "}\n"
        )
        chunks = pipeline._split_functions(code)
        assert len(chunks) >= 2
        result = pipeline.chunked_audit(code)
        assert truncation.TRUNCATION_SECTION_HEADING in result
        for chunk in chunks:
            original = chunk.get("original_len", len(chunk["code"]))
            if original > 4000:
                assert (
                    f"chunked audit chunk '{chunk['name']}': input truncated "
                    f"— original {original} chars, analysed 4000 chars"
                ) in result

    def test_short_function_chunks_have_no_notice(self, monkeypatch):
        monkeypatch.setattr(pipeline, "call_model_with_fallback", lambda *a, **k: "chunk ok")
        code = (
            "contract A {\n"
            "    function f() public { uint a = 1; }\n"
            "    function g() public { uint b = 2; }\n"
            "}\n"
        )
        result = pipeline.chunked_audit(code)
        assert truncation.TRUNCATION_SECTION_HEADING not in result

    def test_fallback_full_chunk_records_original_length(self):
        code = "uint a;\n" * 2000  # no functions at all -> fallback chunk
        chunks = pipeline._split_functions(code)
        assert len(chunks) == 1 and chunks[0]["name"] == "full"
        assert chunks[0]["original_len"] == len(code)
        assert len(chunks[0]["code"]) == 5000


# ─── Pattern learner prompt ─────────────────────────────────────────

class TestPatternLearnerTruncation:
    def test_long_inputs_noticed_inside_prompt(self, monkeypatch):
        captured = {}

        def _fake(prompt, **kwargs):
            captured["prompt"] = prompt
            return "[]"

        monkeypatch.setattr(pattern_learner, "call_model_with_fallback", _fake)
        code = "x" * 2500
        report = "y" * 3500
        pattern_learner.learn_from_audit(code, report, "")
        prompt = captured["prompt"]
        assert "original 2500 chars, shown first 2000 chars" in prompt
        assert "500 chars omitted" in prompt
        assert "original 3500 chars, shown first 3000 chars" in prompt

    def test_short_inputs_have_no_notice(self, monkeypatch):
        captured = {}

        def _fake(prompt, **kwargs):
            captured["prompt"] = prompt
            return "[]"

        monkeypatch.setattr(pattern_learner, "call_model_with_fallback", _fake)
        pattern_learner.learn_from_audit("contract A {}", "short report", "")
        assert "was truncated for this prompt" not in captured["prompt"]


# ─── Telegram bot ───────────────────────────────────────────────────

def _bot_with_captured_send(monkeypatch):
    bot = tg.TelegramBot(token="test")
    sent = []
    monkeypatch.setattr(bot, "_send", lambda chat_id, text, **k: sent.append(text))
    monkeypatch.setattr(bot, "_send_action", lambda *a, **k: None)
    monkeypatch.setattr(bot, "_track", lambda *a, **k: None)
    return bot, sent


class TestTelegramTruncation:
    def test_audit_notifies_before_analysing(self, monkeypatch):
        bot, sent = _bot_with_captured_send(monkeypatch)
        import agents as agents_pkg
        monkeypatch.setattr(agents_pkg, "analyze_code", lambda code: "REPORT")
        bot._run_audit(123, "z" * 5000)
        assert sent, "expected a truncation notice and a result message"
        assert "received 5000 chars" in sent[0]
        assert "first 3000 chars" in sent[0]
        assert "2000 chars were NOT analysed" in sent[0]
        assert any("REPORT" in m for m in sent)

    def test_audit_short_code_sends_no_notice(self, monkeypatch):
        bot, sent = _bot_with_captured_send(monkeypatch)
        import agents as agents_pkg
        monkeypatch.setattr(agents_pkg, "analyze_code", lambda code: "REPORT")
        bot._run_audit(123, "contract A {}")
        assert not any("Input truncated" in m for m in sent)
        assert any("REPORT" in m for m in sent)

    def test_display_text_suffix_carries_lengths(self):
        out = tg.TelegramBot._display_text("x" * 5000)
        assert len(out) <= 4000
        assert "5000 chars total" in out
        assert "first 3900 shown" in out
        assert tg.TelegramBot._display_text("short") == "short"

    def test_zip_per_file_cap_noted_in_header(self, monkeypatch, tmp_path):
        bot, _ = _bot_with_captured_send(monkeypatch)
        zpath = tmp_path / "proj.zip"
        with zipfile.ZipFile(zpath, "w") as zf:
            zf.writestr("A.sol", "a" * 2500)
            zf.writestr("B.sol", "b" * 100)
        combined = bot._extract_zip(str(zpath))
        assert "A.sol" in combined and "(truncated: first 2000 of 2500 chars)" in combined
        assert "(truncated: first 2000 of 100 chars)" not in combined

    def test_document_download_cap_noted_in_receipt(self, monkeypatch):
        bot, sent = _bot_with_captured_send(monkeypatch)
        captured = {}
        monkeypatch.setattr(bot, "_dispatch", lambda fn, chat_id, *a, **k: captured.setdefault("code", a[0] if a else None))

        class _Resp:
            def __init__(self, status=200, text="", file_path=""):
                self.status_code = status
                self.text = text
                self.content = text.encode()
                self._file_path = file_path

            def json(self):
                return {"result": {"file_path": self._file_path}}

        calls = {"n": 0}

        def _fake_get(url, timeout=None):
            calls["n"] += 1
            if "getFile" in url:
                return _Resp(file_path="docs/x.sol")
            return _Resp(text="q" * 6000)

        monkeypatch.setattr(tg.requests, "get", _fake_get)
        bot._handle_document({"file_id": "abc", "file_name": "x.sol"}, 123)
        assert any("first 5000 of 6000 chars" in m for m in sent)
        assert len(captured["code"]) == 5000

    def test_github_file_count_and_per_file_caps_noted(self, monkeypatch):
        bot, sent = _bot_with_captured_send(monkeypatch)
        captured = {}
        monkeypatch.setattr(bot, "_dispatch", lambda fn, chat_id, *a, **k: captured.setdefault("code", a[0] if a else None))
        import github_loader
        monkeypatch.setattr(github_loader, "extract_repo_info", lambda url: ("o", "r"))
        files = [
            {"name": f"F{i}.sol", "code": "c" * 2500} for i in range(6)
        ]
        monkeypatch.setattr(github_loader, "get_all_sol_files", lambda *a, **k: files)
        bot._handle_github(123, "https://github.com/o/r")
        code = captured["code"]
        assert "only first 5 of 6 files included" in code
        assert "(truncated: first 2000 of 2500 chars)" in code


# ─── External tools: SKIPPED ────────────────────────────────────────

class TestExternalToolsSkipped:
    def test_both_missing_reported_as_skipped(self, monkeypatch):
        monkeypatch.setattr(ext, "tool_available", lambda tool, ttl=30.0: False)
        skipped = ext.skipped_external_tools()
        assert [t for t, _ in skipped] == ["slither", "mythril"]
        assert all("not installed" in reason for _, reason in skipped)
        text = ext.external_analysis_text("contract A {}")
        assert "slither: SKIPPED" in text
        assert "mythril: SKIPPED" in text

    def test_available_tool_with_finding_is_not_skipped(self, monkeypatch):
        monkeypatch.setattr(ext, "tool_available", lambda tool, ttl=30.0: True)
        monkeypatch.setattr(
            ext, "_run_slither_on_code",
            lambda code, tmp: [ext.ExternalFinding(tool="slither", check="reentrancy", severity="High", description="d")],
        )
        monkeypatch.setattr(ext, "_run_mythril_on_code", lambda code, tmp: [])
        text = ext.external_analysis_text("contract A {}")
        assert "reentrancy" in text
        assert "SKIPPED" not in text

    def test_partial_availability_reports_only_the_missing_tool(self, monkeypatch):
        monkeypatch.setattr(ext, "tool_available", lambda tool, ttl=30.0: tool == "slither")
        monkeypatch.setattr(ext, "_run_slither_on_code", lambda code, tmp: [])
        text = ext.external_analysis_text("contract A {}")
        assert "slither: SKIPPED" not in text
        assert "mythril: SKIPPED" in text

    def test_audit_service_surface_skipped(self, monkeypatch):
        monkeypatch.setattr(ext, "tool_available", lambda tool, ttl=30.0: False)
        from audit_service import AuditService
        text = AuditService.run_external_analyzers("contract A {}")
        assert "slither: SKIPPED" in text

    def test_mcp_skipped_tools_key(self, monkeypatch):
        monkeypatch.setattr(mcp, "_run_slither", lambda path: [])
        monkeypatch.setattr(mcp, "_run_aderyn", lambda path: [])
        monkeypatch.setattr(mcp.shutil, "which", lambda name: None)
        result = mcp.analyze_contract(
            "contract A {}", contract_path="/tmp/x.sol",
            analyzers=["swc", "slither", "aderyn"],
        )
        tools = [s["tool"] for s in result["skipped_tools"]]
        assert tools == ["slither", "aderyn"]
        assert all(s["status"] == "SKIPPED" for s in result["skipped_tools"])
        monkeypatch.setattr(mcp.shutil, "which", lambda name: "/usr/bin/" + name)
        result2 = mcp.analyze_contract(
            "contract A {}", contract_path="/tmp/x.sol",
            analyzers=["slither", "aderyn"],
        )
        assert result2["skipped_tools"] == []
