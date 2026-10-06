from knowledge_base.db import KnowledgeBase
from knowledge_base.pattern_extractor import PatternExtractor


def test_audit_finding_creates_real_cross_session_pattern(tmp_path):
    kb = KnowledgeBase(str(tmp_path / "knowledge.db"))
    extractor = PatternExtractor(kb)

    report = """## [High]: Unchecked Low-Level Call Return Value
- **Severity**: High
- **Fix**: Require the call result to be checked before continuing.
"""
    stored = extractor.learn_from_report(
        report,
        code="(bool ok,) = target.call(data);",
        protocol_name="test-protocol",
    )

    assert stored == 1

    rows = kb.get_patterns_by_severity("High", limit=10)
    assert len(rows) == 1
    assert rows[0]["name"] == "Unchecked Low-Level Call Return Value"
    assert rows[0]["hit_count"] == 1
    assert rows[0]["confirmed_count"] == 0

    # Unconfirmed discoveries remain candidates and are not RAG-eligible
    # under the default confidence gate.
    assert kb.get_patterns_for_rag(min_confidence=0.25) == []

    assert kb.confirm_pattern(rows[0]["id"], "Independent verification reproduced the finding") is True
    eligible = kb.get_patterns_for_rag(min_confidence=0.25)
    assert [p["name"] for p in eligible] == ["Unchecked Low-Level Call Return Value"]
