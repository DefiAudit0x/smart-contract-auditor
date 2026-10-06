from knowledge_base.db import KnowledgeBase


def test_confirm_pattern_promotes_confidence(tmp_path):
    kb = KnowledgeBase(str(tmp_path / "knowledge.db"))
    pattern_id = kb.add_pattern("Confirmed reentrancy", "High")

    before = kb.get_pattern_confidence(pattern_id)
    assert before["confirmed_count"] == 0
    assert before["confidence"] == 0.1
    assert kb.get_patterns_for_rag(min_confidence=0.25) == []

    assert kb.confirm_pattern(pattern_id) is True

    after = kb.get_pattern_confidence(pattern_id)
    assert after["confirmed_count"] == 1
    assert after["confidence"] == 0.9
    eligible = kb.get_patterns_for_rag(min_confidence=0.25)
    assert [p["id"] for p in eligible] == [pattern_id]


def test_confirm_pattern_rejects_unknown_id(tmp_path):
    kb = KnowledgeBase(str(tmp_path / "knowledge.db"))
    assert kb.confirm_pattern(999999) is False
