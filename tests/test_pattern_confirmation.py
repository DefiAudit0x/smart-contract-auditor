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

    # A second confirmation must not inflate confidence in the current
    # single-admin model.
    assert kb.confirm_pattern(pattern_id) is False
    assert kb.get_pattern_confidence(pattern_id)["confirmed_count"] == 1


def test_confirm_pattern_rejects_unknown_id(tmp_path):
    kb = KnowledgeBase(str(tmp_path / "knowledge.db"))
    assert kb.confirm_pattern(999999) is False


def test_confirmation_remains_high_after_automated_rediscovery(tmp_path):
    kb = KnowledgeBase(str(tmp_path / "knowledge.db"))
    pattern_id = kb.add_pattern("Stable confirmed pattern", "Medium")

    assert kb.confirm_pattern(pattern_id) is True
    assert kb.get_pattern_confidence(pattern_id)["confidence"] == 0.9

    # Repeated automated rediscovery increments hits but is not independent
    # human evidence and must not revoke the existing confirmation.
    for _ in range(10):
        assert kb.find_or_merge_pattern("Stable confirmed pattern", "Medium") == pattern_id

    status = kb.get_pattern_confidence(pattern_id)
    assert status["hit_count"] == 11
    assert status["confirmed_count"] == 1
    assert status["confidence"] == 0.9
    assert [p["id"] for p in kb.get_patterns_for_rag(min_confidence=0.25)] == [pattern_id]
