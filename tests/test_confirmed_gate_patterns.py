from knowledge_base.db import KnowledgeBase


def test_gate_pattern_query_returns_only_human_confirmed(tmp_path):
    kb = KnowledgeBase(str(tmp_path / "knowledge.db"))
    candidate_id = kb.add_pattern("Candidate reentrancy", "High")
    confirmed_id = kb.add_pattern("Confirmed reentrancy", "High")

    assert kb.get_confirmed_patterns_for_gate() == []

    assert kb.confirm_pattern(
        confirmed_id,
        "Independent verification reproduced the finding",
    ) is True

    patterns = kb.get_confirmed_patterns_for_gate()
    assert [p["id"] for p in patterns] == [confirmed_id]
    assert patterns[0]["verification_status"] == "confirmed"
    assert patterns[0]["verification_evidence"] == "Independent verification reproduced the finding"

    # Candidate patterns must never reach the report deduplication gate.
    assert candidate_id not in {p["id"] for p in patterns}


def test_gate_pattern_query_respects_severity(tmp_path):
    kb = KnowledgeBase(str(tmp_path / "knowledge.db"))
    high_id = kb.add_pattern("Confirmed high", "High")
    low_id = kb.add_pattern("Confirmed low", "Low")

    evidence = "Independent verification reproduced the finding"
    assert kb.confirm_pattern(high_id, evidence) is True
    assert kb.confirm_pattern(low_id, evidence) is True

    high = kb.get_confirmed_patterns_for_gate(severity="High")
    assert [p["id"] for p in high] == [high_id]
    assert all(p["severity"] == "High" for p in high)

    low = kb.get_confirmed_patterns_for_gate(severity="Low")
    assert [p["id"] for p in low] == [low_id]
