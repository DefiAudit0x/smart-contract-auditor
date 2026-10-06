import json

import agents.pattern_learner as pl


def test_llm_mined_pattern_is_candidate_and_inactive(monkeypatch, tmp_path):
    path = tmp_path / "learned_patterns.json"
    monkeypatch.setattr(pl, "LEARNED_PATTERNS_PATH", str(path))
    monkeypatch.setattr(
        pl,
        "call_model_with_fallback",
        lambda prompt, timeout=120: '[{"name":"Novel state sync","description":"Detects a novel state synchronization risk","severity":"High","patterns":["state\\\\s+sync"]}]',
    )

    pl.learn_from_audit(
        "contract X { function f() external { state sync; } }",
        "High severity vulnerability with impact and recommendation",
        "No matching static finding",
    )

    stored = json.loads(path.read_text())
    assert stored[0]["verification_status"] == "candidate"
    assert pl.list_candidates()[0]["name"] == "Novel state sync"
    assert pl.get_learned_bug_classes() == {}
    assert pl.patterns_text() == ""


def test_candidate_requires_evidence_before_confirmation(monkeypatch, tmp_path):
    path = tmp_path / "learned_patterns.json"
    monkeypatch.setattr(pl, "LEARNED_PATTERNS_PATH", str(path))
    path.write_text(
        json.dumps([{
            "name": "Novel state sync",
            "description": "Detects a novel state synchronization risk",
            "severity": "High",
            "patterns": ["state\\s+sync"],
            "verification_status": "candidate",
        }])
    )

    assert pl.confirm_pattern("Novel state sync", "too short") is False
    assert pl.get_learned_bug_classes() == {}

    assert pl.confirm_pattern(
        "Novel state sync",
        "Independent reproduction confirms the finding in a Foundry test",
    ) is True

    classes = pl.get_learned_bug_classes()
    assert len(classes) == 1
    assert pl.patterns_text().startswith("### Pre-Scan: Verified Learned Patterns")
    stored = json.loads(path.read_text())
    assert stored[0]["verification_status"] == "confirmed"
    assert "verification_evidence" in stored[0]


def test_rejected_candidate_never_becomes_active(monkeypatch, tmp_path):
    path = tmp_path / "learned_patterns.json"
    monkeypatch.setattr(pl, "LEARNED_PATTERNS_PATH", str(path))
    path.write_text(
        json.dumps([{
            "name": "False pattern",
            "description": "A candidate that does not reproduce",
            "severity": "Medium",
            "patterns": ["never\\s+matches"],
            "verification_status": "candidate",
        }])
    )

    assert pl.reject_pattern(
        "False pattern",
        "Independent review could not reproduce the finding",
    ) is True
    assert pl.get_learned_bug_classes() == {}
    assert pl.patterns_text() == ""
