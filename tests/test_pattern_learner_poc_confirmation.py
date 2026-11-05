"""Fix 1 (2026-11-05): self-learning must be PoC-confirmed, persistent,
and effective without a process restart — or not promised at all.

These tests cover the REAL path: a candidate is listed, it stays
inactive on text evidence alone, it confirms only when its regex
fires on a vulnerable sample and not on a fixed sample, a later
confirmation is picked up by the next pre-scan registration, and
learned patterns are stored on a persistent path (not the repo root).
"""

import json
import os

import agents.pattern_learner as pl
import agents.pre_scan as ps


VULNERABLE = "contract X { function f() external { state sync; } }"
FIXED = "contract X { function f() external { state updated; } }"
CANDIDATE = {
    "name": "Novel state sync",
    "description": "Detects a novel state synchronization risk",
    "severity": "High",
    "patterns": [r"state\s+sync"],
    "verification_status": "candidate",
}


def _seed(monkeypatch, tmp_path):
    path = tmp_path / "learned_patterns.json"
    monkeypatch.setattr(pl, "LEARNED_PATTERNS_PATH", str(path))
    pl._save_learned([dict(CANDIDATE)])
    return path


def test_candidate_listed_but_inactive(monkeypatch, tmp_path):
    _seed(monkeypatch, tmp_path)
    assert [c["name"] for c in pl.list_candidates()] == ["Novel state sync"]
    assert pl.get_learned_bug_classes() == {}
    assert pl.patterns_text() == ""


def test_text_evidence_alone_never_confirms(monkeypatch, tmp_path):
    _seed(monkeypatch, tmp_path)
    ok, reason = pl.confirm_pattern_poc(
        "Novel state sync", "", "",
        "Independent reproduction confirms the finding in a Foundry test",
    )
    assert ok is False
    assert pl.confirm_pattern(
        "Novel state sync",
        "Independent reproduction confirms the finding in a Foundry test",
    ) is False
    assert pl.get_learned_bug_classes() == {}


def test_poc_confirmation_succeeds_only_on_vuln_not_fixed(monkeypatch, tmp_path):
    _seed(monkeypatch, tmp_path)
    # Fires on fixed too -> rejected, stays a candidate.
    ok, _reason = pl.confirm_pattern_poc(
        "Novel state sync", VULNERABLE, VULNERABLE
    )
    assert ok is False
    # Does not fire on vulnerable -> rejected, stays a candidate.
    ok, _reason = pl.confirm_pattern_poc(
        "Novel state sync", FIXED, FIXED
    )
    assert ok is False
    assert pl.get_learned_bug_classes() == {}

    # Fires on vulnerable, not on fixed -> confirmed and active.
    ok, reason = pl.confirm_pattern_poc("Novel state sync", VULNERABLE, FIXED)
    assert ok is True, reason
    classes = pl.get_learned_bug_classes()
    assert len(classes) == 1
    stored = json.loads((tmp_path / "learned_patterns.json").read_text())
    assert stored[0]["verification_status"] == "confirmed"
    assert stored[0]["verification_method"] == "poc_regex"


def test_later_confirmation_takes_effect_without_restart(monkeypatch, tmp_path):
    import bug_detector

    _seed(monkeypatch, tmp_path)
    ps._learned_classes = None
    ps._learned_signature = None
    learned_keys = [k for k in bug_detector._BUG_CLASSES if k.startswith("learned_")]
    try:
        for key in learned_keys:
            del bug_detector._BUG_CLASSES[key]
            if key in bug_detector._BUG_CLASS_ORDER:
                bug_detector._BUG_CLASS_ORDER.remove(key)
        # First registration with zero confirmed patterns: the old code
        # cached {} and never looked again.
        ps._register_learned_classes()
        assert ps._learned_classes == {}
        assert not [k for k in bug_detector._BUG_CLASSES if k.startswith("learned_")]

        ok, _reason = pl.confirm_pattern_poc("Novel state sync", VULNERABLE, FIXED)
        assert ok is True
        # Second registration in the SAME process must pick it up.
        ps._register_learned_classes()
        keys = [k for k in bug_detector._BUG_CLASSES if k.startswith("learned_")]
        assert len(keys) == 1
        # And the registered detector actually fires on vulnerable code.
        assert bug_detector._BUG_CLASSES[keys[0]]["detect"](VULNERABLE)
        assert not bug_detector._BUG_CLASSES[keys[0]]["detect"](FIXED)
    finally:
        for key in [k for k in bug_detector._BUG_CLASSES if k.startswith("learned_")]:
            del bug_detector._BUG_CLASSES[key]
            if key in bug_detector._BUG_CLASS_ORDER:
                bug_detector._BUG_CLASS_ORDER.remove(key)
        ps._learned_classes = None
        ps._learned_signature = None


def test_persistent_path_is_not_repo_root(monkeypatch, tmp_path):
    monkeypatch.delenv("LEARNED_PATTERNS_PATH", raising=False)
    default = pl._default_learned_patterns_path()
    legacy = os.path.abspath(os.fspath(pl._LEGACY_LEARNED_PATTERNS_PATH))
    assert os.path.abspath(default) != legacy
    assert default.endswith("learned_patterns.json")
    # Env override is honoured.
    monkeypatch.setenv("LEARNED_PATTERNS_PATH", str(tmp_path / "custom.json"))
    assert pl._default_learned_patterns_path() == str(tmp_path / "custom.json")


def test_save_creates_missing_persistent_directory(monkeypatch, tmp_path):
    path = tmp_path / "newdir" / "learned_patterns.json"
    monkeypatch.setattr(pl, "LEARNED_PATTERNS_PATH", str(path))
    pl._save_learned([dict(CANDIDATE)])
    assert path.is_file()


def test_legacy_repo_root_file_is_migrated_once(monkeypatch, tmp_path):
    legacy = tmp_path / "legacy_learned_patterns.json"
    legacy.write_text(json.dumps([dict(CANDIDATE)]))
    new_path = tmp_path / "instance" / "learned_patterns.json"
    monkeypatch.setattr(pl, "LEARNED_PATTERNS_PATH", str(new_path))
    monkeypatch.setattr(pl, "_LEGACY_LEARNED_PATTERNS_PATH", str(legacy))
    monkeypatch.setattr(
        pl, "_default_learned_patterns_path", lambda: str(new_path)
    )
    loaded = pl._load_learned()
    assert [p["name"] for p in loaded] == ["Novel state sync"]
    assert new_path.is_file()
    # Legacy file left intact for inspection / rollback.
    assert legacy.is_file()
