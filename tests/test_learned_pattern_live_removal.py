"""Priority 6 (c): removing a confirmed learned pattern from the file
must deregister it from a running process at the next pre-scan —
no restart — while survivors keep firing.

This tests the file-removal path directly (the documented removal
mechanism; there is no separate removal API): seed two confirmed
patterns, register, edit the file, re-register in the SAME process,
and assert the deleted pattern's detector is gone and the survivor
still fires. No toolchain (forge/docker/LLM) is involved: the
patterns are plain regexes checked by the isolated worker.
"""

import json

import agents.pattern_learner as pl
import agents.pre_scan as ps


def _candidate(name, pattern):
    return {
        "name": name,
        "description": f"Detects {name}",
        "severity": "High",
        "patterns": [pattern],
        "verification_status": "candidate",
    }


def _seed_confirmed(monkeypatch, tmp_path):
    path = tmp_path / "learned_patterns.json"
    monkeypatch.setattr(pl, "LEARNED_PATTERNS_PATH", str(path))
    first = _candidate("Alpha marker", r"alpha\s+marker")
    second = _candidate("Beta marker", r"beta\s+marker")
    pl._save_learned([dict(first), dict(second)])
    vuln_a = "contract X { function f() external { alpha marker; } }"
    fixed_a = "contract X { function f() external { alpha clean; } }"
    vuln_b = "contract X { function f() external { beta marker; } }"
    fixed_b = "contract X { function f() external { beta clean; } }"
    assert pl.confirm_pattern_poc("Alpha marker", vuln_a, fixed_a)[0] is True
    assert pl.confirm_pattern_poc("Beta marker", vuln_b, fixed_b)[0] is True
    return path


def _cleanup():
    import bug_detector

    for key in [k for k in bug_detector._BUG_CLASSES if k.startswith("learned_")]:
        del bug_detector._BUG_CLASSES[key]
        if key in bug_detector._BUG_CLASS_ORDER:
            bug_detector._BUG_CLASS_ORDER.remove(key)
    ps._learned_classes = None
    ps._learned_signature = None


def _firing_names(code):
    import bug_detector

    names = set()
    for key in [k for k in bug_detector._BUG_CLASSES if k.startswith("learned_")]:
        if bug_detector._BUG_CLASSES[key]["detect"](code):
            names.add(bug_detector._BUG_CLASSES[key]["name"])
    return names


def test_removing_first_pattern_deregisters_it_survivor_keeps_firing(
    monkeypatch, tmp_path
):
    path = _seed_confirmed(monkeypatch, tmp_path)
    try:
        ps._learned_classes = None
        ps._learned_signature = None
        ps._register_learned_classes()
        assert _firing_names("alpha marker") == {"Alpha marker"}
        assert _firing_names("beta marker") == {"Beta marker"}

        # Remove the FIRST confirmed pattern from the file (the
        # positional-key shift case: Beta moves from learned_1 to
        # learned_0 in the fresh set). No process restart.
        stored = json.loads(path.read_text())
        pl._save_learned([p for p in stored if p["name"] != "Alpha marker"])

        ps._register_learned_classes()
        assert _firing_names("alpha marker") == set()
        assert _firing_names("beta marker") == {"Beta marker"}
        assert pl.get_learned_bug_classes() != {}
    finally:
        _cleanup()


def test_removing_all_patterns_deregisters_everything(monkeypatch, tmp_path):
    _seed_confirmed(monkeypatch, tmp_path)
    try:
        ps._learned_classes = None
        ps._learned_signature = None
        ps._register_learned_classes()
        assert _firing_names("alpha marker") == {"Alpha marker"}

        pl._save_learned([])
        ps._register_learned_classes()
        assert _firing_names("alpha marker") == set()
        assert _firing_names("beta marker") == set()
    finally:
        _cleanup()


def test_unchanged_set_does_not_churn_registered_keys(monkeypatch, tmp_path):
    _seed_confirmed(monkeypatch, tmp_path)
    try:
        ps._learned_classes = None
        ps._learned_signature = None
        ps._register_learned_classes()
        import bug_detector

        before = sorted(
            k for k in bug_detector._BUG_CLASSES if k.startswith("learned_")
        )
        ps._register_learned_classes()
        after = sorted(
            k for k in bug_detector._BUG_CLASSES if k.startswith("learned_")
        )
        assert before == after
        assert _firing_names("beta marker") == {"Beta marker"}
    finally:
        _cleanup()
