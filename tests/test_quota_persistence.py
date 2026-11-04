"""Regression tests for issues #19 (quota ordering) and #22 (atomic
learned-pattern persistence).

#19: /api/analyze/project must reserve quota BEFORE any ZIP
validation/extraction or project parsing, and must release the
reservation on every failure path (bad archive, unsafe archive, no
source files) and consume it exactly once on success.

#22: _save_learned must write atomically (temp file + fsync + atomic
replace) under a lock, so concurrent writers cannot lose independent
updates or expose a partial file, and a corrupt persisted file must be
reported observably instead of silently becoming an empty database.
"""

import io
import json
import threading
import zipfile

import pytest

import agents.pattern_learner as pl
import api_routes
import auth
from _shared import _rate_limit_store
from web_ui import app


# ---------------------------------------------------------------------------
# Fixtures (same auth-db pattern as tests/test_code_quota_api.py)
# ---------------------------------------------------------------------------


@pytest.fixture
def quota_client(tmp_path, monkeypatch):
    previous = getattr(auth._local, "conn", None)
    if previous is not None:
        previous.close()
    auth._local.conn = None
    monkeypatch.setattr(auth, "AUTH_DB_PATH", str(tmp_path / "auth.db"))
    auth.init_auth_db()
    code = "SCA-API-0001"
    conn = auth._get_conn()
    conn.execute(
        "INSERT INTO access_codes (code, max_uses, is_active) VALUES (?, ?, 1)",
        (code, 2),
    )
    conn.commit()
    _rate_limit_store.clear()

    app.config.update(TESTING=True)
    with app.test_client() as client:
        with client.session_transaction() as session:
            session["authenticated"] = True
            session["access_code"] = code
        yield client, code

    conn.close()
    auth._local.conn = None


@pytest.fixture
def quota_code(tmp_path, monkeypatch):
    previous = getattr(auth._local, "conn", None)
    if previous is not None:
        previous.close()
    auth._local.conn = None
    monkeypatch.setattr(auth, "AUTH_DB_PATH", str(tmp_path / "auth.db"))
    auth.init_auth_db()
    conn = auth._get_conn()
    code = "SCA-TEST-0001"
    conn.execute(
        "INSERT INTO access_codes (code, max_uses, is_active) VALUES (?, ?, 1)",
        (code, 2),
    )
    conn.commit()
    yield code
    conn.close()
    auth._local.conn = None


# ---------------------------------------------------------------------------
# Helpers for #19
# ---------------------------------------------------------------------------


def _make_zip(members):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, content in members.items():
            zf.writestr(name, content)
    buf.seek(0)
    return buf


def _post_project(client, zip_bytes, key):
    return client.post(
        "/api/analyze/project",
        data={"project": (zip_bytes, "project.zip"), "entry_contract": ""},
        headers={"X-Idempotency-Key": key},
    )


def _mock_successful_stream(monkeypatch):
    """Make the project stream return a final report without an LLM."""
    monkeypatch.setattr(api_routes, "run_pre_scan", lambda combined: "pre-scan ok")

    def _fake_stream(model, prompt):
        yield (
            'data: {"token": "A sufficiently detailed audit report '
            'that contains more than twenty characters."}\n\n'
        )

    import agents.llm_client as llm_client

    monkeypatch.setattr(llm_client, "_stream_openrouter", _fake_stream)
    monkeypatch.setattr(llm_client, "_stream_ollama", _fake_stream)


_VALID_ZIP = {"Vault.sol": "contract Vault { function withdraw() external {} }"}


# ---------------------------------------------------------------------------
# Issue #19 — quota before expensive work
# ---------------------------------------------------------------------------


def test_exhausted_quota_rejects_before_zip_extraction(
    quota_client, monkeypatch
):
    client, code = quota_client
    # Exhaust the code's quota before the request (2 uses, as seeded).
    for i in range(2):
        reservation = auth.reserve_code_usage(code, f"exhaust-{i}")
        assert reservation["allowed"] is True
        auth.complete_code_usage(code, reservation["event_id"])
    assert auth.check_quota(code)["remaining"] == 0

    calls = []
    real_validate = api_routes.validate_zip_infos

    def _recording_validate(zf):
        calls.append("validate")
        raise AssertionError("ZIP validation must not run before quota")

    monkeypatch.setattr(api_routes, "validate_zip_infos", _recording_validate)

    response = _post_project(
        client, _make_zip(_VALID_ZIP), "exhausted-project"
    )
    assert response.status_code == 402
    assert calls == []
    assert auth.check_quota(code)["used"] == 2
    assert auth.check_quota(code)["reserved"] == 0


def test_invalid_archive_releases_reservation(quota_client, monkeypatch):
    client, code = quota_client
    response = _post_project(client, io.BytesIO(b"not a zip file"), "invalid-1")
    assert response.status_code == 400
    assert auth.check_quota(code)["used"] == 0
    assert auth.check_quota(code)["reserved"] == 0

    # The quota was not burned: a follow-up valid request still succeeds
    # and consumes exactly one unit.
    _mock_successful_stream(monkeypatch)
    response = _post_project(
        client, _make_zip(_VALID_ZIP), "valid-after-invalid"
    )
    response.get_data()
    assert response.status_code == 200
    assert auth.check_quota(code)["used"] == 1
    assert auth.check_quota(code)["reserved"] == 0


def test_unsafe_zip_releases_reservation(quota_client):
    client, code = quota_client
    response = _post_project(
        client, _make_zip({"evil.exe": "MZ"}), "unsafe-1"
    )
    assert response.status_code == 400
    assert auth.check_quota(code)["used"] == 0
    assert auth.check_quota(code)["reserved"] == 0


def test_successful_project_consumes_quota_exactly_once(
    quota_client, monkeypatch
):
    client, code = quota_client
    _mock_successful_stream(monkeypatch)
    response = _post_project(
        client, _make_zip(_VALID_ZIP), "success-1"
    )
    response.get_data()
    assert response.status_code == 200
    assert auth.check_quota(code)["used"] == 1
    assert auth.check_quota(code)["reserved"] == 0

    # Replaying the same idempotency key must not charge a second unit.
    duplicate = _post_project(
        client, _make_zip(_VALID_ZIP), "success-1"
    )
    assert duplicate.status_code == 409
    assert auth.check_quota(code)["used"] == 1


def test_concurrent_reservations_cannot_exceed_quota(quota_code):
    results = []
    barrier = threading.Barrier(10)

    def _try_reserve(i):
        barrier.wait(timeout=10)
        results.append(auth.reserve_code_usage(quota_code, f"race-{i}"))

    threads = [threading.Thread(target=_try_reserve, args=(i,)) for i in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=20)
    assert all(not t.is_alive() for t in threads)

    allowed = [r for r in results if r["allowed"]]
    assert len(allowed) == 2
    quota = auth.check_quota(quota_code)
    assert quota["used"] + quota["reserved"] <= 2


# ---------------------------------------------------------------------------
# Issue #22 — atomic learned-pattern persistence
# ---------------------------------------------------------------------------


def _candidate(name):
    return {
        "name": name,
        "description": "test pattern",
        "severity": "Medium",
        "patterns": ["test"],
        "verification_status": "candidate",
    }


def test_save_roundtrip_and_missing_file(monkeypatch, tmp_path):
    path = tmp_path / "learned_patterns.json"
    monkeypatch.setattr(pl, "LEARNED_PATTERNS_PATH", str(path))
    assert pl._load_learned() == []
    pl._save_learned([_candidate("A")])
    assert [p["name"] for p in pl._load_learned()] == ["A"]


def test_failed_write_leaves_prior_valid_file_intact(monkeypatch, tmp_path):
    path = tmp_path / "learned_patterns.json"
    monkeypatch.setattr(pl, "LEARNED_PATTERNS_PATH", str(path))
    original = [_candidate("Original")]
    pl._save_learned(original)

    def _failing_replace(src, dst):
        raise OSError("simulated replace failure")

    monkeypatch.setattr(pl.os, "replace", _failing_replace)
    with pytest.raises(OSError):
        pl._save_learned([_candidate("New")])
    # Prior file untouched, and no temp file left behind.
    assert [p["name"] for p in pl._load_learned()] == ["Original"]
    assert list(tmp_path.glob(".learned_patterns.*.tmp")) == []


def test_concurrent_confirms_do_not_lose_updates(monkeypatch, tmp_path):
    path = tmp_path / "learned_patterns.json"
    monkeypatch.setattr(pl, "LEARNED_PATTERNS_PATH", str(path))
    names = [f"Candidate-{i}" for i in range(8)]
    pl._save_learned([_candidate(name) for name in names])

    barrier = threading.Barrier(len(names))
    outcomes = []

    def _confirm(name):
        barrier.wait(timeout=10)
        outcomes.append(
            pl.confirm_pattern(name, "Independent reproduction confirms it")
        )

    threads = [threading.Thread(target=_confirm, args=(name,)) for name in names]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=20)
    assert all(outcomes)
    stored = {p["name"]: p["verification_status"] for p in pl._load_learned()}
    assert stored == {name: "confirmed" for name in names}


def test_concurrent_saves_never_produce_partial_file(monkeypatch, tmp_path):
    path = tmp_path / "learned_patterns.json"
    monkeypatch.setattr(pl, "LEARNED_PATTERNS_PATH", str(path))
    written = [[_candidate(f"Writer-{i}")] for i in range(8)]
    barrier = threading.Barrier(len(written))

    def _save(i):
        barrier.wait(timeout=10)
        pl._save_learned(written[i])

    threads = [threading.Thread(target=_save, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=20)
    # Whole-file saves are last-writer-wins by design, but the file on
    # disk must always be one complete, valid document — never partial.
    final = pl._load_learned()
    assert final in written
    assert list(tmp_path.glob(".learned_patterns.*.tmp")) == []


def test_corrupt_file_is_logged_not_silent(monkeypatch, tmp_path, caplog):
    path = tmp_path / "learned_patterns.json"
    monkeypatch.setattr(pl, "LEARNED_PATTERNS_PATH", str(path))
    path.write_text("not json {", encoding="utf-8")
    with caplog.at_level("ERROR", logger="agents.pattern_learner"):
        assert pl._load_learned() == []
    assert "corrupt" in caplog.text
    # Load does not overwrite or delete the corrupt file.
    assert path.read_text(encoding="utf-8") == "not json {"


def test_non_list_file_is_logged(monkeypatch, tmp_path, caplog):
    path = tmp_path / "learned_patterns.json"
    monkeypatch.setattr(pl, "LEARNED_PATTERNS_PATH", str(path))
    path.write_text(json.dumps({"a": 1}), encoding="utf-8")
    with caplog.at_level("WARNING", logger="agents.pattern_learner"):
        assert pl._load_learned() == []
    assert "does not contain a list" in caplog.text
