"""Priority 6 (a)/(b): the admin panel's learned-pattern PoC confirm
affordance and the KB route's RAG-only labelling.

Routes keep the existing admin-auth + CSRF treatment (same as the
KB confirm route): unauthenticated requests get 401, and POSTs
carry the X-CSRFToken header from the login page, exactly as in
test_admin_auth.py. The panel HTML must expose the candidate list
/ confirm form and must label the KB route as RAG context only,
never PoC confirmation.
"""

import re

import agents.pattern_learner as pl
import auth
import pytest
from werkzeug.security import generate_password_hash
from web_ui import app


@pytest.fixture
def admin_client(tmp_path, monkeypatch):
    previous = getattr(auth._local, "conn", None)
    if previous is not None:
        previous.close()
    auth._local.conn = None
    monkeypatch.setattr(auth, "AUTH_DB_PATH", str(tmp_path / "auth.db"))
    monkeypatch.setattr(
        auth, "ADMIN_PASSWORD_HASH", generate_password_hash("correct-password")
    )
    auth.init_auth_db()
    app.config.update(TESTING=True)
    with app.test_client() as client:
        yield client
    conn = auth._get_conn()
    conn.close()
    auth._local.conn = None


def _csrf_headers(client):
    response = client.get("/admin/login")
    match = re.search(
        r'<meta name="csrf-token" content="([^"]+)">',
        response.get_data(as_text=True),
    )
    assert match
    return {"X-CSRFToken": match.group(1)}


def _login(client):
    response = client.post(
        "/api/admin/login",
        json={"password": "correct-password"},
        headers=_csrf_headers(client),
    )
    assert response.status_code == 200


def _seed_candidate(monkeypatch, tmp_path):
    path = tmp_path / "learned_patterns.json"
    monkeypatch.setattr(pl, "LEARNED_PATTERNS_PATH", str(path))
    pl._save_learned([{
        "name": "Novel state sync",
        "description": "Detects a novel state synchronization risk",
        "severity": "High",
        "patterns": [r"state\s+sync"],
        "verification_status": "candidate",
    }])


def test_learned_routes_require_admin_auth(admin_client):
    assert admin_client.get("/api/admin/patterns/learned").status_code == 401
    # A POST with no CSRF token is stopped by the CSRF gate (400)
    # before the view runs; with a valid token the session gate
    # itself answers 401 — either way, nothing is confirmed.
    assert admin_client.post(
        "/api/admin/patterns/learned/confirm", json={}
    ).status_code == 400
    assert admin_client.post(
        "/api/admin/patterns/learned/confirm",
        json={},
        headers=_csrf_headers(admin_client),
    ).status_code == 401


def test_admin_panel_lists_learned_ui_and_labels_kb_rag_only(admin_client):
    _login(admin_client)
    html = admin_client.get("/admin/login").get_data(as_text=True)
    assert "/api/admin/patterns/learned" in html
    assert "learnedName" in html and "learnedVulnerable" in html
    assert "learnedFixed" in html
    assert "RAG context only" in html
    assert "never PoC confirmation" in html


def test_learned_list_and_poc_confirm_via_admin_api(
    admin_client, monkeypatch, tmp_path
):
    _seed_candidate(monkeypatch, tmp_path)
    _login(admin_client)
    headers = _csrf_headers(admin_client)

    listed = admin_client.get("/api/admin/patterns/learned")
    assert listed.status_code == 200
    names = [c["name"] for c in listed.get_json()["candidates"]]
    assert names == ["Novel state sync"]

    # Text evidence alone (no samples) is rejected, not confirmed.
    missing = admin_client.post(
        "/api/admin/patterns/learned/confirm",
        json={"name": "Novel state sync"},
        headers=headers,
    )
    assert missing.status_code == 400

    # Fires on fixed too -> rejected, stays a candidate.
    bad = admin_client.post(
        "/api/admin/patterns/learned/confirm",
        json={
            "name": "Novel state sync",
            "vulnerable_code": "state sync",
            "fixed_code": "state sync",
        },
        headers=headers,
    )
    assert bad.status_code == 409
    assert pl.get_learned_bug_classes() == {}

    ok = admin_client.post(
        "/api/admin/patterns/learned/confirm",
        json={
            "name": "Novel state sync",
            "vulnerable_code": "state sync",
            "fixed_code": "state clean",
            "evidence": "optional note",
        },
        headers=headers,
    )
    assert ok.status_code == 200, ok.get_json()
    assert ok.get_json()["verification_method"] == "poc_regex"
    assert len(pl.get_learned_bug_classes()) == 1
    # Confirmed candidates no longer appear in the candidate list.
    listed = admin_client.get("/api/admin/patterns/learned")
    assert listed.get_json()["candidates"] == []
