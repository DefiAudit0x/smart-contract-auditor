import auth
import pytest
import re
from werkzeug.security import generate_password_hash
from web_ui import app


@pytest.fixture
def admin_client(tmp_path, monkeypatch):
    previous = getattr(auth._local, "conn", None)
    if previous is not None:
        previous.close()
    auth._local.conn = None
    monkeypatch.setattr(auth, "AUTH_DB_PATH", str(tmp_path / "auth.db"))
    monkeypatch.setattr(auth, "ADMIN_PASSWORD_HASH", generate_password_hash("correct-password"))
    auth.init_auth_db()

    app.config.update(TESTING=True)
    with app.test_client() as client:
        yield client

    conn = auth._get_conn()
    conn.close()
    auth._local.conn = None


def _csrf_headers(client):
    response = client.get("/admin/login")
    match = re.search(r'<meta name="csrf-token" content="([^"]+)"', response.get_data(as_text=True))
    assert match
    return {"X-CSRFToken": match.group(1)}

def test_admin_login_requires_a_valid_password_hash_and_preserves_user_session(admin_client):
    with admin_client.session_transaction() as session:
        session["authenticated"] = True
        session["access_code"] = "SCA-TEST-0001"

    response = admin_client.post("/api/admin/login", json={"password": "correct-password"}, headers=_csrf_headers(admin_client))
    assert response.status_code == 200
    assert response.get_json() == {"success": True}

    with admin_client.session_transaction() as session:
        assert session["authenticated"] is True
        assert session["access_code"] == "SCA-TEST-0001"
        assert session["admin_authenticated"] is True

    assert admin_client.post("/api/admin/logout", headers=_csrf_headers(admin_client)).status_code == 200
    with admin_client.session_transaction() as session:
        assert session["authenticated"] is True
        assert session["access_code"] == "SCA-TEST-0001"
        assert "admin_authenticated" not in session


def test_admin_login_returns_a_generic_failure_for_invalid_credentials(admin_client):
    response = admin_client.post("/api/admin/login", json={"password": "wrong-password"}, headers=_csrf_headers(admin_client))

    assert response.status_code == 403
    assert response.get_json() == {"success": False, "error": "Invalid credentials"}


def test_admin_alias_redirects_to_the_login_page(admin_client):
    response = admin_client.get("/admin", follow_redirects=False)

    assert response.status_code == 302
    assert response.headers["Location"].endswith("/admin/login")


def test_admin_state_changing_requests_require_csrf(admin_client):
    response = admin_client.post("/api/admin/login", json={"password": "correct-password"})
    assert response.status_code == 400
