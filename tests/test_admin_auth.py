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
    monkeypatch.setattr(auth, "ADMIN_PASSWORD_HASH", generate_password_hash("correct-password"))
    auth.init_auth_db()

    app.config.update(TESTING=True)
    with app.test_client() as client:
        yield client

    conn = auth._get_conn()
    conn.close()
    auth._local.conn = None


def test_admin_login_requires_a_valid_password_hash_and_preserves_user_session(admin_client):
    with admin_client.session_transaction() as session:
        session["authenticated"] = True
        session["access_code"] = "SCA-TEST-0001"

    response = admin_client.post("/api/admin/login", json={"password": "correct-password"})
    assert response.status_code == 200
    assert response.get_json() == {"success": True}

    with admin_client.session_transaction() as session:
        assert session["authenticated"] is True
        assert session["access_code"] == "SCA-TEST-0001"
        assert session["admin_authenticated"] is True

    assert admin_client.post("/api/admin/logout").status_code == 200
    with admin_client.session_transaction() as session:
        assert session["authenticated"] is True
        assert session["access_code"] == "SCA-TEST-0001"
        assert "admin_authenticated" not in session


def test_admin_login_returns_a_generic_failure_for_invalid_credentials(admin_client):
    response = admin_client.post("/api/admin/login", json={"password": "wrong-password"})

    assert response.status_code == 403
    assert response.get_json() == {"success": False, "error": "Invalid credentials"}


def test_admin_alias_redirects_to_the_login_page(admin_client):
    response = admin_client.get("/admin", follow_redirects=False)

    assert response.status_code == 302
    assert response.headers["Location"].endswith("/admin/login")
