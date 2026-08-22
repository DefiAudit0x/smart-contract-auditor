import auth
import pytest


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


def test_code_logins_do_not_consume_audit_quota(quota_code):
    assert auth.verify_code(quota_code)
    assert auth.verify_code(quota_code)

    quota = auth.check_quota(quota_code)
    assert quota == {"allowed": 2, "remaining": 2, "used": 0, "reserved": 0}


def test_code_quota_reservation_is_idempotent_and_bounded(quota_code):
    first = auth.reserve_code_usage(quota_code, "request-one")
    duplicate = auth.reserve_code_usage(quota_code, "request-one")

    assert first["allowed"] is True
    assert duplicate == {
        "allowed": True,
        "event_id": first["event_id"],
        "idempotent": True,
    }
    assert auth.check_quota(quota_code)["remaining"] == 1

    auth.complete_code_usage(quota_code, first["event_id"])
    second = auth.reserve_code_usage(quota_code, "request-two")
    assert second["allowed"] is True
    auth.complete_code_usage(quota_code, second["event_id"])

    denied = auth.reserve_code_usage(quota_code, "request-three")
    assert denied == {"allowed": False, "error": "No audit quota remaining"}


def test_released_reservation_restores_available_quota(quota_code):
    reservation = auth.reserve_code_usage(quota_code, "retryable-request")
    assert reservation["allowed"] is True

    auth.release_code_usage(quota_code, reservation["event_id"])

    assert auth.check_quota(quota_code) == {
        "allowed": 2,
        "remaining": 2,
        "used": 0,
        "reserved": 0,
    }
