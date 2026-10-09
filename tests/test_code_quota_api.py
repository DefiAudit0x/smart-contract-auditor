import auth
import api_routes
import pytest
from unittest.mock import Mock, patch
from web_ui import app


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

    app.config.update(TESTING=True)
    with app.test_client() as client:
        with client.session_transaction() as session:
            session["authenticated"] = True
            session["access_code"] = code
        yield client, code

    conn.close()
    auth._local.conn = None


def _model_stream(_prompt):
    report = "A sufficiently detailed audit report that contains more than twenty characters."
    yield 'data: {"done": true, "full": "' + report + '"}'


def test_stream_analysis_charges_a_code_once_and_rejects_duplicate_request(quota_client):
    client, code = quota_client
    with patch.object(api_routes, "_stream_model", side_effect=_model_stream):
        with patch("agents.validation.validate_report", side_effect=lambda report, *_: report):
            response = client.post(
                "/api/analyze/stream",
                json={"code": "contract Example {}"},
                headers={"X-Idempotency-Key": "stream-request-one"},
            )
            response.get_data()

    assert response.status_code == 200
    assert auth.check_quota(code)["used"] == 1

    duplicate = client.post(
        "/api/analyze/stream",
        json={"code": "contract Example {}"},
        headers={"X-Idempotency-Key": "stream-request-one"},
    )
    assert duplicate.status_code == 409
    assert auth.check_quota(code)["used"] == 1


def test_stream_analysis_requires_an_idempotency_key_for_access_codes(quota_client):
    client, code = quota_client
    response = client.post("/api/analyze/stream", json={"code": "contract Example {}"})

    assert response.status_code == 400
    assert auth.check_quota(code)["used"] == 0


def test_tool_endpoint_charges_access_code_quota(quota_client):
    client, code = quota_client
    grep_mock = Mock()
    grep_mock.get_summary.return_value = {"matches": []}
    with patch.object(api_routes, "_has_grep", True), patch.object(
        api_routes, "_grep_arsenal", grep_mock
    ):
        first = client.post("/api/grep-arsenal", json={"code": "contract Example {}"})
        second = client.post("/api/grep-arsenal", json={"code": "contract Example {}"})
        third = client.post("/api/grep-arsenal", json={"code": "contract Example {}"})

    assert first.status_code == 200
    assert second.status_code == 200
    assert third.status_code == 402
    assert auth.check_quota(code)["used"] == 2
