import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))


def test_api_mode_fails_closed_without_key(monkeypatch):
    import api_mode

    monkeypatch.setattr(api_mode, "API_KEY", "")
    client = api_mode.app.test_client()
    response = client.post('/v1/audit', json={"code": "contract C {}"})
    assert response.status_code == 503


def test_api_mode_rejects_paths_outside_upload_dir(monkeypatch):
    import api_mode

    monkeypatch.setattr(api_mode, "API_KEY", "test-api-key")
    client = api_mode.app.test_client()
    response = client.post(
        '/v1/batch',
        json={"path": "/etc", "workers": 1},
        headers={"X-API-Key": "test-api-key"},
    )
    assert response.status_code == 400
