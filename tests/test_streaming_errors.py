"""Streaming error sanitization (#25) and bounded streams (#26).

The old streamers yielded ``str(exception)`` to the caller and passed
``timeout`` straight to ``requests.post(..., stream=True)``, where it is
a per-read timeout, not a total deadline. These tests pin the new
behaviour: a stable generic client error, redacted server logs, a
total budget enforced at chunk boundaries, an idle (per-read) budget
handed to requests, and upstream-response cleanup on error, on total
expiry, and on consumer disconnect.
"""

import json
import logging
import time

import pytest
import requests

from agents import llm_client as lc

GENERIC = "Upstream streaming failed. Please try again."


class FakeResp:
    """Minimal stand-in for a requests streaming response."""

    def __init__(self, chunks=None, interval=0.0, error=None):
        self._chunks = list(chunks or [])
        self.interval = interval
        self.error = error
        self.closed = False

    def raise_for_status(self):
        return None

    def iter_lines(self, decode_unicode=True):
        if self.error is not None:
            raise self.error
        for chunk in self._chunks:
            if self.interval:
                time.sleep(self.interval)
            yield chunk

    def close(self):
        self.closed = True


def _ollama_chunks(tokens):
    chunks = [json.dumps({"response": token}) for token in tokens]
    chunks.append(json.dumps({"done": True}))
    return chunks


def _openrouter_chunks(tokens):
    chunks = []
    for token in tokens:
        chunks.append(
            "data: " + json.dumps({"choices": [{"delta": {"content": token}}]})
        )
    chunks.append("data: [DONE]")
    return chunks


def _events_text(events):
    return "\n".join(events)


def _parsed(events):
    out = []
    for event in events:
        if event.startswith("data: "):
            try:
                out.append(json.loads(event[6:].strip()))
            except json.JSONDecodeError:
                pass
    return out


# ---------------------------------------------------------------- #25


def test_ollama_upstream_exception_is_sanitized(monkeypatch, caplog):
    monkeypatch.setattr(lc, "OLLAMA_API_KEY", "")

    def _boom(*args, **kwargs):
        raise requests.HTTPError(
            "500 Internal Server Error for url https://provider.example/x "
            "Bearer sk-abc123xyz provider exploded"
        )

    monkeypatch.setattr(lc.requests, "post", _boom)
    with caplog.at_level(logging.WARNING, logger="agents.llm_client"):
        events = list(lc._stream_ollama("model", "hello", timeout=300))
    text = _events_text(events)
    assert GENERIC in text
    assert "sk-abc123xyz" not in text
    assert "Bearer" not in text
    assert "provider exploded" not in text
    # Diagnostics stay on the server side, redacted.
    log_text = "\n".join(record.getMessage() for record in caplog.records)
    assert "Streaming failed" in log_text
    assert "sk-abc123xyz" not in log_text


def test_openrouter_upstream_exception_is_sanitized(monkeypatch):
    monkeypatch.setattr("config.get_api_key", lambda: "test-key")
    monkeypatch.setattr(lc.requests, "post", lambda *a, **k: (_ for _ in ()).throw(
        requests.ConnectionError("upstream down, api_key=supersecret123")
    ))
    events = list(lc._stream_openrouter("model-id", "hello", timeout=300))
    text = _events_text(events)
    assert GENERIC in text
    assert "supersecret123" not in text
    assert "upstream down" not in text


def test_ollama_provider_chunk_error_is_sanitized(monkeypatch, caplog):
    monkeypatch.setattr(lc, "OLLAMA_API_KEY", "")
    fake = FakeResp([json.dumps({"error": "provider says token=abc123 bad"})])
    monkeypatch.setattr(lc.requests, "post", lambda *a, **k: fake)
    with caplog.at_level(logging.WARNING, logger="agents.llm_client"):
        events = list(lc._stream_ollama("model", "hello", timeout=300))
    text = _events_text(events)
    assert GENERIC in text
    assert "abc123" not in text
    assert fake.closed


def test_openrouter_missing_key_is_generic_not_config_detail(monkeypatch):
    monkeypatch.setattr("config.get_api_key", lambda: "")
    events = list(lc._stream_openrouter("model-id", "hello", timeout=300))
    assert GENERIC in _events_text(events)


def test_redact_secrets_removes_credentials():
    redacted = lc._redact_secrets(
        "Bearer abc123 and api_key=secret123 and sk-xyz987"
    )
    assert "abc123" not in redacted
    assert "secret123" not in redacted
    assert "xyz987" not in redacted
    assert "[REDACTED]" in redacted


# ---------------------------------------------------------------- #26


def test_ollama_trickle_total_is_bounded(monkeypatch):
    """15 chunks at 0.2 s = ~3 s of trickle, with a 1 s total budget.

    Under the old code this completed with ``done`` after ~3.2 s.
    Under the fix it must stop with the generic error, well before the
    trickle finishes, and close the upstream response.
    """
    monkeypatch.setattr(lc, "OLLAMA_API_KEY", "")
    fake = FakeResp(_ollama_chunks([f"t{i} " for i in range(15)]), interval=0.2)
    monkeypatch.setattr(lc.requests, "post", lambda *a, **k: fake)
    started = time.monotonic()
    events = list(lc._stream_ollama("model", "hello", timeout=1))
    elapsed = time.monotonic() - started
    parsed = _parsed(events)
    assert elapsed < 3.0
    assert any(item.get("error") == GENERIC for item in parsed)
    assert not any(item.get("done") for item in parsed)
    assert fake.closed


def test_openrouter_trickle_total_is_bounded(monkeypatch):
    monkeypatch.setattr("config.get_api_key", lambda: "test-key")
    fake = FakeResp(_openrouter_chunks([f"t{i} " for i in range(15)]), interval=0.2)
    monkeypatch.setattr(lc.requests, "post", lambda *a, **k: fake)
    started = time.monotonic()
    events = list(lc._stream_openrouter("model-id", "hello", timeout=1))
    elapsed = time.monotonic() - started
    parsed = _parsed(events)
    assert elapsed < 3.0
    assert any(item.get("error") == GENERIC for item in parsed)
    assert not any(item.get("done") for item in parsed)
    assert fake.closed


def test_idle_timeout_is_handed_to_requests(monkeypatch):
    """Default idle is 60 s for a 300 s total; a small total caps idle."""
    monkeypatch.setattr(lc, "OLLAMA_API_KEY", "")
    captured = {}

    def _capture(*args, **kwargs):
        captured.update(kwargs)
        return FakeResp(_ollama_chunks(["hi "]))

    monkeypatch.setattr(lc.requests, "post", _capture)
    list(lc._stream_ollama("model", "hello", timeout=300))
    assert captured["timeout"] == 60
    assert captured["stream"] is True
    list(lc._stream_ollama("model", "hello", timeout=2))
    assert captured["timeout"] == 2


def test_read_timeout_becomes_generic_error_and_closes(monkeypatch):
    monkeypatch.setattr(lc, "OLLAMA_API_KEY", "")
    fake = FakeResp(error=requests.exceptions.ReadTimeout("Read timed out"))
    monkeypatch.setattr(lc.requests, "post", lambda *a, **k: fake)
    events = list(lc._stream_ollama("model", "hello", timeout=300))
    assert GENERIC in _events_text(events)
    assert "Read timed out" not in _events_text(events)
    assert fake.closed


def test_disconnect_closes_upstream_response(monkeypatch):
    """Consumer close() must close the upstream response deterministically."""
    monkeypatch.setattr(lc, "OLLAMA_API_KEY", "")
    fake = FakeResp(_ollama_chunks(["hi ", "more "]))
    monkeypatch.setattr(lc.requests, "post", lambda *a, **k: fake)
    gen = lc._stream_ollama("model", "hello", timeout=300)
    first = next(gen)
    assert "hi " in first
    gen.close()
    assert fake.closed


def test_fast_streams_still_work(monkeypatch):
    monkeypatch.setattr(lc, "OLLAMA_API_KEY", "")
    monkeypatch.setattr("config.get_api_key", lambda: "test-key")
    fake_ollama = FakeResp(_ollama_chunks(["hello ", "world"]))
    monkeypatch.setattr(lc.requests, "post", lambda *a, **k: fake_ollama)
    events = list(lc._stream_ollama("model", "hello", timeout=300))
    parsed = _parsed(events)
    assert any(item.get("done") for item in parsed)
    assert "hello world" in "".join(
        item.get("token", "") for item in parsed
    ) or "hello world" in _events_text(events)

    fake_openrouter = FakeResp(_openrouter_chunks(["hello ", "world"]))
    monkeypatch.setattr(lc.requests, "post", lambda *a, **k: fake_openrouter)
    events = list(lc._stream_openrouter("model-id", "hello", timeout=300))
    parsed = _parsed(events)
    assert any(item.get("done") for item in parsed)
