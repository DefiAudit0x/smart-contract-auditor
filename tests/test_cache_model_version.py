"""Cache keys must be namespaced by model version (P5 fix).

The old key was (model_id, prompt_hash) only, so a provider updating
the weights behind a fixed model tag could silently serve a stale
cached response. The key now also carries a model version (explicit
argument, else AUDITOR_MODEL_VERSION, else the legacy unversioned
bucket). These tests use an isolated throwaway SQLite file and no
Redis and no network, so they never depend on the real environment's
toolchain or on any pre-existing cache database.
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import pytest

import agents.cache as cache_mod
from agents.cache import _cache_get, _cache_set, _effective_model_id, _init_cache


@pytest.fixture()
def isolated_cache(tmp_path, monkeypatch):
    """Point the cache at a throwaway DB with Redis disabled."""
    monkeypatch.setattr(cache_mod, "_get_redis", lambda: None)
    monkeypatch.setattr(cache_mod, "CACHE_ENABLED", True)
    monkeypatch.delenv("AUDITOR_MODEL_VERSION", raising=False)
    monkeypatch.setattr(cache_mod, "CACHE_DB_PATH", str(tmp_path / "cache.db"))
    if getattr(cache_mod._cache_local, "conn", None) is not None:
        try:
            cache_mod._cache_local.conn.close()
        except Exception:
            pass
        cache_mod._cache_local.conn = None
    _init_cache()
    yield
    if getattr(cache_mod._cache_local, "conn", None) is not None:
        try:
            cache_mod._cache_local.conn.close()
        except Exception:
            pass
        cache_mod._cache_local.conn = None


def test_effective_model_id_keeps_legacy_key_unchanged(isolated_cache):
    assert _effective_model_id("ollama:gpt-oss:120b") == "ollama:gpt-oss:120b"
    assert _effective_model_id("ollama:gpt-oss:120b", "v1") == "ollama:gpt-oss:120b@v1"
    assert _effective_model_id("ollama:gpt-oss:120b", "  ") == "ollama:gpt-oss:120b"


def test_unchanged_model_version_hits_cache(isolated_cache):
    _cache_set("ollama:gpt-oss:120b", "audit this", "OLD-RESULT", model_version="v1")
    assert _cache_get("ollama:gpt-oss:120b", "audit this", model_version="v1") == "OLD-RESULT"


def test_changed_model_version_does_not_reuse_stale_result(isolated_cache):
    _cache_set("ollama:gpt-oss:120b", "audit this", "OLD-RESULT", model_version="v1")
    # Same model id, same prompt, new version: must miss, not serve v1's result.
    assert _cache_get("ollama:gpt-oss:120b", "audit this", model_version="v2") is None
    # And storing under v2 must not clobber v1's entry.
    _cache_set("ollama:gpt-oss:120b", "audit this", "NEW-RESULT", model_version="v2")
    assert _cache_get("ollama:gpt-oss:120b", "audit this", model_version="v1") == "OLD-RESULT"
    assert _cache_get("ollama:gpt-oss:120b", "audit this", model_version="v2") == "NEW-RESULT"


def test_unversioned_entry_still_hits_without_version(isolated_cache):
    # Pre-existing (legacy) entries keep working for unversioned callers.
    _cache_set("ollama:gpt-oss:120b", "audit this", "LEGACY-RESULT")
    assert _cache_get("ollama:gpt-oss:120b", "audit this") == "LEGACY-RESULT"


def test_versioned_entry_does_not_leak_to_unversioned_lookup(isolated_cache):
    _cache_set("ollama:gpt-oss:120b", "audit this", "V1-RESULT", model_version="v1")
    assert _cache_get("ollama:gpt-oss:120b", "audit this") is None


def test_legacy_database_rows_remain_readable(tmp_path, monkeypatch):
    """Rows written by the old (model_id, prompt_hash) schema still hit.

    Versioning folds into the model_id key component, so no schema
    migration was needed; this writes a row exactly as the old code
    did and reads it back through the new code.
    """
    import hashlib
    import sqlite3
    import time

    db_path = str(tmp_path / "legacy-cache.db")
    conn = sqlite3.connect(db_path)
    conn.execute("""CREATE TABLE responses (
        model_id TEXT NOT NULL, prompt_hash TEXT NOT NULL,
        response TEXT NOT NULL, created_at REAL NOT NULL,
        hits INTEGER DEFAULT 1,
        PRIMARY KEY (model_id, prompt_hash))""")
    prompt_hash = hashlib.sha256(b"audit this").hexdigest()
    conn.execute(
        "INSERT INTO responses (model_id, prompt_hash, response, created_at)"
        " VALUES (?, ?, ?, ?)",
        ("ollama:gpt-oss:120b", prompt_hash, "LEGACY-ROW", time.time()),
    )
    conn.commit()
    conn.close()
    monkeypatch.setattr(cache_mod, "_get_redis", lambda: None)
    monkeypatch.setattr(cache_mod, "CACHE_ENABLED", True)
    monkeypatch.delenv("AUDITOR_MODEL_VERSION", raising=False)
    monkeypatch.setattr(cache_mod, "CACHE_DB_PATH", db_path)
    if getattr(cache_mod._cache_local, "conn", None) is not None:
        try:
            cache_mod._cache_local.conn.close()
        except Exception:
            pass
        cache_mod._cache_local.conn = None
    _init_cache()
    try:
        assert _cache_get("ollama:gpt-oss:120b", "audit this") == "LEGACY-ROW"
    finally:
        if getattr(cache_mod._cache_local, "conn", None) is not None:
            try:
                cache_mod._cache_local.conn.close()
            except Exception:
                pass
            cache_mod._cache_local.conn = None


def test_env_model_version_namespaces_cache(isolated_cache, monkeypatch):
    monkeypatch.setenv("AUDITOR_MODEL_VERSION", "env-v9")
    _cache_set("ollama:gpt-oss:120b", "audit this", "ENV-RESULT")
    # Same env version: hit. An explicit different version: miss.
    assert _cache_get("ollama:gpt-oss:120b", "audit this") == "ENV-RESULT"
    assert _cache_get("ollama:gpt-oss:120b", "audit this", model_version="other") is None
    # Dropping the env var returns to the legacy bucket, which is separate.
    monkeypatch.delenv("AUDITOR_MODEL_VERSION")
    assert _cache_get("ollama:gpt-oss:120b", "audit this") is None
