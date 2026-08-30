"""Regression tests for the strict CSP policy (security_headers)."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from security_headers import (  # noqa: E402
    compute_inline_handler_hashes,
    _collect_inline_handlers,
    _hash_handlers,
)
import web_ui  # noqa: E402


def test_csp_script_src_has_no_unsafe_inline():
    client = web_ui.app.test_client()
    resp = client.get('/landing')
    csp = resp.headers.get('Content-Security-Policy', '')
    assert 'script-src' in csp
    assert "'unsafe-inline'" not in csp.split('script-src', 1)[1].split(';', 1)[0]


def test_csp_includes_unsafe_hashes_for_inline_handlers():
    client = web_ui.app.test_client()
    resp = client.get('/landing')
    csp = resp.headers.get('Content-Security-Policy', '')
    assert 'script-src-attr' in csp
    assert "'unsafe-hashes'" in csp


def test_handler_hashes_cover_every_template_handler():
    hashes = set(compute_inline_handler_hashes())
    handlers = _collect_inline_handlers(
        os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'templates')
    )
    # Every distinct handler must have exactly one hash in the set.
    assert len(hashes) == len(_hash_handlers(handlers))
    # No handler may reference un-rendered Jinja expressions: those cannot
    # be pre-hashed and must be migrated to data-attributes + addEventListener.
    jinja_handlers = [h for h in handlers if '{{' in h or '}}' in h]
    assert jinja_handlers == [], (
        f'Inline handlers contain Jinja expressions and will be blocked by CSP: {jinja_handlers}'
    )


def test_hash_list_is_stable_and_deterministic():
    assert compute_inline_handler_hashes() == compute_inline_handler_hashes()
