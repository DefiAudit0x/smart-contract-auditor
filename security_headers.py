"""Compute 'unsafe-hashes' source list for CSP script-src-attr.

The templates still contain legacy inline event handlers (onclick=,
onchange=, …). Removing script-src 'unsafe-inline' blocks those handlers
unless their exact JavaScript source is allow-listed via 'unsafe-hashes'
with SHA-256 hashes (CSP level 3, script-src-attr applies specifically to
event handler attributes).

This helper extracts every inline event handler attribute value from
templates/ (after HTML-entity decoding, which is what browsers hash),
SHA-256 hashes it and caches the base64 'sha256-…' list at import time.
A companion test recomputes the set and fails when a handler is added or
changed without refreshing the hashes.
"""
import base64
import hashlib
import os
import re

_TEMPLATE_DIR = os.path.join(os.path.dirname(__file__), "templates")

# html.parser decodes entities inside attribute values, matching what the
# browser treats as the handler's JS source for hashing purposes.
from html.parser import HTMLParser  # noqa: E402

_EVENT_ATTR_RE = re.compile(r"^on[a-z]+$", re.IGNORECASE)


class _EventHandlerCollector(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.handlers = set()

    def handle_starttag(self, tag, attrs):
        for name, value in attrs:
            if value is not None and _EVENT_ATTR_RE.match(name):
                self.handlers.add(value)


def _collect_inline_handlers(template_dir: str) -> set:
    collector = _EventHandlerCollector()
    for fname in sorted(os.listdir(template_dir)):
        if not fname.endswith(".html"):
            continue
        path = os.path.join(template_dir, fname)
        try:
            with open(path, "r", encoding="utf-8") as fh:
                collector.feed(fh.read())
        except OSError:
            continue
    return collector.handlers


def _hash_handlers(handlers: set) -> list:
    hashes = []
    for source in handlers:
        digest = hashlib.sha256(source.encode("utf-8")).digest()
        hashes.append("'sha256-" + base64.b64encode(digest).decode("ascii") + "'")
    return sorted(hashes)


def compute_inline_handler_hashes(template_dir: str = None) -> list:
    return _hash_handlers(_collect_inline_handlers(template_dir or _TEMPLATE_DIR))


_hash_cache = None


def _inline_handler_hashes() -> str:
    """Return "'sha256-…' 'sha256-…' …" for all inline event handlers."""
    global _hash_cache
    if _hash_cache is None:
        parts = compute_inline_handler_hashes()
        _hash_cache = " ".join(parts) if parts else "'unsafe-hashes'"
    return _hash_cache
