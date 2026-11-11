"""
Pattern Learner — discovers new vulnerability patterns from LLM audit findings
that the static grep-based pre-scan missed, and persists them for future scans.
"""

import json
import logging
import multiprocessing
import os
import re
import tempfile
import threading
import time
from contextlib import contextmanager

from agents.llm_client import call_model_with_fallback

logger = logging.getLogger(__name__)

# Persistent storage for learned patterns (Fix 1, 2026-11-05).
#
# The old default was learned_patterns.json in the repo root: not
# gitignored, not committed, and wiped by a redeploy, so confirmed
# patterns silently vanished. The new default follows the KB's own
# rule (config.py): the persistent /data volume when it exists
# (Render / Docker), otherwise instance/ next to the KB, which is
# gitignored and bind-mounted in docker-compose. Override with the
# LEARNED_PATTERNS_PATH environment variable. Tests keep overriding
# the module global directly, exactly as before.
_LEGACY_LEARNED_PATTERNS_PATH = os.path.join(
    os.path.dirname(__file__), "..", "learned_patterns.json"
)


def _default_learned_patterns_path() -> str:
    env_path = os.getenv("LEARNED_PATTERNS_PATH", "").strip()
    if env_path:
        return env_path
    if os.path.isdir("/data"):
        return "/data/learned_patterns.json"
    return os.path.join(
        os.path.dirname(__file__), "..", "instance", "learned_patterns.json"
    )


LEARNED_PATTERNS_PATH = _default_learned_patterns_path()

# Storage bound (M21 remediation): unbounded LLM-mined growth slowed every
# subsequent scan with unaudited patterns.
MAX_LEARNED_PATTERNS = 100
MAX_PATTERN_LENGTH = 500
# Canary input: catastrophic-backtracking patterns choke on it almost
# instantly while benign ones finish well inside the timeout.
_CANARY_INPUT = "solidity contract function pragma " * 50

# Isolation bounds for LLM-authored regex (issues #30 / #21, F-21 / F-08).
# A Python ``re`` match cannot be interrupted in-process, and a daemon
# thread's join(timeout) does not terminate it: the match keeps consuming
# CPU after the caller has given up. The only reliable bound in-process
# Python is a separate, killable worker process.
#
# These bounds are execution bounds only. They do NOT prove a pattern is
# safe, and they do NOT replace compilation/canary validation below:
# a pattern that passes the canary can still time out on adversarial
# input at runtime, and is then skipped, not reported.
MAX_REGEX_WORKERS = 4
_REGEX_WORKER_MAX_MEMORY_BYTES = 512 * 1024 * 1024
_REGEX_WORKER_SEMAPHORE = threading.BoundedSemaphore(MAX_REGEX_WORKERS)


def _apply_worker_limits(timeout):
    """Best-effort resource limits inside a regex worker (POSIX only).

    RLIMIT_CPU is a backstop for the parent's wall-clock timeout: if the
    parent dies, the worker is still killed by its CPU budget instead of
    running forever. RLIMIT_AS bounds memory. On non-POSIX platforms
    this is a no-op and the wall-clock kill in the parent is the bound.
    """
    try:
        import resource

        cpu_seconds = max(2, int(timeout) + 2)
        resource.setrlimit(resource.RLIMIT_CPU, (cpu_seconds, cpu_seconds))
        resource.setrlimit(
            resource.RLIMIT_AS,
            (_REGEX_WORKER_MAX_MEMORY_BYTES, _REGEX_WORKER_MAX_MEMORY_BYTES),
        )
    except Exception:
        pass


def _regex_worker(conn, pattern, text, mode, class_key, timeout):
    """Run one regex operation in a worker process. Never logs, never
    touches shared state: it only compiles, matches, and sends a result.

    The parent must never trust a late or partial result from this
    worker: on timeout the parent kills it and discards everything.
    """
    try:
        _apply_worker_limits(timeout)
        rx = re.compile(pattern, re.IGNORECASE)
        if mode == "search":
            rx.search(text)
            conn.send(("ok", True))
        elif mode == "scan":
            matches = []
            lines = text.split("\n")
            for i, line in enumerate(lines):
                if rx.search(line):
                    matches.append({
                        "line": i + 1,
                        "content": line.strip(),
                        "pattern": pattern,
                        "class": class_key,
                    })
            # multi-line fallback (deduped against per-line hits), exactly
            # as the old in-process scan: no DOTALL flag is added here.
            for m in rx.finditer(text):
                if "\n" in m.group():
                    line_no = text[:m.start()].count("\n") + 1
                    if not any(
                        x["line"] == line_no and x["pattern"] == pattern
                        for x in matches
                    ):
                        matches.append({
                            "line": line_no,
                            "content": m.group()[:80].replace("\n", "\\n"),
                            "pattern": pattern,
                            "class": class_key,
                        })
            conn.send(("ok", matches))
        else:
            conn.send(("error", "unknown mode"))
    except re.error:
        try:
            conn.send(("error", "invalid pattern"))
        except Exception:
            pass
    except Exception as exc:  # e.g. MemoryError under the worker limit
        try:
            conn.send(("error", str(exc)[:200]))
        except Exception:
            pass
    finally:
        try:
            conn.close()
        except Exception:
            pass


def _run_regex_isolated(pattern, text, mode, class_key="", timeout=1.0):
    """Run a regex in a killable worker process.

    Returns (status, payload) with status in "ok", "timeout" or "error".
    On timeout the worker is terminated (SIGTERM, then SIGKILL) and
    joined, so no worker is left running, and no partial result is
    returned: a timed-out scan contributes nothing. If the global
    worker budget is exhausted, this returns "timeout" without spawning
    a worker at all. The semaphore is per-process, not per-machine: it
    bounds concurrent workers in this Python process only.
    """
    if not _REGEX_WORKER_SEMAPHORE.acquire(blocking=False):
        return ("timeout", None)
    proc = None
    parent_conn = None
    try:
        try:
            ctx = multiprocessing.get_context("fork")
        except ValueError:
            ctx = multiprocessing.get_context()
        parent_conn, child_conn = ctx.Pipe(duplex=False)
        proc = ctx.Process(
            target=_regex_worker,
            args=(child_conn, pattern, text, mode, class_key, timeout),
            daemon=True,
        )
        proc.start()
        child_conn.close()
        if parent_conn.poll(timeout):
            try:
                status, payload = parent_conn.recv()
            except EOFError:
                status, payload = "error", None
            if status not in ("ok", "error"):
                status, payload = "error", None
        else:
            status, payload = "timeout", None
        if proc.is_alive():
            proc.terminate()
            proc.join(1.0)
            if proc.is_alive():
                proc.kill()
                proc.join(1.0)
        else:
            proc.join(1.0)
        return (status, payload)
    except Exception:
        return ("error", None)
    finally:
        if proc is not None and proc.is_alive():
            try:
                proc.kill()
            except Exception:
                pass
            try:
                proc.join(1.0)
            except Exception:
                pass
        if parent_conn is not None:
            try:
                parent_conn.close()
            except Exception:
                pass
        _REGEX_WORKER_SEMAPHORE.release()


def _safe_search_with_timeout(regex, sample, timeout=1.0):
    """True when regex.search(sample) finishes within `timeout` seconds.

    The search runs in a killable subprocess (issues #30 / #21): unlike
    the old daemon-thread version, a hang is terminated, not abandoned.
    True means only "completed without error", not "matched": the caller
    uses this as a safety gate, and a pattern that merely fails to match
    the canary still passes this gate.
    """
    pattern = regex.pattern if hasattr(regex, "pattern") else str(regex)
    status, _payload = _run_regex_isolated(
        pattern, sample, "search", timeout=timeout
    )
    return status == "ok"


def _validate_candidate_pattern(pat) -> bool:
    """Compilable, bounded, and non-catastrophic on the canary (M21)."""
    if not isinstance(pat, str) or not pat.strip():
        return False
    if len(pat) > MAX_PATTERN_LENGTH:
        return False
    try:
        rx = re.compile(pat, re.IGNORECASE)
    except re.error:
        return False
    return _safe_search_with_timeout(rx, _CANARY_INPUT, timeout=1.0)


# Serialisation for learned-pattern updates (issue #22, F-10).
# _learned_lock() is re-entrant in one thread: an outer load-modify-save
# holds it, and _save_learned() inside re-enters without deadlocking.
# In-process it is a threading.RLock, so concurrent writers in one
# Python process are serialised. On POSIX it additionally holds an
# flock on a sidecar "<path>.lock" file for the whole update, so writers
# in separate processes are serialised too; on non-POSIX platforms the
# flock step is best-effort and the in-process lock is the bound. The
# lock file is deliberately left on disk (deleting a flocked file is
# racy); it contains no pattern data.
_LEARNED_WRITE_LOCK = threading.RLock()
_LEARNED_LOCK_STATE = {"depth": 0, "fd": None}


@contextmanager
def _learned_lock():
    """Hold the learned-pattern update lock for a load-modify-save.

    Readers (_load_learned on its own) do not need it: _save_learned
    replaces the destination atomically, so a reader sees either the
    old complete file or the new complete file, never a partial one.
    """
    with _LEARNED_WRITE_LOCK:
        if _LEARNED_LOCK_STATE["depth"] == 0:
            fd = None
            try:
                import fcntl

                lock_path = os.fspath(LEARNED_PATTERNS_PATH) + ".lock"
                fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
                fcntl.flock(fd, fcntl.LOCK_EX)
            except Exception:
                if fd is not None:
                    try:
                        os.close(fd)
                    except OSError:
                        pass
                    fd = None
            _LEARNED_LOCK_STATE["fd"] = fd
        _LEARNED_LOCK_STATE["depth"] += 1
        try:
            yield
        finally:
            _LEARNED_LOCK_STATE["depth"] -= 1
            if _LEARNED_LOCK_STATE["depth"] == 0:
                fd = _LEARNED_LOCK_STATE["fd"]
                if fd is not None:
                    try:
                        import fcntl

                        fcntl.flock(fd, fcntl.LOCK_UN)
                    except Exception:
                        pass
                    try:
                        os.close(fd)
                    except OSError:
                        pass
                _LEARNED_LOCK_STATE["fd"] = None


def _migrate_legacy_if_needed() -> None:
    """One-time, explicit migration from the old repo-root file.

    Runs only when the active path is the computed default (an env
    override is an explicit location choice, and a test monkeypatch is
    not a deployment to migrate), the new file does not exist yet,
    and the legacy file does. The legacy file is left intact on disk
    so nothing is lost if the copy is inspected or rolled back; a
    corrupt legacy file is not copied, it is logged and ignored.
    """
    try:
        resolved = os.path.abspath(os.fspath(LEARNED_PATTERNS_PATH))
        legacy = os.path.abspath(os.fspath(_LEGACY_LEARNED_PATTERNS_PATH))
        default = os.path.abspath(_default_learned_patterns_path())
        if resolved == legacy or resolved != default:
            return
        if os.path.isfile(resolved) or not os.path.isfile(legacy):
            return
        with open(legacy, "r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, list):
            return
    except Exception as exc:
        logger.warning("Legacy learned-patterns migration skipped: %s", exc)
        return
    try:
        _save_learned(data)
        logger.info(
            "Migrated %d learned pattern(s) from legacy %s to %s",
            len(data), legacy, resolved,
        )
    except Exception as exc:
        logger.warning("Legacy learned-patterns migration failed: %s", exc)


def _load_learned() -> list:
    _migrate_legacy_if_needed()
    if not os.path.isfile(LEARNED_PATTERNS_PATH):
        return []
    try:
        with open(LEARNED_PATTERNS_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
    except json.JSONDecodeError as exc:
        # Observable, not silent: the corrupt file is left intact on
        # disk for inspection, and this call returns [] so existing
        # callers (patterns_text, get_learned_bug_classes, confirm /
        # reject) keep working instead of crashing the scan.
        logger.error(
            "Learned patterns file is corrupt (%s): %s; "
            "treating as empty for this call and leaving the file intact",
            LEARNED_PATTERNS_PATH,
            exc,
        )
        return []
    except OSError as exc:
        logger.error(
            "Learned patterns file could not be read (%s): %s; "
            "treating as empty for this call",
            LEARNED_PATTERNS_PATH,
            exc,
        )
        return []
    if not isinstance(data, list):
        logger.warning(
            "Learned patterns file does not contain a list (%s); "
            "treating as empty for this call",
            LEARNED_PATTERNS_PATH,
        )
        return []
    return data


def _save_learned(patterns: list):
    """Persist learned patterns atomically (issue #22, F-10).

    Writes to a temporary file in the same directory, flushes and
    fsyncs it, then atomically replaces the destination with
    os.replace, so an interrupted or failed write leaves the prior
    valid file intact and never exposes a partial file to readers.
    The write is serialised by _learned_lock(). A directory fsync
    after the replace is best-effort (crash durability only).
    """
    data = json.dumps(patterns, indent=2, ensure_ascii=False)
    dest = os.fspath(LEARNED_PATTERNS_PATH)
    directory = os.path.dirname(os.path.abspath(dest))
    # The persistent directory may not exist yet (fresh instance/ or a
    # new /data mount); without this the first save fails instead of
    # persisting, which was part of the old storage failure mode.
    os.makedirs(directory, exist_ok=True)
    with _learned_lock():
        fd, tmp_path = tempfile.mkstemp(
            dir=directory, prefix=".learned_patterns.", suffix=".tmp"
        )
        written = False
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
            written = True
            os.replace(tmp_path, dest)
            tmp_path = None
            try:
                dir_fd = os.open(directory, os.O_RDONLY)
                try:
                    os.fsync(dir_fd)
                finally:
                    os.close(dir_fd)
            except OSError:
                pass
        except Exception:
            if not written:
                try:
                    os.close(fd)
                except OSError:
                    pass
            raise
        finally:
            if tmp_path is not None:
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass


def _is_confirmed(pattern: dict) -> bool:
    """Only explicitly verified patterns are active learning artifacts."""
    return pattern.get("verification_status") == "confirmed"


def patterns_text() -> str:
    """Return only verified learned patterns as pre-scan context."""
    patterns = [p for p in _load_learned() if _is_confirmed(p)]
    if not patterns:
        return ""
    parts = ["### Pre-Scan: Verified Learned Patterns"]
    for p in patterns[-10:]:
        parts.append(f"- [{p['severity']}] {p['name']}: {p['description']}")
    return "\n".join(parts)


def list_candidates() -> list:
    """Return unverified regex-learning candidates for review."""
    return [p for p in _load_learned()
            if not _is_confirmed(p)
            and p.get("verification_status", "candidate") == "candidate"]


def _pattern_fires(pattern: str, code: str) -> bool:
    """True only when the regex actually matches `code`.

    Uses the isolated scan worker (killable on timeout), not the
    search worker: the search worker reports completion, not a match,
    so it cannot answer "does this fire". A timeout or worker error
    counts as "does not fire", never as a confirmation.
    """
    if not code:
        return False
    try:
        re.compile(pattern, re.IGNORECASE)
    except re.error:
        return False
    status, found = _run_regex_isolated(
        pattern, code, "scan", timeout=2.0
    )
    return status == "ok" and bool(found)


def confirm_pattern_poc(name: str, vulnerable_code: str, fixed_code: str,
                        evidence: str = "") -> tuple:
    """Confirm a candidate ONLY on PoC-style evidence.

    Returns (True, reason) only when EVERY regex in the candidate
    fires on the vulnerable sample and NO regex fires on the fixed
    sample. Anything else — text evidence alone, a pattern that
    misses the vulnerable sample, or one that also matches the fixed
    sample — returns (False, reason) and leaves the candidate
    inactive. This replaces the old rule, under which any >=10-char
    string confirmed a pattern with no proof at all.

    Concurrency limit (fail-closed, documented not changed):
    each fire check runs in the isolated-regex worker pool
    (MAX_REGEX_WORKERS = 4, non-blocking). If the pool is
    contended, _run_regex_isolated returns "timeout" without
    spawning a worker, _pattern_fires treats that as "does not
    fire", and confirmation fails — a timeout is never counted
    as a pass, so contention can only delay a confirmation, not
    falsely create one. Retry the confirmation when workers
    free up. The pool is shared with live scans, so raising it
    or queueing confirmations here would change scan behaviour
    and is deliberately not done in this fix.
    """
    if not vulnerable_code or not fixed_code:
        return False, "vulnerable_code and fixed_code are both required"
    # PoC checks run OUTSIDE the write lock (they spawn subprocesses
    # and can take seconds); only the final load-modify-save is locked
    # (issue #22), and it re-checks that the candidate is still a
    # candidate with the same patterns before promoting it.
    snapshot = [p for p in _load_learned()
                if p.get("name") == name
                and p.get("verification_status", "candidate") == "candidate"]
    if not snapshot:
        return False, "candidate not found"
    pats = snapshot[0].get("patterns") or []
    if not pats:
        return False, "candidate has no patterns to verify"
    for pat in pats:
        if not _validate_candidate_pattern(pat):
            return False, f"pattern failed safety validation: {pat[:80]}"
        if not _pattern_fires(pat, vulnerable_code):
            return False, f"pattern did not fire on vulnerable sample: {pat[:80]}"
        if _pattern_fires(pat, fixed_code):
            return False, f"pattern also fired on fixed sample: {pat[:80]}"
    note = (evidence or "").strip() or (
        "PoC check: pattern fires on vulnerable sample "
        "and does not fire on fixed sample"
    )
    with _learned_lock():
        patterns = _load_learned()
        for p in patterns:
            if (p.get("name") == name
                    and p.get("verification_status", "candidate") == "candidate"
                    and p.get("patterns") == pats):
                p["verification_status"] = "confirmed"
                p["verification_method"] = "poc_regex"
                p["verification_evidence"] = note[:2000]
                p["verified_at"] = time.time()
                _save_learned(patterns)
                return True, "confirmed"
    return False, "candidate changed or was already confirmed"


def confirm_pattern(name: str, evidence: str = "", vulnerable_code=None,
                    fixed_code=None) -> bool:
    """Promote one regex-learning candidate only with PoC evidence.

    Text evidence alone is NOT sufficient: `vulnerable_code` and
    `fixed_code` are required, and confirmation succeeds only when
    the candidate's regex fires on the former and not on the latter
    (see confirm_pattern_poc). Older callers passing only a text
    string now get False instead of a silent, unproven confirmation.
    """
    ok, _reason = confirm_pattern_poc(
        name, vulnerable_code, fixed_code, evidence
    )
    return ok


def reject_pattern(name: str, evidence: str) -> bool:
    """Reject one regex-learning candidate so it can never become active."""
    evidence = (evidence or "").strip()
    if len(evidence) < 10:
        return False
    with _learned_lock():
        patterns = _load_learned()
        for p in patterns:
            if p.get("name") == name and p.get("verification_status", "candidate") == "candidate":
                p["verification_status"] = "rejected"
                p["verification_evidence"] = evidence[:2000]
                p["verified_at"] = time.time()
                _save_learned(patterns)
                return True
    return False

def get_learned_bug_classes() -> dict:
    """Return learned patterns as _BUG_CLASSES-compatible dict for bug_detector."""
    patterns = [p for p in _load_learned() if _is_confirmed(p)]
    classes = {}
    for i, p in enumerate(patterns):
        key = f"learned_{i}"
        pats = p.get("patterns", [])
        if not pats:
            continue
        classes[key] = {
            "name": p["name"],
            "rank": 99,
            "frequency": "Learned from past audits",
            "description": p["description"],
            "grep_patterns": [],
            "vulnerable_patterns": pats,
            "kill_signals": [],
            "severity_hint": p["severity"],
            "detect": lambda code, _key=key, _pats=pats: _run_learned(code, _key, _pats),
        }
    return classes


def _run_learned(code: str, class_key: str, patterns: list) -> list:
    """Run learned patterns against code (single-line + multi-line check).

    Each pattern runs in a killable worker process under a hard 2.0s
    timeout (issues #30 / #21): a pattern that passed ingestion can
    still backtrack on adversarial input, and the old daemon-thread
    version left that match running after the timeout. Here a timeout
    kills the worker and the pattern contributes nothing -- never a
    partial match, never a leftover worker. A worker error likewise
    skips the pattern entirely. This is an execution bound, not proof
    that the pattern is safe or that a skipped pattern is benign.
    """
    matches = []
    for pat in patterns:
        try:
            re.compile(pat, re.IGNORECASE)
        except re.error:
            continue
        status, found = _run_regex_isolated(
            pat, code, "scan", class_key=class_key, timeout=2.0
        )
        if status == "timeout":
            logger.warning("Learned pattern timed out and was skipped: %s", pat[:80])
            continue
        if status != "ok" or not found:
            continue
        matches.extend(found)
    return matches


def learn_from_audit(code: str, llm_report: str, pre_scan_summary: str):
    """Call LLM to extract novel vulnerability patterns from this audit."""
    # P3: this prompt used to slice code to 2000 chars and the report to
    # 3000 chars silently, so the miner could "learn" patterns from a
    # partial view and present them as if drawn from the whole audit.
    # The consumer of this prompt is the miner LLM itself, so the
    # notice goes inside the prompt (with exact lengths); learning is
    # not a client finding, so nothing is added to any audit report.
    _learn_notices = []
    if len(code) > 2000:
        _learn_notices.append(
            f"NOTE: the code below was truncated for this prompt: "
            f"original {len(code)} chars, shown first 2000 chars "
            f"({len(code) - 2000} chars omitted — do not infer patterns "
            f"about code you cannot see)."
        )
        logger.warning(
            "Pattern learning: code truncated %d -> 2000 chars", len(code)
        )
    if len(llm_report) > 3000:
        _learn_notices.append(
            f"NOTE: the audit report below was truncated for this prompt: "
            f"original {len(llm_report)} chars, shown first 3000 chars "
            f"({len(llm_report) - 3000} chars omitted)."
        )
        logger.warning(
            "Pattern learning: report truncated %d -> 3000 chars",
            len(llm_report),
        )
    _learn_notice_block = (
        "\n".join(_learn_notices) + "\n\n" if _learn_notices else ""
    )
    prompt = f"""{_learn_notice_block}You are a security pattern miner. Given Solidity code and an AI audit report,
extract NEW vulnerability patterns that a simple regex-based grep scanner would NOT catch.
Return ONLY a JSON array of objects, each with:
- "name": short vulnerability name
- "description": 1-sentence description
- "severity": "Critical", "High", or "Medium"
- "patterns": array of 1-2 Python regex patterns that would detect this vulnerability

Rules:
- Each regex must be a valid Python regex matching Solidity code
- Prefer multi-line patterns using [^}}]* to span function bodies
- Focus on patterns the pre-scan already missed (not standard reentrancy, access control, etc.)
- Return [] if no novel patterns found

### Pre-Scan Results (static analysis already caught these)
{pre_scan_summary or "No pre-scan results"}

### Code
```solidity
{code[:2000]}
```

### AI Audit Report
{llm_report[:3000]}

### JSON output:
```json
"""
    try:
        raw = call_model_with_fallback(prompt, timeout=120)
    except Exception as e:
        logger.debug(f"Pattern learning LLM call failed: {e}")
        return

    json_str = _extract_json(raw)
    if not json_str:
        return

    try:
        new_patterns = json.loads(json_str)
        if not isinstance(new_patterns, list):
            return
    except json.JSONDecodeError:
        return

    # validate each pattern has required fields and is SAFE (M21
    # remediation): compilable, length-bounded, and canary-checked before
    # it can ever be persisted and replayed against future audits.
    validated = []
    for p in new_patterns:
        if not isinstance(p, dict):
            continue
        if not all(k in p for k in ("name", "description", "severity", "patterns")):
            continue
        if not all(isinstance(p[k], str) for k in ("name", "description", "severity")):
            continue
        if not isinstance(p["patterns"], list) or not p["patterns"]:
            continue
        if p["severity"] not in ("Critical", "High", "Medium"):
            p["severity"] = "Medium"
        p["patterns"] = [
            pat for pat in p["patterns"]
            if isinstance(pat, str) and _validate_candidate_pattern(pat)
        ]
        if not p["patterns"]:
            continue
        p["verification_status"] = "candidate"
        p.pop("verification_evidence", None)
        p.pop("verified_at", None)
        validated.append(p)

    if not validated:
        return

    # Only the final load-modify-save is locked (issue #22); the LLM
    # call above deliberately runs outside the lock.
    with _learned_lock():
        existing = _load_learned()
        if len(existing) >= MAX_LEARNED_PATTERNS:
            logger.info("Pattern learner: storage full (%d), skipping save", MAX_LEARNED_PATTERNS)
            return
        names = {e["name"] for e in existing}
        added = 0
        for p in validated:
            if len(existing) + added >= MAX_LEARNED_PATTERNS:
                logger.info("Pattern learner: storage bound reached (%d)", MAX_LEARNED_PATTERNS)
                break
            if p["name"] not in names:
                existing.append(p)
                names.add(p["name"])
                added += 1

        if added:
            _save_learned(existing)
            logger.info(f"Pattern learner: stored {added} candidate pattern(s); candidates remain inactive until independently verified")


def _extract_json(text: str) -> str:
    """Extract one JSON array from an LLM response, including nested arrays."""
    if not text:
        return ""
    start = text.find("[")
    if start < 0:
        return ""
    try:
        decoder = json.JSONDecoder()
        _, end = decoder.raw_decode(text[start:])
    except json.JSONDecodeError:
        return ""
    return text[start:start + end]
