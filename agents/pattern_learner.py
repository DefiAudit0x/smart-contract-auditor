"""
Pattern Learner — discovers new vulnerability patterns from LLM audit findings
that the static grep-based pre-scan missed, and persists them for future scans.
"""

import json
import logging
import multiprocessing
import os
import re
import threading
import time

from agents.llm_client import call_model_with_fallback

logger = logging.getLogger(__name__)

LEARNED_PATTERNS_PATH = os.path.join(os.path.dirname(__file__), "..", "learned_patterns.json")

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


def _load_learned() -> list:
    if not os.path.isfile(LEARNED_PATTERNS_PATH):
        return []
    try:
        with open(LEARNED_PATTERNS_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data if isinstance(data, list) else []
    except (json.JSONDecodeError, OSError):
        return []


def _save_learned(patterns: list):
    with open(LEARNED_PATTERNS_PATH, "w", encoding="utf-8") as f:
        json.dump(patterns, f, indent=2, ensure_ascii=False)


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


def confirm_pattern(name: str, evidence: str) -> bool:
    """Promote one regex-learning candidate only with explicit evidence."""
    evidence = (evidence or "").strip()
    if len(evidence) < 10:
        return False
    patterns = _load_learned()
    for p in patterns:
        if p.get("name") == name and p.get("verification_status", "candidate") == "candidate":
            p["verification_status"] = "confirmed"
            p["verification_evidence"] = evidence[:2000]
            p["verified_at"] = time.time()
            _save_learned(patterns)
            return True
    return False


def reject_pattern(name: str, evidence: str) -> bool:
    """Reject one regex-learning candidate so it can never become active."""
    evidence = (evidence or "").strip()
    if len(evidence) < 10:
        return False
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
    prompt = f"""You are a security pattern miner. Given Solidity code and an AI audit report,
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
        if not all(k in p for k in ("name", "description", "severity", "patterns")):
            continue
        if not isinstance(p["patterns"], list) or not p["patterns"]:
            continue
        if p["severity"] not in ("Critical", "High", "Medium"):
            p["severity"] = "Medium"
        p["patterns"] = [pat for pat in p["patterns"] if _validate_candidate_pattern(pat)]
        if not p["patterns"]:
            continue
        p["verification_status"] = "candidate"
        p.pop("verification_evidence", None)
        p.pop("verified_at", None)
        validated.append(p)

    if not validated:
        return

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
