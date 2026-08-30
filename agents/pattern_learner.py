"""
Pattern Learner — discovers new vulnerability patterns from LLM audit findings
that the static grep-based pre-scan missed, and persists them for future scans.
"""

import json
import logging
import os
import re
import threading

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


def _safe_search_with_timeout(regex, sample, timeout=1.0):
    """True when regex.search(sample) finishes within `timeout` seconds.

    Guards against LLM-authored ReDoS: re cannot be interrupted, so the
    check runs in a throwaway daemon thread and a hang simply fails the
    candidate pattern.
    """
    outcome = [True]

    def _run():
        try:
            regex.search(sample)
        except Exception:
            outcome[0] = False

    worker = threading.Thread(target=_run, daemon=True)
    worker.start()
    worker.join(timeout)
    if worker.is_alive():
        return False
    return outcome[0]


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


def patterns_text() -> str:
    """Return learned patterns as formatted text for pre-scan context."""
    patterns = _load_learned()
    if not patterns:
        return ""
    parts = ["### Pre-Scan: Learned Patterns (from past AI audits)"]
    for p in patterns[-10:]:  # show last 10
        parts.append(f"- [{p['severity']}] {p['name']}: {p['description']}")
    return "\n".join(parts)


def get_learned_bug_classes() -> dict:
    """Return learned patterns as _BUG_CLASSES-compatible dict for bug_detector."""
    patterns = _load_learned()
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

    Each pattern runs under a hard timeout (M21 remediation): a pattern
    that passed ingestion can still backtrack on adversarial input, and
    re cannot be interrupted once started.
    """
    matches = []
    lines = code.split("\n")
    for pat in patterns:
        try:
            regex = re.compile(pat, re.IGNORECASE)
        except re.error:
            continue
        outcome = []
        done = threading.Event()

        def _scan(rx=regex):
            try:
                for i, line in enumerate(lines):
                    if rx.search(line):
                        outcome.append({
                            "line": i + 1,
                            "content": line.strip(),
                            "pattern": pat,
                            "class": class_key,
                        })
                # multi-line fallback (deduped against per-line hits)
                for m in rx.finditer(code):
                    if "\n" in m.group():
                        line_no = code[:m.start()].count("\n") + 1
                        if not any(x["line"] == line_no and x["pattern"] == pat for x in outcome):
                            outcome.append({
                                "line": line_no,
                                "content": m.group()[:80].replace("\n", "\\n"),
                                "pattern": pat,
                                "class": class_key,
                            })
            except re.error:
                pass
            finally:
                done.set()

        worker = threading.Thread(target=_scan, daemon=True)
        worker.start()
        if not done.wait(2.0):
            logger.warning("Learned pattern timed out and was skipped: %s", pat[:80])
            continue
        matches.extend(outcome)
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
        logger.info(f"Pattern learner: saved {added} new pattern(s) (total: {len(existing)})")


def _extract_json(text: str) -> str:
    """Extract JSON array from LLM response (handles markdown fences)."""
    if not text:
        return ""
    m = re.search(r"```(?:json)?\s*\n(\[.*?\])\s*\n```", text, re.DOTALL)
    if m:
        return m.group(1)
    m = re.search(r"(\[.*?\])", text, re.DOTALL)
    if m:
        return m.group(1)
    return ""
