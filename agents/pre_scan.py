import re

import logging
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

logger = logging.getLogger(__name__)

# Registration of LLM-mined patterns is guarded (M21 remediation): bounded
# count, canary-checked complexity, and a lock closing the check-then-act
# race between ThreadPoolExecutor workers.
_learned_lock = threading.Lock()
MAX_LEARNED_CLASSES = 100

_has_detector = False
_detector = None
try:
    import bug_detector as _detector
    _has_detector = True
except ImportError:
    pass

_has_mcp = False
_mcp = None
try:
    import mcp_integration as _mcp
    _has_mcp = True
except ImportError:
    pass

_has_ai_tools = False
_ai_tools = None
try:
    import ai_tools as _ai_tools
    _has_ai_tools = True
except ImportError:
    pass

_has_zksync = False
_zksync = None
try:
    import zksync_detector as _zksync
    _has_zksync = True
except ImportError:
    pass

_has_gate = False
_gate = None
try:
    import gate_validator as _gate
    _has_gate = True
except ImportError:
    pass

_has_external = False
try:
    from external_analyzers import run_external_analyzers, findings_to_text
    _has_external = True
except ImportError:
    pass

_has_sbom = False
try:
    from sbom import analyze_sbom, format_sbom_text
    _has_sbom = True
except ImportError:
    pass

_has_pattern_learner = False
_learned_classes = None
_learned_signature = None
try:
    from agents.pattern_learner import get_learned_bug_classes, _safe_search_with_timeout, patterns_text as _learned_text
    _has_pattern_learner = True
except ImportError:
    pass

_has_ast_detector = False
try:
    from agents.ast_detector import analyze_ast as _run_ast_analysis
    _has_ast_detector = True
except ImportError:
    pass


def _run_detector(code: str) -> str:
    if not _has_detector:
        return ""
    detections = _detector.get_summary(code)
    if not detections:
        return ""
    parts = ["### Pre-Scan: Bug Classes (grep-based)"]
    for d in detections:
        sev = d.get("severity_hint", "?")
        cls_name = d.get("name", d.get("class", "?"))
        count = d.get("match_count", 0)
        parts.append(f"- [{sev}] {cls_name}: {count} pattern(s)")
    logger.info(f"Pre-scan bug detector: {len(detections)} classes")
    return "\n".join(parts)


def _run_mcp(code: str) -> str:
    if not _has_mcp:
        return ""
    mcp_result = _mcp.analyze_contract(code, analyzers=["swc", "defi"])
    if not mcp_result.get("findings"):
        return ""
    parts = ["### Pre-Scan: MCP (SWC + DeFi)"]
    for f in mcp_result["findings"][:8]:
        fid = f.get("id", f.get("name", "?"))
        sev = f.get("severity", "?")
        parts.append(f"- [{sev}] {fid}")
    logger.info(f"Pre-scan MCP: {mcp_result['total']} findings")
    return "\n".join(parts)


def _run_ai_tools(code: str) -> str:
    if not _has_ai_tools:
        return ""
    parts = []
    ai_check = _ai_tools.detect_ai_generated(code)
    if ai_check.get("ai_likely"):
        parts.append("### Pre-Scan: AI-Generated Code Detected — extra scrutiny recommended")
    ai_vulns = _ai_tools.check_ai_vulnerabilities(code)
    if ai_vulns:
        vparts = ["### Pre-Scan: AI-Specific Vulnerabilities"]
        for v in ai_vulns:
            vparts.append(f"- [{v['severity']}] {v['name']}")
        parts.append("\n".join(vparts))
    return "\n\n".join(parts)


def _run_zksync(code: str) -> str:
    if not _has_zksync:
        return ""
    zk_result = _zksync.check_vulnerable_patterns(code)
    if not zk_result.get("findings"):
        return ""
    parts = ["### Pre-Scan: ZKsync Era Attack Vectors"]
    for f in zk_result["findings"][:8]:
        sev = f.get("severity", "?")
        name = f.get("name", f.get("pattern", "?"))
        parts.append(f"- [{sev}] {name}")
    logger.info(f"Pre-scan ZKsync: {len(zk_result['findings'])} findings")
    return "\n".join(parts)


def _run_external(code: str) -> str:
    if not _has_external:
        return ""
    ext_findings = run_external_analyzers(code)
    if not ext_findings:
        return ""
    text = findings_to_text(ext_findings, max_per_tool=8)
    logger.info(f"Pre-scan external analyzers: {len(ext_findings)} findings")
    return text


def _run_sbom(code: str) -> str:
    if not _has_sbom:
        return ""
    sbom_result = analyze_sbom(code)
    text = format_sbom_text(sbom_result)
    if not text:
        return ""
    logger.info(f"Pre-scan SBOM: {len(sbom_result.dependencies)} dependencies")
    return text


def _run_learned(code: str) -> str:
    if not _has_pattern_learner:
        return ""
    return _learned_text()


def _run_pragma_warning(code: str) -> str:
    warnings = []
    for match in re.finditer(r'pragma\s+solidity\s+([\d.]+)', code, re.IGNORECASE):
        version = match.group(1)
        if version.startswith(("0.4.", "0.5.", "0.6.")):
            warnings.append(f"- [CRITICAL] Outdated Solidity version {version}: This version is no longer supported and contains known vulnerabilities. Upgrade to >=0.8.0 immediately.")
    if re.search(r'pragma\s+abicoder\s+v1', code, re.IGNORECASE):
        warnings.append("- [CRITICAL] `pragma abicoder v1` is deprecated and may cause issues. Use `pragma abicoder v2` or remove it.")
    if not warnings:
        return ""
    return "### ⚠️ Pragma Warning\n" + "\n".join(warnings)


def _learned_classes_signature(classes: dict):
    """Content fingerprint of the confirmed learned classes.

    A signature, not a mtime: confirmation changes the confirmed set
    itself, and the file may be rewritten by another process. Comparing
    content catches every confirmation regardless of which path or
    process wrote it.
    """
    try:
        return tuple(sorted(
            (key, tuple(cls.get("vulnerable_patterns", [])))
            for key, cls in classes.items()
        ))
    except Exception:
        return None


def reset_learned_registration():
    """Reset the registration cache (tests / explicit re-scan only).

    This resets the cache only: it does not itself remove keys
    already injected into bug_detector. Removal is applied by the
    next _register_learned_classes() call (see below), which
    reconciles the detector registry against the confirmed set —
    so a file removal takes effect at the next pre-scan, with no
    process restart. It is never applied silently mid-scan.
    """
    global _learned_classes, _learned_signature
    with _learned_lock:
        _learned_classes = None
        _learned_signature = None


def _register_learned_classes():
    """Inject learned patterns into bug_detector's _BUG_CLASSES at runtime.

    Fix 1 (2026-11-05): the old code cached _learned_classes once,
    and an empty first result ({}, not None) made every later call
    return immediately — so a pattern confirmed after the first
    pre-scan never entered bug_detector until a process restart.
    Now every pre-scan re-reads the confirmed set and registers any
    key that is new since the last registration; unchanged keys are
    skipped, so the canary gate is not re-run for them.

    Live deregistration (Priority 6): when the confirmed set
    changes, the registry is RECONCILED by content identity
    (name + vulnerable patterns), not just appended to by key.
    Reconciliation by key alone is wrong because learned keys
    are positional (``learned_0``, ``learned_1``, ... in
    confirmed order): deleting a confirmed pattern from the
    file shifts the survivors' keys, so an append-only update
    would leave the deleted pattern active under its old key
    and never replace the shifted survivors. Instead, keys
    whose content is no longer in the confirmed set are
    removed, and only genuinely new content is registered
    (through the same canary gate as before). Already
    registered content is deliberately NOT re-gated: the
    canary check fails closed on worker-pool contention, so
    re-gating survivors on every change could drop a live
    pattern on a transient timeout and — because the fresh
    signature would then be unchanged — never re-add it.
    An empty fresh set therefore removes all learned keys.
    This runs at a pre-scan boundary under _learned_lock,
    never mid-scan, and it re-uses the pre-existing add-time
    mutation profile of this function (it does not make
    detector-registry access thread-safe against concurrent
    scans — that would be a larger refactor, out of scope
    here). Only the ``learned_*`` namespace is touched;
    built-in classes are never removed.
    """
    if not _has_detector or not _has_pattern_learner:
        return
    global _learned_classes, _learned_signature
    with _learned_lock:
        fresh = get_learned_bug_classes()
        signature = _learned_classes_signature(fresh)
        if _learned_classes is not None and signature == _learned_signature:
            return
        _learned_classes = fresh
        _learned_signature = signature
        # Reconcile by content identity, derived from the registry
        # itself (no separate tracking state that a cache reset
        # could desync from the detector).
        def _identity(cls):
            return (
                cls.get("name"),
                tuple(cls.get("vulnerable_patterns", [])),
            )

        current = {
            key: _identity(cls)
            for key, cls in _detector._BUG_CLASSES.items()
            if key.startswith("learned_")
        }
        fresh_identities = {_identity(cls) for cls in fresh.values()}
        removed = 0
        for key, ident in list(current.items()):
            if ident not in fresh_identities:
                del _detector._BUG_CLASSES[key]
                if key in _detector._BUG_CLASS_ORDER:
                    _detector._BUG_CLASS_ORDER.remove(key)
                removed += 1
                del current[key]
        if removed:
            logger.info(f"Deregistered {removed} learned pattern(s) from bug_detector")
        if not _learned_classes:
            return
        registered_identities = set(current.values())
        canary = "solidity contract function pragma " * 50
        added = 0
        for key, cls in list(_learned_classes.items())[:MAX_LEARNED_CLASSES]:
            if _identity(cls) in registered_identities:
                continue
            if len(_detector._BUG_CLASS_ORDER) > MAX_LEARNED_CLASSES + 16:
                continue
            # Complexity gate: compile and canary-check every LLM-authored
            # pattern BEFORE it can scan any future audit (M21 remediation).
            safe = True
            for pat in cls.get("vulnerable_patterns", []):
                try:
                    rx = re.compile(pat, re.IGNORECASE)
                except re.error:
                    safe = False
                    break
                if not _safe_search_with_timeout(rx, canary, timeout=1.0):
                    safe = False
                    break
            if not safe:
                logger.warning("Learned class '%s' rejected by complexity gate", key)
                continue
            # A survivor keeps its old positional key, so a new
            # entry's positional key may already be taken by
            # different content: never overwrite it — take the
            # first free learned_* key instead. The key is only
            # an identifier; detection uses the class content.
            target = key
            if target in _detector._BUG_CLASSES:
                n = 0
                while f"learned_{n}" in _detector._BUG_CLASSES:
                    n += 1
                target = f"learned_{n}"
            _detector._BUG_CLASSES[target] = cls
            _detector._BUG_CLASS_ORDER.append(target)
            registered_identities.add(_identity(cls))
            added += 1
        if added:
            logger.info(f"Registered {added} learned pattern(s) into bug_detector")


_SCAN_TASKS = [
    ("bug_detector", lambda c: _run_detector(c)),
    # L-27: the dead grep_arsenal stage (module never existed) silently
    # swallowed one of the seven advertised pre-scan phases — removed.
    ("mcp", lambda c: _run_mcp(c)),
    ("ai_tools", lambda c: _run_ai_tools(c)),
    ("zksync", lambda c: _run_zksync(c)),
    ("external", lambda c: _run_external(c)),
    ("sbom", lambda c: _run_sbom(c)),
    ("learned", lambda c: _run_learned(c)),
    ("ast_detector", lambda c: _run_ast_analysis(c) if _has_ast_detector else ""),
    ("pragma_warning", lambda c: _run_pragma_warning(c)),
]


def format_pre_scan_failures(failures) -> str:
    """Render a visible pre-scan completeness section, or "" when none failed.

    A failed task must never be visible only in a log line: the section
    names every failed task and its reason, and states plainly that
    coverage is incomplete, so no report carrying it can claim complete
    pre-scan coverage. A fully successful pre-scan renders no section
    at all (no failure entry).
    """
    failures = list(failures or [])
    if not failures:
        return ""
    total = len(_SCAN_TASKS)
    task_names = {name for name, _fn in _SCAN_TASKS}
    task_failures = [f for f in failures
                     if isinstance(f, dict) and f.get("task") in task_names]
    if task_failures:
        headline = (
            f"Pre-scan coverage is INCOMPLETE: {len(task_failures)} of {total} "
            "pre-scan task(s) failed, so results from the failed task(s) are "
            "missing. Do not treat this pre-scan as complete coverage."
        )
    else:
        # Only a setup step (e.g. learned-pattern registration) failed;
        # it is not one of the scan tasks, so it must not inflate the
        # "of N tasks" count, but it is still listed below.
        headline = (
            "Pre-scan coverage is INCOMPLETE: a pre-scan setup step failed, "
            "so the scan ran without it. Do not treat this pre-scan as "
            "complete coverage."
        )
    lines = [
        "### Pre-Scan Completeness — INCOMPLETE",
        "",
        headline,
    ]
    for failure in failures:
        name = failure.get("task", "?") if isinstance(failure, dict) else "?"
        reason = failure.get("error", "?") if isinstance(failure, dict) else str(failure)
        lines.append(f"- Failed pre-scan task: {name} — {reason}")
    return "\n".join(lines)


def run_pre_scan_with_failures(code: str):
    """Run all pre-scan modules in parallel.

    Returns (context_string, failures) where failures is a list of
    {"task": name, "error": reason} dicts, one per task that raised.
    A task failure never aborts the audit: the remaining tasks still
    run, and the caller must surface the failures (see
    format_pre_scan_failures) instead of claiming complete coverage.
    """
    failures = []
    try:
        _register_learned_classes()
    except Exception as e:
        # Registration is not one of the scan tasks, but its failure
        # must not kill the audit silently either: record it and run
        # the scan tasks without the newly confirmed patterns.
        reason = f"{type(e).__name__}: {e}" if str(e) else type(e).__name__
        logger.warning(f"Pre-scan learned-pattern registration failed: {reason}")
        failures.append({"task": "learned_registration", "error": reason})
    parts = []
    with ThreadPoolExecutor(max_workers=7) as pool:
        future_map = {pool.submit(fn, code): name for name, fn in _SCAN_TASKS}
        for future in as_completed(future_map):
            name = future_map[future]
            try:
                result = future.result()
                if result:
                    parts.append(result)
            except Exception as e:
                reason = f"{type(e).__name__}: {e}" if str(e) else type(e).__name__
                logger.warning(f"Pre-scan {name} failed: {reason}")
                failures.append({"task": name, "error": reason})
    section = format_pre_scan_failures(failures)
    if section:
        parts.append(section)
    text = "\n\n".join(parts) + "\n\n" if parts else ""
    return text, failures


def run_pre_scan(code: str) -> str:
    """Run all pre-scan modules in parallel and return concatenated context string.

    The returned string includes the pre-scan completeness section
    (see format_pre_scan_failures) whenever a task failed, so a
    failure is visible to every caller that surfaces this text, not
    only in a log line. Callers building a final report should use
    run_pre_scan_with_failures and append the section to the report
    itself, rather than relying on the LLM to echo it.
    """
    text, _failures = run_pre_scan_with_failures(code)
    return text
