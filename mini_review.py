"""Mini-Review generator: one small Solidity file, one frozen commit.

This module turns the merged detectors into a client-ready deliverable
without rebuilding the tool and without any new LLM dependency:

- Reentrancy verdicts come from ``analyzers/reentrancy_evidence.py``
  (PR #34): a finding is only "Confirmed" when there is a
  callback-capable external call followed by a relevant state write.
  An unguarded external call with no such evidence is a guard note,
  never a confirmed Critical reentrancy.
- Evidence for other findings comes from ``gate_validator.py``
  (PR #35, Q1b): wording alone is not proof; the finding must name a
  function/state variable that actually exists in the analyzed code
  with a state transition.
- CVSS comes from ``cvss_scorer.py`` (PR #36): explicit attributes
  are "assessed", everything else is a labelled "fallback_estimate"
  or "not_assessed" -- a fallback is never presented as official.

Fix 2 (client-report separation, 2026-11-05): the report no longer
has a single "Findings" section that mixes proven items with guard
notes and LLM prose. It has exactly these buckets, and every triaged
item appears in exactly one of them:

- "Confirmed findings": code evidence AND Critical severity only.
  For reentrancy, code evidence is the PR #34 call-before-write rule.
  For every non-reentrancy finding, code evidence alone is NOT
  enough: it must also have passed Q1b AND have a verified Foundry
  PoC (a structured ``poc_result`` with status PROVED/passed, or a
  PoC executed via ``attempt_poc``). A supplied prose "poc" string
  is not an executed PoC and never upgrades a finding.
- "Unverified LLM hypotheses": non-reentrancy findings that have not
  passed Q1b + a verified PoC. They are explicitly labelled "not a
  finding" and are never listed under Confirmed findings.
- "Appendix: Guard notes (not findings)": guard notes only, labelled
  "not findings". They are not counted as confirmed findings.
- "Other items (not Confirmed findings)": reentrancy items that are
  Unverified, and code-supported items whose severity is not
  Critical (they cannot be Confirmed findings under the rule above).

PoC wiring status (Fix 2, honest limit): ``proof_generator.py``
generates a PoC only via an LLM call and executes it only via Docker
or a local ``forge`` toolchain, and its project builder does not
install ``forge-std`` (which every generated PoC imports). None of
that is run automatically by Mini-Review: in this VM neither
``docker`` nor ``forge`` exists, so an automatic attempt cannot
succeed here. Mini-Review therefore records PoC results only when
the caller supplies a structured ``poc_result`` (recorded verbatim),
or when the caller explicitly passes ``attempt_poc=True`` with a
``poc_path`` -- in which case ``attempt_poc()`` returns
"could-not-run" rather than inventing a pass when the toolchain is
absent. Automatic, per-Confirmed-finding PoC generation + execution
inside Mini-Review is an explicit follow-up, not a claim of this
change.

No detector verdict is changed here. This module only triages and
formats findings that are supplied by the caller, or, when no findings
are supplied, the reentrancy-evidence classification of the functions
in the supplied file. It never invents a commit hash, a line number,
or a PoC: a missing commit is recorded as "not provided", a location
is only reported when it is supplied or found verbatim in the source,
and a finding without code evidence is never upgraded to Confirmed.
"""

import argparse
import json
import re
import shutil
from pathlib import Path

import cvss_scorer as _cvss
import gate_validator as _gate

try:  # Normal package import; analyzers/__init__ is heavy, so fall back
    # to loading the single solc-free module by path if it fails.
    from analyzers.reentrancy_evidence import (
        call_before_write_evidence,
        classify_function,
        is_guarded as _is_guarded,
    )
except Exception:  # pragma: no cover - defensive, for minimal environments
    import importlib.util

    _spec = importlib.util.spec_from_file_location(
        "reentrancy_evidence",
        Path(__file__).with_name("analyzers") / "reentrancy_evidence.py",
    )
    _mod = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(_mod)
    call_before_write_evidence = _mod.call_before_write_evidence
    classify_function = _mod.classify_function
    _is_guarded = _mod.is_guarded

__all__ = [
    "attempt_poc",
    "generate_mini_review",
    "generate_mini_review_from_file",
    "triage_findings",
    "main",
]


# --- Fix 2: PoC result handling -------------------------------------------
#
# A PoC result is a structured dict supplied by the caller, e.g.
# {"status": "PROVED", "output": "<forge output>"} or
# {"status": "INCONCLUSIVE", "error": "docker not found"}. Only a
# passed/PROVED result counts as a verified PoC. A prose "poc" string
# on the finding, a bare poc_verified flag, or a missing result never
# counts: those are not an executed Foundry PoC.

_POC_PASSED = {"proved", "pass", "passed"}
_POC_FAILED = {"disproved", "fail", "failed"}
_POC_COULD_NOT_RUN = {
    "inconclusive", "could-not-run", "could_not_run", "not-run",
    "not_run", "error", "timeout",
}


def _normalize_poc_result(finding: dict):
    """Return (poc_status, poc_detail) for one finding.

    poc_status is one of "passed", "failed", "could-not-run" or
    "not attempted". poc_detail is the supplied output/error recorded
    verbatim (or "" when nothing was supplied); it is never invented.
    """
    result = finding.get("poc_result")
    if isinstance(result, dict):
        raw = str(result.get("status", "") or "").strip().lower()
        detail = result.get("output") or result.get("detail") or result.get("error") or ""
        if raw in _POC_PASSED:
            return "passed", str(detail)
        if raw in _POC_FAILED:
            return "failed", str(detail)
        # Any other supplied status (INCONCLUSIVE, error, unknown) is
        # a run that did not prove the finding, never a pass.
        return "could-not-run", str(detail)
    return "not attempted", ""


def attempt_poc(poc_path, victim_code="", use_docker=True):
    """Attempt one Foundry PoC via proof_generator, safely.

    Returns a poc_result dict {"status": ..., "output"/"error": ...}
    whose status is "passed", "failed" or "could-not-run". It never
    invents a pass: when the toolchain is absent (no docker for the
    Docker path, no forge for the local path), when the PoC file is
    missing, or when proof_generator cannot be imported or run, the
    result is "could-not-run" with the reason recorded. Callers must
    opt in explicitly (generate_mini_review(attempt_poc=True)); this
    is never run automatically, because PoC generation itself needs an
    LLM and execution needs a toolchain this VM does not have.
    """
    if not poc_path or not Path(str(poc_path)).exists():
        return {
            "status": "could-not-run",
            "error": "No PoC file supplied or PoC file does not exist; no PoC was executed.",
        }
    if use_docker and not shutil.which("docker"):
        return {
            "status": "could-not-run",
            "error": "Docker not found; PoC was not executed (Docker-isolated execution unavailable).",
        }
    if not use_docker and not shutil.which("forge"):
        return {
            "status": "could-not-run",
            "error": "forge not installed; PoC was not executed (local Foundry toolchain unavailable).",
        }
    try:
        import proof_generator as _pg

        raw = _pg.run_foundry_test(
            str(poc_path), use_docker=use_docker, victim_code=victim_code or ""
        )
    except Exception as exc:  # fail closed: a broken attempt is not a pass
        return {
            "status": "could-not-run",
            "error": f"PoC execution failed: {type(exc).__name__}: {exc}",
        }
    status = str(raw.get("status", "") or "").strip().lower()
    detail = raw.get("output") or raw.get("error") or ""
    if status in _POC_PASSED:
        return {"status": "passed", "output": str(detail)}
    if status in _POC_FAILED:
        return {"status": "failed", "output": str(detail)}
    return {"status": "could-not-run", "output": str(detail)}


def _is_reentrancy_finding(name: str, description: str) -> bool:
    lowered = (name + " " + description).lower()
    return (
        "reentrancy" in lowered
        or "re-entrancy" in lowered
        or "guard" in lowered
        or "external call" in lowered
    )

# Words that are not modifiers, used when extracting modifiers from a
# function signature suffix (the text between ")" and "{").
_NON_MODIFIER_WORDS = {
    "public", "external", "internal", "private", "view", "pure",
    "payable", "virtual", "override", "returns", "memory", "storage",
    "calldata",
}

_STATE_VAR_RE = re.compile(
    r"\b(?:mapping\s*\([^;]*\)|uint\d*|int\d*|address|bool|bytes\d*|string)"
    r"\s+(?:public\s+|private\s+|internal\s+)?"
    r"([A-Za-z_][A-Za-z0-9_]*)\s*(?:;|=)"
)

# Fix 3, second pattern: contract-scope-only declarations whose type is
# a user-defined name (a struct/contract/enum type), a payable address,
# or an array type -- shapes the built-in-type pattern above never
# matched. Without it, narrowing to contract scope would silently
# downgrade a genuine write through a state struct variable
# (``Position public pos; ... pos.balance = 0;``): the old code only
# "found" that write through the struct *field* name ``balance``,
# which Fix 3 correctly excludes. This pattern is therefore ONLY ever
# applied to matches the scope filter has already placed directly
# inside a contract body (see _state_variables); it never runs
# unfiltered over function bodies, so it cannot re-admit locals.
# Words that can never be a type (visibility, keywords, ``using``/``for``)
# are excluded, so ``using SafeMath for uint256;`` cannot contribute
# a bogus variable named ``uint256``.
_STATE_VAR_CUSTOM_RE = re.compile(
    r"\b([A-Za-z_][A-Za-z0-9_]*)"
    r"(?:\s*\[[^\]]*\])*"
    r"\s+(?:(?:public|private|internal|payable|constant|immutable)\s+)*"
    r"([A-Za-z_][A-Za-z0-9_]*)\s*(?:;|=)"
)
_NON_TYPE_WORDS = {
    "using", "for", "pragma", "import", "contract", "library",
    "interface", "struct", "enum", "function", "modifier",
    "constructor", "event", "error", "returns", "return", "if",
    "else", "while", "assembly", "emit", "try", "catch",
    "unchecked", "new", "delete", "this", "super", "abstract",
    "virtual", "override", "public", "private", "internal",
    "payable", "constant", "immutable", "fallback", "receive",
}

_FUNCTION_LINE_RE = re.compile(r"\bfunction\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(")

_DEFAULT_FIXES = {
    "reentrancy": (
        "Apply checks-effects-interactions: update state before any "
        "external call, and/or add a recognized reentrancy guard "
        "(nonReentrant). Re-test with a Foundry PoC after the fix."
    ),
    "guard": (
        "Add a recognized reentrancy guard (nonReentrant) or document "
        "why this external call cannot be re-entered, with a test."
    ),
}


def _mask_solidity_comments_and_strings(source: str) -> str:
    """Source with comments/strings blanked, length and newlines kept.

    Blanking (instead of deleting) keeps every character offset valid,
    so regex matches on the masked text line up with the original.
    A declaration-looking pattern inside a comment or a string literal
    is not a declaration, so it must not enter the state list.
    """
    out = []
    i, n = 0, len(source)
    while i < n:
        two = source[i:i + 2]
        if two == "//":
            end = source.find("\n", i)
            end = n if end == -1 else end
            out.append(" " * (end - i))
            i = end
        elif two == "/*":
            end = source.find("*/", i + 2)
            end = n if end == -1 else end + 2
            chunk = source[i:end]
            out.append("".join("\n" if c == "\n" else " " for c in chunk))
            i = end
        elif source[i] in ("\"", "'"):
            quote = source[i]
            j = i + 1
            while j < n:
                if source[j] == "\\":
                    j += 2
                    continue
                if source[j] == quote:
                    j += 1
                    break
                j += 1
            chunk = source[i:j]
            out.append("".join("\n" if c == "\n" else " " for c in chunk))
            i = j
        else:
            out.append(source[i])
            i += 1
    return "".join(out)


def _block_kind_before(masked: str, brace_pos: int) -> str:
    """'contract' for a contract/library/interface body, else 'block'.

    Only the segment since the previous ';', '{' or '}' is inspected,
    so a contract header is exactly ``contract Name ...`` (pragma and
    import lines end with ';' and cannot leak into the segment), while
    a function, struct, enum, if/for or modifier header never contains
    a contract keyword followed by a name.
    """
    start = 0
    for sep in (";", "{", "}"):
        idx = masked.rfind(sep, 0, brace_pos)
        if idx >= start:
            start = idx + 1
    segment = masked[start:brace_pos]
    if re.search(r"\b(contract|library|interface)\s+[A-Za-z_]", segment):
        return "contract"
    return "block"


def _state_variables(source: str):
    """Declared state variable names, in source order, de-duplicated.

    Fix 3: contract-level declarations only. The old regex scanned the
    whole file, so a local variable declared inside a function body
    (``uint localBal = ...``) and a struct field (``struct S { uint
    balance; }``) both entered the state list, and a later write to
    that local / local-struct field after an external call was then
    reported as a Confirmed Critical reentrancy write -- false
    evidence. A match now counts only when the brace stack at its
    position is exactly one contract body: directly inside
    ``contract``/``library``/``interface`` and inside no function,
    struct, enum, modifier or nested block. The declaration regex
    itself is unchanged, so a genuine contract-level write (including
    ``pos.balance = ...`` through a state struct variable) still
    counts. Fallback: if the file contains no contract block at all
    (a bare snippet, not a contract file), the legacy unfiltered list
    is kept rather than silently dropping every state variable and
    missing genuine findings -- that shape is not a real contract
    file, and the fallback is documented, not hidden.
    """
    source = source or ""
    masked = _mask_solidity_comments_and_strings(source)
    # (start, name) candidates from both patterns, in source order.
    # The custom pattern's type word must be a plausible type name,
    # never a keyword or visibility word (see _NON_TYPE_WORDS).
    candidates = [
        (m.start(), m.group(1)) for m in _STATE_VAR_RE.finditer(masked)
    ]
    for m in _STATE_VAR_CUSTOM_RE.finditer(masked):
        if m.group(1) in _NON_TYPE_WORDS or m.group(2) in _NON_TYPE_WORDS:
            continue
        candidates.append((m.start(), m.group(2)))
    candidates.sort()
    if not candidates:
        return []
    wanted = {start for start, _ in candidates}
    stack = []
    saw_contract = False
    in_contract_scope = {}
    for i, ch in enumerate(masked):
        if i in wanted:
            in_contract_scope[i] = len(stack) == 1 and stack[0] == "contract"
        if ch == "{":
            kind = _block_kind_before(masked, i)
            if kind == "contract":
                saw_contract = True
            stack.append(kind)
        elif ch == "}":
            if stack:
                stack.pop()
    seen = []
    for start, name in candidates:
        if not saw_contract:
            keep = True
        else:
            keep = in_contract_scope.get(start, False)
        if not keep:
            continue
        if name not in seen:
            seen.append(name)
    return seen


def _modifiers_from_suffix(suffix: str):
    """Modifier names from a function signature suffix."""
    suffix = re.sub(r"\breturns\s*\([^)]*\)", "", suffix or "")
    words = re.findall(r"[A-Za-z_][A-Za-z0-9_]*", suffix)
    return [w for w in words if w not in _NON_MODIFIER_WORDS]


def _find_function_location(source: str, file_label: str, finding: dict):
    """Return 'file:line' only when a function is found verbatim.

    Falls back to a caller-supplied location, otherwise 'Not provided'.
    Line numbers are never guessed: they are counted from the source
    text for the exact 'function <name>(' match.
    """
    if finding.get("location"):
        return str(finding["location"])
    text = " ".join(
        str(finding.get(key, "")) for key in ("name", "description", "poc")
    )
    for name in re.findall(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(", text):
        for lineno, line in enumerate((source or "").splitlines(), start=1):
            if re.search(rf"\bfunction\s+{re.escape(name)}\s*\(", line):
                return f"{file_label}:{lineno}"
    return "Not provided"


def _cvss_for_finding(finding: dict):
    """Score one finding, preserving PR #36 provenance/status exactly.

    Returns a dict with score (float or None), vector (str or None),
    status ('assessed', 'fallback_estimate' or 'not_assessed') and a
    display string that never presents a fallback as official.
    """
    attrs = finding.get("cvss_attributes")
    if attrs:
        result = _cvss.score_from_attributes(attrs)
    elif finding.get("cvss_vector"):
        result = _cvss.score_from_vector(finding["cvss_vector"])
    else:
        # Reuse score_report's labelled fallback for this one finding.
        report = (
            f"- **Name**: {finding.get('name', '?')}\n"
            f"- **Severity**: {finding.get('severity', 'Medium')}\n"
            f"- **Description**: {finding.get('description', '')}\n"
        )
        scored = _cvss.score_report(report)["findings"]
        result = scored[0] if scored else {"status": "not_assessed"}
    status = result.get("status", "not_assessed")
    score = result.get("cvss_score")
    vector = result.get("cvss_vector")
    provenance = result.get("provenance", "")
    method = result.get("method", "")
    if status == "not_assessed" or score is None:
        display = "Not assessed"
        if result.get("note"):
            display += f" ({result['note']})"
    elif status == "fallback_estimate":
        # Never print method=official alone for a fallback: the method
        # field is the scoring formula, not the assessment provenance.
        display = (
            f"{score}/10 ({result.get('cvss_severity', '')}) — "
            f"fallback_estimate (not official, not an attribute "
            f"assessment; provenance: {provenance}) — `{vector}`"
        )
    else:  # assessed
        display = (
            f"{score}/10 ({result.get('cvss_severity', '')}) — assessed "
            f"(method: {method}, provenance: {provenance}) — `{vector}`"
        )
    return {
        "score": score,
        "vector": vector,
        "status": status,
        "provenance": provenance,
        "method": method,
        "display": display,
    }


def _triage_one(finding: dict, source: str, functions: dict, state_vars):
    """Triage one supplied finding by evidence, never by label alone."""
    name = str(finding.get("name", "") or "?")
    severity = str(finding.get("severity", "Medium") or "Medium")
    description = str(finding.get("description", "") or "")
    lowered = (name + " " + description).lower()
    is_reentrancy = _is_reentrancy_finding(name, description)
    poc_status, poc_detail = _normalize_poc_result(finding)
    poc_verified = poc_status == "passed"
    q1b_passed = None

    if finding.get("unverified") or finding.get("validation_error"):
        # Fix 2: a caller-unverified non-reentrancy finding is an
        # unverified LLM hypothesis, not a finding; reentrancy keeps
        # the plain Unverified status (it is a code-evidence failure,
        # not an LLM-supplied hypothesis).
        if is_reentrancy:
            evidence_status = "Unverified"
        else:
            evidence_status = "Unverified LLM hypothesis"
        evidence_note = str(
            finding.get("validation_error") or "Marked unverified by caller."
        )
    else:
        evidence_status = None
        evidence_note = ""
        # 1. Reentrancy evidence (PR #34) is decisive for reentrancy and
        #    guard-note findings. Without this, a guarded function could
        #    fall through to the gate below and be marked Confirmed even
        #    though its reentrancy guard blocks the re-entrant path.
        is_reentrancy_or_guard = (
            "reentrancy" in lowered
            or "re-entrancy" in lowered
            or "guard" in lowered
            or "external call" in lowered
        )
        if is_reentrancy_or_guard:
            # Match function names as whole words, longest first. A
            # plain substring match misattributes fixed variants to
            # the vulnerable function: "withdrawbalance" is a substring
            # of "withdrawbalance_fixed", so a guard note for the fixed
            # variant was triaged as Confirmed for the vulnerable one
            # (NS-RE-01 showed 3 Confirmed for 1 Critical). A word
            # boundary fails after "withdrawbalance" when "_" follows,
            # because "_" is a word character, so the fixed variant
            # now matches itself, not its vulnerable prefix.
            for func_name, info in sorted(
                functions.items(), key=lambda kv: -len(kv[0])
            ):
                if not re.search(
                    r"(?<![A-Za-z0-9_])"
                    + re.escape(func_name.lower())
                    + r"(?![A-Za-z0-9_])",
                    lowered,
                ):
                    continue
                body = info.get("body", "")
                modifiers = _modifiers_from_suffix(info.get("suffix", ""))
                classification, evidence = classify_function(
                    modifiers, body, state_vars
                )
                if classification == "confirmed":
                    evidence_status = "Confirmed by code evidence"
                    if finding.get("poc"):
                        evidence_status = "Confirmed by code evidence / PoC"
                    evidence_note = (
                        f"Callback-capable call followed by a write to "
                        f"'{evidence[2]}' in {func_name}()."
                    )
                elif classification == "guard-note":
                    evidence_status = "Guard note only"
                    evidence_note = (
                        f"External call in {func_name}() with no "
                        f"call-before-write evidence; not confirmed reentrancy."
                    )
                elif _is_guarded(modifiers):
                    evidence_status = "Guard note only"
                    evidence_note = (
                        f"{func_name}() is guarded by a recognized "
                        f"reentrancy guard; not confirmed reentrancy."
                    )
                else:
                    evidence_status = "Unverified"
                    evidence_note = (
                        f"No callback-capable call-before-write evidence "
                        f"in {func_name}()."
                    )
                break
            if evidence_status is None:
                evidence_status = "Unverified"
                evidence_note = "No named function in the analyzed code."
        # 2. Gate code evidence (PR #35, Q1b) for non-reentrancy findings,
        #    or for reentrancy findings the step above did not classify.
        if evidence_status is None:
            try:
                has_evidence, reason = _gate._has_code_evidence(finding, source)
            except Exception as exc:  # fail closed: do not upgrade
                has_evidence, reason = False, f"Evidence check error: {exc}"
            q1b_passed = bool(has_evidence)
            if has_evidence and is_reentrancy:
                # Reentrancy findings that reach the gate (no function
                # matched step 1) keep the old code-evidence status;
                # the reentrancy rule, not the LLM, is their evidence.
                evidence_status = "Confirmed by code evidence"
                if finding.get("poc"):
                    evidence_status = "Confirmed by code evidence / PoC"
                evidence_note = "Named code location exists in the analyzed code with a state transition."
            elif has_evidence and not is_reentrancy:
                # Fix 2: for non-reentrancy findings Q1b alone is NOT
                # confirmation. It also needs a verified Foundry PoC;
                # otherwise it is an unverified LLM hypothesis, even
                # when its prose "poc" field is populated -- that
                # field is unexecuted text, not a PoC run.
                if poc_verified:
                    evidence_status = "Confirmed by code evidence / PoC (verified)"
                    evidence_note = (
                        "Q1b code evidence passed and a Foundry PoC "
                        "result was supplied with status passed."
                    )
                else:
                    evidence_status = "Unverified LLM hypothesis"
                    prose_note = (
                        " Supplied PoC text was not executed and is "
                        "not a verified PoC." if finding.get("poc") else ""
                    )
                    evidence_note = (
                        "Q1b code location exists, but no verified "
                        f"Foundry PoC: PoC status is {poc_status}."
                        + prose_note
                    )
            else:
                # Explicit guard-note findings keep their guard-note status
                # instead of being silently dropped or upgraded.
                if "guard" in lowered or "external call without" in lowered:
                    evidence_status = "Guard note only"
                else:
                    # Fix 2: a non-reentrancy finding without Q1b is an
                    # unverified LLM hypothesis, whatever its severity
                    # label says; a reentrancy one stays Unverified.
                    evidence_status = (
                        "Unverified" if is_reentrancy
                        else "Unverified LLM hypothesis"
                    )
                evidence_note = reason or "No code evidence in the analyzed file."
    # Fix 2, reentrancy: an executed PoC that FAILED (DISPROVED)
    # overrides code evidence -- presenting it as Confirmed after a
    # failed exploit attempt would invent proof. A could-not-run PoC
    # does not downgrade: absence of a run is not disproof.
    if (
        is_reentrancy
        and evidence_status
        and evidence_status.startswith("Confirmed by code evidence")
        and poc_status == "failed"
    ):
        evidence_status = "Unverified"
        evidence_note = (
            "Code evidence existed, but an executed Foundry PoC "
            "failed (DISPROVED); not presented as Confirmed."
        )
    return {
        "name": name,
        "severity": severity,
        "description": description,
        "evidence_status": evidence_status,
        "evidence_note": evidence_note,
        "cvss": _cvss_for_finding(finding),
        "is_reentrancy": is_reentrancy,
        "q1b_passed": q1b_passed,
        "poc_status": poc_status,
        "poc_detail": poc_detail,
        "poc_verified": poc_verified,
    }


def triage_findings(findings, source: str):
    """Triage supplied findings against source, returning triaged dicts."""
    functions = _gate._parse_code_functions(source or "")
    state_vars = _state_variables(source or "")
    return [
        _triage_one(finding, source or "", functions, state_vars)
        for finding in (findings or [])
    ]


def _auto_findings(source: str):
    """Reentrancy-evidence findings only, when the caller supplies none.

    This reuses classify_function only; it does not run the LLM
    pipeline and does not invent other vulnerability classes.
    """
    functions = _gate._parse_code_functions(source or "")
    state_vars = _state_variables(source or "")
    auto = []
    for func_name, info in functions.items():
        modifiers = _modifiers_from_suffix(info.get("suffix", ""))
        classification, evidence = classify_function(
            modifiers, info.get("body", ""), state_vars
        )
        if classification == "confirmed":
            auto.append({
                "name": "Reentrancy",
                "severity": "Critical",
                "description": (
                    f"Reentrancy in {func_name}(): callback-capable call "
                    f"followed by a write to '{evidence[2]}'."
                ),
                "fix": _DEFAULT_FIXES["reentrancy"],
            })
        elif classification == "guard-note":
            auto.append({
                "name": "External Call Without Recognized Guard",
                "severity": "Medium",
                "description": (
                    f"External call in {func_name}() with no recognized "
                    f"guard and no call-before-write evidence."
                ),
                "fix": _DEFAULT_FIXES["guard"],
            })
    return auto


def _severity_counts(triaged):
    order = ["Critical", "High", "Medium", "Low", "Info"]
    counts = {sev: 0 for sev in order}
    other = 0
    for item in triaged:
        if item["severity"] in counts:
            counts[item["severity"]] += 1
        else:
            other += 1
    return counts, other


def _partition_triaged(triaged, raw_findings):
    """Split triaged items into Fix 2 report buckets, in order.

    Returns (confirmed, hypotheses, guard_notes, other) as lists of
    (item, raw_finding) pairs, each item in exactly one bucket:
    - confirmed: severity Critical AND evidence Confirmed AND
      (reentrancy code evidence OR a verified PoC for non-reentrancy).
    - hypotheses: non-reentrancy items that are not confirmed
      (Unverified LLM hypothesis, including caller-unverified ones).
    - guard_notes: evidence "Guard note only" (any severity).
    - other: everything else (reentrancy Unverified, and
      code-supported items whose severity is not Critical).
    """
    confirmed, hypotheses, guard_notes, other = [], [], [], []
    for item, raw in zip(triaged, raw_findings):
        status = item["evidence_status"]
        is_confirmed = status.startswith("Confirmed by code evidence")
        if status == "Guard note only":
            guard_notes.append((item, raw))
        elif (
            is_confirmed
            and item["severity"] == "Critical"
            and (item.get("is_reentrancy") or item.get("poc_verified"))
        ):
            confirmed.append((item, raw))
        elif not item.get("is_reentrancy") and not (
            is_confirmed and item.get("poc_verified")
        ):
            # Non-reentrancy, not confirmed: an unverified LLM
            # hypothesis. A verified-PoC item that only misses the
            # Critical bar falls through to "other", not here.
            hypotheses.append((item, raw))
        else:
            other.append((item, raw))
    return confirmed, hypotheses, guard_notes, other


def _render_item(lines, idx, item, raw, source, file_label, section_status):
    """Render one item with its PoC result recorded verbatim."""
    # Fix suggestions come from the caller, or from the generic
    # reentrancy/guard templates; they are never presented as
    # verified fixes.
    fix = raw.get("fix") or raw.get("fix_suggestion")
    if not fix:
        lowered = (item["name"] + " " + item["description"]).lower()
        if "reentrancy" in lowered:
            fix = _DEFAULT_FIXES["reentrancy"]
        elif "guard" in lowered:
            fix = _DEFAULT_FIXES["guard"]
        else:
            fix = "No fix suggestion supplied — review manually."
    location = _find_function_location(source, file_label, raw)
    lines.append(f"### {idx}. {item['name']}")
    lines.append("")
    if section_status:
        lines.append(f"- **Status**: {section_status}")
    lines.append(f"- **Severity**: {item['severity']}")
    lines.append(f"- **Evidence**: {item['evidence_status']}")
    lines.append(f"- **Evidence note**: {item['evidence_note']}")
    lines.append(f"- **Location**: {location}")
    lines.append(f"- **CVSS**: {item['cvss']['display']}")
    if item["description"]:
        lines.append(f"- **Description**: {item['description']}")
    lines.append(f"- **Fix suggestion**: {fix}")
    poc_status = item.get("poc_status", "not attempted")
    poc_detail = item.get("poc_detail", "")
    if poc_detail:
        # Verbatim: the supplied/executed PoC output or error, as-is.
        lines.append(f"- **PoC result**: {poc_status} — {poc_detail}")
    else:
        lines.append(f"- **PoC result**: {poc_status}")
    lines.append("")


def generate_mini_review(
    source: str,
    *,
    file_path=None,
    commit=None,
    findings=None,
    validation_failed=False,
    attempt_poc=False,
    poc_results=None,
):
    """Generate one clean Markdown Mini-Review report.

    ``source`` is the Solidity source text of the single file in scope.
    ``commit`` is recorded verbatim; when it is missing or empty the
    report says "commit: not provided" and invents nothing.
    ``findings`` is an optional list of dicts (see module docstring).
    When it is None, only reentrancy-evidence findings are generated.
    ``validation_failed`` forces the UNVERIFIED banner (PR #35).
    ``poc_results`` is an optional list, aligned with ``findings`` by
    index, of structured poc_result dicts (see _normalize_poc_result);
    a finding may also carry its own "poc_result" dict. A result is
    recorded verbatim in the report. ``attempt_poc`` (opt-in only)
    attempts a PoC for each finding that carries a "poc_path", via
    attempt_poc(); a missing toolchain yields "could-not-run", never
    an invented pass. Neither option runs PoC generation: generating
    a PoC needs an LLM (proof_generator.generate_poc), which
    Mini-Review deliberately does not call.
    """
    source = source or ""
    file_label = file_path or "Not provided"
    commit_label = commit if commit else "not provided"
    supplied = findings is not None
    raw_findings = [dict(f) for f in findings] if supplied else _auto_findings(source)
    if poc_results:
        for idx, result in enumerate(poc_results):
            if idx < len(raw_findings) and result is not None:
                raw_findings[idx]["poc_result"] = result
    if attempt_poc:
        # The parameter shadows the module function of the same name,
        # so reach the function via globals() explicitly.
        _attempt = globals()["attempt_poc"]
        for raw in raw_findings:
            if raw.get("poc_path") and not raw.get("poc_result"):
                raw["poc_result"] = _attempt(
                    raw["poc_path"], victim_code=source,
                    use_docker=raw.get("poc_use_docker", True),
                )

    # Fail closed (PR #35): a validation failure is a banner on the
    # whole report, never a clean report with unvalidated findings.
    unverified = bool(validation_failed) or any(
        f.get("unverified") or f.get("validation_error") for f in raw_findings
    )
    try:
        triaged = triage_findings(raw_findings, source)
    except Exception as exc:  # pragma: no cover - fail-closed path
        unverified = True
        triaged = []

    confirmed, hypotheses, guard_notes, other = _partition_triaged(
        triaged, raw_findings
    )
    # Summary counts are bucket counts, never label-only counts: a
    # Medium guard note can carry an evidence note whose text mentions
    # confirmation, and the old label-only count turned NS-RE-01's
    # 1 Critical + 2 Medium guard notes into "Confirmed: 3". Only
    # Critical items in the Confirmed bucket count as Confirmed, so
    # the Confirmed count can never exceed the Critical confirmed
    # count, and guard notes are counted only as guard notes.
    confirmed_by_status = {}
    for item, _raw in confirmed:
        confirmed_by_status[item["evidence_status"]] = (
            confirmed_by_status.get(item["evidence_status"], 0) + 1
        )

    lines = []
    lines.append("# Mini-Review Report")
    lines.append("")
    if unverified:
        # Reuse the gate's exact banner wording so the report cannot be
        # mistaken for a validated audit.
        lines.append(_gate.mark_unverified("", "validation failed").strip())
        lines.append("")
    lines.append("## Scope")
    lines.append("")
    lines.append(f"- **File**: {file_label}")
    lines.append(f"- **Commit**: {commit_label}")
    lines.append(
        "- **In scope**: the single Solidity file above, on the frozen "
        "commit above, as supplied for this review."
    )
    lines.append(
        "- **Out of scope**: every other file and contract, deployed or "
        "production code not in the supplied file, private production "
        "code not supplied, off-chain code, deployment configuration, "
        "tokenomics, and any fix review after this report (a fix review "
        "is a separate round)."
    )
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    if not triaged:
        lines.append("No findings are listed in this report.")
    else:
        # Fix 2: "Confirmed findings" is the only findings count.
        # Guard notes and hypotheses are counted separately and are
        # explicitly not findings, so they can never inflate it.
        lines.append(f"- **Confirmed findings**: {len(confirmed)}")
        if confirmed:
            lines.append(f"- **Critical**: {len(confirmed)}")
        for status, count in sorted(confirmed_by_status.items()):
            lines.append(f"- **{status}**: {count}")
        if hypotheses:
            lines.append(
                f"- **Unverified LLM hypotheses (not findings)**: {len(hypotheses)}"
            )
        if guard_notes:
            lines.append(f"- **Guard note only**: {len(guard_notes)}")
            lines.append(
                f"- **Guard notes (not findings)**: {len(guard_notes)}"
            )
        if other:
            lines.append(
                f"- **Other items (not Confirmed findings)**: {len(other)}"
            )
        unverified_count = sum(
            1 for item in triaged if item["evidence_status"] == "Unverified"
        )
        if unverified_count:
            lines.append(f"- **Unverified**: {unverified_count}")
    lines.append("")
    lines.append("## Confirmed findings")
    lines.append("")
    if not triaged:
        lines.append(
            "No findings to report. This does not certify the contract "
            "as secure; it only states that no finding was supplied or "
            "generated for this file in this review."
        )
    elif not confirmed:
        lines.append(
            "No confirmed findings in this report. This does not "
            "certify the contract as secure; it only states that no "
            "code-evidence + Critical finding was confirmed for this "
            "file in this review."
        )
    else:
        lines.append(
            "Confirmed findings are code-evidence + Critical only: "
            "reentrancy by the call-before-write rule, or a "
            "non-reentrancy finding that passed Q1b and a verified "
            "Foundry PoC."
        )
        lines.append("")
        for idx, (item, raw) in enumerate(confirmed, start=1):
            _render_item(
                lines, idx, item, raw, source, file_label,
                section_status="confirmed finding",
            )
    if hypotheses:
        lines.append("## Unverified LLM hypotheses")
        lines.append("")
        lines.append(
            "The following items are NOT findings. They are unverified "
            "LLM hypotheses: each has not passed both Q1b code "
            "evidence and a verified Foundry PoC, and must not be "
            "presented to a client as a finding."
        )
        lines.append("")
        for idx, (item, raw) in enumerate(hypotheses, start=1):
            _render_item(
                lines, idx, item, raw, source, file_label,
                section_status="unverified LLM hypothesis — not a finding",
            )
    if other:
        lines.append("## Other items (not Confirmed findings)")
        lines.append("")
        lines.append(
            "The following items are NOT Confirmed findings: either "
            "their reentrancy evidence is Unverified, or they are "
            "code-supported but not Critical, so they do not meet the "
            "Confirmed-findings rule."
        )
        lines.append("")
        for idx, (item, raw) in enumerate(other, start=1):
            _render_item(
                lines, idx, item, raw, source, file_label,
                section_status="not a Confirmed finding",
            )
    if guard_notes:
        lines.append("## Appendix: Guard notes (not findings)")
        lines.append("")
        lines.append(
            "The following are NOT findings. They are guard notes: an "
            "external call with no recognized guard and no "
            "call-before-write evidence. They are listed here for "
            "completeness only and must not be read as vulnerabilities."
        )
        lines.append("")
        for idx, (item, raw) in enumerate(guard_notes, start=1):
            _render_item(
                lines, idx, item, raw, source, file_label,
                section_status="guard note — not a finding",
            )
    lines.append("## Method and limits")
    lines.append("")
    lines.append(
        "A finding is Confirmed only with code evidence and Critical "
        "severity: reentrancy by call-before-write evidence, or a "
        "non-reentrancy finding that passed Q1b code evidence and a "
        "verified Foundry PoC. Anything else is labelled an unverified "
        "LLM hypothesis or a guard note in the appendix, never a "
        "finding. A fallback CVSS score is never presented as "
        "official, and a validation failure marks the whole report "
        "UNVERIFIED. PoC wiring: Mini-Review does not generate PoCs "
        "(proof_generator generation needs an LLM) and does not run "
        "PoCs automatically (execution needs Docker or forge, and "
        "neither was available in this VM at Fix 2 time; the PoC "
        "project builder also does not install forge-std, which "
        "generated PoCs import). PoC results appear in this report "
        "only when supplied as a structured poc_result or via an "
        "explicit attempt_poc run, and are recorded verbatim as "
        "passed, failed, or could-not-run, never invented. This "
        "Mini-Review covers only the file and commit in Scope above; "
        "it is not a full audit, not a formal verification, and not a "
        "guarantee of security."
    )
    return "\n".join(lines).rstrip() + "\n"


def generate_mini_review_from_file(
    path,
    *,
    commit=None,
    findings=None,
    validation_failed=False,
    attempt_poc=False,
    poc_results=None,
):
    """Read one Solidity file and generate its Mini-Review report."""
    text = Path(path).read_text(encoding="utf-8", errors="replace")
    return generate_mini_review(
        text,
        file_path=str(path),
        commit=commit,
        findings=findings,
        validation_failed=validation_failed,
        attempt_poc=attempt_poc,
        poc_results=poc_results,
    )


def main(argv=None):
    """CLI: python mini_review.py <file.sol> --commit <hash> [--findings-json f.json] [--validation-failed]"""
    parser = argparse.ArgumentParser(description="Generate a Mini-Review report.")
    parser.add_argument("file", help="Single Solidity file in scope")
    parser.add_argument("--commit", default=None, help="Frozen commit hash (required for a client report; recorded verbatim)")
    parser.add_argument("--findings-json", default=None, help="JSON list of finding dicts; when omitted, only reentrancy-evidence findings are generated")
    parser.add_argument("--validation-failed", action="store_true", help="Force the UNVERIFIED banner")
    parser.add_argument("--attempt-poc", action="store_true", help="Attempt a PoC for each finding carrying a poc_path (opt-in; missing toolchain yields could-not-run, never a pass)")
    args = parser.parse_args(argv)
    findings = None
    if args.findings_json:
        findings = json.loads(Path(args.findings_json).read_text(encoding="utf-8"))
    print(
        generate_mini_review_from_file(
            args.file,
            commit=args.commit,
            findings=findings,
            validation_failed=args.validation_failed,
            attempt_poc=args.attempt_poc,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
