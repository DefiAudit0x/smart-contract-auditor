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
    "generate_mini_review",
    "generate_mini_review_from_file",
    "triage_findings",
    "main",
]

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


def _state_variables(source: str):
    """Declared state variable names, in source order, de-duplicated."""
    seen = []
    for match in _STATE_VAR_RE.finditer(source or ""):
        name = match.group(1)
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

    if finding.get("unverified") or finding.get("validation_error"):
        evidence_status = "Unverified"
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
            for func_name, info in functions.items():
                if func_name.lower() not in lowered:
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
            if has_evidence:
                evidence_status = "Confirmed by code evidence"
                if finding.get("poc"):
                    evidence_status = "Confirmed by code evidence / PoC"
                evidence_note = "Named code location exists in the analyzed code with a state transition."
            else:
                # Explicit guard-note findings keep their guard-note status
                # instead of being silently dropped or upgraded.
                if "guard" in lowered or "external call without" in lowered:
                    evidence_status = "Guard note only"
                else:
                    evidence_status = "Unverified"
                evidence_note = reason or "No code evidence in the analyzed file."
    return {
        "name": name,
        "severity": severity,
        "description": description,
        "evidence_status": evidence_status,
        "evidence_note": evidence_note,
        "cvss": _cvss_for_finding(finding),
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


def generate_mini_review(
    source: str,
    *,
    file_path=None,
    commit=None,
    findings=None,
    validation_failed=False,
):
    """Generate one clean Markdown Mini-Review report.

    ``source`` is the Solidity source text of the single file in scope.
    ``commit`` is recorded verbatim; when it is missing or empty the
    report says "commit: not provided" and invents nothing.
    ``findings`` is an optional list of dicts (see module docstring).
    When it is None, only reentrancy-evidence findings are generated.
    ``validation_failed`` forces the UNVERIFIED banner (PR #35).
    """
    source = source or ""
    file_label = file_path or "Not provided"
    commit_label = commit if commit else "not provided"
    supplied = findings is not None
    raw_findings = list(findings) if supplied else _auto_findings(source)

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

    counts, other = _severity_counts(triaged)
    by_evidence = {}
    for item in triaged:
        by_evidence[item["evidence_status"]] = (
            by_evidence.get(item["evidence_status"], 0) + 1
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
        lines.append(f"- **Total findings**: {len(triaged)}")
        for sev in ("Critical", "High", "Medium", "Low", "Info"):
            if counts[sev]:
                lines.append(f"- **{sev}**: {counts[sev]}")
        if other:
            lines.append(f"- **Other severity**: {other}")
        for status in (
            "Confirmed by code evidence",
            "Confirmed by code evidence / PoC",
            "Guard note only",
            "Unverified",
        ):
            if by_evidence.get(status):
                lines.append(f"- **{status}**: {by_evidence[status]}")
    lines.append("")
    lines.append("## Findings")
    lines.append("")
    if not triaged:
        lines.append(
            "No findings to report. This does not certify the contract "
            "as secure; it only states that no finding was supplied or "
            "generated for this file in this review."
        )
    for idx, item in enumerate(triaged, start=1):
        # Fix suggestions come from the caller, or from the generic
        # reentrancy/guard templates; they are never presented as
        # verified fixes.
        raw = raw_findings[idx - 1] if idx - 1 < len(raw_findings) else {}
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
        lines.append(f"- **Severity**: {item['severity']}")
        lines.append(f"- **Evidence**: {item['evidence_status']}")
        lines.append(f"- **Evidence note**: {item['evidence_note']}")
        lines.append(f"- **Location**: {location}")
        lines.append(f"- **CVSS**: {item['cvss']['display']}")
        if item["description"]:
            lines.append(f"- **Description**: {item['description']}")
        lines.append(f"- **Fix suggestion**: {fix}")
        lines.append("")
    lines.append("## Method and limits")
    lines.append("")
    lines.append(
        "Findings are triaged by code evidence only: a severity label "
        "alone never makes a finding Confirmed, a fallback CVSS score "
        "is never presented as official, and a validation failure "
        "marks the whole report UNVERIFIED. This Mini-Review covers "
        "only the file and commit in Scope above; it is not a full "
        "audit, not a formal verification, and not a guarantee of "
        "security."
    )
    return "\n".join(lines).rstrip() + "\n"


def generate_mini_review_from_file(
    path,
    *,
    commit=None,
    findings=None,
    validation_failed=False,
):
    """Read one Solidity file and generate its Mini-Review report."""
    text = Path(path).read_text(encoding="utf-8", errors="replace")
    return generate_mini_review(
        text,
        file_path=str(path),
        commit=commit,
        findings=findings,
        validation_failed=validation_failed,
    )


def main(argv=None):
    """CLI: python mini_review.py <file.sol> --commit <hash> [--findings-json f.json] [--validation-failed]"""
    parser = argparse.ArgumentParser(description="Generate a Mini-Review report.")
    parser.add_argument("file", help="Single Solidity file in scope")
    parser.add_argument("--commit", default=None, help="Frozen commit hash (required for a client report; recorded verbatim)")
    parser.add_argument("--findings-json", default=None, help="JSON list of finding dicts; when omitted, only reentrancy-evidence findings are generated")
    parser.add_argument("--validation-failed", action="store_true", help="Force the UNVERIFIED banner")
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
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
