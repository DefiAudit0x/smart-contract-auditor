"""
7-Question Gate Validator — third-pass validation adapted from web3-triage-report SKILL.
Each finding must pass all 7 questions before being reported.
"""
import logging
import re
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# Known safe names (Q1 filter)
_SAFE_NAME_KEYWORDS = [
    "gas optimization", "gas saving", "unused import", "unused variable",
    "typo", "comment", "naming convention", "code style",
    "pragma", "SPDX", "missing event", "named return",
]

# Patterns that indicate vague / non-exploitable (Q1)
_FP_INDICATORS = [
    "could lead to", "might be", "potentially", "possibly",
    "it is recommended", "best practice", "consider",
    "may result in", "could cause",
]

# Severity downgrade map
_SEVERITY_DOWNGRADE = {
    "Critical": "High",
    "High": "Medium",
    "Medium": "Low",
    "Low": "Info",
}

# Accepted impact tiers (Q2) — from Immunefi standard
_ACCEPTED_IMPACTS = {
    "Critical": ["direct theft", "permanent freezing", "protocol insolvency"],
    "High": ["theft of unclaimed yield", "permanent freezing of unclaimed yield", "temporary freezing"],
    "Medium": ["unable to operate due to lack of token funds", "griefing"],
    "Low": ["fails to deliver promised returns", "best practice"],
}

# Centralization signals (Q4)
_CENTRALIZATION_SIGNALS = [
    "admin", "onlyowner", "onlyRole(", "privileged", "centralization",
    "timelock", "governance", "multisig",
]


def _extract_findings(report: str) -> List[Dict]:
    findings = []
    lines = report.split("\n")
    current: Dict = {}
    for line in lines:
        s = re.sub(r"^(?:[-*+•]|\d+[.)])\s*", "", line.strip())
        if s.startswith("**Name**"):
            if current and current.get("name"):
                findings.append(current)
            current = {"name": s.split(":", 1)[1].strip() if ":" in s else s.replace("**Name**", "").strip()}
        elif s.startswith("**Severity**") and current:
            sev = s.split(":", 1)[1].strip() if ":" in s else "Medium"
            current["severity"] = sev.rstrip("*")
        elif s.startswith("**Description**") and current:
            current["description"] = s.split(":", 1)[1].strip() if ":" in s else ""
        elif s.startswith("**Fix**") and current:
            current["fix"] = s.split(":", 1)[1].strip() if ":" in s else ""
        elif s.startswith("**PoC**") and current:
            current["poc"] = s.split(":", 1)[1].strip() if ":" in s else ""
        elif s.startswith("**Impact**") and current:
            current["impact"] = s.split(":", 1)[1].strip() if ":" in s else ""
        elif s.startswith("**Category**") and current:
            current["category"] = s.split(":", 1)[1].strip() if ":" in s else ""
    if current and current.get("name"):
        findings.append(current)
    return findings


def _has_exploit_path(combined: str) -> bool:
    """Concrete exploit path = ordered steps AND a concrete call reference
    (M22 remediation): any single word like 'call' or a bare '1.' used to
    satisfy the check, letting vague findings slip through the gate."""
    has_steps = (
        any(w in combined for w in ["step", "first", "then", "sequence", "attack", "exploit"])
        or bool(re.search(r"\b[1-3]\.\s\S", combined))
    )
    has_call_ref = (
        bool(re.search(r"\.(?:call|transfer|send|delegatecall|staticcall)\s*\(", combined))
        or bool(re.search(r"\bfunction\s+\w+", combined))
        or any(w in combined for w in ["transaction", "flash", "repay", "borrow", "swap"])
    )
    return has_steps and has_call_ref


def _has_impact_words(combined: str, sev: str) -> bool:
    """Check if the finding describes concrete impact for its severity."""
    if sev in ("Critical", "High"):
        return any(w in combined for w in [
            "steal", "drain", "loss", "theft", "lock", "freeze",
            "burn", "insolvent", "bad debt",
        ])
    return True


def _unverified_banner(reason: str) -> str:
    return (
        "### Validation Warning\n\n"
        "The validation gate failed to validate this run"
        + (f" ({reason})" if reason else "")
        + ". The original report is preserved below UNCHANGED for human review - "
        "treat this run as UNVERIFIED, not as a clean audit.\n\n"
    )


def mark_unverified(report: str, reason: str = "") -> str:
    """Fail-closed wrapper: never present an unvalidated report as validated."""
    if report.startswith("### Validation Warning"):
        return report
    return _unverified_banner(reason) + report


# --- Code-evidence helpers (issue #28 / F-18) ---
#
# The old exploit-path check is wording only: it passes when a report
# *describes* an attack ("first", "then", "attack", "call", numbered
# steps).  That is a triage signal, not proof.  For Critical/High
# findings the gate now additionally requires evidence *in the analyzed
# code*: a function/state variable named by the finding that actually
# exists in the code, reachable by an unprivileged caller, with a state
# transition in its body.  This check is solc-free (regex + brace
# matching) so it stays unit-testable without a compiler.

_FUNCTION_RE = re.compile(
    r"\b(?:function|def)\s+(\w+)\s*\(([^)]*)\)\s*([^{;\n]*)", re.MULTILINE
)
_KEYWORDS = {
    "function", "contract", "interface", "library", "if", "else", "for",
    "while", "return", "require", "revert", "emit", "new", "delete",
    "public", "external", "internal", "private", "view", "pure", "payable",
    "memory", "storage", "calldata", "true", "false", "msg", "sender",
    "value", "this", "address", "uint", "int", "bool", "bytes", "string",
}


def _extract_function_body(code: str, start: int) -> str:
    """Return the brace-matched body starting at the first '{' at/after start.

    A ';' before that '{' means the match was a body-less declaration
    (interface function, abstract function), not a real function: there
    is no body to extract, so return "" instead of jumping forward to
    the next '{' in the file (which would be another declaration's or
    the enclosing contract's brace, misattributing its whole body to
    the declaration).  A real function header never contains ';'
    before its opening brace.
    """
    open_idx = code.find("{", start)
    if open_idx < 0:
        return ""
    semi_idx = code.find(";", start)
    if 0 <= semi_idx < open_idx:
        return ""
    depth = 0
    for i in range(open_idx, len(code)):
        if code[i] == "{":
            depth += 1
        elif code[i] == "}":
            depth -= 1
            if depth == 0:
                return code[open_idx + 1:i]
    return code[open_idx + 1:]


def _parse_code_functions(code: str) -> Dict[str, Dict]:
    functions: Dict[str, Dict] = {}
    for m in _FUNCTION_RE.finditer(code or ""):
        name, params, suffix = m.group(1), m.group(2), m.group(3) or ""
        if name in _KEYWORDS:
            continue
        # Skip body-less declarations (interface / abstract functions):
        # their match ends before a ';' with no '{' body, so they must
        # never appear as analysable functions.  Without this, the
        # extractor below would hand them the enclosing contract's
        # body and every finding in that body would be misattributed
        # to the declaration (e.g. a Critical reentrancy "in addr()"
        # for an interface declaration at line 11 of MandateAquaApp).
        # Note: this checks for a body, not for a non-empty body --
        # a real function with an empty '{}' body still counts as a
        # function, it just yields no findings.
        _open = code.find("{", m.end())
        _semi = code.find(";", m.end())
        if _open < 0 or (0 <= _semi < _open):
            continue
        functions[name] = {
            "params": params,
            "suffix": suffix,
            "body": _extract_function_body(code, m.end()),
            "is_public": bool(re.search(r"\b(public|external)\b", suffix)),
            "is_guarded": bool(re.search(r"\b(onlyOwner|onlyRole|onlyAdmin)\b", suffix)),
        }
    return functions


def _finding_words(finding: Dict) -> List[str]:
    text = " ".join(
        str(finding.get(k, "")) for k in ("name", "description", "poc", "impact")
    )
    return re.findall(r"[A-Za-z_][A-Za-z0-9_]*", text)


def _state_vars_written_in_code(code: str) -> set:
    written = set()
    # Indexed writes (balances[msg.sender] -= amount) have brackets
    # between the variable name and the assignment operator.
    for m in re.finditer(
        r"\b([A-Za-z_][A-Za-z0-9_]*)\s*(?:\[[^\]]*\]\s*)?"
        r"(?:\+=|-=|\*=|/=|%=|=|\+{2}|-{2})",
        code or "",
    ):
        if m.group(1) not in _KEYWORDS:
            written.add(m.group(1))
    # Note: an indexed name on its own (balances[x]) is only a read, so
    # it is not added here; indexed writes are caught by the assignment
    # pattern above (e.g. "balances[msg.sender] -= amount").
    return written


def _has_code_evidence(finding: Dict, code: str) -> Tuple[bool, str]:
    """Return (True, '') only when the code itself supports the finding."""
    functions = _parse_code_functions(code)
    if not functions:
        return False, "No code evidence: no functions could be parsed from the analyzed code"
    words = _finding_words(finding)
    named = [w for w in words if w in functions]
    # A finding that explicitly names a function (foo() / foo.call) that
    # does not exist in the code is naming a hallucinated location.
    explicit = set(re.findall(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(", " ".join(
        str(finding.get(k, "")) for k in ("name", "description", "poc")
    )))
    hallucinated = [
        w for w in explicit
        if w not in functions and w not in _KEYWORDS and w not in {"require", "revert", "emit"}
    ]
    # Only treat a name as hallucinated when the finding presents it as a
    # code location (e.g. "in withdraw()" / "withdraw() is vulnerable"),
    # not when it is an ordinary English verb that happens to end in "()".
    if hallucinated and named:
        # named already proves a real location exists; a stray extra
        # identifier is not, on its own, a hallucination.
        hallucinated = []
    if hallucinated:
        return False, (
            "No code evidence: finding names function(s) not present in the "
            f"analyzed code: {', '.join(sorted(hallucinated))}"
        )
    if not named:
        return False, (
            "No code evidence: no function or state variable named by the "
            "finding is present in the analyzed code"
        )
    written = _state_vars_written_in_code(code)
    for name in named:
        fn = functions[name]
        # Reachability: directly callable by an unprivileged caller, or
        # called from another public/external unguarded function.
        # Merely naming a parameter or msg.sender in the finding does
        # NOT make a guarded (onlyOwner/onlyRole) or internal function
        # reachable — that would let prose override an access control.
        reachable = False
        if fn["is_public"] and not fn["is_guarded"]:
            reachable = True
        if not reachable:
            for other_name, other in functions.items():
                if (
                    other_name != name
                    and other["is_public"]
                    and not other["is_guarded"]
                    and re.search(rf"\b{re.escape(name)}\s*\(", other["body"])
                ):
                    reachable = True
                    break
        if not reachable:
            continue
        # State transition: a write / external call / transfer in this
        # function's body, or a state variable named by the finding that
        # is written somewhere in the code.
        body = fn["body"]
        # .call{value: amount}("") is the standard value-transfer form:
        # allow an optional {…} block between the call name and "(".
        # Indexed writes (balances[x] -= amount) are handled likewise.
        has_transition = bool(
            re.search(
                r"\.(?:call|delegatecall|transfer|send)\s*(?:\{[^}]*\})?\s*\(", body
            )
            or re.search(
                r"\b[A-Za-z_][A-Za-z0-9_]*\s*(?:\[[^\]]*\]\s*)?"
                r"(?:\+=|-=|\*=|/=|%=|=|\+{2}|-{2})",
                body,
            )
        )
        if not has_transition:
            named_vars = {w for w in words if w in written}
            has_transition = bool(named_vars)
        if has_transition:
            return True, ""
    return False, (
        "No code evidence: no named function is both reachable by an "
        "unprivileged caller and tied to a state transition in the code"
    )


def _is_centralization_risk(finding: Dict) -> bool:
    """Check if the finding is just 'admin can drain' which is usually OOS."""
    name = finding.get("name", "").lower()
    desc = finding.get("description", "").lower()
    combined = name + " " + desc
    signals = sum(1 for s in _CENTRALIZATION_SIGNALS if s in combined)
    if signals >= 2 and "without admin" not in combined and "non-admin" not in combined:
        if "frontrun" not in combined and "unprivileged" not in combined:
            return True
    return False


def _is_known_public(finding: Dict) -> bool:
    """Q7: Check if finding is already public (known issue)."""
    name = finding.get("name", "").lower()
    desc = finding.get("description", "").lower()
    combined = name + " " + desc
    known_indicators = [
        "acknowledged", "known issue", "won't fix", "risk accepted",
        "previously reported", "prior audit", "disclosed",
    ]
    for ind in known_indicators:
        if ind in combined:
            return True
    return False


# --- 7 Gates ---

def _gate_q1_exploit_path(finding: Dict, code: str) -> Tuple[bool, str]:
    """Q1: Can an attacker use this RIGHT NOW, step by step?
    Must have concrete function calls, parameters, and result description."""
    name = finding.get("name", "").lower()
    desc = finding.get("description", "").lower()
    combined = name + " " + desc

    # Safe-words gate applies to the finding NAME with word boundaries
    # (M22 remediation): a substring hit in the description - e.g. the
    # legitimate finding "Missing event emission on critical state change"
    # containing the safe-word "missing event" - used to silently delete
    # real results.
    for kw in _SAFE_NAME_KEYWORDS:
        if re.search(r"\b" + re.escape(kw.lower()) + r"\b", name):
            return False, f"Known non-vulnerability pattern: '{kw}'"

    for fp in _FP_INDICATORS:
        if fp in combined and not _has_exploit_path(combined):
            return False, f"Vague language without concrete exploit: '{fp}'"

    if "overall security rating" in name or "gas optimization" in combined:
        if "vulnerability" not in combined:
            return False, "Not a vulnerability finding"

    if not finding.get("description", "").strip():
        return False, "Missing description"

    # Require exploit path for Critical/High/Medium
    sev = finding.get("severity", "Medium")
    if sev in ("Critical", "High", "Medium"):
        if not _has_exploit_path(combined):
            return False, "No concrete exploit path — cannot complete steps 2-3 of attack template"

    # Check for fill-in-the-template capability
    if sev in ("Critical", "High"):
        has_setup = any(w in combined for w in ["setup", "need", "require", "precondition", "prerequisite"])
        has_call = _has_exploit_path(combined)
        has_result = _has_impact_words(combined, sev)
        if not (has_setup and has_call and has_result):
            return False, "Missing one of: preconditions, exploit sequence, or concrete result"

    return True, ""


def _gate_q1b_code_evidence(finding: Dict, code: str) -> Tuple[bool, str]:
    """Q1b (issue #28): wording is triage, code is proof.

    For Critical/High, a finding must pass _has_code_evidence; a
    convincing exploit description with no code path is rejected, not
    passed or silently downgraded.  For Medium/Low the text path is
    still allowed, but a finding that names a function that does not
    exist in the code is rejected at any severity.
    """
    sev = finding.get("severity", "Medium")
    ok, reason = _has_code_evidence(finding, code)
    if ok:
        return True, ""
    if sev in ("Critical", "High"):
        return False, reason
    # Medium/Low: only the hallucinated-location case is a hard reject;
    # other missing-evidence cases are triage, not proof, and are left
    # to the existing downgrade logic.
    if "not present in the analyzed code" in reason:
        return False, reason
    return True, ""


def _gate_q2_impact_in_scope(finding: Dict, code: str) -> Tuple[bool, str]:
    """Q2: Is the impact in the program's accepted impact list?
    Match the finding's impact to one of the Immunefi standard tiers."""
    sev = finding.get("severity", "Medium")
    desc = finding.get("description", "").lower()
    name = finding.get("name", "").lower()
    combined = name + " " + desc

    if sev == "Info":
        return False, "Info-level findings are excluded from vulnerability list"

    if sev == "Low" and "fix" not in finding:
        return False, "Low severity without suggested fix"

    # Check if impact matches accepted categories
    expected_keywords = _ACCEPTED_IMPACTS.get(sev, [])
    if sev in ("Critical", "High"):
        if not any(kw in combined for kw in expected_keywords):
            if not _has_impact_words(combined, sev):
                return False, f"Impact doesn't match expected {sev} categories: {expected_keywords}"

    return True, ""


def _gate_q3_root_contract_scope(finding: Dict, code: str) -> Tuple[bool, str]:
    """Q3: Is the root cause in an in-scope contract?
    Flag if the issue is in external dependencies (Aave, Uniswap, OpenZeppelin)."""
    name = finding.get("name", "").lower()
    desc = finding.get("description", "").lower()
    combined = name + " " + desc

    external_deps = [
        "openzeppelin", "aave", "uniswap", "compound", "maker",
        "chainlink", "pyth", "wormhole", "layerzero",
    ]
    for dep in external_deps:
        if dep in combined:
            # Check if it's really about a bug in the dependency vs using it
            if "vulnerability in" in combined or "bug in" in combined or f"{dep} " in combined:
                if "integration" not in combined:
                    return False, f"Root cause appears to be in external dependency ({dep}) — likely OOS"

    return True, ""


def _gate_q4_no_admin_abuse(finding: Dict, code: str) -> Tuple[bool, str]:
    """Q4: Does it require admin/privileged access?
    'Admin can drain' = centralization risk = usually out of scope.
    Check if exploitation works WITHOUT any privileged action."""
    name = finding.get("name", "").lower()
    desc = finding.get("description", "").lower()
    combined = name + " " + desc

    if _is_centralization_risk(finding):
        admin_phrases = ["admin can", "owner can", "governance can", "privileged"]
        admin_mentioned = any(p in combined for p in admin_phrases)
        non_admin_indicated = any(p in combined for p in ["non-admin", "unprivileged", "anyone can", "any user"])

        if admin_mentioned and not non_admin_indicated:
            return False, "Requires admin/privileged access — centralization risk typically OOS"

    return True, ""


def _norm_tokens(s: str) -> set:
    """Normalized token set of a pattern/finding name for dedup."""
    return set(re.findall(r"[a-z0-9]+", (s or "").lower()))


def _gate_q5_not_known_acknowledged(finding: Dict, kb_patterns: List[Dict]) -> Tuple[bool, str]:
    """Q5: Is this already known/acknowledged in prior audits or KB?"""
    name = finding.get("name", "")
    # Dedup on canonical equality only (M22 remediation): prefix matching
    # ('Reentrancy' vs 'Reentrancy in withdrawPath') silently deleted real
    # findings that merely shared a leading word with a KB entry.
    for p in kb_patterns:
        pname = p.get("name", "")
        if name.lower() == pname.lower() or _norm_tokens(name) == _norm_tokens(pname):
            return False, f"Duplicate of existing KB pattern: '{pname}'"
    return True, ""


def _gate_q7_not_public(finding: Dict) -> Tuple[bool, str]:
    """Q7: Is this already public / disclosed?"""
    if _is_known_public(finding):
        return False, "Already known/acknowledged/public — not a new finding"
    return True, ""


def validate_finding(finding: Dict, code: str, kb_patterns: Optional[List[Dict]] = None) -> Tuple[bool, Optional[str], str]:
    """Run all 7 gates on a single finding. Returns (passed, downgraded_severity, reason)."""
    # Q1: Is It Real? — exploit path required
    passed, reason = _gate_q1_exploit_path(finding, code)
    if not passed:
        return False, None, reason

    # Q1b: Code evidence (issue #28) — wording alone is not proof.
    passed, reason = _gate_q1b_code_evidence(finding, code)
    if not passed:
        return False, None, reason

    # Q2: Impact In Scope?
    passed, reason = _gate_q2_impact_in_scope(finding, code)
    if not passed:
        return False, None, reason

    # Q3: Root Cause In Scope Contract?
    passed, reason = _gate_q3_root_contract_scope(finding, code)
    if not passed:
        return False, None, reason

    # Q4: No Admin Abuse Required?
    passed, reason = _gate_q4_no_admin_abuse(finding, code)
    if not passed:
        return False, None, reason

    # Q5: Not Duplicate?
    if kb_patterns:
        passed, reason = _gate_q5_not_known_acknowledged(finding, kb_patterns)
        if not passed:
            return False, None, reason

    # Q6: Economic Viability (Gate 3 in original — exploitability check)
    sev = finding.get("severity", "Medium")
    name = finding.get("name", "").lower()
    desc = finding.get("description", "").lower()
    combined = name + " " + desc

    if sev in ("Critical", "High"):
        if not _has_impact_words(combined, sev):
            cur_sev = finding.get("severity", "Medium")
            downgraded = _SEVERITY_DOWNGRADE.get(cur_sev)
            if downgraded:
                return True, downgraded, f"Downgraded from {cur_sev} to {downgraded}: no concrete fund loss impact"
            return False, None, f"No concrete fund loss impact described for {sev} finding"

        if not _has_exploit_path(combined):
            cur_sev = finding.get("severity", "Medium")
            downgraded = _SEVERITY_DOWNGRADE.get(cur_sev)
            if downgraded:
                return True, downgraded, f"Downgraded from {cur_sev} to {downgraded}: no exploit path"
            return False, None, "No exploit path described"

    # Q7: Not Already Public?
    passed, reason = _gate_q7_not_public(finding)
    if not passed:
        return False, None, reason

    return True, None, ""


def _looks_like_unparsed_findings(report: str) -> bool:
    """Detect common finding labels when the structured parser found none."""
    for raw_line in report.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        candidate = re.sub(r"^(?:[-*+•]|\d+[.)])\s*", "", line)
        if re.match(r"(?i)(?:finding|vulnerability|issue)\s*[:#-]\s*\S", candidate):
            return True
        if re.search(r"(?i)\bseverity\s*[:=]\s*(?:critical|high|medium|low)\b", candidate):
            return True
    return False


def validate_report(report: str, code: str, kb_patterns: Optional[List[Dict]] = None) -> str:
    """Run 7-Question Gate validation on an entire report. Returns a cleaned report.

    Fail-closed (issue #27): if validation itself raises, the original
    report is returned only with an explicit UNVERIFIED banner — never
    as a cleaned, validated report.
    """
    try:
        findings = _extract_findings(report)
    except Exception as e:
        logger.warning(f"Gate validation failed: {e}")
        return mark_unverified(report, f"validation error: {e}")
    if not findings:
        if _looks_like_unparsed_findings(report):
            return mark_unverified(report, "could not parse findings")
        return report

    removed = []
    downgraded = []
    kept = []

    for f in findings:
        try:
            passed, new_sev, reason = validate_finding(f, code, kb_patterns)
        except Exception as e:
            logger.warning(f"Gate validation failed: {e}")
            return mark_unverified(report, f"validation error: {e}")
        if not passed:
            removed.append((f.get("name", "?"), reason))
            logger.info(f"Gate rejected: {f.get('name')} — {reason}")
        else:
            if new_sev:
                f["severity"] = new_sev
                downgraded.append((f["name"], new_sev, reason))
            kept.append(f)

    if not kept:
        # The gate wiped every finding - do NOT fabricate a clean A+ report
        # (M22 remediation): the original report is preserved with an
        # explicit unverified banner so a broken run cannot masquerade as a
        # clean audit.
        banner = (
            "### Validation Warning\n\n"
            "The validation gate rejected every finding of this run. The "
            "original report is preserved below UNCHANGED for human review - "
            "treat this run as UNVERIFIED, not as a clean audit.\n\n"
        )
        return banner + report

    result_lines = []
    in_vuln_section = False
    in_gas_section = False
    kept_names = {f["name"] for f in kept}
    severity_by_name = {f["name"]: f["severity"] for f in kept if f.get("name")}
    current_name = None

    for line in report.split("\n"):
        s = line.strip()
        if s.startswith("- **Name**"):
            name = s.split(":", 1)[1].strip() if ":" in s else s.replace("**Name**", "").strip()
            in_vuln_section = name in kept_names
            current_name = name if in_vuln_section else None
            in_gas_section = False
        elif s.startswith("### Gas Optimizations"):
            in_vuln_section = False
            in_gas_section = True

        # Apply severity changes INLINE on the finding body (M22
        # remediation): they used to live only in trailing notes while the
        # report text kept showing the stale severity.
        if (in_vuln_section and current_name in severity_by_name
                and s.startswith("- **Severity**")):
            line = f"- **Severity**: {severity_by_name[current_name]}"

        if in_vuln_section or in_gas_section or s.startswith("### Overall") or s.startswith("### Vulnerability") or s.startswith("### Gas"):
            result_lines.append(line)

    result = "\n".join(result_lines)

    if downgraded:
        notes = "\n\n### Validation Notes\n"
        for name, new_sev, reason in downgraded:
            notes += f"- **{name}**: {reason}\n"
        result += notes

    return result


def gate_stats_str(removed: List[Tuple[str, str]], downgraded: List[Tuple[str, str, str]]) -> str:
    lines = []
    for name, reason in removed:
        lines.append(f"  ✗ {name}: {reason}")
    for name, new_sev, reason in downgraded:
        lines.append(f"  ↓ {name} → {new_sev}: {reason}")
    return "\n".join(lines)
