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
        s = line.strip()
        if s.startswith("- **Name**"):
            if current and current.get("name"):
                findings.append(current)
            current = {"name": s.split(":", 1)[1].strip() if ":" in s else s.replace("**Name**", "").strip()}
        elif s.startswith("- **Severity**") and current:
            sev = s.split(":", 1)[1].strip() if ":" in s else "Medium"
            current["severity"] = sev.rstrip("*")
        elif s.startswith("- **Description**") and current:
            current["description"] = s.split(":", 1)[1].strip() if ":" in s else ""
        elif s.startswith("- **Fix**") and current:
            current["fix"] = s.split(":", 1)[1].strip() if ":" in s else ""
        elif s.startswith("- **PoC**") and current:
            current["poc"] = s.split(":", 1)[1].strip() if ":" in s else ""
        elif s.startswith("- **Impact**") and current:
            current["impact"] = s.split(":", 1)[1].strip() if ":" in s else ""
        elif s.startswith("- **Category**") and current:
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


# --- Full-audit gate hardening (remaining Priority 1) ---
#
# Two weaknesses in the pre-hardening gate are closed here:
# (1) The hallucination check was waived whenever the finding named ANY
#     real function, so a finding could name one real function and one
#     invented function and still pass.  A hallucinated location is now
#     a hard reject regardless of what else the finding names.
# (2) _has_code_evidence used to pass on "named function + ANY
#     assignment/call in its body" (or a variable written ANYWHERE in
#     the code).  That is wording-adjacent, not proof: a body can
#     contain an unrelated write while the finding claims something
#     else entirely.  It now additionally requires a concrete artefact
#     TIED to the finding and present in the named function's body (see
#     _finding_body_artefacts).  Naming only a function is no longer
#     enough for Critical/High.
#
# What this gate still cannot enforce (documented, not silently
# assumed): bare English mentions of a variable/function with no code
# syntax (no "foo()", backticks, or assignment/indexing); ordering or
# timing claims (call-before-write across branches or contracts, see
# the branch-parser caveats elsewhere); cross-contract call graphs
# beyond a direct call from a public function; and exploitability
# itself (a code artefact proves the code shape exists, not that an
# attacker can profitably reach it).  Those remain human-review items.

# Global builtins that are never user-defined functions: naming them is
# not naming a hallucinated location.
_BUILTIN_IDENTIFIERS = {"require", "revert", "emit", "assert"}

# External-call verbs: only meaningful as a method (x.call(...)); a
# bare "call()" is not a user function, and a method call is not a
# claim about a user-defined function at all.
_CALL_VERBS = ("call", "delegatecall", "staticcall", "transfer", "send")


def _finding_text(finding: Dict) -> str:
    return " ".join(
        str(finding.get(k, "")) for k in ("name", "description", "poc")
    )


def _explicit_called_names(finding: Dict) -> List[str]:
    """Identifiers the finding presents as code calls, e.g. ``foo()``.

    Method calls (``msg.sender.call(``, ``token.transfer(``) are
    excluded: the identifier after a ``.`` is a method/builtin, not a
    claim that a user-defined function of that name exists.  Global
    builtins (require/revert/emit/assert) are likewise excluded.
    Everything else written as ``name(`` — optionally with a
    ``{...}`` value block, as in ``call{value: x}(`` — is treated as a
    claim that a function of that name exists in the supplied source.
    So is ``function name``: a finding that says "calls function
    claimReward" claims that function exists just as surely as one
    that writes "claimReward()".
    """
    text = _finding_text(finding)
    names: List[str] = []
    for m in re.finditer(r"\bfunction\s+([A-Za-z_][A-Za-z0-9_]*)", text):
        name = m.group(1)
        if name not in _KEYWORDS and name not in _BUILTIN_IDENTIFIERS and name not in names:
            names.append(name)
    for m in re.finditer(
        r"\b([A-Za-z_][A-Za-z0-9_]*)\s*(?:\{[^}]*\})?\s*\(", text
    ):
        # Walk back over whitespace: a '.' immediately before the
        # identifier means this is a method call, not a function claim.
        i = m.start(1) - 1
        while i >= 0 and text[i] in " \t":
            i -= 1
        if i >= 0 and text[i] == ".":
            continue
        name = m.group(1)
        if name in _KEYWORDS or name in _BUILTIN_IDENTIFIERS:
            continue
        if name not in names:
            names.append(name)
    return names


def _claimed_code_identifiers(finding: Dict) -> List[str]:
    """Identifiers the finding claims in unambiguous code syntax.

    Only two shapes count, deliberately: backtick-quoted identifiers
    (`` `balances` ``) and identifiers used as an assignment/index
    target (``balances[msg.sender] -= amount``, ``x = y``).  Bare
    English words are NOT claimed identifiers — treating every word
    as a code claim would reject ordinary prose ("attacker", "funds").
    This is the narrow, enforceable form of "the claimed variable
    must exist in the source" used by Q1b for Medium/Low (task b);
    anything vaguer is documented as unenforceable, not guessed at.
    """
    text = _finding_text(finding)
    claimed: List[str] = []
    for name in re.findall(r"`([A-Za-z_][A-Za-z0-9_]*)`", text):
        if name not in _KEYWORDS and name not in claimed:
            claimed.append(name)
    for m in re.finditer(
        r"\b([A-Za-z_][A-Za-z0-9_]*)\s*(?:\[[^\]]*\]\s*)?"
        r"(?:\+=|-=|\*=|/=|%=|=(?!=))",
        text,
    ):
        name = m.group(1)
        if name not in _KEYWORDS and name not in claimed:
            claimed.append(name)
    return claimed


def _finding_body_artefacts(
    finding: Dict, body: str, functions: Dict, written: set, named_fn: str
) -> List[str]:
    """Concrete artefacts tied to the finding and present in ``body``.

    At least one is required (in addition to reachability and a state
    transition) for Critical/High code evidence.  An artefact is:
    - a state variable named by the finding that is written somewhere
      in the code AND appears in this function's body; or
    - an external-call verb named by the finding (``.call(``,
      ``.transfer(``, ...) that also appears in this body; or
    - another defined function named by the finding that this body
      actually calls.
    A write/call that the finding never mentions is not an artefact:
    it does not tie the finding to the code, it only proves the body
    is non-trivial.
    """
    words = set(_finding_words(finding))
    finding_text = _finding_text(finding)
    artefacts: List[str] = []
    for var in words:
        if var != named_fn and var in written and re.search(
            rf"\b{re.escape(var)}\b", body
        ):
            artefacts.append(f"state variable '{var}'")
    for verb in _CALL_VERBS:
        if re.search(
            rf"\.{verb}\s*(?:\{{[^}}]*\}})?\s*\(", finding_text
        ) or re.search(rf"\b{verb}\s*(?:\{{[^}}]*\}})?\s*\(", finding_text):
            if re.search(rf"\.{verb}\s*(?:\{{[^}}]*\}})?\s*\(", body):
                artefacts.append(f"call pattern '.{verb}('")
    for other in words:
        if (
            other != named_fn
            and other in functions
            and re.search(rf"\b{re.escape(other)}\s*\(", body)
        ):
            artefacts.append(f"called function '{other}()'")
    return artefacts


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
    """Return (True, '') only when the code itself supports the finding.

    Hardened (remaining Priority 1): a finding passes only when
    (1) it names no hallucinated function — the old waiver that cleared
    a hallucinated name merely because some other real function was
    also named is REMOVED, so one real + one invented location still
    fails; (2) a named function is reachable by an unprivileged caller;
    (3) that function's body contains a state transition; AND (4) the
    body contains at least one concrete artefact the finding actually
    claims (a named state variable, a named call pattern, or a named
    called function — see _finding_body_artefacts).  Rule (4) is what
    stops "named function + any unrelated write/call in its body"
    from passing: the artefact must be both claimed and present.
    """
    functions = _parse_code_functions(code)
    if not functions:
        return False, "No code evidence: no functions could be parsed from the analyzed code"
    words = _finding_words(finding)
    named = [w for w in words if w in functions]
    # A finding that explicitly names a function (foo()) that does not
    # exist in the code is naming a hallucinated location.  This is a
    # hard reject even when the finding also names a real function:
    # naming one real location does not launder an invented one.
    # Method calls (x.call() / token.transfer()) and global builtins
    # are excluded by _explicit_called_names — they are not claims
    # about user-defined functions.
    explicit = _explicit_called_names(finding)
    hallucinated = [w for w in explicit if w not in functions]
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
    reachable_any = False
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
        reachable_any = True
        # State transition in THIS function's body (not merely
        # somewhere in the file): a write / external call / transfer.
        body = fn["body"]
        # .call{value: amount}("") is the standard value-transfer form:
        # allow an optional {…} block between the call name and "(".
        # Indexed writes (balances[x] -= amount) are handled likewise.
        # (The "=="-as-write quirk in this regex is pre-existing and
        # out of scope here; the new tied-artefact rule below is what
        # stops an unrelated body write from satisfying a finding.)
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
            continue
        # Tied artefact: the finding must claim something concrete
        # that is actually in this body.  A transition the finding
        # never mentions does not tie the finding to the code.
        artefacts = _finding_body_artefacts(finding, body, functions, written, name)
        if artefacts:
            return True, ""
    if reachable_any:
        return False, (
            "No code evidence: no named, reachable function has both a "
            "state transition and a claimed artefact (state variable, "
            "call pattern, or called function) actually present in its body"
        )
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
    still allowed, but two hard rejects apply at ANY severity:
    (1) a hallucinated location — a function named as ``foo()`` that
    does not exist in the supplied source (now unwaivable: naming a
    real function alongside it no longer clears it); and
    (2) a claimed code identifier that does not exist in the source —
    a backtick-quoted identifier or an assignment/index target named
    by the finding (see _claimed_code_identifiers) that appears
    nowhere in the code.  A claimed function is covered by (1); a
    claimed variable is covered by (2) — but only in those two
    unambiguous code syntaxes, so ordinary prose words are never
    mistaken for code claims.

    What Q1b still cannot enforce (documented limits): a variable or
    function mentioned only in bare English with no code syntax; a
    claim about a variable's value, role, or timing rather than its
    existence; ordering claims (which line runs first, which branch
    is taken); cross-contract or inherited code not present in the
    supplied source; and whether the claimed artefact is actually
    exploitable.  Those remain human-review items — the gate rejects
    provably invented locations, it does not certify the rest.
    """
    sev = finding.get("severity", "Medium")
    ok, reason = _has_code_evidence(finding, code)
    if ok:
        return True, ""
    if sev in ("Critical", "High"):
        return False, reason
    # Medium/Low: hallucinated-location and claimed-identifier cases
    # are hard rejects; other missing-evidence cases are triage, not
    # proof, and are left to the existing downgrade logic.
    if "not present in the analyzed code" in reason:
        return False, reason
    # Second hard check, enforced directly (not via the _has_code_evidence
    # reason string, which conflates several failure modes): a claimed
    # variable in code syntax that exists nowhere in the source.
    code_words = set(re.findall(r"[A-Za-z_][A-Za-z0-9_]*", code or ""))
    functions = _parse_code_functions(code)
    missing_vars = [
        name
        for name in _claimed_code_identifiers(finding)
        if name not in code_words and name not in functions
    ]
    if missing_vars:
        return False, (
            "No code evidence: finding claims code identifier(s) not "
            f"present in the analyzed code: {', '.join(sorted(missing_vars))}"
        )
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
