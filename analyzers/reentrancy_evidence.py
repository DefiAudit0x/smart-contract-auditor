"""Shared reentrancy evidence rules (issues #31, #32, #33).

This module is deliberately free of solc/solcast: it works on function
source text plus the already-parsed function metadata (modifiers,
external-call names, contract state variables).  That keeps the rules
unit-testable without a compiler and keeps the three detectors aligned:

* #31: a function is only a *confirmed* reentrancy finding when there is
  evidence of a callback-capable external call followed by a relevant
  state write.  An unguarded external call with no such evidence is
  reported separately, at lower severity, as
  "External Call Without Recognized Guard" -- never as Critical
  reentrancy.
* #32: cross-function findings require per-function read/write sets and
  a shared, actually-used state variable, not the contract's whole
  state-variable list.
* #33: statement order matters.  A call followed by a write in the same
  straight-line block counts; a write before the call does not.

Recognized guards are the modifiers that actually block re-entry in
common practice: ``nonReentrant`` (OpenZeppelin) and
``reentrancyGuard``.  Anything else (``onlyOwner``, ``locked`` checks
written by hand, etc.) is *not* treated as a recognized guard here,
because the detectors cannot prove from the modifier name alone that
it blocks re-entry.
"""

import re

GUARD_MODIFIERS = frozenset({"nonReentrant", "reentrancyGuard"})

# Calls through which a callee can call back into this contract and
# change state.  ``transfer``/``send`` forward only 2300 gas, which does
# not allow a state-changing callback in practice, and ``staticcall``
# cannot write state at all, so neither counts as callback-capable for
# a *confirmed* reentrancy finding (they may still be external calls
# worth a guard note).
CALLBACK_CAPABLE_CALLS = frozenset({"call", "delegatecall"})
NON_CALLBACK_CALLS = frozenset({"transfer", "send", "staticcall"})

# Old (pre-0.8) low-level-call syntax: the value/gas options are chained
# as members *before* the invocation, e.g. ``msg.sender.call.value(x)()``,
# ``target.call.gas(g).value(x)()`` or ``target.call.value(x).gas(g)()``.
# The previous pattern required '(' immediately after the member (apart
# from an optional modern ``{...}`` options block), so it missed every
# old-syntax call: after ``.call`` comes ``.value``, not '('.  That made
# textbook DAO-era reentrancy (SB-RE-01) invisible to the evidence
# rules even though the call-then-write shape is identical to the
# modern form.  Each chained option takes one argument; the argument
# pattern allows one level of nested parentheses (e.g. ``foo(bar)``)
# so ordinary expressions still match, while deeper nesting remains a
# known limitation.  ``transfer``/``send``/``staticcall`` are still
# matched here only so ``any_external_calls`` can report them as guard
# notes; the ``CALLBACK_CAPABLE_CALLS`` filter below still excludes
# them from confirmed findings, exactly as before.
_OLD_OPTION = r"(?:\.\s*(?:value|gas)\s*\((?:[^()]|\([^()]*\))*\))"
_CALL_RE = re.compile(
    r"\.\s*(call|delegatecall|staticcall|transfer|send)\s*(?:\{[^}]*\})?\s*"
    rf"(?:{_OLD_OPTION})*\s*\("
)
# An external contract method call, e.g. ``token.transfer(...)`` is
# already covered by the member names above; a bare interface call such
# as ``target.foo()`` is not treated as callback-capable here because
# the detectors cannot tell from the name alone that the target is
# attacker-controlled.  Keep the rule conservative: only low-level
# call/delegatecall are confirmed callback channels.


def extract_function_body(code: str, func_name: str) -> str:
    """Extract one function's source (signature + body) from *code*.

    Brace-matched, so nested blocks do not truncate the body early.
    Returns "" when the function cannot be found; callers must treat
    that as "no evidence", never as a confirmed finding.
    """
    pattern = rf"function\s+{re.escape(func_name)}\s*\([^)]*\)[^{{]*\{{"
    for m in re.finditer(pattern, code or "", re.DOTALL):
        start = m.end()
        depth = 1
        i = start
        while i < len(code) and depth > 0:
            if code[i] == "{":
                depth += 1
            elif code[i] == "}":
                depth -= 1
            i += 1
        return code[m.start():i]
    return ""


def is_guarded(modifiers) -> bool:
    """True when any recognized reentrancy guard modifier is present."""
    return any(m in GUARD_MODIFIERS for m in (modifiers or []))


def callback_capable_calls(body: str):
    """Callback-capable external calls in *body* as (position, member)."""
    return [
        (m.start(), m.group(1))
        for m in _CALL_RE.finditer(body or "")
        if m.group(1) in CALLBACK_CAPABLE_CALLS
    ]


def any_external_calls(body: str):
    """All low-level external calls in *body* as (position, member)."""
    return [(m.start(), m.group(1)) for m in _CALL_RE.finditer(body or "")]


def _var_ref_pattern(var: str) -> str:
    v = re.escape(var)
    # var, var[...], var.field, var[...].field, var[...][...].field ...
    return rf"\b{v}\b(?:\s*\[[^\]]*\]|\s*\.\s*[A-Za-z_]\w*)*"


def _is_assignment_tail(tail: str) -> bool:
    """True only for a genuine assignment operator at the start of *tail*.

    ``==`` is a comparison, not a write: the naive pattern ``[+-*/%]?=``
    matches the first '=' of '==', so a comparison such as
    ``strategy.maker == address(0)`` was misread as a write to 'maker'.
    Reject an operator match immediately followed by '=' (``==``) or '>'
    (``=>``); a plain '=', '+=', '-=', '*=', '/=' or '%=' followed by
    anything else is a write.  '>=' / '<=' / '!=' never match in the
    first place because their first character is not in the set.
    """
    m = re.match(r"[+\-*/%]?=", tail or "")
    if m is None:
        return False
    return tail[m.end():m.end() + 1] not in ("=", ">")


def function_read_write_sets(body: str, state_vars):
    """Per-function read/write sets for the given state variables.

    A write is an assignment (``=``/``+=``/``-=``/``*=``/``/=``/``%=``),
    an increment/decrement (``++``/``--``), or a ``delete`` of a state
    variable (including indexed / struct-field forms).  A read is any
    other reference to a state variable.  Reads that are part of a write
    expression (e.g. ``balances[x] -= amt`` still *reads* the old value)
    are counted as both a read and a write, which is the conservative
    choice for shared-state analysis: the function both observes and
    changes that variable.
    """
    body = body or ""
    reads, writes = set(), set()
    for var in state_vars:
        if not var:
            continue
        pat = _var_ref_pattern(var)
        for m in re.finditer(pat, body):
            tail = body[m.end():m.end() + 4].lstrip()
            # delete <var>...
            prefix = body[max(0, m.start() - 8):m.start()]
            if re.search(r"\bdelete\s*$", prefix):
                writes.add(var)
                continue
            if tail.startswith(("++", "--")):
                writes.add(var)
                reads.add(var)
                continue
            if _is_assignment_tail(tail):
                writes.add(var)
                reads.add(var)
                continue
            reads.add(var)
    return reads, writes


def call_before_write_evidence(body: str, state_vars):
    """Return (call_pos, call_member, write_var, write_pos) or None.

    Evidence requires, in order: a callback-capable external call, then
    a write to a declared state variable.  A write that appears only
    before the call, or no state write at all, is not evidence.
    """
    body = body or ""
    calls = callback_capable_calls(body)
    if not calls:
        return None
    first_call_pos, first_call_member = calls[0]
    reads, writes = function_read_write_sets(body, state_vars)
    if not writes:
        return None
    # Find the earliest write *after* the first callback-capable call.
    for var in state_vars:
        if not var:
            continue
        pat = _var_ref_pattern(var)
        for m in re.finditer(pat, body):
            if m.start() <= first_call_pos:
                continue
            tail = body[m.end():m.end() + 4].lstrip()
            prefix = body[max(0, m.start() - 8):m.start()]
            is_write = (
                re.search(r"\bdelete\s*$", prefix) is not None
                or tail.startswith(("++", "--"))
                or _is_assignment_tail(tail)
            )
            if is_write:
                return (first_call_pos, first_call_member, var, m.start())
    return None


def classify_function(modifiers, body: str, state_vars):
    """Classify one unguarded-or-guarded function for the AST check.

    Returns ``("confirmed", evidence)``, ``("guard-note", None)`` or
    ``(None, None)``:
    * guarded -> (None, None): no finding at all;
    * no external call at all -> (None, None);
    * callback-capable call + call-before-write evidence -> confirmed;
    * any external call but no confirmed evidence -> guard note only.
    """
    if is_guarded(modifiers):
        return None, None
    if not any_external_calls(body):
        return None, None
    evidence = call_before_write_evidence(body, state_vars)
    if evidence is not None:
        return "confirmed", evidence
    return "guard-note", None


def cross_function_pairs(functions, state_vars):
    """Feasible cross-function reentrancy pairs.

    ``functions`` is a list of dicts with keys: ``name``, ``modifiers``,
    ``body``, ``callable`` (default True: public/external).  A pair
    (caller, callee) is feasible only when:
    * caller is unguarded, externally callable, and makes a
      callback-capable external call;
    * callee is a *different*, unguarded, externally callable function;
    * caller and callee actually share a state variable (intersection
      of their read/write sets -- not the contract's full list);
    * the shared variable is actually mutated on the reentrant path:
      callee writes it, or caller writes it after its call.
    Read-read sharing alone is not an exploit path and is excluded.
    """
    infos = []
    for fn in functions:
        body = fn.get("body", "") or ""
        reads, writes = function_read_write_sets(body, state_vars)
        infos.append({
            "name": fn.get("name", ""),
            "modifiers": fn.get("modifiers", []) or [],
            "callable": fn.get("callable", True),
            "reads": reads,
            "writes": writes,
            "calls": callback_capable_calls(body),
            "evidence": call_before_write_evidence(body, state_vars),
        })
    pairs = []
    for caller in infos:
        if not caller["callable"] or is_guarded(caller["modifiers"]):
            continue
        if not caller["calls"]:
            continue
        caller_used = caller["reads"] | caller["writes"]
        for callee in infos:
            if callee["name"] == caller["name"]:
                continue
            if not callee["callable"] or is_guarded(callee["modifiers"]):
                continue
            shared = caller_used & (callee["reads"] | callee["writes"])
            if not shared:
                continue
            # Mutation on the reentrant path: callee writes the shared
            # variable, or caller writes it after its own call.
            mutated = shared & callee["writes"]
            if caller["evidence"] is not None:
                mutated |= {caller["evidence"][2]} & shared
            if not mutated:
                continue
            pairs.append({
                "caller": caller["name"],
                "callee": callee["name"],
                "shared": sorted(shared),
                "mutated": sorted(mutated),
            })
    return pairs
