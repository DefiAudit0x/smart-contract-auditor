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


def _skip_string_or_comment(body: str, i: int) -> int:
    """Index just past a string/comment starting at *i*, or *i* itself."""
    if body.startswith("//", i):
        end = body.find("\n", i)
        return len(body) if end < 0 else end
    if body.startswith("/*", i):
        end = body.find("*/", i + 2)
        return len(body) if end < 0 else end + 2
    if body[i] in ("\"", "'"):
        quote = body[i]
        j = i + 1
        while j < len(body):
            if body[j] == "\\":
                j += 2
                continue
            if body[j] == quote:
                return j + 1
            j += 1
        return len(body)
    return i


def _match_balanced(body: str, open_idx: int, open_ch: str, close_ch: str) -> int:
    """Index just past the balanced closer for the opener at *open_idx*.

    Returns -1 when unbalanced. Strings and comments are skipped, so a
    brace or parenthesis inside them never opens or closes a block.
    """
    depth = 0
    i = open_idx
    while i < len(body):
        skipped = _skip_string_or_comment(body, i)
        if skipped != i:
            i = skipped
            continue
        ch = body[i]
        if ch == open_ch:
            depth += 1
        elif ch == close_ch:
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return -1


def _parse_branch_blocks(body: str, start: int, end: int, counter):
    """Parse *body[start:end]* into a branch tree.

    Nodes are tuples: ``("text", start, end)`` or ``("if", node_id,
    then_nodes, else_nodes_or_None, if_start, if_end)``. Bare ``{...}`` blocks are spliced
    into the enclosing sequence (they add no branch), and ``else if``
    chains become an if node nested inside the else branch. Any shape
    the parser cannot establish (unbalanced braces, a missing body) is
    left as plain text, which is the conservative choice: an unknown
    shape never downgrades a finding, it simply is not proven exclusive.
    """
    nodes = []
    text_start = start
    i = start
    while i < end:
        skipped = _skip_string_or_comment(body, i)
        if skipped != i:
            i = skipped
            continue
        if body[i] == "{":
            close = _match_balanced(body, i, "{", "}")
            if close < 0 or close > end:
                i += 1
                continue
            if text_start < i:
                nodes.append(("text", text_start, i))
            nodes.extend(_parse_branch_blocks(body, i + 1, close - 1, counter))
            i = close
            text_start = i
            continue
        if (
            re.match(r"if\b", body[i:]) is not None
            and (i == 0 or not (body[i - 1].isalnum() or body[i - 1] == "_"))
            and (i + 2 >= len(body) or not (body[i + 2].isalnum() or body[i + 2] == "_"))
        ):
            # Skip the "if" keyword, then the balanced condition.
            j = i + 2
            while j < end and body[j].isspace():
                j += 1
            if j >= end or body[j] != "(":
                i += 1
                continue
            cond_end = _match_balanced(body, j, "(", ")")
            if cond_end < 0 or cond_end > end:
                i += 1
                continue
            k = cond_end
            while k < end and body[k].isspace():
                k += 1
            if k < end and body[k] == "{":
                then_close = _match_balanced(body, k, "{", "}")
                if then_close < 0 or then_close > end:
                    i += 1
                    continue
                then_nodes = _parse_branch_blocks(body, k + 1, then_close - 1, counter)
                after = then_close
            else:
                # Single-statement then branch: up to the next ';' at
                # top level (parentheses/braces inside it are balanced).
                semi = k
                paren = brace = 0
                while semi < end:
                    s2 = _skip_string_or_comment(body, semi)
                    if s2 != semi:
                        semi = s2
                        continue
                    if body[semi] == "(":
                        paren += 1
                    elif body[semi] == ")":
                        paren -= 1
                    elif body[semi] == "{":
                        brace += 1
                    elif body[semi] == "}":
                        brace -= 1
                    elif body[semi] == ";" and paren == 0 and brace == 0:
                        semi += 1
                        break
                    semi += 1
                then_nodes = [("text", k, semi)]
                after = semi
            # Optional else branch.
            m = after
            while m < end and body[m].isspace():
                m += 1
            else_nodes = None
            if re.match(r"else\b", body[m:]) is not None and (
                m + 4 >= len(body)
                or not (body[m + 4].isalnum() or body[m + 4] == "_")
            ):
                m2 = m + 4
                while m2 < end and body[m2].isspace():
                    m2 += 1
                if m2 < end and body[m2] == "{":
                    else_close = _match_balanced(body, m2, "{", "}")
                    if else_close >= 0 and else_close <= end:
                        else_nodes = _parse_branch_blocks(
                            body, m2 + 1, else_close - 1, counter
                        )
                        after = else_close
                elif m2 < end and re.match(r"if\b", body[m2:]) is not None:
                    # else-if: do NOT claim an else branch here. The
                    # inner if is left to be parsed as its own node
                    # in the enclosing sequence, so a write after the
                    # else-if chain can never be misread as sitting
                    # inside the else branch (which would wrongly
                    # downgrade a write that executes after either
                    # branch). The cost is conservative: a write
                    # inside an else-if else branch is not proven
                    # exclusive and stays Confirmed, as before.
                    after = m2
                else:
                    semi = m2
                    paren = brace = 0
                    while semi < end:
                        s2 = _skip_string_or_comment(body, semi)
                        if s2 != semi:
                            semi = s2
                            continue
                        if body[semi] == "(":
                            paren += 1
                        elif body[semi] == ")":
                            paren -= 1
                        elif body[semi] == "{":
                            brace += 1
                        elif body[semi] == "}":
                            brace -= 1
                        elif body[semi] == ";" and paren == 0 and brace == 0:
                            semi += 1
                            break
                        semi += 1
                    else_nodes = [("text", m2, semi)]
                    after = semi
            if text_start < i:
                nodes.append(("text", text_start, i))
            counter[0] += 1
            nodes.append(("if", counter[0], then_nodes, else_nodes, i, after))
            i = after
            text_start = i
            continue
        i += 1
    if text_start < end:
        nodes.append(("text", text_start, end))
    return nodes


def _branch_path(nodes, pos):
    """Branch ancestry of *pos* as [(if_node_id, 'then'/'else'), ...].

    Returns None when *pos* is not covered by *nodes* (an unparsed
    shape), which callers treat as "not proven exclusive".
    """
    for node in nodes:
        if node[0] == "text":
            if node[1] <= pos < node[2]:
                return []
        elif node[0] == "if":
            _, node_id, then_nodes, else_nodes, if_start, if_end = node
            if not (if_start <= pos < if_end):
                continue
            sub = _branch_path(then_nodes, pos) if then_nodes else None
            if sub is not None:
                return [(node_id, "then")] + sub
            if else_nodes:
                sub = _branch_path(else_nodes, pos)
                if sub is not None:
                    return [(node_id, "else")] + sub
            # Inside this if node but in neither branch: the condition
            # (e.g. Parity's ``if (!_to.call.value(...)(...))``), a
            # keyword, or whitespace between branches. Such a position
            # executes when the enclosing block executes, before the
            # branch is taken, so it carries no branch side of its own.
            return []
    return None


def _mutually_exclusive_branches(body: str, call_pos: int, write_pos: int) -> bool:
    """True only when call and write are in opposite if/else branches.

    Two positions are mutually exclusive exactly when their branch
    paths share a prefix and first differ at the same if node with
    opposite sides. A call inside an if block followed by a write after
    that if (the classic ``if (!call) throw; write;`` shape) is NOT
    exclusive: the write's path is a prefix of the call's path, so the
    write executes after either branch. Any unparsed shape returns
    False, so the check can only downgrade a finding it positively
    establishes as cross-branch, never one it merely fails to parse.
    """
    try:
        nodes = _parse_branch_blocks(body or "", 0, len(body or ""), [0])
        path_call = _branch_path(nodes, call_pos)
        path_write = _branch_path(nodes, write_pos)
    except Exception:
        return False
    if path_call is None or path_write is None:
        return False
    for (id_call, side_call), (id_write, side_write) in zip(path_call, path_write):
        if id_call != id_write:
            return False
        if side_call != side_write:
            return True
    return False


def call_before_write_evidence(body: str, state_vars):
    """Return (call_pos, call_member, write_var, write_pos) or None.

    Evidence requires, in order: a callback-capable external call, then
    a write to a declared state variable on a path that can actually
    follow the call.  A write that appears only before the call, or no
    state write at all, is not evidence.  A write in the opposite
    branch of an if/else from the call (e.g. Parity execute(): the call
    in the ``if`` branch, the write in the ``else`` branch) is likewise
    not evidence: the two can never execute in one pass, so the pair
    is downgraded to a guard note by classify_function instead of
    being reported as Confirmed. Later writes on a following path are
    still considered, so a same-path write after a cross-branch one
    still counts.
    """
    body = body or ""
    calls = callback_capable_calls(body)
    if not calls:
        return None
    reads, writes = function_read_write_sets(body, state_vars)
    if not writes:
        return None
    for call_pos, call_member in calls:
        # All writes after this call, earliest first (the old code
        # iterated state variables in list order, not position order).
        candidates = []
        for var in state_vars:
            if not var:
                continue
            pat = _var_ref_pattern(var)
            for m in re.finditer(pat, body):
                if m.start() <= call_pos:
                    continue
                tail = body[m.end():m.end() + 4].lstrip()
                prefix = body[max(0, m.start() - 8):m.start()]
                is_write = (
                    re.search(r"\bdelete\s*$", prefix) is not None
                    or tail.startswith(("++", "--"))
                    or _is_assignment_tail(tail)
                )
                if is_write:
                    candidates.append((m.start(), var))
        candidates.sort()
        for write_pos, var in candidates:
            if _mutually_exclusive_branches(body, call_pos, write_pos):
                continue
            return (call_pos, call_member, var, write_pos)
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
