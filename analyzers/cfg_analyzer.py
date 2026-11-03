"""Level 3 CFG/DFG Analyzer — flow-sensitive vulnerability detection for Solidity."""

import logging
from typing import List, Set, Dict, Tuple, Optional

logger = logging.getLogger(__name__)

_HAS_AST = False
try:
    from analyzers.solidity_ast import compile_to_ast, analyze_contracts, _get_node_type, _get_name
    _HAS_AST = True
except ImportError:
    pass

_EXTERNAL_CALL_MEMBERS = {'call', 'delegatecall', 'staticcall', 'transfer', 'send'}
# Only these can call back into the contract and change state.  A
# staticcall cannot write state, and transfer/send forward only 2300
# gas, so neither is a callback-capable channel for confirmed
# reentrancy (issue #33, staticcall semantics).
_CALLBACK_CAPABLE_MEMBERS = {'call', 'delegatecall'}


def _external_call_members(node) -> set:
    """MemberAccess call kinds found in a node subtree."""
    members = set()
    try:
        for child in node.children():
            ct = _get_node_type(child)
            if ct == 'MemberAccess':
                member = getattr(child, 'memberName', '')
                if member in _EXTERNAL_CALL_MEMBERS:
                    members.add(member)
            members.update(_external_call_members(child))
    except Exception:
        pass
    return members


def _has_external_call(node) -> bool:
    """Check if a node subtree contains an external call (MemberAccess with call/transfer/etc)."""
    return bool(_external_call_members(node))


def _func_modifiers(func_node) -> list:
    """Modifier names applied to a function definition node."""
    mods = []
    try:
        for child in func_node.children():
            if _get_node_type(child) == 'ModifierInvocation':
                mod_name = getattr(child, 'modifierName', None)
                mods.append(_get_name(mod_name) if mod_name is not None else _get_name(child))
    except Exception:
        pass
    return mods


_GUARD_MODIFIERS = {'nonReentrant', 'reentrancyGuard'}


def _find_state_writes(node, state_vars: Set[str]) -> Set[str]:
    writes = set()
    nt = _get_node_type(node)
    if nt == 'Assignment':
        lhs = getattr(node, 'leftHandSide', None)
        if lhs:
            lhs_name = _get_name(lhs)
            if lhs_name in state_vars:
                writes.add(lhs_name)
            base_expr = getattr(lhs, 'baseExpression', None) or getattr(lhs, 'base', None)
            if base_expr:
                base_name = _get_name(base_expr)
                if base_name in state_vars:
                    writes.add(base_name)
    elif nt == 'UnaryOperation' and getattr(node, 'operator', '') in ('++', '--'):
        # Counter increments/decrements (issue #33 regression list).
        sub = getattr(node, 'subExpression', None)
        if sub is not None:
            sub_name = _get_name(sub)
            if sub_name in state_vars:
                writes.add(sub_name)
            base_expr = getattr(sub, 'baseExpression', None) or getattr(sub, 'base', None)
            if base_expr:
                base_name = _get_name(base_expr)
                if base_name in state_vars:
                    writes.add(base_name)
    try:
        for child in node.children():
            writes.update(_find_state_writes(child, state_vars))
    except Exception:
        pass
    return writes


def _find_state_reads(node, state_vars: Set[str]) -> Set[str]:
    reads = set()
    nt = _get_node_type(node)
    name = _get_name(node)
    if nt == 'Identifier' and name in state_vars:
        reads.add(name)
    if nt == 'IndexAccess':
        base_expr = getattr(node, 'baseExpression', None) or getattr(node, 'base', None)
        if base_expr:
            base_name = _get_name(base_expr)
            if base_name in state_vars:
                reads.add(base_name)
    try:
        for child in node.children():
            reads.update(_find_state_reads(child, state_vars))
    except Exception:
        pass
    return reads


class Block:
    __slots__ = ('id', 'stmts', 'succ', 'pred', 'has_call', 'has_write', 'writes', 'calls', 'reads', 'has_terminator',
                 'call_stmts', 'write_stmts')
    def __init__(self, bid: int):
        self.id = bid
        self.stmts = []
        self.succ = set()
        self.pred = set()
        self.has_call = False
        self.has_write = False
        self.writes = []
        self.calls = []
        self.reads = set()
        self.has_terminator = False
        # Statement indices *within* this block, so a call and a later
        # write in the same straight-line block can be ordered
        # (issue #33).  Previously every call/write was recorded with
        # index 0 and same-block pairs were ignored entirely.
        self.call_stmts = []   # [(stmt_index, member), ...]
        self.write_stmts = []  # [(stmt_index, var), ...]


class CFG:
    def __init__(self):
        self.blocks = {}
        self.entry = -1

    def _new_block(self) -> Block:
        bid = len(self.blocks)
        b = Block(bid)
        self.blocks[bid] = b
        return b

    def _add_edge(self, frm: int, to: int):
        if frm >= 0:
            self.blocks[frm].succ.add(to)
            self.blocks[to].pred.add(frm)

    def _build_seq(self, stmts: List, state_vars: Set[str], after: List[int]) -> int:
        if not stmts:
            return after[0] if after else -1
        entry = self._new_block()
        cur = entry
        for stmt_index, stmt in enumerate(stmts):
            nt = _get_node_type(stmt)
            if nt == 'IfStatement':
                cur = self._build_if(stmt, state_vars, cur, after)
            elif nt in ('ForStatement', 'WhileStatement', 'DoWhileStatement'):
                cur = self._build_loop(stmt, state_vars, cur, after)
            elif nt in ('Return', 'RevertStatement', 'Revert'):
                cur.stmts.append(stmt)
                cur.has_terminator = True
                cur = self._new_block()
            else:
                cur.stmts.append(stmt)
                members = _external_call_members(stmt)
                callback_members = members & _CALLBACK_CAPABLE_MEMBERS
                if callback_members:
                    cur.has_call = True
                    for member in sorted(callback_members):
                        cur.calls.append((stmt_index, member))
                        cur.call_stmts.append((stmt_index, member))
                writes = _find_state_writes(stmt, state_vars)
                if writes:
                    cur.has_write = True
                    cur.writes.extend((stmt_index, w) for w in writes)
                    cur.write_stmts.extend((stmt_index, w) for w in writes)
                reads = _find_state_reads(stmt, state_vars)
                cur.reads.update(reads)
        if not cur.has_terminator and after:
            self._add_edge(cur.id, after[0])
        return entry.id

    def _build_if(self, node, state_vars: Set[str], entry: Block, after: List[int]) -> Block:
        tb_raw = getattr(node, 'trueBody', None) or []
        fb_raw = getattr(node, 'falseBody', None) or []
        tb = list(tb_raw) if isinstance(tb_raw, (list, tuple)) else [tb_raw]
        fb = list(fb_raw) if isinstance(fb_raw, (list, tuple)) else [fb_raw]
        merge = self._new_block()
        after_merge = [merge.id] + after
        tb_entry = self._build_seq(tb, state_vars, after_merge)
        fb_entry = self._build_seq(fb, state_vars, after_merge)
        if tb_entry >= 0:
            self._add_edge(entry.id, tb_entry)
        else:
            self._add_edge(entry.id, merge.id)
        if fb_entry >= 0:
            self._add_edge(entry.id, fb_entry)
        else:
            self._add_edge(entry.id, merge.id)
        return merge

    def _build_loop(self, node, state_vars: Set[str], entry: Block, after: List[int]) -> Block:
        header = self._new_block()
        self._add_edge(entry.id, header.id)
        body_raw = getattr(node, 'body', None) or []
        body_list = list(body_raw) if isinstance(body_raw, (list, tuple)) else [body_raw]
        body_entry = self._build_seq(body_list, state_vars, [header.id])
        if body_entry >= 0:
            self._add_edge(header.id, body_entry)
        else:
            self._add_edge(header.id, header.id)
        exit_block = self._new_block()
        self._add_edge(header.id, exit_block.id)
        return exit_block

    def build(self, func_node, state_vars: Set[str]) -> int:
        body_nodes = list(getattr(func_node, 'nodes', []))
        after = []
        entry = self._build_seq(body_nodes, state_vars, after)
        self.entry = entry if entry >= 0 else self._new_block().id
        return self.entry

    def reachable(self, src: int, dst: int) -> bool:
        visited = set()
        stack = [src]
        while stack:
            cur = stack.pop()
            if cur == dst:
                return True
            if cur in visited:
                continue
            visited.add(cur)
            b = self.blocks.get(cur)
            if not b:
                continue
            stack.extend(b.succ)
        return False

    def find_reentrancy_paths(self) -> List[dict]:
        findings = []
        # (a) Same-block, straight-line CALL -> WRITE (issue #33).  This
        # was previously impossible: the old code required
        # call_block != write_block, so the classic withdraw pattern --
        # call and state write in one straight-line body -- was missed.
        # Statement indices are monotonic within a block, so index
        # order is execution order here.
        for bid, b in self.blocks.items():
            if b.has_terminator:
                continue
            for call_index, member in b.call_stmts:
                for write_index, var in b.write_stmts:
                    if write_index > call_index:
                        findings.append({
                            'call_block': bid,
                            'write_block': bid,
                            'same_block': True,
                            'calls': [(call_index, member)],
                            'writes': [(write_index, var)],
                        })
        # (b) Cross-block CALL -> WRITE along a CFG edge.
        call_blocks = [bid for bid, b in self.blocks.items() if b.has_call and not b.has_terminator]
        write_blocks = [bid for bid, b in self.blocks.items() if b.has_write]
        for cbid in call_blocks:
            for wbid in write_blocks:
                if cbid != wbid and self.reachable(cbid, wbid):
                    findings.append({
                        'call_block': cbid,
                        'write_block': wbid,
                        'same_block': False,
                        'calls': self.blocks[cbid].calls,
                        'writes': self.blocks[wbid].writes,
                    })
        return findings


def analyze_func_flow(func_node, state_vars: Set[str], modifiers=None) -> dict:
    # Guard modifiers (issue #33): a guarded function cannot be
    # re-entered, so its CFG paths are not confirmed reentrancy.
    if modifiers and any(m in _GUARD_MODIFIERS for m in modifiers):
        return {
            'reentrancy_paths': 0,
            'reentrancy_details': [],
            'blocks': 0,
        }
    cfg = CFG()
    cfg.build(func_node, state_vars)
    reentrancy = cfg.find_reentrancy_paths()
    return {
        'reentrancy_paths': len(reentrancy),
        'reentrancy_details': reentrancy,
        'blocks': len(cfg.blocks),
    }


def analyze_flow(code: str) -> List[str]:
    if not _HAS_AST:
        return []
    units = compile_to_ast(code)
    if not units:
        return []
    contracts = analyze_contracts(units)
    if not contracts:
        return []
    results = []
    for contract in contracts:
        state_vars = {sv['name'] for sv in contract.state_vars if sv.get('name')}
        for func_node in _get_func_nodes(units, contract.name):
            func_name = _get_name(func_node)
            flow = analyze_func_flow(func_node, state_vars, _func_modifiers(func_node))
            if flow['reentrancy_paths'] > 0:
                details = flow['reentrancy_details'][:3]
                detail_str = ', '.join(
                    f"block {d['call_block']}->{d['write_block']}" for d in details)
                results.append(
                    f"- [Critical] CFG Reentrancy: '{func_name}' has {flow['reentrancy_paths']} "
                    f"external-call-to-state-write path(s) ({flow['blocks']} blocks) [{detail_str}]"
                )
    return results


def _get_func_nodes(units, contract_name: str):
    for unit in units:
        if _get_node_type(unit) == 'ContractDefinition' and _get_name(unit) == contract_name:
            for node in getattr(unit, 'nodes', []):
                if _get_node_type(node) == 'FunctionDefinition':
                    yield node
