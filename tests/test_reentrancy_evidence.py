"""Regression tests for reentrancy detector cluster, issues #31/#32/#33.

These tests are deliberately solc-free: the evidence rules live in
``analyzers.reentrancy_evidence`` (pure text + metadata), the AST check
is exercised with hand-built ``ASTContract``/``ASTFunction`` objects,
and the CFG path logic is exercised with hand-built ``CFG`` blocks.
That way the tests run even where solcast/solc are not installed;
the solc-dependent end-to-end tests in test_ast_and_new.py remain the
integration layer on top of this.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from analyzers.reentrancy_evidence import (
    call_before_write_evidence,
    callback_capable_calls,
    classify_function,
    cross_function_pairs,
    function_read_write_sets,
    is_guarded,
)
from analyzers.solidity_analyzer import SolidityAnalyzer
from analyzers.solidity_ast import ASTContract, ASTFunction
from analyzers.cfg_analyzer import CFG, analyze_func_flow

# ------------------------------------------------------------------
# Sample contracts (text only; no compilation required)
# ------------------------------------------------------------------

VULNERABLE_WITHDRAW = """
pragma solidity ^0.8.0;
contract Vault {
    mapping(address => uint) balances;
    function withdraw(uint amt) external {
        require(balances[msg.sender] >= amt);
        (bool ok,) = msg.sender.call{value: amt}("");
        require(ok);
        balances[msg.sender] -= amt;
    }
}
"""

GUARDED_WITHDRAW = """
pragma solidity ^0.8.0;
contract Vault {
    mapping(address => uint) balances;
    modifier nonReentrant() { _; }
    function withdraw(uint amt) external nonReentrant {
        require(balances[msg.sender] >= amt);
        (bool ok,) = msg.sender.call{value: amt}("");
        require(ok);
        balances[msg.sender] -= amt;
    }
}
"""

STATE_INDEPENDENT_CALL = """
pragma solidity ^0.8.0;
contract Ping {
    function ping(address target) external {
        (bool ok,) = target.call("");
        require(ok);
    }
}
"""

SAFE_TRANSFER_NO_WRITE = """
pragma solidity ^0.8.0;
contract Pay {
    function pay(address to) external {
        payable(to).transfer(1);
    }
}
"""

WRITE_BEFORE_CALL = """
pragma solidity ^0.8.0;
contract Vault {
    mapping(address => uint) balances;
    function withdraw(uint amt) external {
        balances[msg.sender] -= amt;
        (bool ok,) = msg.sender.call{value: amt}("");
        require(ok);
    }
}
"""

CROSS_FUNCTION_VAULT = """
pragma solidity ^0.8.0;
contract Vault {
    mapping(address => uint) balances;
    function withdraw() external {
        require(balances[msg.sender] > 0);
        (bool ok,) = msg.sender.call{value: 1}("");
        require(ok);
    }
    function claimBonus() external {
        balances[msg.sender] = 0;
    }
}
"""

UNRELATED_FUNCTIONS = """
pragma solidity ^0.8.0;
contract Mixed {
    mapping(address => uint) balances;
    address owner;
    function withdraw() external {
        require(balances[msg.sender] > 0);
        (bool ok,) = msg.sender.call{value: 1}("");
        require(ok);
        balances[msg.sender] = 0;
    }
    function setOwner(address o) external {
        owner = o;
    }
}
"""


def _analyzer_with_contract(code, fn_name, modifiers, external_calls, state_vars):
    """SolidityAnalyzer with a hand-built contract (no solc)."""
    analyzer = SolidityAnalyzer()
    fn = ASTFunction(name=fn_name, modifiers=list(modifiers))
    fn.external_calls = list(external_calls)
    contract = ASTContract(name="C", kind="contract", functions=[fn], state_vars=[
        {"name": v} for v in state_vars
    ])
    analyzer._contracts_by_file = {"test.sol": [contract]}
    return analyzer, fn


def _findings_by_name(findings):
    return {f.agent_name: f for f in findings}


# ------------------------------------------------------------------
# #31: evidence before Critical (AST check)
# ------------------------------------------------------------------

class TestASTReentrancyEvidence:
    def test_vulnerable_call_before_write_is_critical(self):
        analyzer, _ = _analyzer_with_contract(
            VULNERABLE_WITHDRAW, "withdraw", [], ["call"], ["balances"]
        )
        findings = analyzer._check_reentrancy_ast("test.sol", VULNERABLE_WITHDRAW)
        by_name = _findings_by_name(findings)
        assert "Reentrancy (AST)" in by_name
        assert by_name["Reentrancy (AST)"].severity == "Critical"
        assert "balances" in by_name["Reentrancy (AST)"].description

    def test_guarded_function_not_flagged_as_critical(self):
        analyzer, _ = _analyzer_with_contract(
            GUARDED_WITHDRAW, "withdraw", ["nonReentrant"], ["call"], ["balances"]
        )
        findings = analyzer._check_reentrancy_ast("test.sol", GUARDED_WITHDRAW)
        assert findings == []

    def test_state_independent_call_is_guard_note_not_critical(self):
        analyzer, _ = _analyzer_with_contract(
            STATE_INDEPENDENT_CALL, "ping", [], ["call"], []
        )
        findings = analyzer._check_reentrancy_ast("test.sol", STATE_INDEPENDENT_CALL)
        by_name = _findings_by_name(findings)
        assert "Reentrancy (AST)" not in by_name
        assert by_name["External Call Without Recognized Guard"].severity == "Medium"

    def test_safe_transfer_no_write_is_guard_note_not_critical(self):
        analyzer, _ = _analyzer_with_contract(
            SAFE_TRANSFER_NO_WRITE, "pay", [], ["transfer"], []
        )
        findings = analyzer._check_reentrancy_ast("test.sol", SAFE_TRANSFER_NO_WRITE)
        by_name = _findings_by_name(findings)
        assert "Reentrancy (AST)" not in by_name
        assert by_name["External Call Without Recognized Guard"].severity == "Medium"

    def test_write_before_call_is_not_confirmed(self):
        analyzer, _ = _analyzer_with_contract(
            WRITE_BEFORE_CALL, "withdraw", [], ["call"], ["balances"]
        )
        findings = analyzer._check_reentrancy_ast("test.sol", WRITE_BEFORE_CALL)
        by_name = _findings_by_name(findings)
        assert "Reentrancy (AST)" not in by_name
        assert by_name["External Call Without Recognized Guard"].severity == "Medium"


class TestEvidenceHelpers:
    def test_staticcall_is_not_callback_capable(self):
        body = "(bool ok, bytes memory d) = target.staticcall(data);"
        assert callback_capable_calls(body) == []
        assert call_before_write_evidence(body + " x = 1;", ["x"]) is None

    def test_read_is_not_a_write(self):
        reads, writes = function_read_write_sets(
            "require(balances[msg.sender] >= amt);", ["balances"]
        )
        assert reads == {"balances"}
        assert writes == set()

    def test_compound_assignment_and_increment_are_writes(self):
        _, writes = function_read_write_sets(
            "balances[msg.sender] -= amt; count++;", ["balances", "count"]
        )
        assert writes == {"balances", "count"}

    def test_is_guarded_only_for_recognized_modifiers(self):
        assert is_guarded(["nonReentrant"])
        assert is_guarded(["reentrancyGuard"])
        assert not is_guarded(["onlyOwner"])
        assert not is_guarded([])

    def test_classify_guarded_is_none(self):
        assert classify_function(["nonReentrant"], VULNERABLE_WITHDRAW, ["balances"])[0] is None


# ------------------------------------------------------------------
# #32: per-function read/write sets for cross-function reentrancy
# ------------------------------------------------------------------

class TestCrossFunctionReentrancy:
    def _pairs(self, functions, state_vars):
        return cross_function_pairs(functions, state_vars)

    def test_unrelated_functions_do_not_flag(self):
        # withdraw touches balances; setOwner touches only owner and
        # makes no external call at all.
        pairs = self._pairs([
            {"name": "withdraw", "modifiers": [], "body": """
                require(balances[msg.sender] > 0);
                (bool ok,) = msg.sender.call{value: 1}("");
                balances[msg.sender] = 0;
            """, "callable": True},
            {"name": "setOwner", "modifiers": [], "body": "owner = o;", "callable": True},
        ], ["balances", "owner"])
        assert pairs == []

    def test_functions_using_different_state_do_not_conflate(self):
        pairs = self._pairs([
            {"name": "a", "modifiers": [], "body": """
                (bool ok,) = msg.sender.call{value: 1}(""); balances[msg.sender] = 0;
            """, "callable": True},
            {"name": "b", "modifiers": [], "body": "owner = o;", "callable": True},
        ], ["balances", "owner"])
        assert pairs == []

    def test_confirmed_cross_function_case_still_flags(self):
        pairs = self._pairs([
            {"name": "withdraw", "modifiers": [], "body": """
                require(balances[msg.sender] > 0);
                (bool ok,) = msg.sender.call{value: 1}("");
            """, "callable": True},
            {"name": "claimBonus", "modifiers": [], "body": """
                balances[msg.sender] = 0;
            """, "callable": True},
        ], ["balances"])
        assert len(pairs) == 1
        assert pairs[0]["caller"] == "withdraw"
        assert pairs[0]["callee"] == "claimBonus"
        assert pairs[0]["shared"] == ["balances"]

    def test_guarded_callee_is_not_a_feasible_target(self):
        pairs = self._pairs([
            {"name": "withdraw", "modifiers": [], "body": """
                require(balances[msg.sender] > 0);
                (bool ok,) = msg.sender.call{value: 1}("");
            """, "callable": True},
            {"name": "claimBonus", "modifiers": ["nonReentrant"], "body": """
                balances[msg.sender] = 0;
            """, "callable": True},
        ], ["balances"])
        assert pairs == []

    def test_read_read_sharing_is_not_an_exploit_path(self):
        pairs = self._pairs([
            {"name": "a", "modifiers": [], "body": """
                require(balances[msg.sender] > 0);
                (bool ok,) = msg.sender.call{value: 1}("");
            """, "callable": True},
            {"name": "b", "modifiers": [], "body": """
                require(balances[msg.sender] > 0);
            """, "callable": True},
        ], ["balances"])
        assert pairs == []


# ------------------------------------------------------------------
# #33: CFG statement order within blocks + guard modifiers
# ------------------------------------------------------------------

class TestCFGReentrancyPaths:
    def _cfg_with_block(self, call_stmts, write_stmts):
        cfg = CFG()
        block = cfg._new_block()
        block.call_stmts = list(call_stmts)
        block.write_stmts = list(write_stmts)
        block.has_call = bool(call_stmts)
        block.has_write = bool(write_stmts)
        block.calls = list(call_stmts)
        block.writes = list(write_stmts)
        cfg.entry = block.id
        return cfg

    def test_same_block_call_before_write_counts(self):
        cfg = self._cfg_with_block([(0, "call")], [(1, "balances")])
        paths = cfg.find_reentrancy_paths()
        assert any(p["same_block"] and p["call_block"] == p["write_block"] for p in paths)

    def test_same_block_write_before_call_does_not_count(self):
        cfg = self._cfg_with_block([(1, "call")], [(0, "balances")])
        assert cfg.find_reentrancy_paths() == []

    def test_cross_block_call_to_write_counts(self):
        cfg = CFG()
        call_block = cfg._new_block()
        call_block.call_stmts = [(0, "call")]
        call_block.has_call = True
        call_block.calls = [(0, "call")]
        write_block = cfg._new_block()
        write_block.write_stmts = [(0, "balances")]
        write_block.has_write = True
        write_block.writes = [(0, "balances")]
        cfg._add_edge(call_block.id, write_block.id)
        paths = cfg.find_reentrancy_paths()
        assert any(not p["same_block"] for p in paths)

    def test_guarded_function_has_no_cfg_paths(self):
        # analyze_func_flow short-circuits on guard modifiers before
        # building any CFG, so no AST node is needed here.
        result = analyze_func_flow(object(), {"balances"}, ["nonReentrant"])
        assert result["reentrancy_paths"] == 0


# ------------------------------------------------------------------
# ast_detector integration (only this class is skipped where the
# agents package deps are not installed; run in CI with full
# requirements).  Imported lazily so the rest of this file still runs
# in a minimal environment.
# ------------------------------------------------------------------

try:
    import agents.ast_detector as ast_detector
except Exception:  # pragma: no cover - missing optional deps locally
    ast_detector = None


@pytest.mark.skipif(ast_detector is None, reason="agents.ast_detector deps not installed")
class TestASTDetectorCrossFunction:
    def _contract(self, code, functions):
        fns = []
        for name, modifiers, external_calls in functions:
            fn = ASTFunction(name=name, modifiers=list(modifiers), visibility="external")
            fn.external_calls = list(external_calls)
            fns.append(fn)
        return ASTContract(name="Vault", kind="contract", functions=fns, state_vars=[{"name": "balances"}])

    def test_unrelated_functions_via_detector(self):
        contract = self._contract(UNRELATED_FUNCTIONS, [
            ("withdraw", [], ["call"]),
            ("setOwner", [], []),
        ])
        ok, _ = ast_detector._cross_function_reentrancy(contract, UNRELATED_FUNCTIONS)
        assert ok is False

    def test_confirmed_cross_function_via_detector(self):
        contract = self._contract(CROSS_FUNCTION_VAULT, [
            ("withdraw", [], ["call"]),
            ("claimBonus", [], []),
        ])
        ok, msg = ast_detector._cross_function_reentrancy(contract, CROSS_FUNCTION_VAULT)
        assert ok is True
        assert "balances" in msg

    def test_state_write_detection_ignores_reads(self):
        writes = ast_detector._find_state_writes(
            "require(balances[msg.sender] >= amt); balances[msg.sender] -= amt;",
            [{"name": "balances"}],
        )
        # Exactly one write (the -=), at the second occurrence.
        assert len(writes) == 1
        assert writes[0][1] == "state_write:balances"
