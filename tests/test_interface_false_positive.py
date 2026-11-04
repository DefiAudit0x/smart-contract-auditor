"""Regression tests for the MandateAquaApp false positive (2026-11-04).

Mini-Review from main at 1fce6ab4 reported a Critical "Confirmed by
code evidence" reentrancy "in addr()" at line 11 of MandateAquaApp.sol.
Manual inspection showed line 11 is the interface declaration
``function addr(bytes32 node) external view returns (address);``
inside ``interface IAddrResolver`` -- no body, not a real function --
and the real external-call function execute() is nonReentrant-guarded
with checks-effects-interactions.  The report was a misattribution
caused by two compounding parser flaws, both fixed here:

1. gate_validator._parse_code_functions registered body-less
   declarations as functions, and _extract_function_body jumped
   forward to the next '{' in the file -- the enclosing contract's
   brace -- so the declaration inherited the whole contract body.
2. The assignment check in reentrancy evidence (and the same regex
   in ast_detector._find_state_writes) matched the first '=' of
   '==', so a comparison such as ``strategy.maker == address(0)``
   in a *different* function was misread as a write to 'maker'
   after the external call.

These tests are solc-free: they exercise the text parsers and the
Mini-Review auto-finding path directly.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import gate_validator
import mini_review as mr
from analyzers.reentrancy_evidence import (
    call_before_write_evidence,
    classify_function,
)

# Minimal Mandate-like shape: an interface declaration, then a guarded
# contract whose external call is followed (in file order, in a later
# function) by a comparison -- never by a state write.
INTERFACE_THEN_GUARDED = """
pragma solidity 0.8.30;

interface IAddrResolver {
    function addr(bytes32 node) external view returns (address);
}

contract GuardedApp {
    mapping(bytes32 => uint) public used;
    bool private entered;

    modifier nonReentrant() {
        if (entered) revert();
        entered = true;
        _;
        entered = false;
    }

    function execute(bytes calldata routeData) external nonReentrant {
        used[bytes32(0)] += 1;
        (bool ok, ) = address(0x1234).call(routeData);
        require(ok);
    }

    function validate(uint x) private pure {
        require(x == 1);
    }
}
"""

# Same interface, plus a real unguarded reentrancy that must still
# be found -- the fix must not silence genuine findings.
INTERFACE_THEN_VULNERABLE = """
pragma solidity 0.8.30;

interface IAddrResolver {
    function addr(bytes32 node) external view returns (address);
}

contract Vault {
    mapping(address => uint) balances;

    function withdraw(uint amt) external {
        (bool ok, ) = msg.sender.call{value: amt}("");
        require(ok);
        balances[msg.sender] -= amt;
    }
}
"""

# An abstract (body-less) function declaration followed by a guarded
# function: the declaration itself must yield no finding.
ABSTRACT_THEN_GUARDED = """
pragma solidity 0.8.30;

abstract contract Base {
    function hook() public virtual;
}

contract App is Base {
    bool private entered;

    modifier nonReentrant() {
        if (entered) revert();
        entered = true;
        _;
        entered = false;
    }

    function hook() public override nonReentrant {
        (bool ok, ) = address(0x1234).call("");
        require(ok);
    }
}
"""


def _auto(source):
    return mr._auto_findings(source)


def test_interface_declaration_is_not_a_function():
    funcs = gate_validator._parse_code_functions(INTERFACE_THEN_GUARDED)
    assert "addr" not in funcs
    # The real functions are still parsed.
    assert "execute" in funcs
    assert "validate" in funcs


def test_interface_declaration_yields_no_finding():
    auto = _auto(INTERFACE_THEN_GUARDED)
    assert auto == []
    report = mr.generate_mini_review(
        INTERFACE_THEN_GUARDED, file_path="GuardedApp.sol", commit="test"
    )
    assert "No findings are listed" in report
    assert "addr()" not in report


def test_interface_plus_real_vulnerability_still_found():
    funcs = gate_validator._parse_code_functions(INTERFACE_THEN_VULNERABLE)
    assert "addr" not in funcs
    assert "withdraw" in funcs
    auto = _auto(INTERFACE_THEN_VULNERABLE)
    assert len(auto) == 1
    assert auto[0]["severity"] == "Critical"
    assert "withdraw" in auto[0]["description"]
    assert "addr" not in auto[0]["description"]


def test_abstract_bodyless_declaration_yields_no_finding():
    funcs = gate_validator._parse_code_functions(ABSTRACT_THEN_GUARDED)
    # The guarded override is a real function; the body-less base
    # declaration must not appear as a second, analysable "hook".
    assert "hook" in funcs
    # The surviving entry is the real override, not the declaration:
    # its suffix carries the guard, and its body is the override's own.
    assert "nonReentrant" in funcs["hook"]["suffix"]
    auto = _auto(ABSTRACT_THEN_GUARDED)
    assert auto == []


def test_comparison_after_call_is_not_a_write():
    # An unguarded function whose only post-call reference to a state
    # variable is a '==' comparison: guard note at most, never
    # Confirmed.  (Before the fix, '==' matched the assignment
    # pattern and this was misclassified as confirmed reentrancy.)
    body = """
        (bool ok, ) = msg.sender.call{value: amt}("");
        require(ok);
        require(balances[msg.sender] == amt);
    """
    assert call_before_write_evidence(body, ["balances"]) is None
    classification, _ = classify_function([], body, ["balances"])
    assert classification == "guard-note"


def test_real_assignment_after_call_still_confirmed():
    # Guard against over-correction: a genuine assignment after the
    # call must still be confirmed.
    body = """
        (bool ok, ) = msg.sender.call{value: amt}("");
        require(ok);
        balances[msg.sender] -= amt;
    """
    evidence = call_before_write_evidence(body, ["balances"])
    assert evidence is not None
    assert evidence[2] == "balances"
    classification, _ = classify_function([], body, ["balances"])
    assert classification == "confirmed"


def test_empty_body_function_still_parsed():
    # A real function with an empty '{}' body is a function (it just
    # yields no findings); only body-less declarations are skipped.
    funcs = gate_validator._parse_code_functions(
        "contract C { function noop() external {} }"
    )
    assert "noop" in funcs
    assert funcs["noop"]["body"] == ""


def test_extract_body_returns_empty_for_declaration():
    src = "interface I { function f() external view returns (uint); }\ncontract C { uint x; }"
    assert gate_validator._extract_function_body(src, src.index("function f")) == ""
