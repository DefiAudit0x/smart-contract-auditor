"""Regression tests for the old-syntax (.call.value) reentrancy blind spot.

Mini-Review from main at 0b8a0b28 gave 0 findings on the textbook
SB-RE-01 case (corpus/SB-RE-01/contract.sol):

    function withdrawBalance(){
        if( ! (msg.sender.call.value(userBalance[msg.sender])() ) ){
            throw;
        }
        userBalance[msg.sender] = 0;
    }

The callback-capable rule in analyzers/reentrancy_evidence.py only
matched a modern call -- ``.call(`` / ``.call{...}(`` -- because its
regex required '(' immediately after the member.  In pre-0.8 syntax
the value/gas options are chained as members before the invocation
(``.call.value(x)()``, ``.call.gas(g)()``, ``.call.gas(g).value(x)()``,
``.call.value(x).gas(g)()``), so after ``.call`` comes ``.value``,
not '(', and the whole call was invisible to the evidence rules.

These tests are solc-free: they exercise the text evidence rules
directly, plus the exact SB-RE-01 withdrawBalance shape through
classify_function.  The guard rule, the write-before-call rule, and
the transfer/send/staticcall exclusions are unchanged by the fix and
are asserted here so the fix cannot silently weaken them.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from analyzers.reentrancy_evidence import (
    any_external_calls,
    callback_capable_calls,
    call_before_write_evidence,
    classify_function,
)


def test_old_call_value_is_callback_capable():
    body = "msg.sender.call.value(bal)(); balances[a] = 0;"
    assert callback_capable_calls(body) == [(10, "call")]


def test_old_call_value_indexed_arg_is_callback_capable():
    body = "msg.sender.call.value(userBalance[msg.sender])(); userBalance[msg.sender] = 0;"
    assert callback_capable_calls(body) == [(10, "call")]


def test_old_call_gas_is_callback_capable():
    body = "t.call.gas(1000)(); balances[a] = 0;"
    assert callback_capable_calls(body) == [(1, "call")]


def test_old_call_gas_then_value_is_callback_capable():
    body = "t.call.gas(1000).value(bal)(); balances[a] = 0;"
    assert callback_capable_calls(body) == [(1, "call")]


def test_old_call_value_then_gas_is_callback_capable():
    body = "t.call.value(bal).gas(1000)(); balances[a] = 0;"
    assert callback_capable_calls(body) == [(1, "call")]


def test_old_call_value_nested_arg_is_callback_capable():
    body = "t.call.value(foo(bar))(); balances[a] = 0;"
    assert callback_capable_calls(body) == [(1, "call")]


def test_old_delegatecall_gas_is_callback_capable():
    body = "t.delegatecall.gas(1000)(); balances[a] = 0;"
    assert callback_capable_calls(body) == [(1, "delegatecall")]


def test_old_call_value_without_invocation_is_not_a_call():
    # ``.call.value`` as a bare member access (no trailing ()) is not
    # an invocation and must not be counted.
    assert callback_capable_calls("x.call.value; balances[a] = 0;") == []
    assert any_external_calls("x.call.value; balances[a] = 0;") == []


def test_transfer_send_staticcall_still_excluded():
    for body in (
        "x.transfer(1); balances[a] = 0;",
        "x.send(1); balances[a] = 0;",
        "x.staticcall(\"\"); balances[a] = 0;",
    ):
        assert callback_capable_calls(body) == []
        # They are still external calls, so they still earn a guard note.
        assert any_external_calls(body) != []


def test_sb_re_01_withdraw_shape_is_confirmed():
    body = (
        "if( ! (msg.sender.call.value(userBalance[msg.sender])() ) ){ throw; }"
        " userBalance[msg.sender] = 0;"
    )
    kind, evidence = classify_function([], body, ["userBalance"])
    assert kind == "confirmed"
    assert evidence is not None
    assert evidence[1] == "call"
    assert evidence[2] == "userBalance"


def test_old_call_value_guarded_is_not_confirmed():
    body = "msg.sender.call.value(bal)(); balances[a] = 0;"
    assert classify_function(["nonReentrant"], body, ["balances"]) == (None, None)
    assert classify_function(["reentrancyGuard"], body, ["balances"]) == (None, None)


def test_old_call_value_write_before_call_is_not_confirmed():
    body = "balances[a] = 0; msg.sender.call.value(bal)();"
    kind, evidence = classify_function([], body, ["balances"])
    assert kind == "guard-note"
    assert evidence is None
    assert call_before_write_evidence(body, ["balances"]) is None


def test_modern_call_still_confirmed():
    body = 'x.call{value: bal}(""); balances[a] = 0;'
    kind, evidence = classify_function([], body, ["balances"])
    assert kind == "confirmed"
    assert evidence is not None
    assert evidence[1] == "call"
