"""Regression tests for two client-facing accuracy bugs.

Bug 1 (Parity path over-approximation): the reentrancy evidence rule
was position-order only, so a call in the ``if`` branch and a write in
the mutually exclusive ``else`` branch counted as call-before-write
evidence. In Parity's execute(), the call sits in the ``if`` branch
and the m_txs write sits in the ``else`` branch, so the pair must be
downgraded to a guard note, never Confirmed.

Bug 2 (Mini-Review summary counting): the summary counted findings by
evidence label, and guard notes could inherit the Confirmed label
(NS-RE-01 showed "Confirmed by code evidence: 3" for 1 Critical + 2
Medium guard notes, because triage matched "withdrawbalance" inside
"withdrawbalance_fixed" by substring). The summary must count only
Critical findings with a Confirmed status as Confirmed.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from analyzers.reentrancy_evidence import (
    _mutually_exclusive_branches,
    call_before_write_evidence,
    classify_function,
)

import mini_review as mr

# Parity execute() shape, reduced to the branch structure that matters:
# call in the if branch (here in an inner if condition, as in the real
# file), write in the else branch. The real file's call is
# ``if (!_to.call.value(_value)(_data)) throw;`` inside the outer if.
PARITY_EXECUTE_BODY = """
    if ((_data.length == 0 && underLimit(_value)) || m_required == 1) {
      address created;
      if (_to == 0) {
        created = create(_value, _data);
      } else {
        if (!_to.call.value(_value)(_data))
          throw;
      }
      SingleTransact(msg.sender, _value, _to, _data, created);
    } else {
      o_hash = sha3(msg.data, block.number);
      if (m_txs[o_hash].to == 0 && m_txs[o_hash].value == 0) {
        m_txs[o_hash].to = _to;
        m_txs[o_hash].value = _value;
      }
    }
"""

# Parity confirm() shape: call in the inner else, delete after the
# inner if/else but still inside the outer if -- same path, so this
# stays Confirmed by the tool's rule (its exploitability as reentrancy
# is a separate question: confirm requires onlymanyowners, which is
# not a recognised guard).
PARITY_CONFIRM_BODY = """
    if (m_txs[_h].to != 0 || m_txs[_h].value != 0) {
      address created;
      if (m_txs[_h].to == 0) {
        created = create(m_txs[_h].value, m_txs[_h].data);
      } else {
        if (!m_txs[_h].to.call.value(m_txs[_h].value)(m_txs[_h].data))
          throw;
      }
      MultiTransact(msg.sender, _h, m_txs[_h].value, m_txs[_h].to, created);
      delete m_txs[_h];
      return true;
    }
"""

VULN_BODY = """
    if (!msg.sender.call.value(bal)()) { throw; }
    balances[msg.sender] = 0;
"""

# NS-RE-01 shape: vulnerable function plus two fixed variants whose
# names start with the vulnerable function's name.
NS_RE_01_SOURCE = """
contract Reentrance {
    mapping (address => uint) userBalance;
    function withdrawBalance(){
        if( ! (msg.sender.call.value(userBalance[msg.sender])() ) ){
            throw;
        }
        userBalance[msg.sender] = 0;
    }
    function withdrawBalance_fixed(){
        uint amount = userBalance[msg.sender];
        userBalance[msg.sender] = 0;
        if( ! (msg.sender.call.value(amount)() ) ){
            throw;
        }
    }
    function withdrawBalance_fixed_2(){
        msg.sender.transfer(userBalance[msg.sender]);
        userBalance[msg.sender] = 0;
    }
}
"""


def test_parity_execute_cross_branch_is_not_confirmed():
    classification, _evidence = classify_function(
        [], PARITY_EXECUTE_BODY, ["m_txs", "to", "value", "o_hash"]
    )
    assert classification == "guard-note"
    assert (
        call_before_write_evidence(
            PARITY_EXECUTE_BODY, ["m_txs", "to", "value", "o_hash"]
        )
        is None
    )


def test_parity_confirm_same_path_stays_confirmed():
    classification, evidence = classify_function(
        [], PARITY_CONFIRM_BODY, ["m_txs"]
    )
    # Same path (delete after the call, inside the same outer if), so
    # the tool's rule still counts it. This is reported honestly, not
    # forced to zero: the shape is genuine call-before-write, even
    # though confirm()'s reentrancy exploitability is not established.
    assert classification == "confirmed"
    assert evidence is not None
    assert evidence[2] == "m_txs"


def test_genuine_same_path_still_confirmed():
    classification, evidence = classify_function([], VULN_BODY, ["balances"])
    assert classification == "confirmed"
    assert evidence is not None


def test_call_in_condition_write_in_else_still_confirmed():
    # A call in an if condition executes before the branch is taken,
    # so a write in the else branch does follow the call on the else
    # path. Downgrading this would be a false negative.
    body = """
        if (msg.sender.call.value(bal)()) {
        } else {
          balances[msg.sender] = 0;
        }
    """
    classification, _evidence = classify_function([], body, ["balances"])
    assert classification == "confirmed"


def test_mutually_exclusive_helper():
    body = """
        if (cond) {
          msg.sender.call.value(bal)();
        } else {
          balances[msg.sender] = 0;
        }
    """
    call_pos = body.index(".call")
    write_pos = body.index("balances[msg.sender] = 0")
    assert _mutually_exclusive_branches(body, call_pos, write_pos) is True
    # Exclusivity is a symmetric relation; call_before_write_evidence
    # only ever asks it call-first (it only considers writes after a
    # call), so the reversed order is also True by definition.
    assert _mutually_exclusive_branches(body, write_pos, call_pos) is True
    # Write after the if (not inside either branch) is not exclusive.
    after = """
        if (cond) {
          msg.sender.call.value(bal)();
        }
        balances[msg.sender] = 0;
    """
    call_pos = after.index(".call")
    write_pos = after.index("balances[msg.sender] = 0")
    assert _mutually_exclusive_branches(after, call_pos, write_pos) is False


def test_fixed_variants_are_guard_notes_not_confirmed():
    # Fix 2: guard notes are counted in the appendix, not as findings;
    # the summary findings count is the 1 Critical Confirmed finding.
    report = mr.generate_mini_review(
        NS_RE_01_SOURCE, file_path="Reentrance.sol", commit="test"
    )
    assert "- **Confirmed findings**: 1" in report
    assert "- **Critical**: 1" in report
    assert "- **Confirmed by code evidence**: 1" in report
    assert "- **Guard note only**: 2" in report
    assert "- **Guard notes (not findings)**: 2" in report
    triaged = mr.triage_findings(
        [
            {
                "name": "External Call Without Recognized Guard",
                "severity": "Medium",
                "description": (
                    "External call in withdrawBalance_fixed() "
                    "with no recognized guard"
                ),
            }
        ],
        NS_RE_01_SOURCE,
    )
    assert triaged[0]["evidence_status"] == "Guard note only"


def test_summary_counts_only_critical_as_confirmed():
    # Even when supplied Medium findings carry a Confirmed evidence
    # status (they name the same vulnerable function, so triage marks
    # them Confirmed while preserving their supplied severity), the
    # summary must never claim more Confirmed than Critical findings.
    findings = [
        {
            "name": "Reentrancy",
            "severity": "Critical",
            "description": "Reentrancy in withdrawBalance()",
        },
        {
            "name": "Reentrancy",
            "severity": "Medium",
            "description": "Reentrancy in withdrawBalance()",
        },
        {
            "name": "Reentrancy",
            "severity": "Medium",
            "description": "Reentrancy in withdrawBalance()",
        },
    ]
    report = mr.generate_mini_review(
        NS_RE_01_SOURCE, file_path="Reentrance.sol", findings=findings
    )
    # Fix 2: only the Critical item is a Confirmed finding; the two
    # Medium code-supported reentrancy items are "other items", not
    # Confirmed findings and not guard notes.
    assert "- **Confirmed findings**: 1" in report
    assert "- **Critical**: 1" in report
    assert "- **Confirmed by code evidence**: 1" in report
    assert "- **Confirmed by code evidence**: 3" not in report
    assert "- **Other items (not Confirmed findings)**: 2" in report
