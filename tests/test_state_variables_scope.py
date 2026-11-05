"""Fix 3 tests: mini_review._state_variables is contract-level only.

The old regex scanned the whole file, so a local declared inside a
function body and a struct field both entered the state list, and a
write to that local / local-struct field after an external call was
reported as a Confirmed Critical reentrancy write -- false evidence.
These tests pin the narrowed rule:

- locals inside function bodies (including nested blocks) are excluded;
- struct fields are excluded, whether the struct is contract-level or
  local, while a genuine state struct variable IS included, so a write
  through it (``pos.balance = 0``) still counts as a state write;
- genuine contract-level declarations still count, including mapping
  (even multi-line), payable, array, custom-type and late (after a
  function) declarations;
- declarations inside comments / string literals and ``using ... for``
  lines contribute nothing.

Solc-free by design, like the other Mini-Review tests.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import mini_review as mr

LOCAL_ONLY = """
contract Vault {
    function withdraw() public {
        uint localBal = 100;
        (bool ok, ) = msg.sender.call{value: 1}("");
        require(ok, "fail");
        localBal = 0;
    }
}
"""

LOCAL_STRUCT = """
contract Vault {
    struct Position { uint balance; }
    function close() public {
        Position memory p;
        (bool ok, ) = msg.sender.call{value: 1}("");
        require(ok, "fail");
        p.balance = 0;
    }
}
"""

STATE_STRUCT = """
contract Vault {
    struct Position { uint balance; }
    Position public pos;
    function close() public {
        (bool ok, ) = msg.sender.call{value: 1}("");
        require(ok, "fail");
        pos.balance = 0;
    }
}
"""

GENUINE = """
contract Vault {
    mapping(address => uint256) public balances;
    function withdraw(uint256 amount) public {
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "fail");
        balances[msg.sender] -= amount;
    }
}
"""


def _buckets(source):
    auto = mr._auto_findings(source)
    triaged = mr.triage_findings(auto, source)
    confirmed, _hyp, guard, _other = mr._partition_triaged(triaged, auto)
    return confirmed, guard, triaged


def test_local_declaration_is_not_a_state_variable():
    assert mr._state_variables(LOCAL_ONLY) == []


def test_struct_field_is_not_a_state_variable():
    assert "balance" not in mr._state_variables(LOCAL_STRUCT)
    assert mr._state_variables(LOCAL_STRUCT) == []


def test_state_struct_variable_is_a_state_variable_not_its_field():
    assert mr._state_variables(STATE_STRUCT) == ["pos"]


def test_local_assignment_after_call_is_not_confirmed():
    confirmed, guard, _ = _buckets(LOCAL_ONLY)
    assert confirmed == []
    assert len(guard) == 1


def test_local_struct_field_write_after_call_is_not_confirmed():
    confirmed, guard, _ = _buckets(LOCAL_STRUCT)
    assert confirmed == []
    assert len(guard) == 1


def test_genuine_contract_level_write_after_call_is_still_confirmed():
    confirmed, guard, triaged = _buckets(GENUINE)
    assert len(confirmed) == 1
    assert triaged[0]["evidence_status"] == "Confirmed by code evidence"
    assert guard == []


def test_state_struct_write_after_call_is_still_confirmed_via_pos():
    confirmed, _guard, triaged = _buckets(STATE_STRUCT)
    assert len(confirmed) == 1
    # The evidence variable is the state variable itself, not the
    # struct field name the old code reported.
    assert "'pos'" in triaged[0]["description"]


def test_contract_level_forms_still_count():
    source = """
    contract Vault {
        mapping(address =>
            uint256) public balances;
        address payable public owner;
        address[] public owners;
        uint256 public lateVar;
        function withdraw(uint256 amount) public {
            (bool ok, ) = msg.sender.call{value: amount}("");
            require(ok, "fail");
            balances[msg.sender] -= amount;
        }
        uint256 public afterFunction;
    }
    """
    assert mr._state_variables(source) == [
        "balances", "owner", "owners", "lateVar", "afterFunction",
    ]


def test_comment_string_and_using_lines_contribute_nothing():
    source = """
    // uint fakeVar;
    /* mapping(address => uint) public fakeMap; */
    contract Vault {
        using SafeMath for uint256;
        string public note = "uint decoyVar;";
        uint256 public total;
    }
    """
    assert mr._state_variables(source) == ["note", "total"]


def test_nested_block_local_and_inherited_contract():
    source = """
    contract Vault is Ownable, Pausable {
        uint256 public total;
        function f() public {
            if (true) {
                uint inner = 1;
                total = inner;
            }
        }
    }
    """
    assert mr._state_variables(source) == ["total"]
