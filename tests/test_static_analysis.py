import sys
import os
import pytest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from static_analysis.opcode_tracer import analyze_opcodes
from static_analysis.storage_analyzer import analyze_storage_single, _extract_contracts_from_code, _compute_storage_layout
from static_analysis.inheritance_analyzer import analyze_inheritance
from static_analysis.combined_report import generate_combined_report


SIMPLE_CONTRACT = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Vulnerable {
    mapping(address => uint) public balances;

    function withdraw(uint _amount) public {
        require(balances[msg.sender] >= _amount);
        (bool success,) = msg.sender.call{value: _amount}("");
        balances[msg.sender] -= _amount;
    }

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }
}
"""

INHERITANCE_CONTRACT = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Base {
    uint public x;
}

contract Middle is Base {
    uint public y;
}

contract Child is Middle {
    uint public z;
}
"""

STORAGE_CONTRACT = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract StorageTest {
    uint256 public a;
    address public b;
    bool public c;
    mapping(address => uint) public d;
}
"""


class TestOpcodeAnalysis:
    def test_detect_call_value(self):
        report = analyze_opcodes(SIMPLE_CONTRACT)
        assert "call_value" in report or ".call{value}" in report or "CRITICAL" in report
        assert len(report) > 50

    def test_clean_contract_no_findings(self):
        clean = "contract Safe { function f() public pure returns (uint) { return 1; } }"
        report = analyze_opcodes(clean)
        assert "No dangerous" in report

    def test_detect_assembly(self):
        code = "contract C { function f() { assembly { let x := 1 } } }"
        report = analyze_opcodes(code)
        assert "assembly" in report.lower() and "MEDIUM" in report


class TestStorageAnalysis:
    def test_extract_contracts(self):
        contracts = _extract_contracts_from_code(SIMPLE_CONTRACT)
        assert "Vulnerable" in contracts
        assert len(contracts["Vulnerable"]["state_vars"]) > 0

    def test_storage_layout(self):
        contracts = _extract_contracts_from_code(STORAGE_CONTRACT)
        layout = _compute_storage_layout(contracts, "StorageTest")
        assert len(layout) >= 3
        assert layout[0]["name"] == "a"
        assert layout[0]["slot"] == 0

    def test_storage_report(self):
        report = analyze_storage_single(STORAGE_CONTRACT)
        assert "Storage Analysis" in report
        assert "StorageTest" in report


class TestInheritanceAnalysis:
    def test_inheritance_chain(self):
        report = analyze_inheritance(INHERITANCE_CONTRACT)
        assert "Child" in report and "Middle" in report and "Base" in report
        assert "depth" in report

    def test_no_contracts(self):
        report = analyze_inheritance("// just a comment")
        assert "No contracts found" in report


class TestCombinedReport:
    def test_combined_generation(self):
        report = generate_combined_report(SIMPLE_CONTRACT, "TestContract")
        assert "TestContract" in report
        assert "Opcode Analysis" in report
        assert "Storage Analysis" in report
        assert "Inheritance Analysis" in report


class TestASTAnalysis:
    def test_ast_storage_simple(self):
        from static_analysis.ast_analyzer import analyze_storage_with_ast
        code = "contract C { uint256 public a; address public b; bool public c; }"
        report = analyze_storage_with_ast(code)
        assert "C" in report
        assert "a" in report
        assert "b" in report
        assert "c" in report

    def test_ast_storage_no_contracts(self):
        from static_analysis.ast_analyzer import analyze_storage_with_ast
        report = analyze_storage_with_ast("// just comment")
        assert report is not None

    def test_ast_inheritance_simple(self):
        from static_analysis.ast_analyzer import analyze_inheritance_with_ast
        code = INHERITANCE_CONTRACT
        report = analyze_inheritance_with_ast(code)
        assert "Child" in report
        assert "Middle" in report
        assert "Base" in report

    def test_ast_inheritance_empty(self):
        from static_analysis.ast_analyzer import analyze_inheritance_with_ast
        report = analyze_inheritance_with_ast("// nothing")
        assert report is not None

    def test_ast_storage_layout(self):
        from static_analysis.ast_analyzer import analyze_storage_with_ast
        code = STORAGE_CONTRACT
        report = analyze_storage_with_ast(code)
        assert "StorageTest" in report
        assert "slot" in report.lower() or "Slot" in report

    def test_ast_combined_report(self):
        from static_analysis.ast_analyzer import generate_combined_ast_report
        code = SIMPLE_CONTRACT
        report = generate_combined_ast_report(code, "TestVuln")
        assert "TestVuln" in report

    def test_ast_inheritance_detects_storage_collision(self):
        from static_analysis.ast_analyzer import analyze_inheritance_with_ast
        code = """
        pragma solidity ^0.8.0;
        contract Base { uint256 x; }
        contract Child is Base {
            function callBase(address addr) public {
                (bool ok,) = addr.delegatecall(abi.encodeWithSignature("setX(uint256)", 1));
                require(ok);
            }
        }"""
        report = analyze_inheritance_with_ast(code)
        assert "DELEGATECALL" in report or "Delegatecall" in report or "delegatecall" in report


def test_storage_layout_assigns_base_contract_vars_to_lower_slots():
    """Solidity puts the most-base contract's state vars at slot 0.

    Regression: the layout used to consume the postorder linearization
    reversed, giving the DERIVED contract slot 0 (mirror of the compiler).
    """
    from static_analysis.storage_analyzer import _compute_storage_layout

    contracts = {
        "A": {"name": "A", "parents": [], "state_vars": [
            {"name": "a", "type": "uint256", "size": 32}]},
        "B": {"name": "B", "parents": ["A"], "state_vars": [
            {"name": "b", "type": "uint256", "size": 32}]},
    }
    layout = _compute_storage_layout(contracts, "B")
    by_name = {v["name"]: v["slot"] for v in layout}
    assert by_name["a"] == 0, f"base var 'a' must live in slot 0, got {by_name}"
    assert by_name["b"] == 1, f"derived var 'b' must live in slot 1, got {by_name}"


def test_storage_layout_packing_and_dynamic_slots():
    """Packing, full-slot advance and dynamic-slot placement match the
    Solidity storage model (base-first layout fixed elsewhere)."""
    from static_analysis.storage_analyzer import _compute_storage_layout

    contracts = {
        "C": {"name": "C", "parents": [], "state_vars": [
            {"name": "x", "type": "uint128", "size": 16},
            {"name": "y", "type": "address", "size": 20},
            {"name": "z", "type": "uint256", "size": 32},
            {"name": "m", "type": "mapping(address => uint256)", "size": 32},
            {"name": "w", "type": "uint256", "size": 32},
        ]},
    }
    by_name = {v["name"]: v["slot"] for v in _compute_storage_layout(contracts, "C")}
    # x packs slot 0 alone (16+20 > 32); y slot 1; z slot 2 (fresh, full);
    # mapping owns slot 3; w slot 4.
    assert by_name == {"x": 0, "y": 1, "z": 2, "m": 3, "w": 4}, by_name


def test_storage_layout_dynamic_var_can_start_at_slot_zero():
    from static_analysis.storage_analyzer import _compute_storage_layout

    contracts = {
        "D": {"name": "D", "parents": [], "state_vars": [
            {"name": "m", "type": "mapping(address => uint256)", "size": 32},
        ]},
    }
    layout = _compute_storage_layout(contracts, "D")
    assert layout[0]["slot"] == 0, layout
