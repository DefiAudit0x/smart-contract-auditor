"""Test Generation - generate Foundry/Hardhat tests from detected vulnerabilities."""
import re
from typing import List, Dict


VULN_TEMPLATES = {
    "reentrancy": {
        "name": "Reentrancy",
        "check": "assertEq(counter, expected, 'Reentrancy guard failed');",
        "setup": "vm.expectRevert();",
        "needs_api": True,
        "reason": "the reentrancy guard state (counter) is target-specific",
    },
    "access_control": {
        "name": "Access Control",
        "check": "vm.expectRevert(bytes('Ownable: caller is not the owner'));",
        "setup": "",
        "needs_api": True,
        "reason": "expectRevert must target a specific access-controlled function",
    },
    "unchecked": {
        "name": "Unchecked Return",
        "check": "assertTrue(success, 'call should not revert');",
        "setup": "",
        "needs_api": True,
        "reason": "the probe must call the specific function with the unchecked return value",
    },
    "overflow": {
        "name": "Overflow",
        "check": "assertEq(counter, type(uint256).max, 'Overflow check');",
        "setup": "vm.assume(counter < type(uint256).max);",
        "needs_api": True,
        "reason": "the arithmetic entry point (counter) is target-specific",
    },
    "txorigin": {
        "name": "TxOrigin",
        "check": "assertEq(tx.origin, attacker, 'tx.origin check');",
        "setup": "vm.prank(attacker);",
    },
    "selfdestruct": {
        "name": "Selfdestruct",
        # L-14: 'contract' is a reserved word — the old check could not
        # compile; reference the deployed target instead.
        "check": "assertEq(address(target).code.length, 0, 'contract should be destroyed');",
        "setup": "",
    },
    "delegatecall": {
        "name": "DelegateCall",
        # L-14: storageVar/expected never existed in the generated harness —
        # assert on something the harness actually has instead.
        "check": "assertGt(address(target).balance, 0, 'target must retain balance after delegatecall');",
        "setup": "",
    },
    "flashloan": {
        "name": "Flash Loan",
        "check": "assertGe(token.balanceOf(address(this)), fee, 'flash loan fee');",
        "setup": "",
        "needs_api": True,
        "reason": "the token/fee pair is target-specific",
    },
}


_VULN_REVERSE = {v["name"].lower().replace(" ", "_"): k for k, v in VULN_TEMPLATES.items()}


def _detect_vulnerabilities(report: str) -> List[str]:
    """Extract vulnerability types from audit report."""
    found = []
    report_lower = report.lower()
    patterns = {
        "reentrancy": r"reentrancy|re[\s-]*entry",
        "access_control": r"access\s*control|access[\s-]*control|permissions|owner|onlyowner",
        "unchecked": r"unchecked|uncheck|\s.call\s*\(|low.level",
        "overflow": r"overflow|flood|underflow",
        "txorigin": r"tx\.origin|msg\.sender",
        "selfdestruct": r"selfdestruct|self.destruct|destroy|destruct",
        "delegatecall": r"delegatecall|delegate.call|delegate[\s-]*call",
        "flashloan": r"flash\s*loan|flash[\s-]*loan|flashloan",
    }
    for vuln, pat in patterns.items():
        if re.search(pat, report_lower, re.IGNORECASE):
            found.append(vuln)
    return found


def generate_foundry_test(contract_name: str, report: str, sol_code: str) -> str:
    """Generate Foundry tests from audit report."""
    vulns = _detect_vulnerabilities(report)

    lines = [
        f"// SPDX-License-Identifier: MIT",
        f"pragma solidity ^0.8.20;",
        f"",
        f'import "forge-std/Test.sol";',
        f'import "../src/{contract_name}.sol";',
        f"",
        f"contract {contract_name}Test is Test {{",
        f"    {contract_name} public target;",
        f"    address public attacker = makeAddr('attacker');",
        f"",
        f"    function setUp() public {{",
        f"        target = new {contract_name}();",
        f"        vm.deal(attacker, 100 ether);",
        f"    }}",
        f"",
    ]

    for vuln in vulns:
        template = VULN_TEMPLATES.get(vuln)
        if not template:
            continue
        if template.get("needs_api"):
            # L-14: these checks referenced harness-undefined identifiers
            # (counter, token, success) and could never compile. The generic
            # harness cannot know the target's API — emit an explicit skip
            # with the reason instead of fake-compiling or fake-passing code.
            lines.append(f"    function test{vuln.title()}() public {{")
            lines.append(f"        // {template['reason']} — extend this test manually.")
            lines.append(f"        vm.skip(true);")
            lines.append(f"    }}")
            lines.append(f"")
            continue
        lines.append(f"    function test{vuln.title()}() public {{")
        lines.append(f'        vm.label(attacker, "Attacker");')
        if template["setup"]:
            lines.append(f"        {template['setup']}")
        # L-14: only call functions that take NO parameters — the old
        # regex emitted target.foo() for every declared function, producing
        # tests that do not compile whenever a picked function had args.
        funcs = [
            m.group(1)
            for m in re.finditer(r"function\s+(\w+)\s*\(([^)]*)\)\s*[^{;]*", sol_code)
            if not m.group(2).strip()
        ]
        for func in funcs[:2]:
            lines.append(f"        // Test {func} for {template['name']}")
            lines.append(f"        target.{func}();")
        lines.append(f"        {template['check']}")
        lines.append(f"    }}")
        lines.append(f"")

    lines.append(f"    function testInvariant() public {{")
    lines.append(f'        // Invariant: the target must retain deployable bytecode —')
    lines.append(f'        // assertGe(balance, 0) is trivially true for uint and proves nothing.')
    lines.append(f'        assertGt(address(target).code.length, 0, "target must retain code");')
    lines.append(f"    }}")
    lines.append(f"}}")
    lines.append(f"")

    return "\n".join(lines)


def generate_hardhat_test(contract_name: str, report: str) -> str:
    """Generate Hardhat tests (JavaScript) from audit report."""
    vulns = _detect_vulnerabilities(report)
    lines = [
        'const { expect } = require("chai");',
        f'const {contract_name} = artifacts.require("{contract_name}");',
        "",
        f'contract("{contract_name}", (accounts) => {{',
        "  let target;",
        "  const [owner, attacker] = accounts;",
        "",
        '  beforeEach(async () => {',
        f"    target = await {contract_name}.new({{ from: owner }});",
        "  });",
        "",
    ]
    for vuln in vulns[:5]:
        lines.append(f'  describe("{vuln}", () => {{')
        lines.append('    it("should detect vulnerability", async () => {')
        lines.append("      // Test for " + vuln)
        lines.append("      // await target.vulnerableFunction({ from: attacker });")
        lines.append("      // expect(await target.someVar()).to.equal(expected);")
        lines.append("    });")
        lines.append("  });")
        lines.append("")

    lines.append("  after(async () => {")
    lines.append("    // Cleanup")
    lines.append("  });")
    lines.append("});")
    return "\n".join(lines)
