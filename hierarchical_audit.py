"""
Hierarchical audit for Solidity smart contracts.
Layer 1 (3 analysts) + Layer 2 (The Crucible) + static analysis.
"""
import json
import logging
import os
import time
from typing import Dict, List, Optional

from config import FREE_MODELS, REPORT_DIR, PROGRESS_FILE
from agents import call_model_with_fallback, truncate_code
from static_analysis import analyze_opcodes, analyze_storage_single, analyze_inheritance
from hierarchical_base import HierarchicalAuditor
from external_analyzers import external_analysis_text, tool_available

logger = logging.getLogger(__name__)

LAYER1_AGENTS = [
    {
        "key": "security", "name": "Security Expert",
        "model": "llama-3.3-70b",
        "prompt": """You are a smart contract security expert specializing in vulnerability discovery.
Your tasks:
1. Analyze the code line by line for security vulnerabilities
2. Focus on: Reentrancy, Access Control, Flash Loan Attacks, Integer Overflows, Front-Running, Oracle Manipulation, Signature Replay, Uninitialized Proxies
3. For each vulnerability: identify affected code, explain attack mechanism, rate severity (Critical/High/Medium/Low/Info)
4. Provide specific fix code for each vulnerability

Output format:
## Security Vulnerabilities
### [Number]: [Name] — [Critical/High/Medium/Low]
- **File/Line**: [location]
- **Attack Mechanism**: [explanation]
- **Impact**: [effect]
- **Fix**: [code + explanation]
"""
    },
    {
        "key": "logic", "name": "Logic & Design Expert",
        "model": "llama-3.3-70b",
        "prompt": """You are an expert in business logic and decentralized protocol design.
Your tasks:
1. Analyze contract design and business logic
2. Focus on: Business Logic Flaws, State Machine Errors, Invariant Violations, Design Pattern Misuse, Upgradeability Risks, Composability Issues
3. Find contradictions in design assumptions
4. Find unexpected state transition paths

Output format:
## Design & Logic Vulnerabilities
### [Number]: [Name] — [Critical/High/Medium/Low]
- **Component**: [location]
- **Design Issue**: [explanation]
- **Attack Path**: [steps]
- **Fix**: [suggestion]
"""
    },
    {
        "key": "economics", "name": "Economics & Gas Expert",
        "model": "llama-3.3-70b",
        "prompt": """You are an expert in protocol economics and gas optimization.
Your tasks:
1. Analyze the economic model
2. Focus on: MEV Opportunities, Oracle Manipulation Economics, Incentive Misalignment, Fee Calculation Errors, Liquidation Logic, MEV Extraction Paths, Tokenomics Attacks
3. Analyze gas consumption: expensive loops, inefficient storage, unoptimized operations
4. Provide specific gas optimizations

Output format:
## Economic Vulnerabilities
### [Number]: [Name] — [Critical/High/Medium/Low]
## Gas Optimizations
### [Number]: [Optimization] — [savings]
"""
    },
]

LAYER2_AGENTS = [
    {
        "key": "investigator", "name": "Investigator",
        "model": "llama-3.3-70b",
        "prompt": """You are an investigator specialized in root cause analysis of smart contract vulnerabilities.
Your role: After Layer 1 analysis from 3 angles (security, logic, economics):
1. Study all Layer 1 analyses
2. For each vulnerability: identify the root cause, find links between vulnerabilities, discover attack chains
3. Add new vulnerabilities from cross-referencing Layer 1
4. Rate exploitability (Easy/Medium/Hard)

Output:
## Investigation Report
### [Number]: [Name]
- **Root Cause**: [analysis]
- **Attack Chains**: [steps]
- **Exploitability**: [Easy/Medium/Hard]
"""
    },
    {
        "key": "skeptic", "name": "Skeptic",
        "model": "llama-3.3-70b",
        "prompt": """You are a skeptic specialized in debunking false vulnerabilities.
Your role: Review the investigator's report and Layer 1 analyses:
1. Impractical vulnerabilities?
2. Vulnerabilities requiring impossible conditions?
3. Severity overestimation?
Rate each: Confirmed / Suspected / Rejected

Output:
## Skeptic Report
### [Name]: [Confirmed/Suspected/Rejected]
"""
    },
    {
        "key": "critic", "name": "Critic",
        "model": "llama-3.3-70b",
        "prompt": """You are a lead critic specialized in Bug Bounty reports.
Your role: After Layer 1, investigator, and skeptic:
1. Filter remaining findings
2. Assign final severity (Critical/High/Medium/Low)
3. Note disagreements

Output format:
# [Protocol] — Security Report
## [C/H/M/L-XX]: [Title]
### Severity: **[Critical/High/Medium/Low]**
### Description
[explanation]
### Affected Contracts
[path]
### Root Cause
[cause]
### Impact
[effect]
### Proof of Concept
[steps]
### Remediation
[fix]
---
## Summary
| ID | Finding | Severity | File |
"""
    },
]


def _structural_brace_counts(line: str, in_block_comment: bool = False):
    """Count Solidity braces while ignoring comments and quoted strings."""
    depth = 0
    opened = False
    quote = None
    escaped = False
    i = 0
    while i < len(line):
        if in_block_comment:
            if line.startswith("*/", i):
                in_block_comment = False
                i += 2
            else:
                i += 1
            continue
        if quote:
            ch = line[i]
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == quote:
                quote = None
            i += 1
            continue
        if line.startswith("//", i):
            break
        if line.startswith("/*", i):
            in_block_comment = True
            i += 2
            continue
        ch = line[i]
        if ch in ("'", '"'):
            quote = ch
        elif ch == "{":
            depth += 1
            opened = True
        elif ch == "}":
            depth -= 1
        i += 1
    return depth, opened, in_block_comment


def _extract_contract(code: str, focus_name: str) -> str:
    """Extract a single contract by name from Solidity code."""
    lines = code.split("\n")
    name_lower = focus_name.replace(".sol", "").lower()
    contract_ranges = []
    i = 0
    while i < len(lines):
        stripped = lines[i].strip()
        if any(stripped.startswith(x) for x in ["contract ", "interface ", "library ", "abstract contract "]):
            decl = stripped.split("{")[0] if "{" in stripped else stripped
            cname = ""
            for keyword in ["contract ", "interface ", "library ", "abstract contract "]:
                if keyword in decl:
                    cname = decl.split(keyword, 1)[1].strip().split("(")[0].split()[0].strip()
                    break
            start = i; depth = 0; j = i; found_open = False
            in_block_comment = False
            while j < len(lines):
                delta, opened, in_block_comment = _structural_brace_counts(
                    lines[j], in_block_comment
                )
                depth += delta
                found_open = found_open or opened
                if found_open and depth <= 0:
                    break
                j += 1
            contract_ranges.append((start, j, cname))
            i = j
        i += 1
    for start, end, cname in contract_ranges:
        if cname and cname.lower() == name_lower:
            result = "\n".join(lines[start:end+1])
            return result
    logger.warning(f"Contract '{focus_name}' not found — using full code")
    return code


def hierarchical_audit(code: str, protocol_name: str = "Protocol", repo_url: str = "",
                       focus: str = "") -> str:
    if focus:
        code = _extract_contract(code, focus)

    # Layer 0: External tools — availability re-checked at call time (L-30)
    # P3: external_analysis_text carries the SKIPPED entries for tools
    # that did not run, so the returned report (attachments below) no
    # longer reads as if missing tools had cleared the contract.
    available = [t for t in ("slither", "mythril") if tool_available(t)]
    logger.info(f"Layer 0: available external tools: {available or 'none'}")
    ext_text = external_analysis_text(code)

    # Static analysis
    opcode_report = analyze_opcodes(code)
    try:
        storage_report = analyze_storage_single(code)
    except Exception as e:
        logger.warning(f"Storage analysis failed: {e}")
        storage_report = "## Storage Analysis\n\nFailed.\n"
    try:
        inheritance_report = analyze_inheritance(code)
    except Exception as e:
        logger.warning(f"Inheritance analysis failed: {e}")
        inheritance_report = "## Inheritance Analysis\n\nFailed.\n"

    extra_ctx = f"### Opcode Analysis\n{opcode_report[:2000]}\n"
    if ext_text:
        extra_ctx += f"\n{ext_text}\n"
    auditor = HierarchicalAuditor(LAYER1_AGENTS, LAYER2_AGENTS,
                                   default_model="llama-3.3-70b",
                                   protocol_name=protocol_name)
    layer1, layer2, final = auditor.run(code, extra_context=extra_ctx)

    final += "\n\n---\n\n## Attachments\n\n"
    if ext_text:
        final += ext_text + "\n"
    final += opcode_report + "\n"
    final += storage_report + "\n"
    final += inheritance_report + "\n"
    return final


def run_hierarchical_audit_interactive(code: str, focus: str = "",
                                       protocol_name: str = "Smart Contract",
                                       repo_url: str = "") -> str:
    return hierarchical_audit(code, protocol_name, repo_url, focus=focus)


generate_combined_report_interactive = lambda code: __import__('static_analysis').combined_report.generate_combined_report_interactive(code, "english")
generate_combined_report = lambda code, protocol: __import__('static_analysis').combined_report.generate_combined_report(code, protocol)
