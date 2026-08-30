import logging
import re
import os
from collections import Counter
from typing import Dict, List, Optional
from dataclasses import dataclass

from analyzers.base import Finding
from proof_generator import generate_poc, run_foundry_test, PROOFS_DIR

logger = logging.getLogger(__name__)

_CRITICAL_HEADER_RE = re.compile(r"^\[Critical[^\]]*\]", re.IGNORECASE)
_NEXT_SEV_RE = re.compile(r"^\s*\[?(High|Medium|Low|Info)\b", re.IGNORECASE)


@dataclass
class ParsedCritical:
    agent_name: str
    description: str
    header_line: str = ""  # exact first line — the per-finding identity


def _parse_critical_findings(report: str) -> List[ParsedCritical]:
    findings = []
    lines = report.split("\n")
    capturing = False
    current: Optional[ParsedCritical] = None
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("[Critical") or stripped.upper().startswith("[CRITICAL"):
            if current:
                findings.append(current)
            label = stripped.split("]")[0].lstrip("[").strip()
            desc_start = stripped.find("]")
            desc = stripped[desc_start + 1:].strip() if desc_start != -1 else ""
            # Keep the exact header line: verdicts are applied per finding
            # by matching this line, so one PoC result can never flip the
            # verdict of every other Critical finding.
            current = ParsedCritical(agent_name=label, description=desc,
                                     header_line=stripped)
            capturing = True
        elif capturing and current:
            if _NEXT_SEV_RE.match(stripped):
                findings.append(current)
                current = None
                capturing = False
            elif stripped:
                current.description += "\n" + stripped
    if current:
        findings.append(current)
    return findings


def _create_finding_from_parsed(p: ParsedCritical, code: str) -> Optional[Finding]:
    if not p.agent_name or len(p.description) < 10:
        return None
    return Finding(
        agent_name=p.agent_name,
        severity="Critical",
        category="Auto-PoC",
        file="source.sol",
        function_name=p.agent_name.split(".")[-1] if "." in p.agent_name else "",
        description=p.description[:500],
        code_snippet=code[:200],
    )


def _rewrite_header(line: str, verdict: str) -> str:
    """Replace the whole [Critical…] severity token on one finding line."""
    if verdict == "proved":
        return _CRITICAL_HEADER_RE.sub("[Critical ✅ PROVED by PoC]", line, count=1)
    return _CRITICAL_HEADER_RE.sub(
        "[Info ❌ FALSE POSITIVE (PoC disproved — downgraded)]", line, count=1)


def _adjust_report(report: str, proved: List[str], disproved: List[str]) -> str:
    """Apply per-finding verdicts.

    `proved`/`disproved` hold the exact original header lines of the
    findings each verdict belongs to. Counts are consumed on first match,
    so duplicated header lines are handled and unrelated findings are
    never touched.
    """
    proved_pending = Counter(proved)
    disproved_pending = Counter(disproved)
    adjusted = []
    for line in report.split("\n"):
        stripped = line.strip()
        if (_CRITICAL_HEADER_RE.match(stripped) or stripped.upper().startswith("[CRITICAL")):
            if disproved_pending.get(stripped, 0) > 0:
                disproved_pending[stripped] -= 1
                adjusted.append(_rewrite_header(line, "disproved"))
                continue
            if proved_pending.get(stripped, 0) > 0:
                proved_pending[stripped] -= 1
                adjusted.append(_rewrite_header(line, "proved"))
                continue
        adjusted.append(line)
    return "\n".join(adjusted)


def validate_with_poc(report: str, code: str) -> str:
    parsed = _parse_critical_findings(report)
    if not parsed:
        logger.info("auto_poc: no Critical findings to validate")
        return report

    logger.info(f"auto_poc: validating {len(parsed)} Critical finding(s) with PoC")

    proved: List[str] = []
    disproved: List[str] = []
    inconclusive = 0

    for p in parsed:
        finding = _create_finding_from_parsed(p, code)
        if not finding:
            logger.debug(f"auto_poc: skipped '{p.agent_name}' — insufficient data")
            continue

        poc_path = generate_poc(finding, code)
        if not poc_path:
            logger.warning(f"auto_poc: PoC generation failed for '{p.agent_name}' — keeping as Critical")
            continue

        try:
            result = run_foundry_test(poc_path, use_docker=True, victim_code=code)
            status = result.get("status", "INCONCLUSIVE")
            if status == "PROVED":
                logger.info(f"auto_poc: ✅ PoC PASSED for '{p.agent_name}' — vulnerability confirmed")
                proved.append(p.header_line)
            elif status == "DISPROVED":
                logger.info(f"auto_poc: ❌ PoC FAILED for '{p.agent_name}' — clean disproof, downgrading to Info")
                disproved.append(p.header_line)
            else:
                # Compile failure / missing toolchain / zero tests — the PoC
                # carries no evidence either way, so the finding stands.
                inconclusive += 1
                logger.info(
                    f"auto_poc: ⚠️ PoC inconclusive for '{p.agent_name}' "
                    f"({result.get('error', 'unknown reason')}) — keeping as Critical"
                )
        finally:
            if os.path.exists(poc_path):
                os.unlink(poc_path)

    if proved or disproved:
        report = _adjust_report(report, proved, disproved)

    summary = (
        f"\n\n---\n### Auto-PoC Validation\n"
        f"- Critical findings validated: {len(parsed)}\n"
        f"- ✅ Proved (confirmed): {len(proved)}\n"
        f"- ❌ False positives (downgraded to Info): {len(disproved)}\n"
        f"- ⚠️ Inconclusive (kept as Critical): {inconclusive}\n"
    )
    report += summary
    return report


def validate_with_poc_silent(report: str, code: str) -> str:
    try:
        return validate_with_poc(report, code)
    except Exception as e:
        logger.error(f"auto_poc: validation failed — {e}")
        report += (
            f"\n\n---\n### Auto-PoC Validation\n"
            f"- ❌ Auto-PoC validation failed due to an internal error.\n"
            f"- Findings are reported as-is without proof verification.\n"
        )
        return report
