"""Gas Analysis - analyze gas consumption and optimization.

Single source of truth (M29 remediation): findings are computed once into
structured records; the text report and the savings estimate both derive
from the SAME records, so the two consumers (/api/gas fields and the
report text) can no longer disagree for the same code. USD pricing uses
explicit, documented parameters instead of hidden invented constants.
"""
import logging
import os
import re
import time
from dataclasses import dataclass
from typing import List, Dict, Optional, Tuple

logger = logging.getLogger(__name__)

_ETH_PRICE_CACHE: Optional[float] = None
_ETH_PRICE_TS: float = 0.0
_ETH_PRICE_TTL: float = 300.0

# Rule-of-thumb savings per finding severity, in gas units. These are
# documented heuristics (not measurements); they are shown as such in the
# report and are the ONLY place these numbers live.
GAS_ESTIMATE_PER_SEVERITY: Dict[str, int] = {"high": 5000, "medium": 500, "low": 50, "info": 0}
# Documented default gas price in gwei (override via GAS_PRICE_GWEI).
DEFAULT_GAS_PRICE_GWEI: float = 20.0


def _fetch_eth_price() -> Optional[float]:
    """Live ETH price; returns None when unavailable (no invented price)."""
    global _ETH_PRICE_CACHE, _ETH_PRICE_TS
    now = time.time()
    if _ETH_PRICE_CACHE is not None and (now - _ETH_PRICE_TS) < _ETH_PRICE_TTL:
        return _ETH_PRICE_CACHE
    try:
        import requests
        resp = requests.get(
            "https://api.coingecko.com/api/v3/simple/price?ids=ethereum&vs_currencies=usd",
            timeout=5,
        )
        if resp.status_code == 200:
            _ETH_PRICE_CACHE = resp.json()["ethereum"]["usd"]
            _ETH_PRICE_TS = time.time()
            logger.info(f"ETH price: ${_ETH_PRICE_CACHE}")
            return _ETH_PRICE_CACHE
    except Exception as e:
        logger.debug(f"Failed to fetch ETH price: {e}")
    return None


def _loop_ranges(lines: List[str]) -> List[Tuple[int, int]]:
    """(start_line, end_line) pairs of for-loop bodies via brace matching."""
    ranges = []
    for i, line in enumerate(lines):
        if re.search(r"\bfor\s*\(", line, re.IGNORECASE):
            depth = 0
            for j in range(i, len(lines)):
                depth += lines[j].count("{") - lines[j].count("}")
                if depth == 0 and "{" in "".join(lines[i:j + 1]):
                    ranges.append((i, j))
                    break
    return ranges


def _in_loop(line_no: int, ranges: List[Tuple[int, int]]) -> bool:
    return any(start <= line_no <= end for start, end in ranges)


@dataclass
class GasFinding:
    pattern: str
    severity: str
    line: int
    gas_estimate: int
    code: str


def _find_gas_issues(code: str) -> List[GasFinding]:
    """Single source of truth for gas findings (M29 remediation)."""
    findings: List[GasFinding] = []
    lines = code.split("\n")
    loops = _loop_ranges(lines)

    def add(line_no: int, severity: str, desc: str):
        findings.append(GasFinding(
            pattern=desc, severity=severity, line=line_no,
            gas_estimate=GAS_ESTIMATE_PER_SEVERITY.get(severity, 0),
            code=lines[line_no - 1].strip()[:120],
        ))

    for i, line in enumerate(lines, 1):
        # i++ / i = i + 1 in loop increments
        if re.search(r"\bfor\s*\([^;]*;\s*[^;]*;\s*(?:i\+\+|i\s*=\s*i\s*\+\s*1)\s*\)", line, re.IGNORECASE):
            add(i, "medium", "Loop increment with i++/i=i+1 (prefix ++i or unchecked-block pattern is cheaper)")
            continue
        # require WITHOUT a message only (the old pattern matched every require)
        if re.search(r"\brequire\s*\([^,()]*\)\s*;", line, re.IGNORECASE):
            add(i, "low", "require() without a reason string adds no cost, but consider one for UX; require WITH a long string costs gas")
            continue
        if re.search(r"\bstring\s+\w+\s*;", line, re.IGNORECASE):
            add(i, "medium", "String state variable (bytes32 is cheaper when the content is short and fixed)")
        # .length only INSIDE loops (as advertised)
        if re.search(r"\.length\b", line, re.IGNORECASE) and _in_loop(i - 1, loops):
            add(i, "info", ".length inside a loop (cache it in a local variable)")
        # msg.sender / tx.origin only INSIDE loops
        if re.search(r"\b(?:msg\.sender|tx\.origin)\b", line, re.IGNORECASE) and _in_loop(i - 1, loops):
            add(i, "low", "msg.sender/tx.origin read inside a loop (read once before the loop)")
        if re.search(r"\bkeccak256\b", line, re.IGNORECASE):
            add(i, "medium", "keccak256 call (expensive - batch hashing where possible)")

    return findings


def analyze_gas(code: str) -> str:
    """Analyze gas consumption; text view of _find_gas_issues."""
    findings = _find_gas_issues(code)

    if not findings:
        return "## Gas Analysis\n\n_No gas issues detected._"

    result = ["# Gas Optimization Report\n"]

    sev_count = {"high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev_count[f.severity] = sev_count.get(f.severity, 0) + 1

    gas_saved = sum(f.gas_estimate for f in findings)
    eth_price = _fetch_eth_price()
    result.append("### Summary")
    result.append(f"- High: {sev_count['high']} | Medium: {sev_count['medium']} | Low: {sev_count['low']} | Info: {sev_count['info']}")
    result.append(f"- **Estimated savings (rule-of-thumb):** ~{gas_saved} gas")
    if eth_price:
        gas_price_gwei = float(os.environ.get("GAS_PRICE_GWEI", str(DEFAULT_GAS_PRICE_GWEI)))
        usd_saved = gas_saved * gas_price_gwei * 1e-9 * eth_price
        result.append(f"- USD view: ~${usd_saved:.2f} at {gas_price_gwei:g} gwei / ${eth_price:.0f}/ETH (override GAS_PRICE_GWEI)")
    result.append("")

    result.append("### Recommendations")
    for s in ["high", "medium", "low", "info"]:
        items = [f for f in findings if f.severity == s]
        if not items:
            continue
        label = {"high": "🔴 High", "medium": "🟡 Medium", "low": "🟢 Low", "info": "🔵 Info"}[s]
        result.append(f"**{label}**")
        for it in items[:10]:
            result.append(f"- Line {it.line}: {it.pattern}")
            result.append(f"  `{it.code}`")
        if len(items) > 10:
            result.append(f"  _...and {len(items) - 10} more_")
        result.append("")

    return "\n".join(result)


def estimate_gas_savings(code: str, gas_price_gwei: Optional[float] = None,
                         eth_price: Optional[float] = None) -> dict:
    """Savings estimate derived from the SAME structured findings as the
    report text (M29 remediation) - the two numbers can no longer diverge."""
    findings = _find_gas_issues(code)
    gas_saved = sum(f.gas_estimate for f in findings)

    if gas_price_gwei is None:
        gas_price_gwei = float(os.environ.get("GAS_PRICE_GWEI", str(DEFAULT_GAS_PRICE_GWEI)))
    if eth_price is None:
        eth_price = _fetch_eth_price() or 0.0

    eth_saved = gas_saved * gas_price_gwei * 1e-9
    usd_saved = eth_saved * eth_price if eth_price else 0.0
    return {
        "gas_saved": gas_saved,
        "eth_saved": round(eth_saved, 6),
        "usd_saved": round(usd_saved, 2),
        "eth_price": eth_price or 0.0,
        "gas_price_gwei": gas_price_gwei,
    }
