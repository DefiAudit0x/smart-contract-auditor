"""
Layer 0: External static analysis tools (Slither, Mythril) with graceful fallback.
Acts as a first layer before LLM — passes results as context to Agents.
"""
import json
import logging
import os
import re
import subprocess
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import List, Optional

logger = logging.getLogger(__name__)


@dataclass
class ExternalFinding:
    tool: str
    check: str
    severity: str
    description: str
    file: str = ""
    line: int = 0
    code_snippet: str = ""
    extra: dict = field(default_factory=dict)


def _check_tool(name: str) -> bool:
    try:
        r = subprocess.run([name, "--version"], capture_output=True, text=True, timeout=15)
        return r.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


# L-30: tool availability used to be probed once at import time, so
# analyzers installed after boot were never detected. Availability is now
# checked lazily with a small TTL cache (thread-safe).
_TOOL_TTL_SECONDS = 30.0
_tool_cache: dict = {}
_tool_cache_lock = threading.Lock()


def tool_available(tool: str, ttl: float = _TOOL_TTL_SECONDS) -> bool:
    """Deferred availability probe with a TTL cache."""
    now = time.monotonic()
    with _tool_cache_lock:
        cached = _tool_cache.get(tool)
        if cached is not None and (now - cached[0]) < ttl:
            return cached[1]
    ok = _check_tool(tool)
    with _tool_cache_lock:
        _tool_cache[tool] = (time.monotonic(), ok)
    return ok


# ─── Slither ───

def _run_slither_on_code(code: str, tmp_dir: str) -> List[ExternalFinding]:
    src_path = os.path.join(tmp_dir, "contract.sol")
    with open(src_path, "w", encoding="utf-8") as f:
        f.write(code)
    findings: List[ExternalFinding] = []
    try:
        r = subprocess.run(
            ["slither", src_path, "--json", "-"],
            capture_output=True, text=True, timeout=120,
        )
        if r.returncode != 0:
            logger.warning(f"Slither stderr: {r.stderr[:500]}")
        raw = r.stdout
        if raw.strip():
            data = json.loads(raw)
            for detector in data.get("results", {}).get("detectors", []):
                sev_map = {"high": "Critical", "medium": "High", "low": "Medium", "informational": "Info"}
                for ele in detector.get("elements", []):
                    # Per-element isolation (M15 remediation): one malformed
                    # element must not discard every finding of the run.
                    # `lines or [0]` also handles "lines": [] which the old
                    # .get("lines", [0]) default did not.
                    try:
                        lines = ele.get("source_mapping", {}).get("lines") or [0]
                        findings.append(ExternalFinding(
                            tool="slither",
                            check=detector.get("check", "unknown"),
                            severity=sev_map.get(detector.get("impact", "").lower(), "Medium"),
                            description=detector.get("description", ""),
                            file=ele.get("source_mapping", {}).get("filename_relative", ""),
                            line=lines[0],
                            code_snippet=str(ele.get("source_mapping", {}).get("content", ""))[:300],
                            extra={"id": detector.get("id", "")},
                        ))
                    except Exception:
                        logger.warning("Slither: skipped malformed element", exc_info=True)
                        continue
    except FileNotFoundError:
        logger.info("Slither not installed — skipping detectors")
    except json.JSONDecodeError:
        logger.warning("Slither: JSON parse failed")
    except subprocess.TimeoutExpired:
        logger.warning("Slither: timeout expired")
    except Exception as e:
        logger.warning(f"Slither: {e}")

    try:
        r2 = subprocess.run(
            ["slither", src_path, "--print", "human-summary"],
            capture_output=True, text=True, timeout=60,
        )
        if r2.stdout.strip():
            findings.append(ExternalFinding(
                tool="slither",
                check="human-summary",
                severity="Info",
                description=r2.stdout[:1000],
                file="",
                extra={"print": "human-summary"},
            ))
        r3 = subprocess.run(
            ["slither", src_path, "--print", "inheritance-graph"],
            capture_output=True, text=True, timeout=60,
        )
        if r3.stdout.strip():
            findings.append(ExternalFinding(
                tool="slither",
                check="inheritance-graph",
                severity="Info",
                description=r3.stdout[:800],
                file="",
                extra={"print": "inheritance-graph"},
            ))
    except Exception:
        pass

    return findings


# ─── Mythril ───

def _run_mythril_on_code(code: str, tmp_dir: str) -> List[ExternalFinding]:
    src_path = os.path.join(tmp_dir, "contract.sol")
    with open(src_path, "w", encoding="utf-8") as f:
        f.write(code)
    findings: List[ExternalFinding] = []
    try:
        r = subprocess.run(
            ["myth", "analyze", src_path, "-o", "json"],
            capture_output=True, text=True, timeout=180,
        )
        if r.returncode != 0 and r.returncode != 1:
            logger.warning(f"Mythril exit code: {r.returncode}")
        raw = r.stdout
        if not raw.strip():
            return findings
        # Mythril JSON may be an array or one line per issue
        try:
            data = json.loads(raw)
            items = data if isinstance(data, list) else data.get("issues", [])
        except json.JSONDecodeError:
            items = []
            for line in raw.strip().split("\n"):
                line = line.strip()
                if line:
                    try:
                        items.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass
        for issue in items:
            # Per-issue isolation (M15 remediation): a malformed Mythril
            # issue is skipped, the rest of the run survives.
            try:
                sev_map = {0: "Info", 1: "Low", 2: "Medium", 3: "High", 4: "Critical"}
                findings.append(ExternalFinding(
                    tool="mythril",
                    check=issue.get("title", issue.get("swc-id", "unknown")),
                    severity=sev_map.get(issue.get("severity", 1), "Medium"),
                    description=issue.get("description", issue.get("title", "")),
                    file=issue.get("filename", ""),
                    line=issue.get("lineno", 0) or 0,
                    code_snippet=issue.get("code", "")[:300],
                    extra={"swc_id": issue.get("swc-id", "")},
                ))
            except Exception:
                logger.warning("Mythril: skipped malformed issue", exc_info=True)
                continue
    except FileNotFoundError:
        logger.info("Mythril not installed — skipping")
    except subprocess.TimeoutExpired:
        logger.warning("Mythril: timeout expired")
    except Exception as e:
        logger.warning(f"Mythril: {e}")
    return findings


# ─── Public API ───
# L-30: TOOL_AVAILABLE (probed once at import) was replaced by the lazy
# tool_available() probe above — see run_external_analyzers.

def run_external_analyzers(code: str, tools: Optional[List[str]] = None) -> List[ExternalFinding]:
    """Run external analyzers and return a unified list of ExternalFinding."""
    if tools is None:
        tools = ["slither", "mythril"]
    # L-30: availability is re-checked at call time, and the independent
    # analyzer subprocesses run in parallel (slither + mythril used to run
    # sequentially for up to ~7 minutes). Each tool gets its own scratch
    # directory — both wrote contract.sol into the shared one.
    selected = [t for t in tools if t in ("slither", "mythril") and tool_available(t)]
    if not selected:
        return []
    findings: List[ExternalFinding] = []
    with tempfile.TemporaryDirectory(prefix="sca_ext_") as tmp_dir:
        tool_dirs = {t: os.path.join(tmp_dir, t) for t in selected}
        for d in tool_dirs.values():
            os.makedirs(d, exist_ok=True)
        runners = {"slither": _run_slither_on_code, "mythril": _run_mythril_on_code}
        with ThreadPoolExecutor(max_workers=len(selected)) as pool:
            futures = {t: pool.submit(runners[t], code, tool_dirs[t]) for t in selected}
            for t in selected:  # merge in the caller's tool order
                findings.extend(futures[t].result())
    return findings


def findings_to_text(findings: List[ExternalFinding], max_per_tool: int = 10) -> str:
    """Convert external findings to text that can be passed as context to the LLM."""
    lines = ["## External Analysis Findings (Layer 0)\n"]
    by_tool: dict = {}
    for f in findings:
        by_tool.setdefault(f.tool, []).append(f)
    for tool, items in by_tool.items():
        lines.append(f"### {tool.title()}")
        for f in items[:max_per_tool]:
            lines.append(f"- [{f.severity}] {f.check}: {f.description[:150]}")
            if f.line:
                lines.append(f"  - Line: {f.line}")
        if len(items) > max_per_tool:
            lines.append(f"  - ... and {len(items) - max_per_tool} more")
        lines.append("")
    return "\n".join(lines)
