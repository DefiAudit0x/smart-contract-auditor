"""Narrow invariant for the owned Parity WalletLibrary reproduction."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class ParityInvariantResult:
    status: str
    reason: str
    evidence_lines: tuple[int, ...]


def evaluate(source_path: str | Path) -> ParityInvariantResult:
    path = Path(source_path)
    source = path.read_text(encoding="utf-8")
    has_public_initializer = bool(
        re.search(r"function\s+initWallet\s*\([^)]*\)[^{;]*\bexternal\b", source, re.IGNORECASE)
    )
    has_deployment_initialization = bool(
        re.search(r"constructor\s*\([^)]*\)[^{]*\{.*?initialized\s*=\s*true", source, re.IGNORECASE | re.DOTALL)
    )
    has_destructive_path = bool(
        re.search(r"function\s+kill\s*\([^)]*\)[^{]*\{.*?selfdestruct\s*\(", source, re.IGNORECASE | re.DOTALL)
    )
    has_disabled_kill = bool(
        re.search(r"function\s+kill\s*\([^)]*\)[^{]*\{.*?destruction\s+disabled", source, re.IGNORECASE | re.DOTALL)
    )
    evidence_lines = tuple(
        index
        for index, line in enumerate(source.splitlines(), start=1)
        if "initWallet" in line
        or "constructor" in line
        or "initialized" in line
        or "kill" in line
        or "selfdestruct" in line
    )
    if has_public_initializer and not has_deployment_initialization and has_destructive_path:
        return ParityInvariantResult(
            status="Violated",
            reason="An externally callable initializer can acquire ownership of an uninitialized shared library before invoking its destructive kill path.",
            evidence_lines=evidence_lines,
        )
    if has_deployment_initialization and has_disabled_kill and not has_destructive_path:
        return ParityInvariantResult(
            status="Satisfied",
            reason="Initialization is completed at deployment and the destructive library path is disabled.",
            evidence_lines=evidence_lines,
        )
    return ParityInvariantResult(
        status="Inconclusive",
        reason="Owned fixture does not match the expected Parity shared-library contrast.",
        evidence_lines=evidence_lines,
    )
