"""Narrow invariant for the owned Nomad zero-root reproduction."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class NomadInvariantResult:
    status: str
    reason: str
    evidence_lines: tuple[int, ...]


def evaluate(source_path: str | Path) -> NomadInvariantResult:
    path = Path(source_path)
    source = path.read_text(encoding="utf-8")
    has_zero_root_initialization = bool(
        re.search(r"confirmAt\s*\[\s*committedRoot\s*\]\s*=\s*1", source)
    )
    has_zero_root_rejection = bool(
        re.search(r"require\s*\(\s*committedRoot\s*!=\s*bytes32\s*\(\s*0\s*\)\s*,", source)
    )
    lines = tuple(
        index
        for index, line in enumerate(source.splitlines(), start=1)
        if "confirmAt[committedRoot]" in line or "committedRoot != bytes32(0)" in line
    )
    if has_zero_root_rejection:
        return NomadInvariantResult(
            status="Satisfied",
            reason="Initialization rejects a zero committed root before pre-approval can authorize it.",
            evidence_lines=lines,
        )
    if has_zero_root_initialization:
        return NomadInvariantResult(
            status="Violated",
            reason="Initialization pre-approves a zero committed root without rejecting zero-root state.",
            evidence_lines=lines,
        )
    return NomadInvariantResult(
        status="Inconclusive",
        reason="Owned fixture does not match the expected Nomad zero-root contrast.",
        evidence_lines=lines,
    )
