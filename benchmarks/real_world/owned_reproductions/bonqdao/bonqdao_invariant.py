"""Narrow invariant for the owned BonqDAO dispute-window reproduction."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class BonqInvariantResult:
    status: str
    reason: str
    evidence_lines: tuple[int, ...]


def _price_function(source: str) -> str:
    match = re.search(r"function\s+price\s*\([^)]*\)[^{]*\{(?P<body>.*?)\n\s*\}", source, re.DOTALL)
    return match.group("body") if match else ""


def evaluate(source_path: str | Path) -> BonqInvariantResult:
    path = Path(source_path)
    source = path.read_text(encoding="utf-8")
    price_body = _price_function(source)
    has_fresh_value = bool(re.search(r"oracle\s*\.\s*getCurrentValue\s*\(", price_body))
    has_dispute_cutoff = bool(
        re.search(
            r"oracle\s*\.\s*getDataBefore\s*\(.*?block\.timestamp\s*-\s*[^)]*DISPUTE_WINDOW",
            price_body,
            re.DOTALL,
        )
    )
    evidence_lines = tuple(
        index
        for index, line in enumerate(source.splitlines(), start=1)
        if "getCurrentValue" in line or "getDataBefore" in line or "DISPUTE_WINDOW" in line
    )
    if has_dispute_cutoff:
        return BonqInvariantResult(
            status="Satisfied",
            reason="The price consumer queries a report before the explicit dispute-window cutoff.",
            evidence_lines=evidence_lines,
        )
    if has_fresh_value:
        return BonqInvariantResult(
            status="Violated",
            reason="The price consumer returns the latest oracle report without enforcing a dispute window.",
            evidence_lines=evidence_lines,
        )
    return BonqInvariantResult(
        status="Inconclusive",
        reason="Owned fixture does not contain a recognizable Bonq price-consumer contrast.",
        evidence_lines=evidence_lines,
    )
