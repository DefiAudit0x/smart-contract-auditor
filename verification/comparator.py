"""Deterministic finding comparator for static Solidity detector results.

The comparator deliberately uses source-level evidence only. It does not call an
LLM, access the network, or claim exploitability beyond the verified pattern.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable


class ComparisonStatus(str, Enum):
    CONFIRMED = "Confirmed"
    REJECTED = "Rejected"
    INCONCLUSIVE = "Inconclusive"


@dataclass(frozen=True)
class Hypothesis:
    detector: str
    severity: str
    category: str
    file: str
    function: str
    description: str


@dataclass(frozen=True)
class Evidence:
    kind: str
    location: str
    excerpt: str


@dataclass(frozen=True)
class Verification:
    supported: bool
    reason: str


@dataclass(frozen=True)
class ComparisonResult:
    hypothesis: Hypothesis
    verification: Verification
    evidence: tuple[Evidence, ...]
    status: ComparisonStatus
    reason: str


EvidenceMatcher = Callable[[str, str], list[Evidence]]


def _value(finding: Any, name: str, default: str = "") -> str:
    if isinstance(finding, dict):
        return str(finding.get(name, default) or default)
    return str(getattr(finding, name, default) or default)


def build_hypothesis(finding: Any) -> Hypothesis:
    """Convert an analyzer Finding or compatible mapping into a hypothesis."""
    return Hypothesis(
        detector=_value(finding, "agent_name"),
        severity=_value(finding, "severity"),
        category=_value(finding, "category"),
        file=_value(finding, "file"),
        function=_value(finding, "function_name"),
        description=_value(finding, "description"),
    )


def _function_span(source: str, function_name: str) -> tuple[str, int, int] | None:
    """Return a function signature/body span and its start/end offsets."""
    if not function_name:
        return source, 0, len(source)
    pattern = re.compile(
        rf"function\s+{re.escape(function_name)}\s*\([^)]*\)[^{{;]*\{{",
        re.IGNORECASE | re.DOTALL,
    )
    match = pattern.search(source)
    if not match:
        return None
    opening = source.find("{", match.start(), match.end())
    depth = 0
    for index in range(opening, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[match.start() : index + 1], match.start(), index + 1
    return None


def _line_number(source: str, offset: int) -> int:
    return source.count("\n", 0, offset) + 1


def _evidence(kind: str, source: str, offset: int, excerpt: str) -> list[Evidence]:
    line = _line_number(source, offset)
    return [Evidence(kind=kind, location=f"line {line}", excerpt=excerpt.strip()[:160])]


def _match_reentrancy(source: str, function_name: str) -> list[Evidence]:
    span = _function_span(source, function_name)
    if not span:
        return []
    text, start, _ = span
    if "nonReentrant" in text:
        return []
    match = re.search(r"\.call\s*\{[^}]*\}\s*\(", text, re.IGNORECASE)
    if not match:
        return []
    return _evidence("external_call_without_nonReentrant", source, start + match.start(), match.group())


def _match_delegatecall(source: str, function_name: str) -> list[Evidence]:
    span = _function_span(source, function_name)
    text, start, _ = span or (source, 0, len(source))
    match = re.search(r"\bdelegatecall\s*\(", text, re.IGNORECASE)
    if not match:
        return []
    return _evidence("delegatecall", source, start + match.start(), match.group())


def _match_selfdestruct(source: str, function_name: str) -> list[Evidence]:
    span = _function_span(source, function_name)
    text, start, _ = span or (source, 0, len(source))
    match = re.search(r"\bselfdestruct\s*\(", text, re.IGNORECASE)
    if not match:
        return []
    return _evidence("selfdestruct", source, start + match.start(), match.group())


def _match_public_mint(source: str, function_name: str) -> list[Evidence]:
    span = _function_span(source, "mint")
    if not span:
        return []
    text, start, _ = span
    signature = text.split("{", 1)[0]
    if not re.search(r"\b(public|external)\b", signature, re.IGNORECASE):
        return []
    if re.search(
        r"\bonlyOwner\b|msg\.sender\s*==\s*owner|owner\s*==\s*msg\.sender",
        text,
        re.IGNORECASE,
    ):
        return []
    return _evidence("unrestricted_mint_function", source, start, signature)


def _match_tx_origin(source: str, function_name: str) -> list[Evidence]:
    span = _function_span(source, function_name)
    text, start, _ = span or (source, 0, len(source))
    match = re.search(r"\btx\.origin\b", text, re.IGNORECASE)
    if not match:
        return []
    return _evidence("tx_origin", source, start + match.start(), match.group())


_MATCHERS: dict[str, EvidenceMatcher] = {
    "Reentrancy (AST)": _match_reentrancy,
    "DELEGATECALL Usage (AST)": _match_delegatecall,
    "Selfdestruct": _match_selfdestruct,
    "Public Mint/Burn": _match_public_mint,
    "tx.origin Auth (AST)": _match_tx_origin,
}


def collect_evidence(hypothesis: Hypothesis, source: str) -> list[Evidence]:
    """Collect deterministic source evidence for a known detector."""
    matcher = _MATCHERS.get(hypothesis.detector)
    if matcher is None:
        return []
    return matcher(source, hypothesis.function)


def verify_hypothesis(hypothesis: Hypothesis, source: str) -> Verification:
    """Verify whether the detector's primary source pattern is present."""
    if hypothesis.detector not in _MATCHERS:
        return Verification(False, "No deterministic evidence rule is registered for this detector")
    evidence = collect_evidence(hypothesis, source)
    if evidence:
        return Verification(True, "Registered source pattern is present")
    return Verification(True, "Registered source pattern is absent")


def compare_finding(finding: Any, source: str) -> ComparisonResult:
    """Run Hypothesis → Verification → Evidence → status classification."""
    hypothesis = build_hypothesis(finding)
    verification = verify_hypothesis(hypothesis, source)
    evidence = collect_evidence(hypothesis, source)

    if hypothesis.detector not in _MATCHERS:
        status = ComparisonStatus.INCONCLUSIVE
        reason = verification.reason
    elif evidence:
        status = ComparisonStatus.CONFIRMED
        reason = "The detector finding is supported by deterministic source evidence"
    else:
        status = ComparisonStatus.REJECTED
        reason = "The detector finding has no matching deterministic source evidence"

    return ComparisonResult(
        hypothesis=hypothesis,
        verification=verification,
        evidence=tuple(evidence),
        status=status,
        reason=reason,
    )


__all__ = [
    "ComparisonResult",
    "ComparisonStatus",
    "Evidence",
    "Hypothesis",
    "Verification",
    "build_hypothesis",
    "collect_evidence",
    "compare_finding",
    "verify_hypothesis",
]
