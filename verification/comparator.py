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


def _mask_non_code(source: str) -> str:
    """Mask comments and string literals while preserving source offsets."""
    pattern = re.compile(
        r"//[^\n]*|/\*.*?\*/|\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'",
        re.DOTALL,
    )

    def mask(match: re.Match[str]) -> str:
        return "".join("\n" if char == "\n" else " " for char in match.group(0))

    return pattern.sub(mask, source)


def _function_span(source: str, function_name: str) -> tuple[str, int, int] | None:
    """Return a masked function signature/body span and its original offsets."""
    spans = _function_spans(source, function_name)
    return spans[0] if spans else None


def _function_spans(source: str, function_name: str) -> list[tuple[str, int, int]]:
    """Masked spans of EVERY function with this name (M24 remediation):
    the previous first-match-only search gathered the second withdraw()'s
    evidence from the first occurrence."""
    code = _mask_non_code(source)
    if not function_name:
        return [(code, 0, len(code))]
    pattern = re.compile(
        rf"function\s+{re.escape(function_name)}\s*\([^)]*\)[^{{;]*\{{",
        re.IGNORECASE | re.DOTALL,
    )
    spans = []
    for match in pattern.finditer(code):
        opening = code.find("{", match.start(), match.end())
        if opening < 0:
            continue
        depth = 0
        for index in range(opening, len(code)):
            if code[index] == "{":
                depth += 1
            elif code[index] == "}":
                depth -= 1
                if depth == 0:
                    spans.append((code[match.start() : index + 1], match.start(), index + 1))
                    break
    return spans


def _iter_spans(source: str, function_name: str) -> list[tuple[str, int, int]]:
    """Candidate scopes for a matcher. A named function that cannot be
    located yields NO scope at all (M24 remediation): silently falling back
    to the whole file made a delegatecall in an unrelated contract of the
    same file 'confirm' a finding about a function that does not exist."""
    if function_name:
        return _function_spans(source, function_name)
    code = _mask_non_code(source)
    return [(code, 0, len(code))]


def _line_number(source: str, offset: int) -> int:
    return source.count("\n", 0, offset) + 1


def _evidence(kind: str, source: str, offset: int, excerpt: str) -> list[Evidence]:
    line = _line_number(source, offset)
    return [Evidence(kind=kind, location=f"line {line}", excerpt=excerpt.strip()[:160])]


def _match_reentrancy(source: str, function_name: str) -> list[Evidence]:
    evidence = []
    for text, start, _ in _iter_spans(source, function_name):
        if "nonReentrant" in text:
            continue
        # All external-value-call forms count as reentrancy surface (M24
        # remediation): transfer/send-based findings used to be rejected
        # for lack of deterministic evidence.
        for match in re.finditer(
            r"\.(?:call\s*\{[^}]*\}\s*\(|call\s*\(|transfer\s*\(|send\s*\()",
            text,
            re.IGNORECASE,
        ):
            evidence.extend(_evidence(
                "external_call_without_nonReentrant", source, start + match.start(), match.group()
            ))
    return evidence


def _match_delegatecall(source: str, function_name: str) -> list[Evidence]:
    evidence = []
    for text, start, _ in _iter_spans(source, function_name):
        for match in re.finditer(r"\bdelegatecall\s*\(", text, re.IGNORECASE):
            evidence.extend(_evidence("delegatecall", source, start + match.start(), match.group()))
    return evidence


def _match_selfdestruct(source: str, function_name: str) -> list[Evidence]:
    evidence = []
    for text, start, _ in _iter_spans(source, function_name):
        for match in re.finditer(r"\bselfdestruct\s*\(", text, re.IGNORECASE):
            evidence.extend(_evidence("selfdestruct", source, start + match.start(), match.group()))
    return evidence


def _match_public_mint(source: str, function_name: str) -> list[Evidence]:
    evidence = []
    for text, start, _ in _iter_spans(source, "mint"):
        signature = text.split("{", 1)[0]
        if not re.search(r"\b(public|external)\b", signature, re.IGNORECASE):
            continue
        if re.search(
            r"\bonlyOwner\b|msg\.sender\s*==\s*owner|owner\s*==\s*msg\.sender",
            text,
            re.IGNORECASE,
        ):
            continue
        evidence.extend(_evidence("unrestricted_mint_function", source, start, signature))
    return evidence


def _match_tx_origin(source: str, function_name: str) -> list[Evidence]:
    evidence = []
    for text, start, _ in _iter_spans(source, function_name):
        for match in re.finditer(r"\btx\.origin\b", text, re.IGNORECASE):
            evidence.extend(_evidence("tx_origin", source, start + match.start(), match.group()))
    return evidence


def _match_flash_loan(source: str, function_name: str) -> list[Evidence]:
    evidence = []
    for name in ("flashLoan", "flash_loan"):
        for text, start, _ in _iter_spans(source, name):
            if "nonReentrant" in text:
                continue
            for match in re.finditer(r"function\s+flash[_]?Loan\b", text, re.IGNORECASE):
                evidence.extend(_evidence("unguarded_flash_loan", source, start + match.start(), match.group()))
    return evidence


def _match_storage_collision(source: str, function_name: str) -> list[Evidence]:
    code = _mask_non_code(source)
    delegate = re.search(r"\bdelegatecall\s*\(", code, re.IGNORECASE)
    layout = re.search(r"\bstruct\b|\bmapping\s*\(", code, re.IGNORECASE)
    if not delegate or not layout:
        return []
    return _evidence("delegatecall_storage_layout", source, delegate.start(), delegate.group())


def _match_unchecked_transfer(source: str, function_name: str) -> list[Evidence]:
    evidence = []
    for text, start, _ in _iter_spans(source, function_name):
        for match in re.finditer(r"\.(?:send|transfer)\s*\(", text, re.IGNORECASE):
            evidence.extend(_evidence("unchecked_transfer", source, start + match.start(), match.group()))
    return evidence


def _match_unbounded_loop(source: str, function_name: str) -> list[Evidence]:
    evidence = []
    for text, start, _ in _iter_spans(source, function_name):
        for match in re.finditer(r"\bfor\s*\(", text, re.IGNORECASE):
            evidence.extend(_evidence("unbounded_loop", source, start + match.start(), match.group()))
    return evidence


def _match_block_timestamp(source: str, function_name: str) -> list[Evidence]:
    evidence = []
    for text, start, _ in _iter_spans(source, function_name):
        for match in re.finditer(r"\bblock\.timestamp\b", text, re.IGNORECASE):
            evidence.extend(_evidence("block_timestamp", source, start + match.start(), match.group()))
    return evidence


_MATCHERS: dict[str, EvidenceMatcher] = {
    "Reentrancy (AST)": _match_reentrancy,
    "DELEGATECALL Usage (AST)": _match_delegatecall,
    "Selfdestruct": _match_selfdestruct,
    "Public Mint/Burn": _match_public_mint,
    "tx.origin Auth (AST)": _match_tx_origin,
    "Flash Loan Attack Vector": _match_flash_loan,
    "Storage Collision (Delegatecall)": _match_storage_collision,
    "Unchecked Transfer": _match_unchecked_transfer,
    "Unbounded Loop (AST)": _match_unbounded_loop,
    "block.timestamp Usage (AST)": _match_block_timestamp,
}


def collect_evidence(hypothesis: Hypothesis, source: str) -> list[Evidence]:
    """Collect deterministic source evidence for a known detector."""
    matcher = _MATCHERS.get(hypothesis.detector)
    if matcher is None:
        return []
    return matcher(source, hypothesis.function)


def verify_hypothesis(hypothesis: Hypothesis, source: str) -> Verification:
    """Verify whether the detector's primary source pattern is present.

    supported honestly reflects the evidence (M24 remediation): it used to
    be True both with and without evidence, making the field meaningless
    to every consumer. A named function that cannot be located is reported
    as inconclusive instead of silently scanning the whole file.
    """
    if hypothesis.detector not in _MATCHERS:
        return Verification(False, "No deterministic evidence rule is registered for this detector")
    if hypothesis.function and not _function_spans(source, hypothesis.function):
        return Verification(
            False,
            "Function scope could not be located - verification is inconclusive (no whole-file fallback)",
        )
    evidence = collect_evidence(hypothesis, source)
    if evidence:
        return Verification(True, "Registered source pattern is present")
    return Verification(False, "Registered source pattern is absent")


def compare_finding(finding: Any, source: str) -> ComparisonResult:
    """Run Hypothesis → Verification → Evidence → status classification."""
    hypothesis = build_hypothesis(finding)
    verification = verify_hypothesis(hypothesis, source)
    evidence = collect_evidence(hypothesis, source)

    if hypothesis.detector not in _MATCHERS:
        status = ComparisonStatus.INCONCLUSIVE
        reason = verification.reason
    elif hypothesis.function and not _function_spans(source, hypothesis.function):
        # Scope failure is NOT a rejection: the function may live in
        # another file or the name may be malformed (M24 remediation).
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
