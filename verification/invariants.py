"""Deterministic source-level security invariants for Solidity fixtures.

These invariants are narrow regression checks. A violated invariant indicates a
source pattern that requires review; it is not by itself proof of exploitability.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from typing import Callable

from verification.comparator import Evidence


class InvariantStatus(str, Enum):
    SATISFIED = "Satisfied"
    VIOLATED = "Violated"
    INCONCLUSIVE = "Inconclusive"


@dataclass(frozen=True)
class InvariantSpec:
    invariant_id: str
    description: str
    check: Callable[[str], tuple[InvariantStatus, str, tuple[Evidence, ...]]]


@dataclass(frozen=True)
class InvariantResult:
    invariant_id: str
    description: str
    status: InvariantStatus
    reason: str
    evidence: tuple[Evidence, ...]


def _strip_comments(source: str) -> str:
    def mask(match: re.Match[str]) -> str:
        return "".join("\n" if char == "\n" else " " for char in match.group(0))

    source = re.sub(r"//[^\n]*|/\*.*?\*/", mask, source, flags=re.DOTALL)
    return source


def _line_number(source: str, offset: int) -> int:
    return source.count("\n", 0, offset) + 1


def _evidence(kind: str, source: str, offset: int, excerpt: str) -> tuple[Evidence, ...]:
    return (
        Evidence(
            kind=kind,
            location=f"line {_line_number(source, offset)}",
            excerpt=excerpt.strip()[:160],
        ),
    )


def _function_spans(source: str) -> list[tuple[str, str, int]]:
    """Extract balanced function bodies with their source offsets."""
    spans: list[tuple[str, str, int]] = []
    pattern = re.compile(
        r"function\s+(\w+)\s*\([^)]*\)[^{;]*\{",
        re.IGNORECASE | re.DOTALL,
    )
    for match in pattern.finditer(source):
        opening = source.find("{", match.start(), match.end())
        depth = 0
        for index in range(opening, len(source)):
            if source[index] == "{":
                depth += 1
            elif source[index] == "}":
                depth -= 1
                if depth == 0:
                    spans.append((match.group(1), source[match.start() : index + 1], match.start()))
                    break
    return spans


def _inconclusive_if_invalid(source: str) -> tuple[InvariantStatus, str, tuple[Evidence, ...]] | None:
    if not source.strip() or not re.search(r"\bcontract\s+\w+", source):
        return InvariantStatus.INCONCLUSIVE, "Source does not contain a Solidity contract", ()
    return None


def _check_reentrancy_guarded(source: str) -> tuple[InvariantStatus, str, tuple[Evidence, ...]]:
    clean = _strip_comments(source)
    for name, body, start in _function_spans(clean):
        call = re.search(r"\.call\s*\{[^}]*\}\s*\(", body, re.IGNORECASE)
        if call and "nonReentrant" not in body:
            return (
                InvariantStatus.VIOLATED,
                f"Function {name} performs a value call without nonReentrant",
                _evidence("unguarded_external_call", source, start + call.start(), call.group()),
            )
    return InvariantStatus.SATISFIED, "Value-calling functions are guarded or absent", ()


def _check_no_delegatecall(source: str) -> tuple[InvariantStatus, str, tuple[Evidence, ...]]:
    clean = _strip_comments(source)
    match = re.search(r"\bdelegatecall\s*\(", clean, re.IGNORECASE)
    if match:
        return (
            InvariantStatus.VIOLATED,
            "Source contains delegatecall",
            _evidence("delegatecall", source, match.start(), match.group()),
        )
    return InvariantStatus.SATISFIED, "Source contains no delegatecall", ()


def _check_no_selfdestruct(source: str) -> tuple[InvariantStatus, str, tuple[Evidence, ...]]:
    clean = _strip_comments(source)
    match = re.search(r"\bselfdestruct\s*\(", clean, re.IGNORECASE)
    if match:
        return (
            InvariantStatus.VIOLATED,
            "Source contains selfdestruct",
            _evidence("selfdestruct", source, match.start(), match.group()),
        )
    return InvariantStatus.SATISFIED, "Source contains no selfdestruct", ()


def _check_authorized_mint(source: str) -> tuple[InvariantStatus, str, tuple[Evidence, ...]]:
    clean = _strip_comments(source)
    mint_functions = [item for item in _function_spans(clean) if item[0].lower() == "mint"]
    if not mint_functions:
        return InvariantStatus.SATISFIED, "No mint function is present", ()
    for name, body, start in mint_functions:
        signature = body.split("{", 1)[0]
        is_external = bool(re.search(r"\b(public|external)\b", signature, re.IGNORECASE))
        has_owner_guard = bool(
            re.search(
                r"\bonlyOwner\b|msg\.sender\s*==\s*owner|owner\s*==\s*msg\.sender",
                body,
                re.IGNORECASE,
            )
        )
        if is_external and not has_owner_guard:
            return (
                InvariantStatus.VIOLATED,
                f"Function {name} exposes mint without an owner guard",
                _evidence("unprotected_mint", source, start, signature),
            )
    return InvariantStatus.SATISFIED, "All exposed mint functions have an owner guard", ()


def _check_flash_loan_guarded(source: str) -> tuple[InvariantStatus, str, tuple[Evidence, ...]]:
    clean = _strip_comments(source)
    for name, body, start in _function_spans(clean):
        if re.search(r"flashLoan|flash_loan|flashloan", name, re.IGNORECASE):
            if "nonReentrant" not in body:
                match = re.search(r"function\s+\w+", clean[start:], re.IGNORECASE)
                offset = start + (match.start() if match else 0)
                return (
                    InvariantStatus.VIOLATED,
                    f"Function {name} exposes a flash-loan callback without a reentrancy guard",
                    _evidence("unguarded_flash_loan", source, offset, body[:160]),
                )
    return InvariantStatus.SATISFIED, "Flash-loan entry points are guarded or absent", ()


def _check_storage_collision_safe(source: str) -> tuple[InvariantStatus, str, tuple[Evidence, ...]]:
    clean = _strip_comments(source)
    delegate = re.search(r"\bdelegatecall\s*\(", clean, re.IGNORECASE)
    layout = re.search(r"\bstruct\b|\bmapping\s*\(", clean, re.IGNORECASE)
    if delegate and layout:
        return (
            InvariantStatus.VIOLATED,
            "Source combines delegatecall with structured storage layout",
            _evidence("delegatecall_storage_layout", source, delegate.start(), delegate.group()),
        )
    return InvariantStatus.SATISFIED, "No delegatecall storage collision pattern is present", ()


def _check_transfer_result_checked(source: str) -> tuple[InvariantStatus, str, tuple[Evidence, ...]]:
    clean = _strip_comments(source)
    match = re.search(r"\.(?:send|transfer)\s*\(", clean, re.IGNORECASE)
    if match:
        return (
            InvariantStatus.VIOLATED,
            "Source uses send/transfer without an explicit return-value check",
            _evidence("unchecked_transfer", source, match.start(), match.group()),
        )
    return InvariantStatus.SATISFIED, "No unchecked send/transfer call is present", ()


def _check_distribution_bounded(source: str) -> tuple[InvariantStatus, str, tuple[Evidence, ...]]:
    clean = _strip_comments(source)
    match = re.search(r"\bfor\s*\(", clean, re.IGNORECASE)
    if match:
        return (
            InvariantStatus.VIOLATED,
            "Source contains a loop without a benchmark-declared batch bound",
            _evidence("unbounded_loop", source, match.start(), match.group()),
        )
    return InvariantStatus.SATISFIED, "No unbounded distribution loop is present", ()


def _check_no_block_timestamp_gate(source: str) -> tuple[InvariantStatus, str, tuple[Evidence, ...]]:
    clean = _strip_comments(source)
    match = re.search(r"\bblock\.timestamp\b", clean, re.IGNORECASE)
    if match:
        return (
            InvariantStatus.VIOLATED,
            "Source uses block.timestamp in a timing-sensitive path",
            _evidence("block_timestamp", source, match.start(), match.group()),
        )
    return InvariantStatus.SATISFIED, "Source contains no block.timestamp gate", ()


def _check_no_tx_origin_auth(source: str) -> tuple[InvariantStatus, str, tuple[Evidence, ...]]:
    clean = _strip_comments(source)
    match = re.search(r"\btx\.origin\b", clean, re.IGNORECASE)
    if match:
        return (
            InvariantStatus.VIOLATED,
            "Source uses tx.origin for authentication or control flow",
            _evidence("tx_origin", source, match.start(), match.group()),
        )
    return InvariantStatus.SATISFIED, "Source contains no tx.origin", ()


INVARIANTS: tuple[InvariantSpec, ...] = (
    InvariantSpec(
        "reentrancy.external_calls_guarded",
        "Value-calling functions must use a reentrancy guard",
        _check_reentrancy_guarded,
    ),
    InvariantSpec(
        "no_untrusted_delegatecall",
        "Contracts must not use delegatecall without an explicit review",
        _check_no_delegatecall,
    ),
    InvariantSpec(
        "no_selfdestruct",
        "Contracts must not expose selfdestruct",
        _check_no_selfdestruct,
    ),
    InvariantSpec(
        "authorized_mint",
        "Exposed mint functions must enforce owner authorization",
        _check_authorized_mint,
    ),
    InvariantSpec(
        "no_tx_origin_auth",
        "Authentication must not rely on tx.origin",
        _check_no_tx_origin_auth,
    ),
    InvariantSpec(
        "flash_loan.callback_guarded",
        "Flash-loan entry points must guard callback-sensitive state",
        _check_flash_loan_guarded,
    ),
    InvariantSpec(
        "storage_collision.no_delegatecall_layout_risk",
        "Structured storage must not be combined with mutable delegatecall",
        _check_storage_collision_safe,
    ),
    InvariantSpec(
        "unchecked_transfer.return_value_checked",
        "External payment results must be checked",
        _check_transfer_result_checked,
    ),
    InvariantSpec(
        "dos.distribution_bounded",
        "Distribution loops must be bounded or batchable",
        _check_distribution_bounded,
    ),
    InvariantSpec(
        "timestamp.no_block_timestamp_gate",
        "Timing-sensitive gates must not rely on block.timestamp",
        _check_no_block_timestamp_gate,
    ),
)

INVARIANT_BY_ID = {spec.invariant_id: spec for spec in INVARIANTS}


def evaluate_invariants(source: str, invariant_ids: list[str] | None = None) -> list[InvariantResult]:
    """Evaluate selected invariants, or all registered invariants, in stable order."""
    invalid = _inconclusive_if_invalid(source)
    selected = invariant_ids or [spec.invariant_id for spec in INVARIANTS]
    results: list[InvariantResult] = []
    for invariant_id in selected:
        spec = INVARIANT_BY_ID.get(invariant_id)
        if spec is None:
            results.append(
                InvariantResult(
                    invariant_id=invariant_id,
                    description="Unknown invariant",
                    status=InvariantStatus.INCONCLUSIVE,
                    reason="No invariant with this id is registered",
                    evidence=(),
                )
            )
            continue
        if invalid:
            status, reason, evidence = invalid
        else:
            status, reason, evidence = spec.check(source)
        results.append(
            InvariantResult(
                invariant_id=spec.invariant_id,
                description=spec.description,
                status=status,
                reason=reason,
                evidence=evidence,
            )
        )
    return results


def summarize_invariants(results: list[InvariantResult]) -> dict[str, int]:
    """Return stable counts by invariant status."""
    return {
        status.value: sum(item.status is status for item in results)
        for status in InvariantStatus
    }


__all__ = [
    "INVARIANTS",
    "INVARIANT_BY_ID",
    "InvariantResult",
    "InvariantSpec",
    "InvariantStatus",
    "evaluate_invariants",
    "summarize_invariants",
]
