"""Isolated compiler-resolution policy for Gate 2.

This module is a validation harness, not the production compiler resolver. It
makes candidate selection and rejection reasons explicit without changing the
existing analyzer or compiler runner.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Iterable


_VERSION_RE = re.compile(r"(?<!\d)(\d+)\.(\d+)(?:\.(\d+))?(?!\d)")
_PRAGMA_RE = re.compile(r"pragma\s+solidity\s+([^;]+);", re.IGNORECASE)


class ResolutionStatus(str, Enum):
    RESOLVED = "Resolved"
    AMBIGUOUS_CANDIDATES = "AmbiguousCandidates"
    PRAGMA_CONFLICT = "PragmaConflict"
    NO_PRAGMA_POLICY = "NoPragmaPolicy"
    UNSUPPORTED_COMPILER = "UnsupportedCompiler"
    VERSION_CONFLICT = "VersionConflict"


@dataclass(frozen=True, order=True)
class SemanticVersion:
    major: int
    minor: int
    patch: int = 0

    @classmethod
    def parse(cls, value: str) -> "SemanticVersion":
        match = _VERSION_RE.search(value)
        if not match:
            raise ValueError(f"Unsupported compiler version syntax: {value}")
        return cls(int(match.group(1)), int(match.group(2)), int(match.group(3) or 0))

    def __str__(self) -> str:
        return f"{self.major}.{self.minor}.{self.patch}"


@dataclass(frozen=True)
class CompilerCandidate:
    version: str
    binary_path: str
    available: bool
    binary_hash: str = ""
    build: str = ""
    support_status: str = "registered"

    def normalized_version(self) -> SemanticVersion:
        return SemanticVersion.parse(self.version)


@dataclass(frozen=True)
class CompilerResolutionRequest:
    sources: dict[str, str]
    entry_source_id: str
    explicit_version: str = ""
    verified_version: str = ""
    allow_highest_compatible: bool = False
    policy_version: str = "gate2-policy-v1"

    @property
    def source_set_sha256(self) -> str:
        payload = json.dumps(
            {key: self.sources[key] for key in sorted(self.sources)},
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return hashlib.sha256(payload).hexdigest()


@dataclass(frozen=True)
class CompilerResolutionResult:
    status: ResolutionStatus
    selected: CompilerCandidate | None
    candidates_considered: tuple[str, ...]
    compatible_candidates: tuple[str, ...]
    constraints_by_source: dict[str, tuple[str, ...]]
    diagnostics: tuple[str, ...] = ()
    selection_reason: str = ""
    request_source_set_sha256: str = ""
    policy_version: str = "gate2-policy-v1"

    def to_dict(self) -> dict[str, object]:
        return {
            "status": self.status.value,
            "selected": asdict(self.selected) if self.selected else None,
            "candidates_considered": list(self.candidates_considered),
            "compatible_candidates": list(self.compatible_candidates),
            "constraints_by_source": {
                key: list(value) for key, value in self.constraints_by_source.items()
            },
            "diagnostics": list(self.diagnostics),
            "selection_reason": self.selection_reason,
            "request_source_set_sha256": self.request_source_set_sha256,
            "policy_version": self.policy_version,
        }


def extract_pragma_constraints(sources: dict[str, str]) -> dict[str, tuple[str, ...]]:
    return {
        source_id: tuple(match.strip() for match in _PRAGMA_RE.findall(source))
        for source_id, source in sorted(sources.items())
    }


def _caret_upper_bound(version: SemanticVersion) -> SemanticVersion:
    if version.major > 0:
        return SemanticVersion(version.major + 1, 0, 0)
    if version.minor > 0:
        return SemanticVersion(0, version.minor + 1, 0)
    return SemanticVersion(0, 0, version.patch + 1)


def _constraint_matches(version: SemanticVersion, expression: str) -> bool:
    expression = expression.strip()
    if not expression:
        return True

    # Solidity permits OR alternatives. A candidate satisfies the expression
    # if it satisfies one complete alternative.
    alternatives = [item.strip() for item in expression.split("||")]
    for alternative in alternatives:
        tokens = alternative.replace(",", " ").split()
        if not tokens:
            return True
        if all(_token_matches(version, token) for token in tokens):
            return True
    return False


def _token_matches(version: SemanticVersion, token: str) -> bool:
    token = token.strip()
    if token in {"*", "x", "X"}:
        return True
    if token.startswith("^"):
        lower = SemanticVersion.parse(token[1:])
        return lower <= version < _caret_upper_bound(lower)
    if token.startswith(">="):
        return version >= SemanticVersion.parse(token[2:])
    if token.startswith(">"): 
        return version > SemanticVersion.parse(token[1:])
    if token.startswith("<="):
        return version <= SemanticVersion.parse(token[2:])
    if token.startswith("<"):
        return version < SemanticVersion.parse(token[1:])
    if token.startswith("="):
        return version == SemanticVersion.parse(token[1:])
    if re.fullmatch(r"\d+\.\d+\.(?:x|X|\*)", token):
        major, minor, _ = token.split(".")
        return version.major == int(major) and version.minor == int(minor)
    if re.fullmatch(r"\d+\.x", token, re.IGNORECASE):
        major = int(token.split(".")[0])
        return version.major == major
    return version == SemanticVersion.parse(token)


def _candidate_satisfies(candidate: CompilerCandidate, constraints: Iterable[str]) -> bool:
    version = candidate.normalized_version()
    return all(_constraint_matches(version, constraint) for constraint in constraints)


def _find_version(candidates: list[CompilerCandidate], requested: str) -> CompilerCandidate | None:
    requested_version = SemanticVersion.parse(requested)
    return next(
        (candidate for candidate in candidates if candidate.normalized_version() == requested_version),
        None,
    )


def resolve_compiler(
    request: CompilerResolutionRequest,
    candidates: Iterable[CompilerCandidate],
) -> CompilerResolutionResult:
    """Resolve a compiler without guessing or silently falling back.

    Explicit and verified versions have priority. Without either, a single
    compatible available candidate is accepted. Multiple candidates are
    rejected unless the caller explicitly opts into the deterministic
    highest-compatible policy.
    """
    candidate_list = sorted(list(candidates), key=lambda item: item.normalized_version())
    constraints_by_source = extract_pragma_constraints(request.sources)
    constraints = [constraint for values in constraints_by_source.values() for constraint in values]
    considered = tuple(candidate.version for candidate in candidate_list)
    available = [candidate for candidate in candidate_list if candidate.available]

    def result(
        status: ResolutionStatus,
        selected: CompilerCandidate | None,
        compatible: Iterable[str],
        diagnostics: Iterable[str],
        reason: str,
    ) -> CompilerResolutionResult:
        return CompilerResolutionResult(
            status=status,
            selected=selected,
            candidates_considered=considered,
            compatible_candidates=tuple(compatible),
            constraints_by_source=constraints_by_source,
            diagnostics=tuple(diagnostics),
            selection_reason=reason,
            request_source_set_sha256=request.source_set_sha256,
            policy_version=request.policy_version,
        )

    if request.explicit_version and request.verified_version:
        explicit = SemanticVersion.parse(request.explicit_version)
        verified = SemanticVersion.parse(request.verified_version)
        if explicit != verified:
            return result(
                ResolutionStatus.VERSION_CONFLICT,
                None,
                (),
                (
                    f"Explicit compiler {request.explicit_version} conflicts with "
                    f"verified compiler {request.verified_version}; no precedence is applied",
                ),
                "explicit-verified-conflict",
            )

    requested_version = request.explicit_version or request.verified_version
    if requested_version:
        candidate = _find_version(candidate_list, requested_version)
        if candidate is None or not candidate.available:
            return result(
                ResolutionStatus.UNSUPPORTED_COMPILER,
                None,
                (),
                (f"Requested compiler {requested_version} is not available in the registered candidate set",),
                "explicit-or-verified-version-unavailable",
            )
        if constraints and not _candidate_satisfies(candidate, constraints):
            return result(
                ResolutionStatus.PRAGMA_CONFLICT,
                None,
                (),
                (f"Requested compiler {candidate.version} violates at least one source pragma",),
                "explicit-or-verified-version-rejected-by-pragma",
            )
        return result(
            ResolutionStatus.RESOLVED,
            candidate,
            (candidate.version,),
            (),
            (
                "explicit-and-verified-agree"
                if request.explicit_version and request.verified_version
                else "verified-version"
                if request.verified_version
                else "explicit-version"
            ),
        )

    if not constraints:
        return result(
            ResolutionStatus.NO_PRAGMA_POLICY,
            None,
            (),
            ("No explicit/verified compiler and no Solidity pragma constraints were provided",),
            "no-pragma-requires-explicit-configuration",
        )

    compatible = [
        candidate
        for candidate in available
        if _candidate_satisfies(candidate, constraints)
    ]
    compatible_versions = tuple(candidate.version for candidate in compatible)
    if not compatible:
        return result(
            ResolutionStatus.PRAGMA_CONFLICT,
            None,
            (),
            ("No available compiler candidate satisfies every source pragma",),
            "no-compatible-candidate",
        )
    if len(compatible) == 1:
        return result(
            ResolutionStatus.RESOLVED,
            compatible[0],
            compatible_versions,
            (),
            "single-compatible-candidate",
        )
    if request.allow_highest_compatible:
        selected = compatible[-1]
        return result(
            ResolutionStatus.RESOLVED,
            selected,
            compatible_versions,
            ("Multiple compatible candidates resolved by explicit highest-compatible policy",),
            "highest-compatible-explicit-policy",
        )
    return result(
        ResolutionStatus.AMBIGUOUS_CANDIDATES,
        None,
        compatible_versions,
        ("Multiple compatible candidates exist; no implicit compiler guess is allowed",),
        "multiple-compatible-candidates-require-explicit-policy",
    )
