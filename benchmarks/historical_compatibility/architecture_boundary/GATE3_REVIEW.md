# Gate 3 Review — Provenance and Retention

## Decision

**Gate 3: Pass inside the isolated POC.** This is not production retention approval.

The existing POC evidence covers content-addressed source/raw-AST/Canonical-AST/analysis artifacts, finding-level provenance, failure provenance, replay verification, and tamper detection. The review therefore closes the POC gate while keeping production artifact-store operations and retention policy implementation outside this decision.

## Evidence reviewed

- `provenance_retention.py` persists source manifest, raw AST, Canonical AST, analysis payload, compiler provenance, and bundle identity.
- `verify_bundle()` verifies the persisted bundle and returns `ReplayVerified` or `ReplayVerificationFailed` rather than silently accepting tampered content.
- Existing gate tests cover source, raw AST, Canonical AST, analysis payload, compiler metadata, adapter identity, and finding-provenance tampering.
- Failure provenance is represented for `CompilationFailed`, `ASTUnavailable`, `UnsupportedCompiler`, `UnsupportedASTVersion`, `ASTNormalizationFailed`, and `Inconclusive`.
- Imported-source Gate 1 evidence preserves `source_id = Lib.sol`, source range, canonical expression identity, and unchanged Comparator evidence.

## Required production caveats

The POC does not prove a production artifact store, deletion scheduler, legal/compliance retention policy, external compiler attestation, or cross-process recovery from an unavailable artifact backend. Those remain Stage 1 production design/operations gates.

## Acceptance interpretation

A replay-verifiable POC bundle is sufficient to establish the architectural contract:

> finding/status → source manifest → compiler/raw-AST artifact → canonical artifact → analysis payload

with content hashes and explicit verification state.

It is not sufficient to claim that production retention is already implemented.

## Track preservation

No production analyzer or Comparator migration is part of this review. Primary benchmark metrics remain independent, and Nomad, BonqDAO, and Parity remain Quarantined with no Case #4.
