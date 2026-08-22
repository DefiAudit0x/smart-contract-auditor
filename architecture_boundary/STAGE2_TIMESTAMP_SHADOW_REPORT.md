# Stage 2 — `block.timestamp` Shadow Compatibility Gate Report

## Decision status

**Pending CI and independent review.** This artifact is isolated compatibility evidence only. It does not authorize production detector migration.

## Scope

The gate exercises the existing `block.timestamp Usage (AST)` detector as a control path and the Canonical-AST timestamp projection as a shadow path. It covers Solidity 0.8.25 `block.timestamp`, Solidity 0.4.10 `now`, fixed controls, context-safe negative controls, imported-source attribution, explicit failure semantics, provenance, and the unchanged Comparator boundary.

No production detector migration is included. `analyzers/` and `verification/comparator.py` are intentionally untouched by the Stage 2 implementation. Primary benchmark and Real-World adjudications are outside the gate.

## Required evidence

1. Modern vulnerable: production and Canonical paths each produce one timestamp finding for `readTime`; the existing Comparator confirms the modern source spelling.
2. Modern fixed: both paths produce zero findings.
3. Historical vulnerable: the Canonical path recognizes `now` semantically; the production result remains observational only; the existing Comparator is invoked without an alias and its historical rejection is preserved.
4. Historical fixed: Canonical path remains clean.
5. Negative controls: identifiers, strings, comments, unrelated member accesses, nested/non-primitive contexts, and malformed/unknown AST shapes remain clean or fail explicitly.
6. Imported source: the timestamp exists only in `Lib.sol`; the Canonical finding is attributed to `Lib.sol`, with source range and canonical expression ID, while `Main.sol` remains clean. Existing Comparator behavior is preserved.
7. Failure safety: invalid normalization yields an explicit failure status and no detector/Comparator invocation.
8. Provenance: shadow findings retain source manifest/hash, compiler identity, raw-AST hash, adapter identity, Canonical AST identity, detector identity, Comparator identity, source range, and canonical expression ID through the existing POC bridge.
9. Track preservation: no production analyzer/Comparator changes, no Primary metric change, no Real-World adjudication change, and no Case #4.

## Implementation

`benchmarks/historical_compatibility/stage2_timestamp_shadow.py` is the reproducible runner. It writes `benchmarks/historical_compatibility/canonical_ast_poc/metadata/stage2_timestamp_shadow_results.json` during execution. `tests/test_stage2_timestamp_shadow.py` executes the runner and validates the result matrix and machine-readable artifact.

The imported-source fixtures are `imported_timestamp_main_0_8_25.sol` and `imported_timestamp_lib_0_8_25.sol`. The entry source imports `Lib.sol`, and the vulnerable expression exists only in the imported library.

## Comparator boundary

The Comparator is not modified. Modern `block.timestamp` evidence is expected to remain confirmable. Historical `now` is semantic detector evidence but remains subject to the current source-vocabulary matcher; a rejection is recorded as divergence evidence rather than converted into a detector failure or repaired with an alias.

## CI note

The repository's separate external Smart Contract Audit workflow previously failed because the configured `AUDITOR_API_KEY` is empty and its multiline shell loop was unsafe. The workflow was hardened to handle multiline filenames and to skip the optional external audit cleanly when the credential is absent. This is CI infrastructure only and does not alter analyzer, Comparator, benchmark, or compatibility semantics.

## Exit rule

Stage 2 should be marked **Passed** only after the focused tests and full CI pass and an independent review verifies the machine-readable artifact. A pass permits the next isolated compatibility gate; it does not authorize production migration.
