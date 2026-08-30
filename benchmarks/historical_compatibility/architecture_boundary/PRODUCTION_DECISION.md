# Production Architecture Decision

## Decision: Adopt at proposal level, Stage 1 gated

The Production Architecture Proposal is **Adopted at the proposal level**. This decision authorizes preparation for Stage 1 production implementation; it does **not** authorize a broad production migration or a change to the current analyzer path.

### Evidence gates

| Gate | Decision | Boundary |
|---|---|---|
| Gate 1 — imported-source semantic detection | Passed in isolated POC | One imported-source vulnerability path was traced through Canonical AST, finding attribution, provenance, and unchanged Comparator evidence. |
| Gate 2 — compiler-resolution policy | Passed in isolated POC | Deterministic policy, explicit conflicts, pragma filtering, no silent fallback, and now an explicit resolver→runner bridge with version equality checks. |
| Gate 3 — provenance/retention | Passed in isolated POC | Content-addressed artifacts, finding provenance, replay verification, and tamper detection are covered. Production artifact-store operations remain open. |

## Stage 1 entry conditions

Stage 1 production implementation must remain opt-in and must satisfy these conditions before activation:

1. Implement the real `CompilerResolver` against the production compiler/artifact registry rather than POC candidate placeholders.
2. Make the selected resolver candidate the only compiler input to the production compiler runner; retain an explicit invariant equivalent to `compiled.compiler_version == resolved.selected.version`.
3. Persist production provenance and raw AST through the approved artifact boundary with an operational retention policy and failure visibility.
4. Select exactly one detector for the first production contract migration and define its complete `DetectorInput` contract.
5. Run legacy and Canonical paths in shadow mode before changing user-visible findings.
6. Preserve Primary benchmark metrics and Real-World quarantine status; do not introduce Case #4 as part of migration.
7. Define rollback and feature-flag behavior before enabling the new path.

## Explicit non-decisions

This decision does not approve:

- changes to `analyzers/` as part of this gate closure;
- changes to `verification/comparator.py`;
- historical Comparator aliases;
- arbitrary compiler fallback;
- re-adjudication of Parity, Nomad, or BonqDAO;
- removal of the legacy path;
- broad Canonical AST expansion without detector/evidence consumers.

## Current status

The compatibility work remains isolated. The next engineering stage is **Stage 1 production pilot design/implementation**, beginning with the compiler boundary and one detector in shadow mode. Production rollout remains separately gated.
