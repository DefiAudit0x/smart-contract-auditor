# Stage 2 — `block.timestamp` Shadow Compatibility Plan

## Decision status

This document defines the next isolated compatibility gate after Stage 1. It is a **planning artifact only**. It does not migrate production detectors, change `analyzers/`, change `verification/comparator.py`, alter Primary metrics, or re-adjudicate Real-World cases.

Stage 1 established the shadow-mode pattern with the Selfdestruct detector: production and Canonical-AST paths can run side by side, modern parity can be measured, historical divergence can remain visible, and fixed controls can remain clean. Stage 2 applies the same discipline to the AST-only `block.timestamp Usage (AST)` detector.

## Objective

Demonstrate, in isolation, that the Canonical AST path can provide the semantic contract required by the timestamp detector across modern and historical Solidity syntax without introducing detector-side compiler knowledge or changing Comparator policy.

The historical syntax under test is `now`; the modern syntax is `block.timestamp`.

## Scope

### Included

- Existing production `block.timestamp Usage (AST)` detector as the control path.
- Canonical-AST timestamp semantic projection as the shadow path.
- Solidity 0.8.25 modern fixture.
- Solidity 0.4.10 historical fixture using `now`.
- Fixed controls for both compiler eras.
- Identifier, string, comment, nested-expression, and wrong-context negative controls.
- Imported-source fixture where the timestamp usage exists only in an imported source unit.
- Explicit comparison artifact showing production result, canonical result, divergence, and evidence status.
- Provenance sufficient to trace a shadow finding to source unit, canonical expression, and source range.
- Existing Comparator invoked unchanged; historical Comparator rejection remains an observed boundary rather than a repair target.

### Explicitly excluded

- No production detector migration.
- No modification to `analyzers/`.
- No modification to `verification/comparator.py`.
- No compiler fallback or alias added to production.
- No change to Primary Benchmark metrics.
- No change to Nomad, BonqDAO, or Parity adjudications.
- No Case #4.
- No production CompilerResolver implementation.
- No production raw-AST retention change.

## Required acceptance gates

### Gate 2A — Semantic mapping safety

`now` and `block.timestamp` normalize to the same canonical timestamp semantic **only when they occur in the AST-native expression context represented by the adapter**.

The following must remain clean:

- variable/identifier named `now`;
- variable/identifier named `timestamp`;
- string literals containing `now` or `block.timestamp`;
- comments containing either spelling;
- unrelated member accesses containing `timestamp`;
- nested expressions whose context does not represent a timestamp primitive;
- malformed or unknown AST nodes.

No textual fallback is permitted in the shadow path.

### Gate 2B — Modern parity

For the modern fixture:

- production detector result is captured;
- canonical detector result is captured;
- both identify the same semantic vulnerability location;
- fixed control produces no finding on either path;
- Comparator remains `Confirmed` where the existing source matcher recognizes the modern spelling.

### Gate 2C — Historical divergence visibility

For the historical fixture:

- canonical path recognizes `now` semantically;
- production result is recorded without changing it;
- Comparator is invoked unchanged;
- any historical Comparator rejection is preserved as explicit evidence;
- the harness does not translate Comparator rejection into detector failure and does not add an alias.

### Gate 2D — Imported-source attribution

A multi-file fixture must place the vulnerable timestamp expression only in an imported source unit.

Acceptance requires:

- compilation succeeds using the isolated compatibility path;
- canonical detection identifies the imported source unit;
- `source_id` points to the imported file;
- source range and canonical expression ID are retained;
- the entry source remains clean when it contains no timestamp usage;
- Comparator evidence, if confirmed, points to the imported source location.

### Gate 2E — Failure semantics

The shadow harness must distinguish at minimum:

- compiler failure;
- unsupported AST format;
- normalization failure;
- inconclusive/unknown semantic state;
- successful analysis with no findings;
- successful analysis with findings.

A failed normalization must never become zero findings.

### Gate 2F — Provenance

Every shadow finding must carry enough provenance to reproduce its interpretation:

- source manifest/hash;
- source ID;
- compiler version and artifact hash;
- raw-AST hash where retained by the POC;
- adapter identity/version;
- Canonical AST contract identity/version;
- detector identity/version;
- Comparator identity/version;
- source range;
- canonical expression ID.

### Gate 2G — Track preservation

The Stage 2 artifact must demonstrate that:

- Primary benchmark inputs/results are untouched;
- Real-World adjudication records are untouched;
- Nomad, BonqDAO, and Parity remain Quarantined;
- no Case #4 is created;
- production analyzer and Comparator diffs are empty.

## Required result matrix

| Case | Production path | Canonical path | Comparator | Expected interpretation |
|---|---|---|---|---|
| Modern vulnerable | existing detector result | timestamp semantic finding | Confirmed | parity |
| Modern fixed | no finding | no finding | no call | clean control |
| Historical vulnerable (`now`) | existing detector result | timestamp semantic finding | Rejected/other existing status | divergence evidence |
| Historical fixed | no finding | no finding | no call | clean control |
| Identifier/string/comment negatives | no findings | no findings | no call | mapping safety |
| Imported-source vulnerable | source-scoped result | finding attributed to imported source | existing Comparator behavior | multi-file attribution |
| Invalid/unknown AST | not treated as clean success | explicit failure/inconclusive | no call | failure safety |

## Implementation boundary

The implementation should live under the existing isolated historical-compatibility/architecture track used by Stage 1. The Stage 2 harness may reuse the established shadow comparison and provenance utilities, but it must not import the new Canonical path into the production analyzer as a side effect.

The bridge should expose the minimum detector input required by the timestamp detector. It must not expose compiler version to detector logic.

## Review evidence required before any merge

1. Focused Stage 2 tests pass.
2. Full test suite passes.
3. `git diff --check` passes.
4. Machine-readable shadow artifact is generated and internally consistent.
5. Modern parity is demonstrated.
6. Historical `now` divergence is visible and not silently reconciled.
7. Imported-source attribution is demonstrated.
8. Negative controls remain clean.
9. Comparator remains unmodified.
10. Production analyzer remains unmodified.
11. Primary/Real-World tracks remain unchanged.
12. Independent review explicitly decides Pass / Revise / Reject before any production migration discussion.

## Exit criteria

Stage 2 is **Passed** only if all required gates are demonstrated in the isolated harness. A pass authorizes review of the evidence and planning of the next compatibility stage; it does **not** authorize production detector migration.

If any gate fails, the result is **Revise** and the failure is recorded as evidence. No alias, detector patch, Comparator patch, or compiler fallback should be added merely to make the gate pass.

## Next-stage ordering

After Stage 2 review:

1. If Pass, run the next detector family as a separate shadow gate rather than batching production migration.
2. Keep the Comparator boundary explicit until an independent evidence policy is approved.
3. Complete the remaining production architecture gates, especially compiler-resolution-to-compilation wiring and production provenance/raw-AST retention.
4. Only after all mandatory architecture gates are independently accepted should a production migration proposal be considered.
