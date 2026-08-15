# Canonical AST Compatibility POC Report

## Scope and decision status

This report evaluates the isolated compatibility-track proof of concept described in the [Compiler / AST Boundary Architecture Design](../architecture_boundary/ARCHITECTURE_DESIGN.md). The POC is intentionally limited to three detector families: `Selfdestruct`, `block.timestamp`, and `DELEGATECALL`. It implements compiler invocation for explicitly requested versions, version-specific raw-AST adapters, a minimum semantic Canonical AST, structural validation, explicit normalization failure, and a bridge into the existing detector methods.

The POC is **not** a production refactor. It does not modify `analyzers/`, `verification/comparator.py`, the primary benchmark, or Real-World adjudication records. It does not re-adjudicate Parity and does not change the status of Nomad, BonqDAO, or Parity. A successful POC is evidence for independent review; it is not an automatic merge or production decision.

## Architectural contract tested

> **No compiler guess → no silent fallback → no usable AST claim.**

The compiler runner accepts only an explicitly requested version. It uses the 0.4.10 binary for the historical path and the 0.8.25 binary for the modern path. It records the compiler build, binary hash, source hash, raw-AST hash, and AST format. It does not try another compiler when the requested one fails.

The Canonical AST is deliberately a **minimum semantic contract**, not a second complete Solidity frontend. For this POC it represents contract and function identity, visibility, source ranges, and three normalized semantic expressions: a destructive operation, block timestamp usage, and an external call whose canonical kind is `delegatecall`. Historical `suicide`, `now`, and `callcode` are normalized to the same semantic properties as modern `selfdestruct`, `timestamp`, and `delegatecall` only inside the version-specific adapter.

Before detectors run, the adapter validates that the normalized contract and function structure is consistent with the source structure. A raw AST that exists but normalizes to zero contracts is therefore a failure, not an empty successful program.

## Files added by the POC

| File | Purpose |
|---|---|
| `canonical.py` | Minimal Canonical AST dataclasses, provenance, and explicit status values. |
| `compiler.py` | Explicit-version compiler runner with no fallback and hash-based provenance. |
| `adapters.py` | Shared structural conversion and validation primitives used by the two version-specific entry points. |
| `legacy_ast_adapter.py` | Adapter entry point for the 0.4.10 legacy JSON AST. |
| `modern_ast_adapter.py` | Adapter entry point for the 0.8.25 compact JSON AST. |
| `detector_bridge.py` | Compatibility bridge that projects only canonical semantic fields needed by the existing detector methods. |
| `run_poc.py` | Reproducible matrix runner and machine-readable result writer. |
| `fixtures/` | Historical, modern, and fixed-control Solidity fixtures. |
| `metadata/poc_results.json` | Full results, provenance, detector outputs, and Comparator statuses. |
| `tests/test_architecture_poc.py` | Five regression tests for the POC contract. |

## Evaluation matrix

| Case | Compiler path | Canonical AST | Detector result | Comparator result | Expected interpretation |
|---|---|---:|---:|---|---|
| Historical vulnerable | 0.4.10 legacy AST → legacy adapter | Valid; 1 contract and 3 functions | One finding for each of the three families | `Rejected` for each finding | Semantic detector compatibility is demonstrated; unchanged Comparator still recognizes only its current source vocabulary. |
| Modern vulnerable | 0.8.25 compact AST → modern adapter | Valid; 1 contract and 3 functions | One finding for each of the three families | `Confirmed` for each finding | Current modern semantics remain available through the Canonical AST path. |
| Historical fixed control | 0.4.10 legacy AST → legacy adapter | Valid; 1 contract and 1 function | Zero findings for all three families | No Comparator calls | Clean control remains clean. |
| Modern fixed control | 0.8.25 compact AST → modern adapter | Valid; 1 contract and 1 function | Zero findings for all three families | No Comparator calls | Clean control remains clean. |
| Invalid AST container | Broken legacy-shaped container | `ASTNormalizationFailed` | Detectors not run | No Comparator calls | The pipeline does not convert normalization failure into zero findings. |

## Semantic equivalence result

The central equivalence assertion passed for all three families. The 0.4.10 adapter produced the following canonical signals from historical syntax: `suicide → destructive_operation/selfdestruct`, `now → block_timestamp/timestamp`, and `callcode → external_call/delegatecall`. The 0.8.25 adapter produced the corresponding canonical signals from `selfdestruct`, `block.timestamp`, and `delegatecall`.

Both paths therefore reached the same semantic detector contract without passing compiler version into detector logic. The detector bridge reports `detector_compiler_knowledge = false` for every invocation. The bridge is intentionally isolated and does not change the existing analyzer implementation.

## Failure semantics result

The invalid fixture contains a raw-AST-shaped dictionary with no contract definition. The adapter returned `ASTNormalizationFailed`, included diagnostics, and retained compiler/source/raw-AST provenance. No detector was invoked. This directly validates the required invariant:

> **Raw AST + expected contracts + normalized contract count of zero = `ASTNormalizationFailed`, not successful zero findings.**

The POC does not use an exception-swallowing fallback such as `CanonicalProgram([])`. Adapter failure is returned as a status-bearing result with diagnostics.

## Comparator boundary result

The Comparator was not changed. On the historical path, the existing Comparator rejected the three semantically valid detector findings because its source matchers currently recognize modern spellings such as `selfdestruct`, `block.timestamp`, and `delegatecall`, not the historical aliases. On the modern path, the same detector families were confirmed.

This is an intentional POC observation, not a Comparator patch recommendation. The result demonstrates two separate boundaries: the Canonical AST adapter can restore semantic detector compatibility, while the unchanged downstream source-evidence Comparator retains its existing exact-source behavior. Parity therefore remains Quarantined pending a separate independent re-adjudication after any future production-approved path exists.

## Validation

| Command | Result |
|---|---|
| `PYTHONPATH=. python3 -m benchmarks.historical_compatibility.canonical_ast_poc.run_poc` | Passed; wrote `metadata/poc_results.json`. |
| `PYTHONPATH=. pytest -q tests/test_architecture_poc.py` | **5 passed**. |
| Primary benchmark | Not modified by the POC. |
| Production analyzer | Not modified by the POC. |
| Comparator | Not modified by the POC. |
| Real-World adjudications | Not modified; all three remain Quarantined. |

## Decision and next gate

The isolated POC meets its defined success criteria: both compiler paths produce a valid minimum Canonical AST; the same three detector semantics are available on historical and modern syntax; fixed controls remain clean; invalid normalization fails explicitly; detector logic has no compiler-version branch; and Comparator behavior remains unchanged.

The appropriate next step is **independent review of this POC**, not automatic production adoption. Production work should remain gated until the review resolves the open questions in the architecture design, including multi-file source manifests, verified deployment metadata precedence, additional legacy AST schemas, provenance propagation into production findings, and the exact production detector input contract.

## Track separation

| Track | POC effect |
|---|---|
| Controlled | Unchanged. The primary benchmark and its 1.0/1.0/1.0 result remain outside this POC. |
| Compatibility | Extended with the isolated POC, its fixtures, machine-readable results, and regression tests. |
| Real-World | Unchanged. Nomad, BonqDAO, and Parity remain Quarantined; no Case #4 was added. |

## References

[1]: ../architecture_boundary/ARCHITECTURE_DESIGN.md "Compiler / AST Boundary Architecture Design"

[2]: ../architecture_boundary/REPORT.md "Read-only Compiler / AST Boundary Audit"

[3]: ../../../../analyzers/solidity_analyzer.py "Current detector implementation"

[4]: ../../../../verification/comparator.py "Current Comparator implementation"
