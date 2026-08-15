# Revised Compatibility POC Report

## Scope and decision boundary

This report evaluates the revision gates requested after the initial Independent Review of commit `f1418a4da06c87d5ebd318f28f169f5304e1bb0b`. The work remains isolated under the Compatibility track. It does not modify `analyzers/`, `verification/comparator.py`, the Primary Benchmark, Nomad, BonqDAO, Parity, or Case #4.

The revised POC is deliberately still a POC. It does not migrate production detectors. It establishes a stronger compatibility boundary, a status-bearing detector contract, an end-to-end provenance chain, and one deterministic multi-file slice. Passing these revision gates authorizes preparation of a **Production Architecture Proposal**; it does not authorize production implementation or merge.

## Revised result

> **Revision gates: Passed within the defined POC scope. Production decision: Pending a separate Production Architecture Proposal.**

The revised POC removed the specific false positives found by the Independent Review, rejected cross-format AST containers, detected structural loss involving constructor/fallback/receive declarations, emitted explicit status-bearing outcomes, propagated finding provenance to canonical expressions, and compiled a two-file import graph with per-file manifest data. The primary and Real-World tracks remained untouched.

## Gate evaluation

| Gate | Result | Evidence |
|---|---|---|
| Context-safe semantic mapping | **Passed** | Legacy `suicide`, `now`, and `callcode` and modern `selfdestruct`, `block.timestamp`, and `delegatecall` require AST call/member shape. Identifier, nested-expression, wrong-call-shape, string, and comment controls remained clean on both paths. The POC bridge disables the existing Selfdestruct textual fallback and exercises the Canonical AST signal only; production analyzer code remains unchanged. |
| Strict schema ownership | **Passed** | Legacy adapter accepts only legacy `name/children` AST shape; modern adapter accepts only modern compact `nodeType/nodes` or the explicit standard-json source-unit wrapper. Cross-format probes return `UnsupportedASTVersion`. |
| Structural completeness | **Passed for the revised scope** | AST traversal now understands source units, contracts, function-like definitions, modifiers, state variables, source ranges, and unknown/skipped contract nodes. A broken constructor/fallback/receive structure returns `ASTNormalizationFailed`; unknown contract nodes return `Inconclusive`. Regex is used only as a secondary source-structure cross-check, not as the AST parser or sole success criterion. |
| Status-bearing result | **Passed** | The revised runner emits `UnsupportedCompiler`, `CompilationFailed`, `ASTUnavailable`, `UnsupportedASTVersion`, `ASTNormalizationFailed`, `Inconclusive`, `AnalysisSucceededNoFindings`, and `AnalysisSucceededWithFindings`. A zero finding count is no longer treated as a status by itself. |
| Provenance propagation | **Passed at POC level** | Compiler/build/hash, source hash, source manifest, raw-AST hash, adapter version, Canonical AST version, detector version, Comparator identity, source range, evidence kind, and canonical expression ID reach every vulnerable finding. |
| Detector contract | **Passed as an isolated contract test; production migration pending** | `DetectorInput = CanonicalProgram + SourceView + detector provenance` is now the bridge input. Existing private detector methods remain behind the isolated harness; no claim is made that production detectors have been migrated. |
| Multi-file slice | **Passed** | `Main.sol` imports `Lib.sol` through solc standard-json. The result preserves both source units, per-file source hashes, pragma constraints, compiler settings hash, and deterministic no-finding analysis on the entry source. |
| Track preservation | **Passed** | No production analyzer or Comparator file changed. The original v1 result remains preserved as `metadata/poc_results.json`; revised output is separate in `metadata/revised_poc_results.json`. Primary metrics and Real-World adjudications remain unchanged. |

## Context-safe mapping

The initial adapter treated direct token values as semantic evidence. The revised adapter now validates the AST shape for each family. In the legacy schema, `suicide` must be the callee identifier of a `FunctionCall`; `callcode` must be the member of a `MemberAccess` used as a function-call callee; and `now` must be an identifier that is not declared as a local or parameter symbol. In the modern schema, `selfdestruct` must be the identifier callee of a `FunctionCall`; `delegatecall` must be the member of a `MemberAccess` used as a call callee; and `timestamp` must be a `MemberAccess` whose receiver is the magic `block` identifier with `typeIdentifier = t_magic_block`.

The negative fixtures contain direct identifier collisions, ordinary call shapes, nested arithmetic, strings, and comments containing the target words. All three detector families returned `AnalysisSucceededNoFindings` with zero findings on both compiler paths. This directly addresses the three false positives proven in the initial review.

## Schema ownership and malformed inputs

The adapter entry points no longer rely on metadata alone. The legacy path rejects modern `nodeType/nodes` structures, and the modern path rejects legacy `name/children` structures. The modern multi-file path additionally requires the POC's `standard-json-source-units-v1` wrapper and validates every source unit as a modern `SourceUnit` with a `nodes` array.

A malformed registered container is classified as `ASTNormalizationFailed`. A structurally different schema is classified as `UnsupportedASTVersion`. The distinction is preserved in the machine-readable result and is visible before detector execution.

## Structural validation

The revised validator treats AST structure as the primary source of normalized contract and function-like information. It recognizes `FunctionDefinition` nodes, including constructor/fallback/receive forms represented by the compiler, and records modifier and state-variable nodes. It validates source-unit, contract, and function source ranges and records skipped known nodes separately from unknown nodes.

The source declaration scan remains only an independent lower-bound cross-check. It is masked against comments and strings and is not used to discover semantic expressions. The constructor/fallback/receive structural-loss probe now fails with `ASTNormalizationFailed` because the AST contains zero function-like nodes while the source declares three function-like entries.

Unknown contract children are not silently discarded. They produce `Inconclusive`, which prevents the pipeline from claiming successful absence of findings when the adapter does not understand part of the contract structure.

## Status-bearing analysis result

The revised bridge returns a status-bearing analysis result for every detector invocation. Positive vulnerable controls return `AnalysisSucceededWithFindings`; fixed and negative controls return `AnalysisSucceededNoFindings`. Upstream compiler and adapter failures retain their explicit status and do not invoke detectors. An unknown AST node returns `Inconclusive`.

The key invariant is now exercised end to end:

> **Zero findings is evidence of absence only when compilation, AST availability, schema ownership, normalization, structural validation, and detector execution all report success.**

## Provenance chain

The revised finding output contains a reversible link from detector finding to canonical expression. For each vulnerable finding, the machine-readable record includes `canonical_expression_id`, semantic evidence kind, source range, source identity, source manifest, source hash, compiler version and binary hash, raw-AST hash, adapter version, Canonical AST version, detector version, and Comparator identity. The POC uses `existing-comparator-unchanged` as the explicit identity because the production Comparator was intentionally not modified or versioned in this isolated change.

This is sufficient for the POC-level reverse trace:

> **Finding → canonical expression → source range/source hash → raw AST hash/compiler artifact → adapter version.**

A production proposal must replace the descriptive Comparator identity with the project's real version/revision mechanism and define retention and lookup policy for raw AST artifacts.

## Detector contract

The revised bridge accepts a `DetectorInput` containing `CanonicalProgram`, `SourceView`, and detector provenance. The existing detector methods still run through an isolated projection into their current DTO shape, because changing production detector signatures is outside this POC. The bridge declares and tests the intended boundary without claiming that production code already consumes `CanonicalProgram` directly.

The bridge also applies a `canonical-ast-only` source policy to detector execution. The unchanged source is still supplied to the Comparator as evidence, but the POC Selfdestruct detector path does not use the production textual fallback. This prevents strings and comments from becoming detector findings while keeping the Comparator observation separate.

## Multi-file slice

The revised compiler runner adds a narrow standard-json path for an explicit source map. The slice contains `Main.sol` importing `Lib.sol`. It preserves the ordered source manifest, each source hash, per-source pragma constraints, compiler settings hash, standard-json AST format, source-unit ASTs, and entry source identity. Both source units normalize successfully and the entry-source detector analysis returns `AnalysisSucceededNoFindings`.

This is not a complete compiler resolver. It intentionally does not implement verified deployment metadata precedence, compiler candidate search, optimizer setting discovery, historical multi-file compilation, or a production import policy. Those remain requirements for the Production Architecture Proposal.

## Machine-readable and regression artifacts

| Artifact | Purpose |
|---|---|
| `metadata/revised_poc_results.json` | Revised POC output with all cases, statuses, multi-file manifest, and provenance. |
| `metadata/poc_results.json` | Preserved initial v1 POC output from commit `f1418a4`. |
| `tests/test_architecture_poc.py` | Twelve regression tests covering the original contract and revised gates. |
| `fixtures/negative_0_4_10.sol` | Historical context, identifier, call-shape, string, and comment negative controls. |
| `fixtures/negative_0_8_25.sol` | Modern equivalent negative controls. |

## Validation

| Command | Result |
|---|---|
| `PYTHONPATH=. python3 -m benchmarks.historical_compatibility.canonical_ast_poc.run_poc` | Passed; wrote the revised machine-readable result before preserving it as `revised_poc_results.json`. |
| `PYTHONPATH=. pytest -q tests/test_architecture_poc.py` | **12 passed**. |
| Production analyzer and Comparator diff | None. |
| Primary benchmark | Not modified. |
| Real-World track | Nomad, BonqDAO, and Parity remain Quarantined; no Case #4. |

## Next gate

The revised POC is strong enough to begin a **Production Architecture Proposal**, not production implementation. That proposal must specify the real multi-file compiler resolver, production provenance retention, detector migration strategy, Comparator identity/versioning, and rollout/rollback boundaries. The current work remains local until independently reviewed; no commit or push is part of this revised stage.

## References

[1]: ../architecture_boundary/ARCHITECTURE_DESIGN.md "Compiler / AST Boundary Architecture Design"

[2]: INDEPENDENT_REVIEW.md "Initial Independent Review — Decision Revise"

[3]: POC_REPORT.md "Initial Canonical AST Compatibility POC Report"

[4]: adapters.py "Revised context-safe adapters"

[5]: compiler.py "Revised explicit and multi-file compiler runner"

[6]: detector_bridge.py "Revised DetectorInput bridge and provenance"

[7]: run_poc.py "Revised POC matrix runner"
