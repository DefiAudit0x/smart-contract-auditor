# Independent Review of the Canonical AST POC

## Review scope and baseline

This review evaluates commit `f1418a4da06c87d5ebd318f28f169f5304e1bb0b` on `main`, using the isolated compatibility-track POC and the architecture contract in [`ARCHITECTURE_DESIGN.md`](../architecture_boundary/ARCHITECTURE_DESIGN.md). The review is non-modifying with respect to production: it does not change `analyzers/`, `verification/comparator.py`, the primary benchmark, or the Real-World adjudications.

The POC result is valid evidence for the narrow experiment that it actually runs. It is not yet evidence that the abstraction is safe to generalize to production. The review therefore distinguishes **narrow POC validity** from **production architecture readiness**.

## Executive decision

> **Decision: B — Revise.**

The Canonical AST idea is supported by the positive experiment: historical and modern fixtures reached the same three semantic detector properties, fixed controls remained clean, and an incompatible container produced `ASTNormalizationFailed`. However, the current implementation has review-blocking gaps. The most important are context-insensitive alias recognition, acceptance of cross-format raw ASTs, incomplete structural validation, missing status-bearing analysis results for no-findings and inconclusive outcomes, incomplete provenance propagation, and a bridge that bypasses the production detector input contract.

This is not a rejection of the abstraction. It is a refusal to promote a successful narrow POC directly into production without a revision cycle.

## Review findings

| ID | Area | Result | Severity | Evidence and implication |
|---|---|---|---|---|
| R-01 | Minimal Canonical AST | **Narrowly valid; incomplete for production** | High | The POC represents exactly the three tested semantic families, but current detectors also rely on parameters, external-call lists, modifiers, `has_require`, `uses_tx_origin`, loops, assembly, call value, initializer state, storage/state variables, and other AST fields. The POC proves a minimum contract for three families, not the full current detector surface. |
| R-02 | Legacy alias mapping | **Not semantically safe yet** | Critical | `_expressions()` matches direct token values such as `attributes.value` and `name` without verifying node kind, parent expression, member receiver, or call shape. A legacy `uint now = 1; now;` probe produced a canonical timestamp finding although no time primitive was used. |
| R-03 | Modern alias mapping | **Same context problem** | Critical | A modern `uint256 timestamp = 1; timestamp;` probe produced `block_timestamp/timestamp`, and `bool delegatecall = true; delegatecall;` produced `external_call/delegatecall`. These are AST token coincidences, not proven semantic equivalences. |
| R-04 | Version-specific schema boundary | **Too permissive** | High | A legacy raw container with modern provenance was accepted by `adapt_modern`; a modern raw container with legacy provenance was accepted by `adapt_legacy`. The wrappers check the metadata string but the shared adapter does not validate schema markers such as `nodeType/nodes` versus `name/children`. |
| R-05 | Structural validation | **Insufficiently fail-closed** | High | Validation compares contract/function counts derived from regular expressions. It does not cover constructor, fallback, receive, modifier-only, source-unit, import, missing-body, duplicate, or source-range conditions. A broken modern AST with a contract but zero functions was accepted as `CanonicalASTReady` when the source contained constructor/fallback/receive declarations, because the regex counted zero named `function` declarations. |
| R-06 | Provenance | **Useful but not sufficient or reliably enforced** | High | The compiler result records compiler build, binary hash, source hash, raw-AST hash, and AST format. It lacks `source_id`, source manifest, canonical-AST version, detector/comparator versions, and per-finding provenance. A `Compiled` result with `provenance=None` raised `AttributeError` while creating the summary instead of returning an explicit failure state. |
| R-07 | Detector bridge | **Harness projection, not production detector contract** | Critical | The bridge instantiates `SolidityAnalyzer`, injects private `_contracts`, and calls private detector methods. It projects only a subset into `ASTFunction`/`ASTContract`; existing detectors therefore do not consume `CanonicalProgram` directly. The `detector_compiler_knowledge` and `comparator_implementation_changed` fields are hard-coded assertions, not independently derived properties. |
| R-08 | Multi-file architecture | **Explicitly out of scope and unimplemented** | High | `compiler.py` accepts one source string through stdin and has no source manifest, filename map, import resolver, pragma constraint set, or verified metadata. A source importing `Lib.sol` returned `CompilationFailed` for both compiler paths. This is an honest failure, but production architecture cannot claim multi-file support yet. |
| R-09 | Failure semantics | **Partially implemented** | Critical | `UnsupportedCompiler`, `CompilationFailed`, `ASTUnavailable`, `UnsupportedASTVersion`, and `ASTNormalizationFailed` can be returned by direct paths. But `AnalysisSucceededNoFindings`, `AnalysisSucceededWithFindings`, and `Inconclusive` are only enum declarations; the runner emits only `finding_count=0` for fixed controls. A `Compiled` result with missing provenance crashes, and the published matrix covers only one normalization-failure shape. |
| R-10 | Source evidence and replay | **Not sufficient for later interpretation** | High | Canonical expressions retain source ranges, but the bridge-generated `Finding` objects use `line=0` and do not carry canonical expression references or provenance. The Comparator sees source text and existing detector labels, not an end-to-end provenance-bearing finding. |

## 1. Canonical AST contract

The contract is **minimal for the stated POC**, but not minimal for the current detector system as a whole. This distinction matters. The three tested detector methods require only the booleans projected by the bridge, so the POC avoided building a complete second Solidity frontend. That was the correct experiment design.

The design document, however, lists a broader detector contract: function name, visibility, modifiers, parameters, external-call kind, expression kind and arguments, selfdestruct, timestamp, source range, and provenance. The current POC implements only a subset of that list. It does not yet represent source units, source names, base contracts, state variables, state mutability, parameters, returns, statements, body structure, or a read-only `SourceView`. Current detectors outside the three POC families use several of these fields or related derived properties.

The review conclusion is therefore: **keep the minimum semantic principle, but define the minimum per detector family rather than declaring the current three-family projection sufficient for production.**

## 2. Legacy and modern semantic mapping

The positive mappings are real in the narrow fixtures. The legacy adapter observed `suicide`, `now`, and `callcode` in the 0.4.10 AST and normalized them to destructive operation, timestamp, and canonical delegatecall semantics. The modern adapter observed `selfdestruct`, `block.timestamp`, and `delegatecall` in the 0.8.25 AST. The same existing detector methods then returned one finding per family.

The mapping is not yet based on enough AST context to be called semantically proven. The shared `_expressions()` routine traverses a broad set of dictionaries and treats any matching direct token as evidence. It does not require `suicide` or `selfdestruct` to be the callee of a function-call node, does not require `timestamp` to be a member access on `block`, does not require `now` to be a time expression, and does not require `delegatecall` or `callcode` to be a member access followed by a call.

The review probes produced the following concrete false positives:

| Source form | Adapter output | Correct interpretation |
|---|---|---|
| `uint256 timestamp = 1; timestamp;` on 0.8.25 | `block_timestamp/timestamp` | No timestamp primitive; should be clean. |
| `uint now = 1; now;` on 0.4.10 | `block_timestamp/timestamp` | No historical time primitive; should be clean. |
| `bool delegatecall = true; delegatecall;` on 0.8.25 | `external_call/delegatecall` | No delegate call; should be clean. |

The required revision is not a textual alias patch. Each adapter must prove the relevant AST shape and context before emitting a canonical semantic expression. If a schema cannot prove equivalence, the adapter should return a failure or an explicit unsupported/inconclusive result rather than guessing.

## 3. Modern adapter and schema isolation

The modern and legacy entry points enforce the expected `ast_format` metadata, but the shared adapter accepts either raw schema. A legacy `name/children/attributes` tree with `ast-compact-json` provenance was accepted by the modern adapter. A modern `nodeType/nodes` tree with `ast-json` provenance was accepted by the legacy adapter.

This means the current version-specific boundary is a naming convention, not a structural gate. Before production review can pass, each adapter must validate the schema markers it claims to own and reject the other schema with `UnsupportedASTVersion` or `ASTNormalizationFailed`, retaining the raw-AST hash and diagnostics.

## 4. Structural validation

The zero-contract invariant is correctly expressed and works for the tested broken container. It is not sufficient as the complete structural validator. The current validator counts `contract`, `library`, and `interface` declarations and named `function` declarations in the raw source using regular expressions. It then checks only that normalized counts are not below those estimates.

This approach can miss special functions and source structure that is not represented by a named `function` declaration. A probe with constructor, fallback, and receive declarations and a raw AST containing one empty contract returned `CanonicalASTReady` with zero functions. The validator therefore did not detect a plausible loss of all executable function structure.

The production proposal should validate the AST-to-canonical transformation structurally: source-unit count, contract identity, all function-like declarations, modifiers, source-range bounds, required node kinds for each detector family, and explicit treatment of unknown or skipped nodes. A count lower bound can remain as a cheap invariant, but it must not be the sole completeness check.

## 5. Provenance sufficiency

The compiler provenance fields are a strong start. Compiler version, build string, compiler binary hash, source hash, raw-AST hash, and AST format are enough to identify the narrow compiler artifact used in the POC. They are not enough to reproduce or reinterpret a production finding later.

The production-level record also needs a stable source identifier, ordered multi-file source manifest and per-file hashes, pragma constraints, optimization and compilation settings, canonical AST contract version, adapter version, detector version, Comparator version, analysis status, source range, evidence kind, and an explicit link from each finding to the canonical expression or function that produced it. The POC stores provenance on `CanonicalProgram`, but the bridge findings do not carry it forward. A later reviewer could identify the AST artifact but not reliably reconstruct the exact finding-to-expression-to-source-evidence chain from the emitted `Finding` alone.

The adapter also needs to reject a `Compiled` result without required provenance. The current behavior is an `AttributeError`, which violates the explicit-failure objective.

## 6. Detector bridge

The bridge is useful as a narrow harness, but it is not a clean proof of the production detector contract. It constructs a production `SolidityAnalyzer`, mutates its private `_contracts` field, and invokes private methods. This bypasses the current parser path, which is exactly why the POC can demonstrate detector semantics without changing production code. It also means the POC does not prove that production detectors can receive `CanonicalProgram` directly.

The projection is also lossy by design. It drops expression source ranges, arguments, parameters, external-call lists, body information, state variables, and other fields. For the three detector methods this is enough to produce findings; for broader production use it can hide differences between old and modern ASTs. The next architecture proposal must either define a deliberate `DetectorInput` interface that accepts Canonical AST plus `SourceView`, or explicitly label this bridge as a temporary compatibility harness and test every production detector family against the fields it consumes.

## 7. Multi-file boundary

The POC is single-file. That is acceptable for the experiment and must remain explicit. It does not yet implement the architecture design's `sources`, `source_manifest`, complete pragma constraints, verified metadata, or import relationship model. Feeding an import source through stdin fails explicitly rather than silently selecting another compiler, which is correct failure behavior but not multi-file support.

No production architecture decision should be made until a separate multi-file design slice specifies source identity, import resolution, compiler settings, pragma intersection, complete-source compilation, raw-AST partitioning by source unit, and provenance for every file.

## 8. Failure semantics boundary matrix

| State | Current POC behavior | Review assessment |
|---|---|---|
| `UnsupportedCompiler` | Returned when requested version is not registered; adapter preserves it. | Good narrow behavior; add source/request provenance in production. |
| `CompilationFailed` | Returned for solc non-zero exit, including missing imports; adapter preserves it. | Good fail-closed behavior; diagnostics should be structured rather than flat strings. |
| `ASTUnavailable` | Returned for invalid JSON output; adapter preserves it, but runner-level provenance is absent on this path. | Revise to retain compiler/source context where available. |
| `UnsupportedASTVersion` | Returned by wrapper when metadata format does not match the wrapper's expected format. | Incomplete because raw schema markers are not checked. |
| `ASTNormalizationFailed` | Returned for broken/incompatible containers and zero normalized contracts. | Core invariant works, but structural coverage is incomplete. |
| `Inconclusive` | Declared but not emitted by the POC. | Must be an explicit status-bearing analysis result before production. |
| `AnalysisSucceededNoFindings` | Declared but fixed controls expose only `finding_count=0`. | Must be emitted after compiler, adapter, structural validation, and detector execution all succeed. |
| `AnalysisSucceededWithFindings` | Declared but not emitted. | Must be emitted and attached to every result carrying findings. |

The core distinction remains correct:

> **No evidence** is not the same as **evidence of absence**.

The revised pipeline must make that distinction machine-readable at every boundary. A detector must not run on any failure state, and a zero-finding result must carry an explicit successful analysis status.

## Required revision gates before a production proposal

| Gate | Required evidence |
|---|---|
| Context-safe semantic mapping | Negative controls for identifier collisions, nested expressions, member receivers, call shapes, strings/comments, and historical syntax variants. |
| Strict adapter ownership | Cross-format raw ASTs are rejected; each adapter validates its schema markers and supported AST version. |
| Structural completeness | AST-native validation covers source units, contracts, function-like declarations, modifiers, ranges, imports, and unknown/skipped nodes. |
| Status-bearing analysis result | `CompilationFailed`, `ASTUnavailable`, `UnsupportedCompiler`, `UnsupportedASTVersion`, `ASTNormalizationFailed`, `Inconclusive`, `AnalysisSucceededNoFindings`, and `AnalysisSucceededWithFindings` are exercised through one end-to-end result contract. |
| Provenance propagation | Every finding references source identity, source manifest/hash, compiler artifact, adapter/canonical versions, detector/Comparator versions, source range, and evidence. |
| Detector contract | A deliberate Canonical AST plus SourceView interface is tested, or the bridge is explicitly limited to a non-production harness with no claim of detector migration. |
| Multi-file slice | At least one complete import graph is compiled with deterministic compiler/settings resolution and per-source-unit provenance. |
| Track preservation | Primary Precision/Recall/F1 remains 1.0/1.0/1.0; Real-World cases remain quarantined; no Comparator or detector patch is smuggled into the review. |

## Final review conclusion

The POC should be **revised, not adopted or rejected**. Its positive result is meaningful: the architecture can normalize the three measured semantic families across two AST schema families when the fixtures are direct and clean. Its negative probes are equally meaningful: the current adapter can create false positives, accept a schema it does not own, miss structural loss, and fail to emit complete status/provenance contracts.

Accordingly, the next stage should be a revised compatibility POC or a narrowly scoped Architecture Revision, not a production implementation. Production code, the Comparator, the primary benchmark, Real-World adjudications, Parity status, and Case #4 should remain unchanged until every revision gate above is satisfied.

## References

[1]: ../architecture_boundary/ARCHITECTURE_DESIGN.md "Compiler / AST Boundary Architecture Design"

[2]: POC_REPORT.md "Canonical AST Compatibility POC Report"

[3]: canonical.py "POC Canonical AST and status definitions"

[4]: adapters.py "POC AST adapter and structural validation"

[5]: compiler.py "POC explicit-version compiler runner"

[6]: detector_bridge.py "POC detector bridge"

[7]: run_poc.py "POC matrix runner"

[8]: ../../../../analyzers/solidity_analyzer.py "Current production detector implementation"

[9]: ../../../../verification/comparator.py "Current Comparator implementation"
