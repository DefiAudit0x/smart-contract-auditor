# Compiler / AST Boundary Architecture Design

## Status and scope

This document defines the architecture contract and records the result of the isolated proof of concept. The POC implements only compatibility-track compiler invocation, version-specific AST adapters, a minimum semantic Canonical AST, explicit normalization failure states, and a detector bridge. It does **not** implement a production compiler resolver, production analyzer changes, Comparator changes, or architecture refactoring.

The design is deliberately limited to the pipeline below:

> **Source → Compiler Resolution → solc Invocation → Raw AST → Version-Specific Adapter → Canonical AST → Detector → Evidence → Comparator**

The controlled benchmark, Real-World adjudications, and current primary metrics remain separate tracks. No fourth Real-World case is introduced by this design.

## Evidence that motivates the design

The current implementation fixes `SOLC_VERSION = "0.8.25"` in `analyzers/solidity_ast.py`, invokes `solcx.compile_source(..., output_values=['ast'], solc_version=SOLC_VERSION)`, passes the result through `solcast.from_ast()`, and then calls `analyze_contracts()`. The boundary experiment demonstrated that a valid historical raw AST can be returned by solc 0.4.10 while `solcast.from_ast()` produces a plain dictionary with `children` and `name`; the current contract extraction then yields zero normalized contracts and functions. The modern 0.8.25 path instead produces a `SourceUnit` and reaches `ASTFunction` objects. These observations are recorded in [`REPORT.md`](REPORT.md) and [`compiler_ast_boundary_experiment.json`](metadata/compiler_ast_boundary_experiment.json).

The design response is not to add a textual alias. It is to make the contracts between compiler, adapter, canonical AST, detector, and evidence explicit, versioned, and fail-closed.

## A. Compiler layer

### A.1 Compiler request

Compiler selection should be an explicit operation rather than an implicit constant. The resolver should receive a `CompilerRequest` containing at least the following information.

| Field | Meaning |
|---|---|
| `source_id` | Stable identifier for the source set or verified deployment source. |
| `source_sha256` | Hash of the exact source bytes being compiled. |
| `sources` | The complete source-unit map, including filenames and import relationships. |
| `pragma_constraints` | Parsed Solidity pragma constraints for every relevant source unit. |
| `requested_version` | An explicitly requested compiler version, if supplied by verified metadata or an adjudication record. |
| `verification_metadata` | Compiler, optimization, ABI, source-map, and metadata hints from a verified deployment. |
| `allowed_versions` | An optional policy constraint limiting candidate versions. |
| `context` | Whether the request is a benchmark fixture, real-world reproduction, or production analysis. |

The resolver must not infer a compiler solely from the first pragma in one file when the source set contains multiple files or imported dependencies.

### A.2 Compiler resolver contract

The proposed `CompilerResolver` has the following deterministic flow:

> **CompilerRequest → candidate versions → compile attempts → selected CompilerResult or explicit failure**

Candidate ordering should prefer verified deployment metadata when it is available, then an explicitly requested version, then versions satisfying the complete source-set pragma constraints. The resolver must compile the complete source set, not only one file, and must preserve every diagnostic from every candidate attempt.

A candidate is selectable only when compilation succeeds for the intended output and the selected compiler is compatible with the source-set constraints. A compiler that merely parses one file while imports or other source units fail is not a successful resolution. The resolver must never silently fall back to 0.8.25 when a historical candidate fails, and it must never claim that a failed candidate produced a usable raw AST.

### A.3 Compiler result

The resolver should return a `CompilerResult` with an explicit success or failure status.

| Field | Required meaning |
|---|---|
| `status` | `Compiled` or an explicit compiler failure state. |
| `compiler_version` | Semantic version, such as `0.4.10`, not only a short family label. |
| `compiler_binary_hash` | SHA-256 of the compiler binary used for the result. |
| `compiler_build` | Full build identifier, such as the Solidity commit suffix. |
| `source_sha256` | Hash of the complete source-set bytes or canonical source manifest. |
| `ast_format` | Raw output format and schema family, for example `solc-legacy-json-ast` or `solc-json-ast`. |
| `raw_ast` | The serialized raw AST when compilation succeeds. |
| `diagnostics` | Warnings and errors with severity, source location, and candidate version. |
| `source_manifest` | Ordered filenames and hashes used in the compilation. |

`CompilerResult` is the only object that should cross the compiler boundary. It must remain available for provenance even after adaptation.

## B. AST layer

### B.1 Raw AST definition

Raw AST means the compiler’s serialized AST before project-specific conversion. It is not a canonical detector input. The raw artifact must be retained with its compiler version, build, format, source manifest, and hash.

The investigation encountered at least two materially different forms:

| AST family | Observed form | Compatibility implication |
|---|---|---|
| Legacy solc 0.4.x | Combined JSON with `sources[filename].AST`, legacy nodes and `attributes` such as `value` | `solcast.from_ast()` can return a plain dictionary rather than the modern `SourceUnit` object expected by current extraction code. |
| Modern solc 0.8.25 | AST object consumed by `solcast.from_ast()` as a `SourceUnit` with iterable child nodes | Current `analyze_contracts()` and `_extract_function()` can build the project’s internal function representation. |

A raw AST being present is not evidence that normalization succeeded. The adapter must validate the output container and the required semantic nodes before reporting success.

### B.2 Version-specific adapter

The adapter is responsible for converting exactly one raw AST schema family into the canonical AST. It should perform the following checks before conversion:

1. It verifies the compiler result status and raw AST presence.
2. It identifies the raw AST format from compiler metadata and structural markers rather than guessing from a source string.
3. It validates the minimum schema required by the adapter.
4. It converts contracts, functions, modifiers, statements, expressions, source ranges, and relevant semantic properties.
5. It reports the adapter version and diagnostics.
6. It rejects an incompatible output container instead of returning an empty program.

An adapter must not silently treat a dictionary of legacy AST fields as an iterable of normalized AST nodes. If the adapter cannot produce the canonical contract, it must return `ASTNormalizationFailed` or `UnsupportedASTVersion` with a reason and raw artifact hash.

### B.3 Canonical AST contract

Detectors should consume a stable internal contract rather than a `solc` version-specific shape or a `solcast` object model. The exact class names are implementation details; the required semantic contract is the important part.

```text
CanonicalProgram
├── compiler_provenance
├── source_units[]
│   ├── source_name
│   ├── source_range
│   └── contracts[]
│       ├── name
│       ├── kind
│       ├── base_contracts[]
│       ├── state_variables[]
│       ├── modifiers[]
│       └── functions[]
│           ├── name
│           ├── visibility
│           ├── state_mutability
│           ├── modifiers[]
│           ├── parameters[]
│           ├── returns[]
│           ├── body
│           ├── statements[]
│           ├── expressions[]
│           └── source_range
└── diagnostics[]
```

The minimum semantic properties required by the current detector families are:

| Canonical property | Consumers |
|---|---|
| `function.name`, `visibility`, `modifiers`, `parameters` | Reentrancy, access-control, public mint, proxy and ownership checks |
| `function.external_calls` and call kind | Reentrancy and delegatecall checks |
| `expression.kind`, `member`, `arguments` | `delegatecall`, `callcode` normalization, `tx.origin`, timestamp and transfer checks |
| `function.uses_selfdestruct` | Selfdestruct detector, including historical semantic aliases after adapter normalization |
| `function.uses_block_timestamp` | Timestamp detector, including historical `now` after adapter normalization |
| `source_range` | Evidence snippets, Comparator locations, and reproducibility |
| `compiler_provenance` | Reporting only; detectors should not branch on compiler version |

The canonical AST must represent semantic equivalence explicitly. For example, a legacy `suicide(_to)` and modern `selfdestruct(_to)` should become the same canonical destructive-operation expression only if the version-specific adapter can prove that equivalence. A legacy `now` expression should become the canonical timestamp semantic only in an adapter that recognizes the old AST schema.

## C. Detector contract

### C.1 Detector input

A detector should receive a validated `CanonicalProgram` and a read-only `SourceView`, not a raw compiler AST and not a compiler-specific object. The detector must not need to know whether the input originated from solc 0.4.10 or 0.8.25. Compiler version belongs in provenance and diagnostics, not in detector branching logic.

The minimum detector input contract is:

```text
DetectorInput
├── canonical_program
├── source_view
│   ├── source_name
│   ├── source_bytes
│   └── source_hash
└── analysis_context
    ├── canonical_ast_version
    ├── adapter_version
    └── provenance_reference
```

The detector is allowed to report a finding only when `canonical_program.status` is analysis-ready. It must not interpret an empty contract list as a successful no-finding analysis unless the program explicitly states that normalization succeeded and the source contains no contracts.

### C.2 Detector output

The detector should return findings plus a status-aware result. A finding must include the detector identity, canonical function or expression reference, semantic description, and a source range that can be resolved against the original source.

The detector should not perform compiler selection, parse raw AST formats, or decide whether a failed adapter can be ignored. Those responsibilities belong to the compiler and adapter layers.

## D. Failure semantics

The pipeline must distinguish absence of evidence from evidence that analysis succeeded and found nothing. The following states are proposed.

| State | Meaning | May detectors run? | May pipeline claim “no finding”? |
|---|---|---:|---:|
| `CompilationFailed` | No valid compiler result for the complete source set. | No | No |
| `ASTUnavailable` | Compilation did not produce the requested raw AST artifact. | No | No |
| `UnsupportedCompiler` | No policy-approved compiler candidate is available or compatible. | No | No |
| `UnsupportedASTVersion` | Raw AST exists but no adapter is registered for its schema family. | No | No |
| `ASTNormalizationFailed` | Registered adapter could not produce a valid canonical program, including incompatible output containers or zero contracts when contracts are expected. | No | No |
| `Inconclusive` | Analysis could not establish a reliable conclusion for a declared reason. | No, unless a downstream stage explicitly supports partial analysis | No |
| `AnalysisSucceededNoFindings` | Compiler, AST, adapter, canonical contract, and detector execution all succeeded; no detector finding was returned. | Yes | Yes |
| `AnalysisSucceededWithFindings` | All required stages succeeded and one or more findings were returned. | Yes | Yes, only for unrelated detector classes |

The key invariant is:

> If raw AST exists, the source contains contract definitions, and normalized contract count is zero, the pipeline must produce `ASTNormalizationFailed` rather than continue as zero findings.

A failure state must stop detector execution for that source unit and must be visible to Comparator and reporting layers. Comparator should not convert an upstream normalization failure into `Rejected`; it should receive no finding or an explicit `Inconclusive` analysis context.

## E. Evidence provenance

Every finding and every analysis status should retain enough provenance to reproduce the decision. The minimum provenance record is:

| Field | Purpose |
|---|---|
| `source_id` and `source_sha256` | Identify exact source bytes and source-set identity. |
| `compiler_version` and `compiler_binary_hash` | Identify the compiler result. |
| `ast_format` and `raw_ast_sha256` | Identify raw compiler representation. |
| `ast_adapter_version` | Identify the version-specific conversion logic. |
| `canonical_ast_version` | Identify the detector input contract. |
| `source_range` | Point to the original source location used by a finding. |
| `detector_name` and `detector_version` | Identify the detector logic. |
| `analysis_status` | Distinguish success, no findings, and upstream failure. |
| `evidence_kind` and `evidence_excerpt` | Explain deterministic source evidence without replacing provenance. |
| `comparator_version` | Identify the evidence-verification logic. |

The raw AST and compiler diagnostics should remain available as supporting artifacts, while findings should reference them by hash rather than embedding unbounded compiler output.

## Comparator boundary

The Comparator remains a downstream evidence verifier. Its contract stays:

> **Finding + source evidence + invariant → Confirmed / Rejected / Inconclusive**

The Comparator must not become an old-Solidity parser or an AST adapter. If a canonical detector finding has a source range, the Comparator may verify source-level evidence. If upstream normalization failed, the pipeline must preserve that failure state and must not manufacture a rejected finding merely because no detector finding was emitted.

## Isolated proof of concept and evaluation

The design-approved implementation is a small isolated proof of concept, not a production refactor. It uses only the three already measured families: `Selfdestruct`, `block.timestamp`, and `DELEGATECALL`. The implementation and machine-readable output are under [`canonical_ast_poc/`](../canonical_ast_poc/), and the evaluation is recorded in [`POC_REPORT.md`](../canonical_ast_poc/POC_REPORT.md).

| POC path | Required observation |
|---|---|
| solc 0.4.10 → legacy raw AST → legacy adapter → canonical AST → existing detectors | The same detector semantics become available without the detector reading compiler version. |
| solc 0.8.25 → modern raw AST → modern adapter → canonical AST → existing detectors | The modern path preserves the current findings and source ranges. |
| Fixed controls through both adapters | Canonical AST and detectors remain clean on safe controls. |
| Invalid old AST/container | Pipeline returns `ASTNormalizationFailed`; it does not return zero findings as success. |

The POC remains isolated under the compatibility track. It does not alter the primary benchmark, real-world adjudication status, or production analyzer. Its result is evidence for independent review, not an automatic production merge. Parity remains Quarantined and is not re-adjudicated by this POC.

## Track separation and decision gates

The project should retain three independent tracks:

| Track | Purpose | Current status |
|---|---|---|
| Controlled track | Synthetic benchmark and deterministic regression | Primary Precision/Recall/F1 remains 1.0/1.0/1.0; compatibility fixtures remain outside it. |
| Compatibility track | Historical compiler, raw AST, adapter, canonical AST, and failure semantics | Isolated POC implemented and evaluated; production adoption remains pending independent review. |
| Real-World track | Independent adjudication and abstention | Nomad, BonqDAO, and Parity remain Quarantined; no Case #4. |

The next gate is independent review of the isolated POC, followed by a separate production decision. No alias, detector patch, Comparator patch, random compiler fallback, or architecture-wide refactor is included in this change.

## Open design questions

The design still requires decisions before production adoption: how verified deployment metadata is prioritized over pragma constraints; how multi-file source manifests are normalized; which additional legacy AST schemas receive first-class adapters; whether the minimum semantic contract should expand beyond the POC families; how adapter versioning is released; and how partial source-set failures are represented. These questions remain open rather than being hidden inside the isolated POC.

## References

[1]: REPORT.md "Read-only Compiler / AST Boundary Audit"

[2]: metadata/compiler_ast_boundary_experiment.json "Machine-readable boundary experiment"

[3]: ../cross_detector/REPORT.md "Cross-Detector Compatibility Audit"

[4]: ../../../../analyzers/solidity_ast.py "Current compiler invocation and AST normalization"

[5]: ../../../../analyzers/solidity_analyzer.py "Current detector path"

[6]: ../../../../verification/comparator.py "Current Comparator contract"
