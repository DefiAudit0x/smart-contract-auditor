# Architecture Boundary Audit: Compiler → Raw AST → Normalizer → Detector

## Scope and read-only rule

This is a **read-only architecture investigation** limited to the Solidity compiler/AST boundary. It does not modify a detector, add a legacy alias, add a compiler fallback, change AST normalization, change Comparator behavior, or refactor architecture. The purpose is to answer one question:

> Why can the system obtain a historical raw AST, but fail to produce the normalized AST contract expected by AST-based detectors?

The machine-readable experiment is [`compiler_ast_boundary_experiment.json`](metadata/compiler_ast_boundary_experiment.json). It includes the exact Parity source SHA-256, the direct solc 0.4.10 and 0.4.11 observations, a minimal 0.4.11 control, and a modern 0.8.25 control.

## 1. Actual production trace

The current production path is the following concrete call chain.

| Stage | File and function | Observed behavior |
|---|---|---|
| Source entry | `analyzers/solidity_analyzer.py:66-69` — `SolidityAnalyzer.analyze_file(filename, code)` | Receives the filename and complete Solidity source, calls `_parse_single_file`, then delegates to the base agent loop. |
| Compiler/AST entry | `analyzers/solidity_analyzer.py:71-79` — `SolidityAnalyzer._parse_single_file` | Calls `compile_to_ast(code)`. If the result is truthy, extends `self._contracts`; if not, it only logs a debug message and leaves the contract list empty. |
| Compiler selection | `analyzers/solidity_ast.py:21` — `SOLC_VERSION = "0.8.25"` | A single fixed compiler version is declared. No pragma inspection or version selection occurs in this path. |
| solc invocation | `analyzers/solidity_ast.py:115-121` — `compile_to_ast` | Calls `solcx.compile_source(resolved, output_values=['ast'], solc_version=SOLC_VERSION)`. The source pragma is not used to select a historical compiler. |
| Raw AST conversion | `analyzers/solidity_ast.py:121-126` — `compile_to_ast` | Reads the compiler result’s `ast` field and calls `from_ast(ast_json)` from `solcast`. The returned object is passed upward without a schema/version assertion. |
| Contract normalization | `analyzers/solidity_ast.py:165-200` — `analyze_contracts` | Iterates the normalized unit and accepts only nodes whose type is `ContractDefinition`; it then extracts each function with `_extract_function`. |
| Function normalization | `analyzers/solidity_ast.py:203-290` — `_extract_function` | Traverses normalized AST children and sets `uses_selfdestruct`, `uses_delegatecall`, `uses_tx_origin`, `uses_block_timestamp`, `uses_assembly`, and related fields on `ASTFunction`. |
| Detector execution | `analyzers/base.py:101-134` — `LanguageAnalyzer.analyze_file` | Iterates every registered `Agent` and calls `agent.check(filename, code)`. AST detectors read `self._contracts`; source fallbacks read the original `code`. |
| Selfdestruct exception | `analyzers/solidity_analyzer.py:200-213` — `_check_selfdestruct` | First checks normalized AST, then falls back to the literal string `"selfdestruct" in code`; it does not map `suicide` to the same semantic signal. |
| Deterministic evidence | `verification/comparator.py:142-148` — `_match_selfdestruct` and `verification/comparator.py:242-257` — `collect_evidence`/`verify_hypothesis` | Comparator evidence is source-level and lexical. The Selfdestruct matcher searches for `\bselfdestruct\s*\(` and has no `suicide` branch. |

The production trace therefore has no compiler negotiation stage. It has a fixed `0.8.25` compiler invocation, followed by a conversion call whose output type is not validated before `analyze_contracts` consumes it.

## 2. Exact boundary experiment

The experiment uses the exact pinned Parity `WalletLibrary.sol` source with SHA-256 `dedb7a47a4a37cf61689e8f655beb58b4fe0e026ef591a93ccb62be4041b2e42`. For historical compiler execution, it invokes the official solc 0.4.10 and 0.4.11 binaries directly because the installed `py-solc-x` wrapper does not expose a 0.4.10 installer. It then feeds the resulting raw AST into the same `solcast.from_ast` and `analyze_contracts` path used by the current normalizer. The modern control uses the existing `solc 0.8.25` path.

| Probe | Compiler result | Raw AST result | Current `compile_to_ast` path | Same normalizer on historical raw AST | Boundary interpretation |
|---|---|---|---|---|---|
| Exact Parity source, solc 0.4.10 | **Compiled**; one source AST; raw tokens include `suicide` and `delegatecall` | Present | **Compile failed** because current path invokes 0.8.25 against `pragma ^0.4.9` | `solcast.from_ast` returns a plain `dict` with `children` and `name`; `analyze_contracts` receives no iterable of normalized AST nodes and returns zero contracts/functions | **A and B:** fixed compiler selection fails first; when raw AST is supplied, the normalizer output container is incompatible and the failure is silent at contract extraction. |
| Exact Parity source, solc 0.4.11 | **Compile failed** on the exact deployed source with an `Unbalanced stack at the end of a block` compiler error in the historical assembly; this is source/compiler-specific | Not available for this exact row | **Compile failed** under current 0.8.25 path | Not run | Does not disprove the boundary; the minimal 0.4.11 control isolates the normalizer behavior below. |
| Minimal `suicide`, solc 0.4.11 | **Compiled**; raw AST token `suicide` present | Present | **Compile failed** under current 0.8.25 path | `solcast.from_ast` again returns a plain `dict` with `children` and `name`; normalized contract/function count is zero | **B:** historical raw AST exists, but the current normalizer/container contract does not produce the `SourceUnit`/node structure expected by `analyze_contracts`. |
| Modern `selfdestruct`, solc 0.8.25 | **Compiled**; raw AST token `selfdestruct` present | Present | **Normalized** as a `SourceUnit`; one contract and one function | Same normalizer produces one contract, one function, and `uses_selfdestruct: true` | Modern control passes through the current pipeline. |

The raw AST is therefore not universally missing. The experiment identifies two separate boundaries. The first is **compiler selection**: production always invokes 0.8.25 and cannot compile a 0.4.x source. The second is **AST normalization/container compatibility**: when the old raw AST is manually supplied, `solcast.from_ast` returns a plain dictionary rather than the modern `SourceUnit` object. The current `analyze_contracts` function does not reject that type; it iterates the dictionary keys, finds no `ContractDefinition` nodes, and silently yields zero normalized contracts.

## 3. A/B/C classification

| Question | Result | Evidence |
|---|---|---|
| **A — Compiler selection** | Confirmed for the production path | `SOLC_VERSION` is fixed to `0.8.25`; exact Parity source requiring `^0.4.9` fails before raw AST is returned. |
| **B — AST normalization** | Confirmed for an old raw AST supplied to the current normalizer | 0.4.10 Parity raw AST and minimal 0.4.11 `suicide` raw AST both exist, but `from_ast` returns `dict`; `analyze_contracts` produces zero contracts/functions. |
| **C — Detector contract** | Not established as the primary boundary | The AST-based detectors do not receive normalized function objects in the failing rows, so a detector-specific schema expectation is not tested yet. The modern control reaches `ASTFunction` and detects `selfdestruct`. |
| Evidence/Comparator | Not the first boundary in this experiment | Comparator independently confirms canonical source patterns when its lexical matcher exists; it is not involved in producing normalized AST input. |

The correct architecture verdict is therefore **not yet a project-wide architecture verdict**, but the bounded compiler/AST investigation has confirmed both a fixed compiler-selection limitation and a historical AST normalization/container incompatibility. A detector contract failure remains unproven because the failing historical rows do not reach the detector with a valid normalized AST contract.

## 4. Why Parity’s previous result looked different

The earlier Parity A/B/C result reported an exact-source detector miss and a Comparator rejection for `suicide(_to)`. That remains correct. This boundary trace explains the upstream cause more precisely: the current production compiler path cannot parse the historical source under 0.8.25, and the current normalizer cannot consume the old AST shape even when the raw AST is supplied manually. Selfdestruct’s textual fallback allows canonical `selfdestruct` text to be detected in some historical probes, but it does not provide semantic normalization for `suicide`.

The exact Parity 0.4.11 compiler failure is recorded separately rather than conflated with the normalizer result. The minimal 0.4.11 probe proves that the old compiler can produce a raw AST for a valid historical `suicide` contract, which is the required control for isolating the AST boundary.

## 5. Current decision

This stage remains **read-only**. No alias, compiler fallback, AST adapter, normalizer change, detector modification, Comparator change, or architecture refactor is justified inside this measurement commit. The next design review can now distinguish two possible work items: a version-aware compiler-selection layer and an AST compatibility adapter for old solc output. A detector-interface redesign should not be proposed until a normalized `ASTFunction` object is successfully produced for a historical source and the detector still fails.

The primary benchmark, real-world adjudications, and metrics are untouched by this investigation. The three real-world cases remain quarantined, and no fourth case is introduced.

## References

[1]: metadata/compiler_ast_boundary_experiment.json "Machine-readable compiler/AST boundary experiment"

[2]: ../../../../analyzers/solidity_ast.py "Current compiler invocation and AST normalization"

[3]: ../../../../analyzers/solidity_analyzer.py "Current Solidity analyzer and detector path"

[4]: ../../../../analyzers/base.py "Current agent execution contract"

[5]: ../../../../verification/comparator.py "Current deterministic Comparator path"

[6]: ../REPORT.md "Cross-Detector Compatibility Audit"

[7]: ../../../real_world/source_snapshots/parity/WalletLibrary.sol "Pinned exact Parity WalletLibrary source snapshot"
