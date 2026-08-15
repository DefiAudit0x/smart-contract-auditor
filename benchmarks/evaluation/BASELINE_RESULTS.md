# Baseline Comparison

This document records the isolated evaluation tracks produced by `benchmarks/run_track_baseline.py`. The tracks are intentionally non-additive: the primary benchmark remains the only source of the project's headline detector metrics, while supplementary suites and the Real-World candidate registry are reported separately.

## Current run

The latest local run used the ten-case Synthetic Ground Truth Benchmark, the existing Synthetic negative controls and attack variants, five Real-World-inspired negative controls, ten quarantined Real-World candidates, and the provenance-bearing LLM report generated with `gpt-5-mini`.

| Track | Scope | Result | Included in primary metrics |
|---|---|---:|---:|
| Synthetic primary | 10 vulnerable/fixed cases | TP=10, FP=0, FN=0; Precision=1.0, Recall=1.0 | Yes |
| Synthetic supplementary controls | Existing safe controls | FP checks=0 | No |
| Synthetic supplementary variants | 5 attack variants | 7/7 detector assertions confirmed; 5/5 PoCs passed | No |
| Real-World negative controls | 5 safe, incident-inspired fixtures | 15 absence checks; FP checks=0; FP rate=0.0 | No |
| Real-World candidates | 10 provenance records | 0 admitted; 10 quarantined | No |
| LLM comparison | 10 controls + 5 variants; 7 positive assertions | TP=7, FP=3, FN=0; Precision=0.7, Recall=1.0 | No |

The LLM value is an experimental comparison, not a replacement for Ground Truth. The model, prompt version, source hashes, catalog check, usage, and per-case outputs are recorded in the evaluation run artifact. A later run may change the LLM metrics even when the source corpus is unchanged; therefore the report must always be interpreted together with its provenance fields.

## Real-World admission boundary

The registry at [`benchmarks/real_world/registry.json`](../real_world/registry.json) contains discovery candidates only. Each candidate has a separate quarantined adjudication record under [`benchmarks/real_world/adjudications/`](../real_world/adjudications/). The current baseline runner reports these cases but explicitly excludes them from metrics because source implementation versions, exact line mappings, independent reproduction, and reviewer adjudication are not complete for all cases.

> A real-world incident reference can support a hypothesis, but it cannot by itself become a detector label. The source version and affected location must be pinned first, and Ground Truth must remain independent of analyzer and LLM output.

The first candidate set was discovered from [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs) and cross-checked against incident analyses. The selected references include the official Nomad root-cause analysis [1], the Bonq Protocol post-mortem [2], Sturdy's exploit post-mortem [3], Conic's post-mortem [4], Euler's incident analysis [5], BlockSec's KyberSwap analysis [6], the Seneca incident analysis [7], and CertiK's Dough Finance analysis [8]. These sources are evidence for curation and source mapping; they are not silently copied into the analyzer or treated as automatically executable dependencies.

## First adjudication result: Nomad Bridge

Nomad is the first candidate processed through the complete stage-by-stage workflow. The official `Replica.sol` source is pinned, its relevant source ranges are recorded, the cited `process(bytes)` transaction is independently anchored to Ethereum mainnet block `15259101`, and the owned minimal reproduction passes its vulnerable/fixed contrast. The narrow invariant returns `Violated` for the vulnerable model and `Satisfied` for the fixed model. The current analyzer does not have a semantically valid detector mapping for this root-cause family, so the comparator is `NotApplicable` rather than forced into a false detector label. The LLM observed `block.timestamp Usage (AST)` on both sides, which is recorded as an observation only.

Nomad remains quarantined because the owned reproduction is not a historical mainnet fork, the current detector taxonomy does not cover zero-root message-proof validation, and a second independent adjudication is pending. See [`rw-003-nomad-report.md`](../real_world/adjudications/rw-003-nomad-report.md) and [`rw-003-nomad-pipeline.json`](../real_world/adjudications/rw-003-nomad-pipeline.json).

## Second adjudication result: BonqDAO

BonqDAO is the second candidate processed through the complete stage-by-stage workflow. Polygon transactions, independent incident analyses, the exact-match verified `TellorPriceFeed` source, the pinned TellorFlex implementation, and the owned dispute-window contrast establish the incident mechanism. The owned invariant returns `Violated` for direct `getCurrentValue` consumption and `Satisfied` for the historical cutoff path; the self-contained Foundry PoC passes both checks.

BonqDAO remains quarantined because oracle manipulation and spot-price consumption without a dispute window are not covered by the current detector taxonomy. Static and LLM runs observed `block.timestamp Usage (AST)`, but that observation is not a semantically valid Bonq detector mapping. The comparator is therefore `NotApplicable`, and the case is excluded from all admitted-case metrics. See [`rw-004-bonqdao-report.md`](../real_world/adjudications/rw-004-bonqdao-report.md) and [`rw-004-bonqdao-pipeline.json`](../real_world/adjudications/rw-004-bonqdao-pipeline.json).

## Third adjudication result: Parity WalletLibrary

Parity is the first case in this set whose semantic family is represented by the controlled taxonomy: the independently established root cause includes a destructive shared-library `kill`/`suicide` path, mapping to the existing `Selfdestruct` family. The exact Etherscan source, the initialization and kill transactions, the owned invariant contrast, and the self-contained Foundry PoC are all complete.

Parity nevertheless remains quarantined. The exact deployed Solidity 0.4.x source uses legacy `suicide(_to)`, while the current analyzer/comparator path is fixed to modern compiler/matcher behavior and did not confirm `Selfdestruct` on the exact source. The LLM predicted `Selfdestruct`, and the owned modern contrast was detector- and Comparator-confirmed, but neither observation substitutes for exact-source evidence. The A/B/C result is therefore **A: Missed, B: Completed observation, C: Quarantined**. See [`rw-001-parity-report.md`](../real_world/adjudications/rw-001-parity-report.md) and [`rw-001-parity-pipeline.json`](../real_world/adjudications/rw-001-parity-pipeline.json).

## Three-case cross-case review

The joint review distinguishes two taxonomy-definition gaps from one detector implementation/compatibility gap. Nomad lacks a message-proof validation family, BonqDAO lacks an oracle/dispute-window family, and Parity has semantic `Selfdestruct` coverage but no exact-source confirmation for the legacy spelling. All three remain metric-neutral. No detector or architecture change is justified from these three cases alone. See [`taxonomy-gap-analysis-three-cases.md`](../real_world/adjudications/taxonomy-gap-analysis-three-cases.md).

## Historical Compatibility Audit: Selfdestruct

The measurement-only historical compatibility track contains 25 fixtures across Solidity 0.4.11, 0.5.17, 0.6.12, 0.7.6, and 0.8.25. The exact source forms are separated from current analyzer behavior: Solidity 0.4.x compiles both `selfdestruct` and legacy `suicide`, but the current detector and Comparator return **HIT/Confirmed** only for the canonical `selfdestruct` spelling. The 0.4.x `suicide` and assembly-`suicide` fixtures compile and produce **MISS/Rejected**. From Solidity 0.5.x onward, the `suicide` fixtures fail in the historical compiler matrix, while the `selfdestruct` forms remain **HIT/Confirmed**. Fixed controls compile cleanly and remain detector-clean.

This result is measurement-only: no production detector, parser, compiler-selection path, Comparator matcher, or architecture was changed. It identifies a narrowly scoped legacy-alias compatibility gap rather than proving an architecture-wide failure. The primary benchmark remains unchanged at Precision=1.0, Recall=1.0, F1=1.0. See [`REPORT.md`](../historical_compatibility/REPORT.md) and [`selfdestruct_compatibility_measurement.json`](../historical_compatibility/metadata/selfdestruct_compatibility_measurement.json).

## Cross-Detector Compatibility Audit

The measurement-only cross-detector track extends the historical probe to three existing families: `Selfdestruct`, `block.timestamp Usage (AST)`, and `DELEGATECALL Usage (AST)`. It contains 45 rows across five Solidity compiler families and three forms per detector: canonical, legacy/equivalent, and fixed. The historical compiler accepts all canonical forms, while the unchanged current normalized-AST path succeeds only for the Solidity 0.8.25 canonical rows. The `Selfdestruct` textual fallback still detects canonical historical text; the two AST-only detectors miss canonical historical source when the current compiler path cannot normalize it. Legacy forms are either compiler-rejected in later versions or rejected by the current detector/Comparator vocabulary.

This is evidence of a **possible shared compiler/AST compatibility boundary**, not yet an architecture verdict. No alias, detector, Comparator matcher, compiler fallback, or architecture change was made, and Case #4 remains paused. See [`cross-detector/REPORT.md`](../historical_compatibility/cross_detector/REPORT.md) and [`cross_detector_compatibility_measurement.json`](../historical_compatibility/cross_detector/metadata/cross_detector_compatibility_measurement.json).

## Architecture Boundary Audit

The read-only Compiler/AST boundary investigation traced the actual production path through `SolidityAnalyzer.analyze_file`, `SolidityAnalyzer._parse_single_file`, `solidity_ast.compile_to_ast`, `solcast.from_ast`, `analyze_contracts`, `_extract_function`, and the base `LanguageAnalyzer.analyze_file` agent loop. It confirmed that `SOLC_VERSION = "0.8.25"` is fixed in the current path; no pragma-based compiler selection occurs. Exact Parity `WalletLibrary.sol` source compiles to raw AST with direct solc 0.4.10, but `solcast.from_ast` returns a plain `dict` with `children` and `name`, so the current `analyze_contracts` contract extraction returns zero normalized contracts. A minimal 0.4.11 `suicide` probe reproduces the same container incompatibility. The exact Parity source fails the 0.4.11 compiler with a source-specific historical assembly stack error, while a modern 0.8.25 control returns a `SourceUnit` and normalizes to one contract/function with `uses_selfdestruct=true`.

This confirms a bounded compiler-selection limitation and an old-AST normalizer/container incompatibility, but does not establish a detector-interface failure or justify a fix. The investigation is read-only: no alias, compiler fallback, normalizer adapter, detector, Comparator, or architecture component was changed. See [`architecture_boundary/REPORT.md`](../historical_compatibility/architecture_boundary/REPORT.md) and [`compiler_ast_boundary_experiment.json`](../historical_compatibility/architecture_boundary/metadata/compiler_ast_boundary_experiment.json).

## Reproduction

From the repository root, the deterministic cross-track report can be regenerated with:

```bash
PYTHONPATH=. python3 benchmarks/run_track_baseline.py \
  --llm-report /path/to/evaluation_run.json \
  --json-out /path/to/track_baseline_report.json
```

The primary benchmark remains runnable independently with `PYTHONPATH=. python3 benchmarks/run_benchmark.py --require-poc`. The Real-World negative-control track is independently runnable with `PYTHONPATH=. python3 benchmarks/real_world/run_negative_controls.py`.

## References

[1]: https://medium.com/nomad-xyz-blog/nomad-bridge-hack-root-cause-analysis-875ad2e5aacd "Nomad Bridge Hack: Root Cause Analysis"

[2]: https://medium.com/@omniscia.io/bonq-protocol-incident-post-mortem-4fd79fe5c932 "Bonq Protocol Incident Post-Mortem"

[3]: https://sturdyfinance.medium.com/exploit-post-mortem-49261493307a "Sturdy Exploit Post-Mortem"

[4]: https://medium.com/@ConicFinance/post-mortem-eth-and-crvusd-omnipool-exploits-c9c7fa213a3d "Conic Finance Post Mortem"

[5]: https://rekt.news/euler-rekt "Euler Finance - REKT"

[6]: https://blocksec.com/blog/yet-another-tragedy-of-precision-loss-an-in-depth-analysis-of-the-kyber-swap-incident-1 "KyberSwap Precision-Loss Analysis"

[7]: https://rekt.news/seneca-protocol-rekt "Seneca Protocol - REKT"

[8]: https://www.certik.com/resources/blog/3SMOuGMCSttY4pQW6I49W2-dough-finance-incident-analysis "Dough Finance Incident Analysis"
