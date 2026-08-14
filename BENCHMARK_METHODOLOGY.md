# Benchmark Methodology

## Purpose

The benchmark is a deterministic regression corpus for the current Solidity analyzer. It measures whether selected primary detectors fire on intentionally vulnerable fixtures, remain quiet on paired fixed fixtures, and can be supported by source evidence, declared invariants, and executable PoC tests.

The benchmark is a measurement instrument, not a claim that five categories represent the Solidity security universe.

## Corpus

| Case | Vulnerability | Primary detector | Invariant | PoC mode |
|---|---|---|---|---|
| `reentrancy` | Reentrancy | `Reentrancy (AST)` | `reentrancy.value_call_guard` | `negative_control` |
| `delegatecall` | Untrusted delegatecall | `DELEGATECALL Usage (AST)` | `delegatecall.no_external_delegatecall` | `exploit` |
| `selfdestruct` | Destructive selfdestruct path | `Selfdestruct` | `selfdestruct.no_destroy_path` | `exploit` |
| `public_mint` | Unauthorised public mint | `Public Mint/Burn` | `public_mint.owner_guard` | `exploit` |
| `tx_origin` | `tx.origin` authentication | `tx.origin Auth (AST)` | `tx_origin.no_tx_origin_auth` | `exploit` |

Every case contains `vulnerable.sol`, `fixed.sol`, `metadata.json`, and `poc.t.sol`. Metadata is the source of the expected primary detector, severity, location, invariant identifier, PoC path, and PoC mode.

## Measurement procedure

For each metadata case, the runner performs the following sequence:

1. It loads and validates metadata and both Solidity files.
2. It runs `SolidityAnalyzer` on the vulnerable and fixed sources.
3. It compares the expected primary detector with the vulnerable findings and fixed findings.
4. It converts the matching finding into a deterministic comparator result: hypothesis, verification, evidence, and `Confirmed`, `Rejected`, or `Inconclusive`.
5. It evaluates the declared invariant on both sources and records `Satisfied`, `Violated`, or `Inconclusive` with line evidence.
6. It runs the declared Foundry PoC through the safe wrapper and records `Passed`, `Failed`, or `Inconclusive`. A `negative_control` is not interpreted as a successful exploit.
7. It aggregates detector metrics and serializes the result for review or CI.

The strict command is:

```bash
export PATH="$HOME/.foundry/bin:$PATH"
PYTHONPATH=. python benchmarks/run_benchmark.py --require-poc
```

The strict option fails when a PoC cannot execute. Without it, an unavailable runtime is reported as `Inconclusive` rather than converted into a false success.

## Confusion matrix

For each case's primary detector, the expected labels are:

| Condition | Classification |
|---|---|
| Detector appears in vulnerable findings | True Positive |
| Expected detector absent from vulnerable findings | False Negative |
| Detector appears in fixed findings | False Positive |
| Expected detector absent from fixed findings | True Negative |

The corpus-level values are sums over the five primary detector/case pairs. Secondary findings are retained in the output but do not change the primary denominator.

## Metrics

The Metrics Engine computes:

```text
precision = TP / (TP + FP)
recall    = TP / (TP + FN)
F1        = 2 * precision * recall / (precision + recall)
FP rate   = FP / (FP + TN)
FN rate   = FN / (FN + TP)
```

If a denominator is zero, the engine returns `null`. Comparator and runtime `Inconclusive` states are reported separately and do not silently become FP, FN, or Passed.

## Current reproducible result

With the current five-case corpus, Solidity compiler `0.8.25`, and Foundry `v1.7.1`, the latest local run reports:

| Metric | Value |
|---|---:|
| TP | 5 |
| FP | 0 |
| FN | 0 |
| TN | 5 |
| Precision | 1.0 |
| Recall | 1.0 |
| F1 | 1.0 |
| FP rate | 0.0 |
| FN rate | 0.0 |
| Comparator Confirmed | 5 |
| Invariant vulnerable Violated | 5 |
| Invariant fixed Satisfied | 5 |
| PoC Passed | 5 |
| PoC Failed | 0 |
| PoC Inconclusive | 0 |

These values describe this corpus and run configuration only. They must be recalculated whenever source fixtures, metadata, detector logic, compiler, or Foundry version changes.

## Adding a case

A new case should include a minimal vulnerable fixture, a semantically fixed pair, metadata with one primary detector and one invariant, and a self-contained PoC. The fixed fixture must remove the primary vulnerable condition rather than merely rename it. Tests must assert vulnerable detection, fixed cleanliness for the primary detector, comparator confirmation, invariant contrast, and correct PoC mode.

## References

[1]: benchmarks/README.md "Benchmark directory and metadata schema"

[2]: benchmarks/run_benchmark.py "Benchmark runner"

[3]: verification/comparator.py "Deterministic comparator"

[4]: verification/invariants.py "Invariant engine"

[5]: verification/poc.py "Executable PoC wrapper"

[6]: verification/metrics.py "Unified metrics engine"
