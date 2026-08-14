# Benchmark Methodology

## Purpose

The repository contains a deterministic regression corpus for the Solidity analyzer. The primary benchmark measures whether selected detectors fire on intentionally vulnerable fixtures, remain quiet on paired fixed fixtures, and can be supported by source evidence, declared invariants, and executable Foundry PoCs. Separate negative controls measure expected detector absence, while attack variants test whether multiple source patterns within an existing vulnerability family remain detectable.

> The benchmark is a measurement instrument for the covered fixtures. It is not a claim that ten categories represent the Solidity security universe or that a clean fixture is a complete production security guarantee.

## Primary corpus

The primary corpus contains ten metadata-driven cases. Each case contains `vulnerable.sol`, `fixed.sol`, `metadata.json`, and `poc.t.sol`.

| Case | Vulnerability | Primary detector | Invariant | PoC mode |
|---|---|---|---|---|
| `reentrancy` | Reentrancy | `Reentrancy (AST)` | `reentrancy.external_calls_guarded` | `negative_control` |
| `delegatecall` | Untrusted delegatecall | `DELEGATECALL Usage (AST)` | `no_untrusted_delegatecall` | `exploit` |
| `selfdestruct` | Destructive selfdestruct path | `Selfdestruct` | `no_selfdestruct` | `exploit` |
| `public_mint` | Unauthorised public mint | `Public Mint/Burn` | `authorized_mint` | `exploit` |
| `tx_origin` | `tx.origin` authentication | `tx.origin Auth (AST)` | `no_tx_origin_auth` | `exploit` |
| `flash_loan` | Unguarded flash-loan callback | `Flash Loan Attack Vector` | `flash_loan.callback_guarded` | `exploit` |
| `storage_collision` | Delegatecall storage collision risk | `Storage Collision (Delegatecall)` | `storage_collision.no_delegatecall_layout_risk` | `exploit` |
| `unchecked_transfer` | Unchecked `send` result | `Unchecked Transfer` | `unchecked_transfer.return_value_checked` | `exploit` |
| `unbounded_loop` | Unbounded distribution loop | `Unbounded Loop (AST)` | `dos.distribution_bounded` | `exploit` |
| `timestamp` | Timestamp-dependent gate | `block.timestamp Usage (AST)` | `timestamp.no_block_timestamp_gate` | `negative_control` |

The runner discovers only directories containing `metadata.json`, so the primary corpus remains isolated from the supplementary suites.

## Measurement procedure

For each primary case, the runner validates metadata and both Solidity files, runs `SolidityAnalyzer` on the vulnerable and fixed sources, compares the expected detector against both result sets, and applies the deterministic comparator to matching vulnerable findings. The comparator records a normalized hypothesis, source verification, evidence excerpt, and one of `Confirmed`, `Rejected`, or `Inconclusive`. The runner then evaluates the declared invariant on both sources and executes the declared Foundry PoC through the repository-owned safe wrapper. The final report aggregates detector metrics, comparator statuses, invariant statuses, and PoC statuses.

The strict command is:

```bash
export PATH="$HOME/.foundry/bin:$PATH"
PYTHONPATH=. python benchmarks/run_benchmark.py --require-poc
```

The strict option fails when a PoC cannot execute. Without it, an unavailable runtime is reported as `Inconclusive` rather than converted into a false success.

## Confusion matrix and metrics

For each primary detector/case pair, the expected labels are:

| Condition | Classification |
|---|---|
| Detector appears in vulnerable findings | True Positive |
| Expected detector absent from vulnerable findings | False Negative |
| Detector appears in fixed findings | False Positive |
| Expected detector absent from fixed findings | True Negative |

The Metrics Engine reports aggregate metrics and a `per_detector` table. Secondary findings are retained in reports but do not change the primary denominator.

```text
precision = TP / (TP + FP)
recall    = TP / (TP + FN)
F1        = 2 * precision * recall / (precision + recall)
FP rate   = FP / (FP + TN)
FN rate   = FN / (FN + TP)
```

If a denominator is zero, the engine returns `null`. Comparator and runtime `Inconclusive` states remain separate and do not silently become FP, FN, or Passed.

## Supplementary suites

### Negative controls

`benchmarks/negative_controls/manifest.json` defines ten safe contracts. The suite analyzes each contract with the same `SolidityAnalyzer` used by the primary benchmark and asserts that the category-specific detector is absent. The suite currently covers reentrancy, delegatecall/storage layout, selfdestruct, authorized minting, `msg.sender` authorization, guarded flash loans, checked value calls, bounded distribution, and `block.number` gates.

Run it with:

```bash
PYTHONPATH=. pytest -q tests/test_negative_controls.py
```

The extended runner reports the number of expected absence checks and the control false-positive rate without adding these cases to the primary TP/FP/FN denominator.

### Attack variants

`benchmarks/attack_variants/manifest.json` defines five distinct variants: cross-function reentrancy, mutable delegatecall proxy, callback flash loan, attacker-inflatable batch loop, and a timestamp claim gate. Each variant has a Solidity source and a self-contained Foundry PoC. They are checked for expected detector coverage, deterministic comparator confirmation, and PoC success.

Run it with:

```bash
export PATH="$HOME/.foundry/bin:$PATH"
PYTHONPATH=. python benchmarks/run_extended_benchmark.py --json-out extended-benchmark.json
PYTHONPATH=. pytest -q tests/test_attack_variants.py
```

## Current reproducible results

With Solidity `0.8.25`, Foundry `v1.7.1`, and the current local source tree, the primary benchmark reports:

| Metric | Value |
|---|---:|
| Primary cases | 10 |
| TP | 10 |
| FP | 0 |
| FN | 0 |
| TN | 10 |
| Precision | 1.0 |
| Recall | 1.0 |
| F1 | 1.0 |
| FP rate | 0.0 |
| FN rate | 0.0 |
| Comparator Confirmed | 10 |
| Invariant vulnerable Violated | 10 |
| Invariant fixed Satisfied | 10 |
| PoC Passed | 10 |

The supplementary extended run reports ten controls with eleven expected absence checks and zero control false positives. It reports five attack variants with seven expected detector assertions, seven true positives, zero false negatives, seven comparator confirmations, and five passing PoCs.

These values describe the current fixtures and toolchain only. They must be recalculated whenever source fixtures, metadata, detector logic, comparator rules, compiler, or Foundry version changes.

## Deterministic versus LLM comparison

`benchmarks/run_llm_comparison.py` provides a separate structured-output comparison over the ten controls and five attack variants. It obtains the live model catalog before model selection, uses an explicit detector enum and JSON schema, and records model output, rationale, token usage, errors, and metrics. One recorded run used `gpt-5-mini` and produced seven expected positives, zero missed positives, and three control false positives, for LLM precision `0.7` and recall `1.0`. The deterministic targeted layer produced seven true positives, zero false positives, and zero false negatives on the same expected assertions. A prior run with the same model produced a different false-positive count, so the LLM result is explicitly treated as non-deterministic experimental evidence rather than a fixed regression gate.

This comparison is descriptive rather than a universal ranking. Prompt wording, model version, temperature defaults, source scope, and the selected target detectors can change the result.

## Adding a case or variant

A new primary case should include a minimal vulnerable fixture, a semantically fixed pair, metadata with one primary detector and one invariant, and a self-contained PoC. The fixed fixture must remove the primary vulnerable condition rather than merely rename it. A new negative control should document the safe pattern and the detector expected to remain absent. A new attack variant should represent a distinct source pattern and include a PoC that proves the claimed runtime behavior. Tests should assert the intended detector outcome, comparator status, invariant contrast where applicable, and PoC mode.

## References

[1]: benchmarks/README.md "Benchmark directory and metadata schema"

[2]: benchmarks/run_benchmark.py "Primary benchmark runner"

[3]: benchmarks/run_extended_benchmark.py "Supplementary controls and variants runner"

[4]: benchmarks/run_llm_comparison.py "Structured deterministic-versus-LLM comparison"

[5]: verification/comparator.py "Deterministic comparator"

[6]: verification/invariants.py "Invariant engine"

[7]: verification/poc.py "Executable PoC wrapper"

[8]: verification/metrics.py "Unified metrics engine"
