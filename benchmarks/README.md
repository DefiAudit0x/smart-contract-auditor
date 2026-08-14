# Solidity Ground Truth Benchmark

This directory contains a small, deterministic benchmark for the Solidity static analyzer. Each case pairs a deliberately vulnerable contract with a minimally remediated counterpart so detector behavior can be measured without LLM output or network access.

## Dataset layout

Each vulnerability category contains three files:

```text
benchmarks/<category>/
├── vulnerable.sol
├── fixed.sol
└── metadata.json
```

The vulnerable contracts are adapted from the repository's existing `stress_test/` corpus. The fixed contracts remove or remediate the primary pattern represented by the case. They are intended as regression fixtures, not as a complete security guarantee for production contracts.

## Metadata schema

Every `metadata.json` file uses this schema:

| Field | Meaning |
|---|---|
| `vulnerability` | Human-readable vulnerability name. |
| `location` | Function or Solidity construct containing the primary pattern. |
| `severity` | Expected severity of the primary vulnerability. |
| `category` | Stable benchmark category identifier. |
| `invariant_id` | Deterministic invariant evaluated for the pair. |
| `poc_file` | Repository-owned Foundry test fixture for executable verification. |
| `poc_mode` | `exploit` for positive reproduction or `negative_control` for an expected blocked path. |
| `expected_detectors` | Detector names that must appear for `vulnerable.sol`. |
| `expected_clean` | Whether `fixed.sol` is expected to avoid every detector in `expected_detectors`. |

The current primary benchmark covers ten categories: reentrancy, delegatecall, selfdestruct, unrestricted minting, `tx.origin` authentication, flash loans, storage collision, unchecked transfers, unbounded loops, and timestamp-dependent gates. The expected detector names are taken directly from `analyzers/solidity_analyzer.py`. Supplementary safe controls live under `negative_controls/`, while attack variants live under `attack_variants/`; neither directory is discovered by the primary runner.

## Running the benchmark

From the repository root:

```bash
python benchmarks/run_benchmark.py
python benchmarks/run_benchmark.py --require-poc
pytest -q tests/test_benchmark.py
```

The runner reports per-case true positives, false positives, and false negatives. For this benchmark, a true positive means an expected detector is present in the vulnerable contract, a false positive means an expected detector is present in the fixed contract, and a false negative means an expected detector is absent from the vulnerable contract. The metrics are scoped to the primary expected detectors in each metadata file; they do not represent full analyzer precision or recall across all Solidity vulnerabilities. The default command reports PoC execution as `Inconclusive` when Foundry is unavailable; `--require-poc` turns that unavailable runtime into a failing gate.

The supplementary suites can be run with:

```bash
PYTHONPATH=. pytest -q tests/test_negative_controls.py tests/test_attack_variants.py tests/test_adversarial_comparator.py
export PATH="$HOME/.foundry/bin:$PATH"
PYTHONPATH=. python benchmarks/run_extended_benchmark.py --json-out extended-benchmark.json
PYTHONPATH=. python benchmarks/run_llm_comparison.py --model gpt-5-mini --json-out llm-comparison.json
```

`run_extended_benchmark.py` reports control false-positive checks and attack-variant coverage without changing the primary benchmark denominator. `run_llm_comparison.py` is a separate structured-output experiment and records model, rationale, errors, and metrics; it is not used by the deterministic benchmark gate.

The Real-World track is maintained separately under [`real_world/`](real_world/). Its [`registry.json`](real_world/registry.json) currently contains ten quarantined candidates discovered from publicly documented incidents. The registry stores source commits, file hashes, transaction anchors, external references, and affected-function hypotheses, but it does not admit a case into metrics until the adjudication gates in [`real_world/README.md`](real_world/README.md) are complete. The Real-World-inspired negative-control suite is run with:

```bash
PYTHONPATH=. python benchmarks/real_world/run_negative_controls.py
PYTHONPATH=. pytest -q tests/test_real_world_registry.py tests/test_track_baseline.py
PYTHONPATH=. python benchmarks/run_track_baseline.py --llm-report /path/to/evaluation_run.json
```

`run_track_baseline.py` reports the primary benchmark, supplementary suites, Real-World negative controls, quarantined candidates, and LLM comparison as isolated tracks. It never merges quarantined candidates into the primary denominator.

## Deterministic comparator

For every expected detector finding, `verification/comparator.py` applies a deterministic four-stage workflow:

1. **Hypothesis** — normalize the analyzer finding into detector, severity, category, file, function, and description fields.
2. **Verification** — check whether a rule exists for the detector and evaluate its source-level predicate.
3. **Evidence** — record a short source excerpt and one-based line location for the matching pattern.
4. **Classification** — return `Confirmed` when evidence supports the finding, `Rejected` when a known rule has no supporting evidence, or `Inconclusive` when no deterministic rule is registered.

The comparator is intentionally local and reproducible: it does not call an LLM, access the network, or claim that source evidence alone proves exploitability. The benchmark runner includes per-case comparator statuses and fails in strict mode when a primary finding is rejected or inconclusive.

## Invariant engine

Each metadata file also identifies one deterministic invariant. The runner evaluates that invariant against both files: the vulnerable fixture must return `Violated`, while the fixed fixture must return `Satisfied`. An invalid source or an unknown invariant id returns `Inconclusive` and causes strict benchmark execution to fail. The invariant engine records the same kind of line-based evidence used by the comparator, but it remains a source-level regression check rather than a proof of runtime exploitability.

## Executable PoCs

Each case includes a repository-owned `poc.t.sol` fixture. The PoC runner copies only that file into a temporary Foundry project and invokes `forge test --offline` with a bounded timeout. It rejects paths outside the repository, requires the `.t.sol` suffix, does not use a shell, and never enables broadcast, FFI, filesystem, or network cheatcodes. A successful runtime test is `Passed`; a failing test is `Failed`; missing Foundry or an unavailable runtime is `Inconclusive`. `poc_mode: exploit` identifies a positive reproduction, while `poc_mode: negative_control` identifies an expected blocked attempt. No claim of runtime confirmation is made when the status is `Inconclusive`.

## Metrics

`verification/metrics.py` computes a machine-readable metrics object from the runner's case records. It reports aggregate detector metrics and a `per_detector` breakdown. Detector metrics use the primary expected detectors only:

| Metric | Definition |
|---|---|
| Precision | `TP / (TP + FP)` |
| Recall | `TP / (TP + FN)` |
| F1 | harmonic mean of precision and recall |
| FP rate | `FP / (FP + TN)` |
| FN rate | `FN / (FN + TP)` |

Comparator `Confirmed`, `Rejected`, and `Inconclusive` counts are reported separately from detector metrics. Invariant statuses are split between vulnerable and fixed fixtures. PoC metrics are split by `poc_mode`, and runtime coverage excludes `Inconclusive` results from the denominator. A missing runtime is never converted into a false positive, false negative, or successful exploit reproduction.
