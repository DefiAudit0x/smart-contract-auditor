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
| `expected_detectors` | Detector names that must appear for `vulnerable.sol`. |
| `expected_clean` | Whether `fixed.sol` is expected to avoid every detector in `expected_detectors`. |

The current benchmark covers reentrancy, delegatecall, selfdestruct, unrestricted minting, and `tx.origin` authentication. The expected detector names are taken directly from `analyzers/solidity_analyzer.py`.

## Running the benchmark

From the repository root:

```bash
python benchmarks/run_benchmark.py
pytest -q tests/test_benchmark.py
```

The runner reports per-case true positives, false positives, and false negatives. For this benchmark, a true positive means an expected detector is present in the vulnerable contract, a false positive means an expected detector is present in the fixed contract, and a false negative means an expected detector is absent from the vulnerable contract. The metrics are scoped to the primary expected detectors in each metadata file; they do not represent full analyzer precision or recall across all Solidity vulnerabilities.

## Deterministic comparator

For every expected detector finding, `verification/comparator.py` applies a deterministic four-stage workflow:

1. **Hypothesis** — normalize the analyzer finding into detector, severity, category, file, function, and description fields.
2. **Verification** — check whether a rule exists for the detector and evaluate its source-level predicate.
3. **Evidence** — record a short source excerpt and one-based line location for the matching pattern.
4. **Classification** — return `Confirmed` when evidence supports the finding, `Rejected` when a known rule has no supporting evidence, or `Inconclusive` when no deterministic rule is registered.

The comparator is intentionally local and reproducible: it does not call an LLM, access the network, or claim that source evidence alone proves exploitability. The benchmark runner includes per-case comparator statuses and fails in strict mode when a primary finding is rejected or inconclusive.

## Invariant engine

Each metadata file also identifies one deterministic invariant. The runner evaluates that invariant against both files: the vulnerable fixture must return `Violated`, while the fixed fixture must return `Satisfied`. An invalid source or an unknown invariant id returns `Inconclusive` and causes strict benchmark execution to fail. The invariant engine records the same kind of line-based evidence used by the comparator, but it remains a source-level regression check rather than a proof of runtime exploitability.
