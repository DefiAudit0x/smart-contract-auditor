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
