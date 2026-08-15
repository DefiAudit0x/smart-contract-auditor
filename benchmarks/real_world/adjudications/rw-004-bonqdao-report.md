# BonqDAO (rw-004) — Real-World Adjudication Report

## Decision

> **Ground Truth decision: Quarantined.** The incident mechanism is independently supported and reproduced, but the current detector taxonomy does not cover oracle manipulation or consumption of a Tellor spot value before its dispute window. The case is therefore excluded from admitted-case precision, recall, and F1 metrics.

This is the second fully adjudicated real-world case after Nomad Bridge. The decision is intentionally conservative: **a confirmed incident mechanism is not the same thing as a mapped detector finding**. Static output, LLM output, and PoC success are retained as observations and verification evidence, but none is promoted to Ground Truth classification.

## Protocol and evidence chain

BonqDAO was attacked on Polygon on 1 February 2023 through a two-stage price manipulation. The first transaction submitted an inflated WALBT price and borrowed BEUR against a small amount of WALBT; the second submitted a very low price and enabled liquidation of WALBT troves. PolygonScan records the first transaction at block `38792978` and the second at block `38793029`; the independent reproduction material uses block `38792977` as a one-block-before fork anchor [1] [2] [3].

The deployed consumer chain is `TroveFactory` `0x3bB7...768B3` -> `TokenToPriceFeed` `0x20d5...10b8a` -> WALBT `ConvertedPriceFeed` `0x7D4c...4bc8` -> `TellorPriceFeed` `0xa162...a5d6` -> TellorFlex `0x8f55...d5B` [4]. The exact-match verified `TellorPriceFeed` source is compiled with Solidity `0.8.17+commit.8df45f5f`, and its source explorer exposes the vulnerable statement at line 31 [4].

The independently pinned TellorFlex source is the official repository file at commit `3b3820f2111ec2813cb51455ef68cf0955c51674`. The repository snapshot is stored in the project at `benchmarks/real_world/source_snapshots/bonqdao/TellorFlex_3b3820f.sol` and has SHA-256 `db633e4080e3e95410e0eec34b17fbacaadca42281bbde5dd6282f61cd40a522`. The relevant line ranges are `submitValue:282-345`, `getCurrentValue:419-427`, and `getDataBefore:437-454`. PolygonScan independently identifies the deployed TellorFlex contract as verified Solidity `0.8.3+commit.8d00100c` [5].

| Evidence item | Result | Reference or artifact |
|---|---|---|
| Incident transactions | Two successful Polygon transactions at blocks 38792978 and 38793029 | [1] [2] |
| Independent analyses | Omniscia, Immunefi, Rekt, Think and Dev, and Numen converge on the same two-stage mechanism | [3] [6] [7] [8] [9] |
| Exact consumer | `TellorPriceFeed.price()` calls `oracle.getCurrentValue(queryId)` and converts the result to `uint256` | PolygonScan source snapshot, lines 30–32 [4] |
| Oracle implementation | `getCurrentValue` selects the newest report through `getDataBefore(..., block.timestamp + 1)` | `TellorFlex_3b3820f.sol`, lines 419–427 |
| Alternative safe boundary | `getDataBefore` accepts an explicit historical cutoff | `TellorFlex_3b3820f.sol`, lines 437–454; [8] |
| Taxonomy gate | No current detector semantically covers oracle manipulation or dispute-window enforcement | `detector_mapping` in `rw-004-bonqdao.json` |

## Root cause and invariant

TellorFlex’s `submitValue` is a permissionless reporter path constrained by stake, nonce, reporting-lock, query-id, and timestamp checks. Its `getCurrentValue` function asks for data before `block.timestamp + 1`, which means the newest available report is returned. This behavior is valid as an oracle API, but Bonq’s `TellorPriceFeed.price()` consumed it as collateral valuation without an additional delay [4] [5].

> **Invariant:** An oracle price used for collateral, debt, conversion, or liquidation must not return the newest report until a dispute window has elapsed.

The owned vulnerable fixture violates the invariant because its price feed calls `getCurrentValue()` directly. The owned fixed fixture satisfies it by calling `getDataBefore(block.timestamp - DISPUTE_WINDOW)` and reverting while the report is still inside the 20-minute window. This is a deliberately narrow model of the consumer boundary, not a claim that the fixture is the historical Bonq deployment.

## Owned reproduction

The repository-owned reproduction is located at `benchmarks/real_world/owned_reproductions/bonqdao/`. `BonqTellorVulnerable.sol` models an immediately consumable latest report, while `BonqTellorFixed.sol` models the dispute-window boundary. `bonqdao_dispute_window_poc.t.sol` is self-contained, uses an inline `Vm` interface, imports no `forge-std` library, and contains two deterministic tests.

| Reproduction check | Expected result | Observed result |
|---|---:|---:|
| Vulnerable feed consumes a freshly submitted manipulated price | Pass | Pass |
| Fixed feed rejects a fresh report inside the window | Revert | Revert observed |
| Fixed feed accepts the same report after 20 minutes plus one second | Pass | Pass |
| Narrow source invariant on vulnerable fixture | Violated | Violated |
| Narrow source invariant on fixed fixture | Satisfied | Satisfied |

Foundry execution compiled the self-contained PoC with Solidity `0.8.25` and passed both tests. The PoC intentionally does not fork Polygon and does not reproduce the full BEUR/WALBT liquidation flow; it verifies only the adjudicated oracle-consumer mechanism. The independent Polygon fork block remains recorded as incident evidence rather than being used as a hidden dependency.

## Pipeline observations

The stage-by-stage output is stored at `benchmarks/real_world/adjudications/rw-004-bonqdao-pipeline.json`. Static analysis completed on both fixtures and observed `block.timestamp Usage (AST)`, together with incidental `Event Emission` and `Pragma Fixed` observations. The LLM comparison used `gpt-5-mini` after checking the live catalog and predicted only `block.timestamp Usage (AST)` for both fixtures. These observations are not the confirmed Bonq classification.

| Stage | Status | Interpretation |
|---|---|---|
| Static | Completed | Observational detector output; no semantically valid oracle detector fired |
| LLM | Completed | Predictions recorded with live catalog check and usage; not Ground Truth |
| Static + LLM | ObservationalOnly | Outputs cannot create or alter the adjudication label |
| Comparator | NotApplicable | No expected detector mapping exists for this vulnerability family |
| Invariant | Violated / Satisfied | Owned source contrast matches the adjudicated invariant |
| PoC | Passed | Both vulnerable and fixed behavioral checks passed |
| Full pipeline | Quarantined | Taxonomy Coverage Gate fails; no detector is forced |

## Acceptance decision and next review gate

The incident mechanism is accepted as independently supported **for adjudication purposes**, and the owned reproduction is accepted as a valid narrow reproduction. The case is not admitted to detector metrics. Its correct current status is `quarantine`, not `admitted` and not a forced match to the `block.timestamp` detector.

Before Case 3, Nomad and BonqDAO must be reviewed together to identify recurring patterns and prevent premature detector expansion. A second independent adjudication is also required before either quarantined case changes status. Any proposal for an oracle or dispute-window detector must be handled as a separate design review and must not be smuggled into this case’s metrics.

## References

[1]: https://polygonscan.com/tx/0x31957ecc43774d19f54d9968e95c69c882468b46860f921668f2c55fadd51b19 "PolygonScan first BonqDAO attack transaction"
[2]: https://polygonscan.com/tx/0xa02d0c3d16d6ee0e0b6a42c3cc91997c2b40c87d777136dedebe8ee0f47f32b1 "PolygonScan second BonqDAO attack transaction"
[3]: https://immunefi.com/blog/bug-fix-reviews/hack-analysis-bonqdao-february-2023/ "Immunefi — Hack Analysis: BonqDAO, February 2023"
[4]: https://polygonscan.com/address/0xa1620af6138d2754f7250299dc9024563bd1a5d6#code "PolygonScan — verified TellorPriceFeed"
[5]: https://polygonscan.com/address/0x8f55d884cad66b79e1a131f6bcb0e66f4fd84d5b#code "PolygonScan — verified TellorFlex"
[6]: https://medium.com/@omniscia.io/bonq-protocol-incident-post-mortem-4fd79fe5c932 "Omniscia — Bonq Protocol Incident Post-Mortem"
[7]: https://rekt.news/bonq-rekt "Rekt — BonqDAO"
[8]: https://medium.com/think-and-dev/the-bonq-dao-attack-d197d13cddd0 "Think and Dev — The Bonq DAO attack"
[9]: https://www.numencyber.com/bonqdao-price-manipulation-attack-analysis-with-poc/ "Numen — BonqDAO Price Manipulation Attack Analysis with POC"
