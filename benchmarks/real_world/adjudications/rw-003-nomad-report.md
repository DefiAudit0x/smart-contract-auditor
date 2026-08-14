# Nomad Bridge Real-World Adjudication

## Decision

The case is **quarantined**. The incident claim is strongly supported by an official post-mortem, an independently pinned `Replica.sol` source version, exact source line ranges, an on-chain transaction, and an owned minimal reproduction. It is not admitted to detector metrics because the current analyzer has no semantically valid detector for zero-root message-proof validation, the owned reproduction is not a historical mainnet fork, and a second independent adjudication is still required.

> The successful PoC is evidence that the owned model exhibits the claimed mechanism. It is not the source of Ground Truth. The causal order used here is implementation, incident claim, independent evidence, source reasoning, invariant, owned reproduction, and observed behavior.

## Case identity and source pinning

| Field | Value |
|---|---|
| Case ID | `rw-003-nomad-bridge` |
| Incident | Nomad Bridge empty-root initialization failure |
| Primary contract | `Replica` logic at `0xB92336759618F55bd0F8313bd843604592E27bd8` |
| Proxy observed in cited transaction | `0x5D94309E5a0090b165FA4181519701637B6DAEBA` |
| On-chain transaction | `0xa5fe9d044e4f3e5aa5bc4c0709333cd2190cba0f4e7f16bcf73f49f83e4a5460` |
| Verified block | `15259101` |
| Historical source commit | `7510d54a5cd334d283d84fdff59827abfceb2da7` |
| Historical source path | `packages/contracts-core/contracts/Replica.sol` |
| Historical source SHA-256 | `3b6439fe258ffeeec58586e6d21ae3286903409b10b28f46b4b8cb64b4a773d6` |
| Compiler shown by verified source | Solidity `0.7.6+commit.7338295f` |

The source snapshot is available at the [pinned `Replica.sol` commit][1]. The discovery PoC remains recorded separately in the registry as discovery provenance; it is not treated as the official implementation source and is not imported into the owned fixture.

## Claim and causal reasoning

The official Nomad post-mortem states that an implementation bug caused `Replica` to fail to authenticate messages, allowing forged messages that had not already been processed.[2] The pinned source sets `confirmAt[_committedRoot] = 1` in `initialize` at line 115. The same source reads `confirmAt[_root]` at line 268 and rejects only a zero timestamp at lines 269–270 before returning `block.timestamp >= _time` at line 272. The `process` function checks `acceptableRoot(messages[_messageHash])` at line 192.

When the initially empty Merkle tree supplies `bytes32(0)` as the committed root, initialization pre-approves that zero root with timestamp `1`. For an ordinary historical block timestamp, `acceptableRoot(bytes32(0))` therefore returns true. An unproven message whose stored root remains `bytes32(0)` can then pass the `process` proof gate. This is a source-level causal explanation of the incident, not merely a statement that an exploit transaction succeeded.

The exact source ranges are `initialize:103–116`, `proveAndProcess:162–172`, `process:186–207`, and `acceptableRoot:262–273`. The Nomad audit reference identifies the related issue as QSP-19, “Proving With An Empty Leaf.”[3]

## Independent on-chain evidence

[Etherscan reports][4] that the cited transaction succeeded in Ethereum mainnet block `15259101`, called `process(bytes)`, emitted a successful `Process` event, and transferred 100 WBTC from the Nomad ERC20 Bridge to the recipient. The transaction page identifies the interaction as going through the Nomad Replica proxy. The verified logic page identifies the target logic as an exact-match `Replica` source compiled with Solidity `0.7.6`.[5]

This evidence verifies the transaction anchor and observed outcome. A public RPC attempt to read the beacon implementation at the historical block returned HTTP 521, so the record does not claim a completed historical beacon-slot read. The verified proxy/source pages and the pinned source commit are retained as separate provenance facts.

## Owned reproduction and invariant

The project-owned fixtures are:

| Artifact | Purpose |
|---|---|
| `NomadReplicaVulnerable.sol` | Minimal source model that pre-approves zero root and accepts an unproven message. |
| `NomadReplicaFixed.sol` | Contrast model that rejects zero-root initialization before pre-approval. |
| `nomad_zero_root_poc.t.sol` | Self-contained Foundry PoC containing both vulnerable and fixed assertions. |
| `nomad_invariant.py` | Local invariant implementation for `nomad.zero_root_not_accepted`. |

The invariant is: **initialization must not allow `bytes32(0)` to become an accepted root for message processing**. The vulnerable fixture returns `Violated`; the fixed contrast returns `Satisfied`. The PoC passes two tests: the vulnerable fixture accepts and processes the forged message, while the fixed contrast rejects zero-root initialization and does not process the unproven message.

The reproduction is intentionally a minimal owned model. It does not fork mainnet, import third-party PoC code, or reproduce the complete BridgeRouter/WBTC transfer path. Those limitations are recorded rather than hidden.

## Stage-by-stage pipeline observation

The stage report is stored at [`rw-003-nomad-pipeline.json`](rw-003-nomad-pipeline.json). It records the following observations:

| Stage | Observation | Interpretation |
|---|---|---|
| Static | `block.timestamp Usage (AST)` on both owned fixtures, plus generic findings | The current analyzer does not detect the Nomad root-validation mechanism. |
| LLM | `block.timestamp Usage (AST)` on both fixtures | The model noticed a surface pattern but did not identify the zero-root proof failure. This is an observation, not Ground Truth. |
| Static + LLM | Observational only | No expected detector is assigned, so predictions cannot create a label. |
| Comparator | `NotApplicable` | No existing comparator matcher is semantically valid for this vulnerability family. |
| Invariant | Vulnerable `Violated`; fixed `Satisfied` | The owned source contrast supports the declared narrow property. |
| PoC | `Passed` | Both vulnerable and fixed assertions passed in Foundry. |
| Full pipeline | `Quarantined` | Admission gates remain open; no primary metric changed. |

The LLM stage used `gpt-5-mini` with live catalog validation and the repository's versioned prompt/schema machinery. Its result is not used to assign the expected detector or to override the quarantine decision.

## Admission gates remaining

The case can move from quarantine only after a second independent reviewer confirms the implementation mapping and causal reasoning, the historical proxy-to-beacon mapping is resolved to the required confidence, and the project decides whether this is an uncovered detector family or a candidate for a separately reviewed detector design. Even if those gates pass, admission should not silently turn the existing timestamp finding into a Nomad-specific Ground Truth label.

## References

[1]: https://github.com/nomad-xyz/monorepo/blob/7510d54a5cd334d283d84fdff59827abfceb2da7/packages/contracts-core/contracts/Replica.sol "Nomad Replica.sol at the pinned historical commit"

[2]: https://medium.com/nomad-xyz-blog/nomad-bridge-hack-root-cause-analysis-875ad2e5aacd "Nomad Bridge Hack: Root Cause Analysis"

[3]: https://github.com/nomad-xyz/docs/blob/1ff0c55dba2a842c811468c57793ff9a6542ef0f/docs/public/Nomad-Audit.pdf "Nomad Audit PDF"

[4]: https://etherscan.io/tx/0xa5fe9d044e4f3e5aa5bc4c0709333cd2190cba0f4e7f16bcf73f49f83e4a5460 "Nomad process transaction at block 15259101"

[5]: https://etherscan.io/address/0xb92336759618f55bd0f8313bd843604592e27bd8#code "Verified Nomad Replica logic contract"
