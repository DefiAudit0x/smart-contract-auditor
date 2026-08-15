# Real-World Adjudication Report: Parity WalletLibrary Selfdestruct

## Decision

> **Decision: QUARANTINED.** The Parity incident is independently supported, the semantic taxonomy gate passes through the existing `Selfdestruct` family, the owned invariant and PoC pass, but the current detector does not confirm the exact deployed Solidity 0.4.x source because it uses legacy `suicide(_to)` and the current comparator recognizes only `selfdestruct(`.

This is the first real-world case in the review set where the vulnerability family is represented in the controlled taxonomy but the exact implementation does not pass the detector/comparator gate. It is therefore not a taxonomy-definition gap like Nomad or BonqDAO, and it is not evidence for adding a detector now. It is a precisely recorded **detector compatibility/implementation miss**.

## 1. Source and incident identification

The selected incident is the November 2017 destruction of the shared Parity `WalletLibrary`. Parity’s post-mortem states that the library was deployed as a shared component for Parity multisig wallets, remained uninitialized, was initialized by an external user, and was subsequently destructed. The post-mortem reports 587 affected wallets holding 513,774.16 ETH plus additional tokens [1].

The affected library is `0x863DF6BFa4469f3ead0bE8f9F2AAE51c91A907b4`. Etherscan identifies the contract as an exact-match verified `WalletLibrary`, compiled with Solidity `v0.4.10+commit.f0d539ae` and optimizer enabled with 200 runs [2]. The successful kill transaction is `0x47f7cff7a5e671884629c93b368cb18f58a993f4b19c2a53a8662e3f1482f690`, mined in block `4501969` at `2017-11-06 15:25:21 UTC`; its input decodes to `kill(address _to)` and Etherscan records a `SELF DESTRUCT` trace [3].

The exact Etherscan source was extracted into [`WalletLibrary.sol`](../source_snapshots/parity/WalletLibrary.sol) and pinned with SHA-256 `dedb7a47a4a37cf61689e8f655beb58b4fe0e026ef591a93ccb62be4041b2e42`. The upstream historical lineage is retained separately at commit `4d08e7b0aec46443bf26547b17d10cb302672835`; the source-pin record documents the small difference in `only_uninitialized` guard placement rather than silently treating the two texts as identical.

## 2. Vulnerability claim and exact source mapping

The claim is that an uninitialized shared library exposed an initialization path that allowed an external caller to acquire ownership, after which the caller could invoke the destructive `kill` path and destroy code relied upon by dependent multisig wallets. The exact deployed snapshot maps the mechanism as follows.

| Component | Exact lines | Security meaning |
|---|---:|---|
| `only_uninitialized` | 215 | The first caller is permitted while `m_numOwners == 0`; deployment did not perform that initialization on the shared library instance. |
| `initWallet` | 219–222 | Public initialization path that sets daily limit and multisig ownership state. |
| `kill` | 225–227 | Destructive path guarded by `onlymanyowners`; after ownership acquisition it reaches the destructive primitive. |
| `suicide(_to)` | 226 | Solidity 0.4.x spelling of the selfdestruct-equivalent operation. |
| Wallet constructor delegatecall | 420 | New wallets delegate initialization to the shared library. |
| Wallet fallback delegatecall | 432 | Dependent wallets delegate runtime behavior to the shared library. |

The contemporaneous issue confirms the same chain: the library was uninitialized, the caller became its owner using the initialization transaction, and the dependent wallets referenced the library at the affected address [4]. EIP-999 independently describes the accidental self-destruction of the same `WalletLibrary` and the resulting inaccessibility of dependent wallet assets [5].

## 3. Owned reproduction

The repository-owned reproduction is intentionally minimal. [`ParityWalletLibraryVulnerable.sol`](../owned_reproductions/parity/ParityWalletLibraryVulnerable.sol) models an externally callable initializer on a library instance that has not been initialized at deployment, followed by a `kill` function containing `selfdestruct`. [`ParityWalletLibraryFixed.sol`](../owned_reproductions/parity/ParityWalletLibraryFixed.sol) completes initialization in the constructor and disables both reinitialization and the destructive path. The Foundry PoC is self-contained, has no third-party imports, and tests both sides of the contrast.

The invariant is:

> **An untrusted caller must not be able to initialize a shared library and then destroy code relied upon by dependent wallets.**

The invariant checker returns `Violated` for the vulnerable fixture and `Satisfied` for the fixed fixture. The PoC passes two tests: takeover followed by destructive invocation succeeds in the vulnerable model, while both initialization and destruction are rejected in the fixed model. Foundry emits the expected post-Cancun deprecation warning for the modern `selfdestruct` spelling; this warning is a local execution note, not historical evidence about the 2017 EVM.

## 4. Taxonomy gate and A/B/C experiment

At the semantic taxonomy level, the gate is **Covered** because `Selfdestruct` is an existing controlled detector family and the independent root cause includes a selfdestruct-equivalent operation. The controlled experiment then separates detector execution from taxonomy naming.

| View | Observation | Interpretation |
|---|---|---|
| **A — Existing detector only** | `Missed` on the exact deployed source. The analyzer emitted storage/delegatecall and advisory observations, but no `Selfdestruct`. The owned modern vulnerable contrast emitted `Selfdestruct`, and Comparator confirmed `selfdestruct(`. | The existing detector can represent the family on modern spelling but does not confirm the exact legacy source. The miss is an implementation/compatibility observation. |
| **B — LLM only** | `Completed`. The model predicted `Selfdestruct` for the exact source and the owned vulnerable contrast, with no expected detector for the fixed contrast. | Useful semantic observation, but not Ground Truth and not a replacement for exact-source Comparator evidence. |
| **C — Full pipeline** | `Quarantined`. Evidence, source pin, semantic taxonomy gate, invariant, and PoC passed; exact-source detector confirmation did not. | Correct abstention. No forced admission and no architecture or detector change. |

The legacy spelling matters. The pinned deployed source contains `suicide(_to)`, while the current comparator’s registered matcher searches for the literal `selfdestruct(`. The current AST path is also fixed at solc 0.8.25, while the source declares Solidity 0.4.x. These facts explain why the case is neither `NotApplicable` for taxonomy nor admitted as a confirmed detector finding.

## 5. Acceptance rationale

Parity remains quarantined for a narrower reason than Nomad and BonqDAO. Nomad lacks a semantically valid message-proof detector mapping, and BonqDAO lacks a semantically valid oracle/dispute-window mapping. Parity has a valid semantic mapping to `Selfdestruct`, but the current implementation does not confirm the exact historical source. The pipeline therefore demonstrates a useful third behavior: **taxonomy coverage can be present while detector confirmation is absent, and the correct result is still quarantine**.

This case must not trigger a detector patch now. Adding `suicide` as an alias, changing compiler selection, or modifying the comparator would turn this adjudication into an implementation change rather than a measurement. Such work belongs only in a later design review after three to five diverse cases.

## References

[1]: https://medium.com/paritytech/a-postmortem-on-the-parity-multi-sig-library-self-destruct-63daca3a4cf7 "Parity Technologies — A Postmortem on the Parity Multi-Sig Library Self-Destruct"

[2]: https://etherscan.io/address/0x863df6bfa4469f3ead0be8f9f2aae51c91a907b4#code "Etherscan — verified Parity WalletLibrary source"

[3]: https://etherscan.io/tx/0x47f7cff7a5e671884629c93b368cb18f58a993f4b19c2a53a8662e3f1482f690 "Etherscan — Parity WalletLibrary kill transaction"

[4]: https://github.com/openethereum/parity-ethereum/issues/6995 "OpenEthereum issue #6995 — anyone can kill your contract"

[5]: https://eips.ethereum.org/EIPS/eip-999 "EIP-999 — Restore Contract Code at WalletLibrary"
