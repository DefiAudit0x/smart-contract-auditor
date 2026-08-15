# Case #3 Selection Memo: Parity WalletLibrary Selfdestruct

## Selection

The third real-world case selected for adjudication is **rw-001-parity-kill**, the November 2017 Parity shared `WalletLibrary` selfdestruct incident. It is materially different from Nomad’s message-proof validation failure and BonqDAO’s oracle dispute-window failure. Its primary vulnerability family is **uninitialized shared-library access control leading to a destructive `kill`/`suicide` path**, with the existing controlled taxonomy candidate **`Selfdestruct`**.

The selection is deliberately not a claim that the case will be admitted. It is a coverage experiment: the root cause is close enough to an existing detector family to test whether the pipeline can move from independent Ground Truth to a confirmed finding. The historical source uses Solidity 0.4.x `suicide`, so the exact detector/source compatibility must be measured rather than assumed.

## Why Parity is the right third experiment

The Parity post-mortem states that an uninitialized shared library was initialized by an external user, who became its owner and then destroyed the library. The destruction blocked functionality for 587 dependent wallets holding 513,774.16 ETH plus additional tokens [1]. Etherscan independently identifies the deployed `WalletLibrary` at `0x863DF6BFa4469f3ead0bE8f9F2AAE51c91A907b4`, marks the source as exact-match verified with Solidity `0.4.10+commit.f0d539ae`, and records the contract selfdestruct [2]. The kill transaction succeeded at Ethereum block `4501969` and decoded to `kill(address _to)` [3].

| Selection criterion | Parity result |
|---|---|
| Different from Nomad | Yes. The root cause is shared-library initialization and destructive access control, not message/proof validation. |
| Different from BonqDAO | Yes. The root cause is not oracle freshness, price manipulation, or accounting. |
| Independent incident evidence | Yes. Parity’s post-mortem, Etherscan transaction/source records, and the contemporaneous GitHub issue converge on the same mechanism [1] [2] [3] [4]. |
| Existing taxonomy proximity | Yes at the family level: `Selfdestruct` is a controlled detector. `Uninitialized Proxy` and delegatecall are adjacent observations, not the primary expected mapping. |
| Reproducible owned contrast | Yes. A minimal vulnerable library can be initialized and killed; a fixed contrast can initialize at deployment and remove the destructive path. |
| Fairness risk | The historical alias is `suicide`, while the current comparator and detector key on literal `selfdestruct`; this is an explicit compatibility question for A/B/C, not something to hide or normalize. |

## Expected protocol

The independent expected detector, declared before the auditor run, is **`Selfdestruct`**. The semantic claim is narrower than “the source contains a dangerous opcode”: an externally acquired owner can invoke the historical `kill(address)` path and destroy shared code relied upon by dependent wallets. If the current static detector does not recognize the legacy `suicide` spelling, that is recorded as a detector implementation observation. It must not be repaired during this case, and it must not be replaced by an unrelated detector.

The three views will be reported separately. **A — Existing detector only** will run the current Solidity analyzer and deterministic comparator against the pinned source/owned vulnerable contrast. **B — LLM only** will record the live-catalog model prediction without using it as Ground Truth. **C — Full pipeline** will combine source evidence, expected detector mapping, Comparator, invariant, and owned PoC, then make an explicit admission or quarantine decision. The final result will distinguish semantic taxonomy coverage from detector implementation success.

## References

[1]: https://medium.com/paritytech/a-postmortem-on-the-parity-multi-sig-library-self-destruct-63daca3a4cf7 "Parity Technologies — A Postmortem on the Parity Multi-Sig Library Self-Destruct"

[2]: https://etherscan.io/address/0x863df6bfa4469f3ead0be8f9f2aae51c91a907b4#code "Etherscan — verified WalletLibrary source"

[3]: https://etherscan.io/tx/0x47f7cff7a5e671884629c93b368cb18f58a993f4b19c2a53a8662e3f1482f690 "Etherscan — Parity WalletLibrary kill transaction"

[4]: https://github.com/openethereum/parity-ethereum/issues/6995 "OpenEthereum issue #6995 — anyone can kill your contract"
