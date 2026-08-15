# Cross-Case Analysis: Nomad, BonqDAO, and Parity

## Scope

This document reviews the first three real-world adjudications together. The comparison is intentionally performed **before Case #4** and does not add a detector, alter the analyzer, change the comparator, or modify architecture. Its purpose is to identify what the existing pipeline can distinguish and where it abstains.

> **Central finding:** The first two cases are taxonomy-definition gaps. The third case is different: its semantic vulnerability family is already represented by `Selfdestruct`, but the current detector/comparator does not confirm the exact historical source because the deployed code uses the legacy `suicide` spelling and the analyzer is fixed to a modern compiler. This is an implementation/compatibility observation, not yet a reason to patch the system.

## 1. Three-case taxonomy and admission table

| Case | Independently established real vulnerability | Current taxonomy | Semantic coverage | Exact detector result | Full-pipeline result | Reason for final status |
|---|---|---|---|---|---|---|
| **Nomad Bridge** | Message/proof authentication failure: the zero Merkle root became acceptable after initialization, allowing an unproven message through `process`. | No message-proof, Merkle-root, or authentication-integrity family. | ❌ **Not covered** | No valid expected detector mapping; static/LLM observations were non-equivalent. | **Quarantined** | Taxonomy-definition gap. Evidence, invariant, and owned PoC were completed, but forcing a timestamp or proxy-related detector would be semantically false. |
| **BonqDAO** | Oracle price manipulation: Bonq consumed the newest Tellor spot value through `getCurrentValue` without a dispute window before collateral valuation. | No oracle freshness, dispute-window, or price-manipulation family. | ❌ **Not covered** | No valid expected detector mapping; `block.timestamp` observations were non-equivalent. | **Quarantined** | Taxonomy-definition gap. Evidence, invariant, and owned PoC were completed, but a timestamp detector is not an oracle-manipulation detector. |
| **Parity WalletLibrary** | An uninitialized shared library could be initialized by an external caller, who then invoked `kill(address)` and legacy `suicide(_to)`, destroying code relied upon by dependent multisig wallets. | `Selfdestruct` exists as a controlled detector family; initialization/delegatecall are adjacent observations. | ✅ **Covered semantically** | **Missed on exact deployed source.** The owned modern contrast emitted `Selfdestruct` and Comparator confirmed it, but the historical source uses `suicide`. | **Quarantined** | Detector/compatibility gap within an existing taxonomy family. The pipeline correctly refused to promote an LLM prediction or a modern contrast into exact-source confirmation. |

## 2. What caused non-admission?

The first two cases answer the user’s central question clearly. Their non-admission is primarily caused by **taxonomy not being defined for the independently established vulnerability families**, not by demonstrated inability of an existing valid detector. No semantically equivalent expected detector existed, so Comparator was correctly `NotApplicable` and Full Pipeline abstained.

Parity provides the necessary third distinction. Its root cause is close enough to an existing controlled family that the Taxonomy Coverage Gate passes. The current analyzer can detect the same semantic family in a modern owned contrast containing `selfdestruct(`, and the deterministic Comparator confirms that owned source. However, it does not confirm the exact deployed source containing `suicide(_to)`. The result is therefore not a taxonomy gap and not an admission: it is an **exact-source detector implementation/compatibility miss**.

| Diagnostic category | Nomad | BonqDAO | Parity |
|---|---:|---:|---:|
| Independent incident evidence complete | Yes | Yes | Yes |
| Exact source and line mapping complete | Yes | Yes | Yes |
| Owned invariant contrast complete | Yes | Yes | Yes |
| Owned PoC passed | Yes | Yes | Yes |
| Semantically valid existing detector mapping | No | No | Yes (`Selfdestruct`) |
| Existing detector confirmed on exact source | Not applicable | Not applicable | No |
| Quarantine justified without architecture change | Yes | Yes | Yes |

The data supports a narrow conclusion only: **two cases are insufficient to infer a recurring architectural deficiency, while the third demonstrates that semantic taxonomy coverage and implementation-level detector coverage are separate gates.** It does not justify adding an alias, changing compiler selection, or rewriting the Comparator before more diverse cases are observed.

## 3. A/B/C contribution matrix

The A/B/C experiment is more informative than a single correctness score because each component answers a different question.

| Case | A — Existing detector only | B — LLM only | C — Full pipeline | What the comparison adds |
|---|---|---|---|---|
| Nomad | No valid detector mapping | Advisory observations only | Quarantined | Shows that LLM/static observations cannot manufacture a proof-validation taxonomy. |
| BonqDAO | No valid detector mapping | Advisory observations only | Quarantined | Shows that a timestamp observation cannot be promoted into an oracle/dispute-window detector. |
| Parity | Missed exact historical `suicide`; modern owned contrast detected | Predicted `Selfdestruct` on exact source | Quarantined | Shows the difference between semantic recognition and exact-source detector confirmation. LLM supplies a useful hypothesis, while Comparator and Full Pipeline prevent over-admission. |

The three cases therefore establish complementary roles. The **existing detector** is the only component allowed to produce a taxonomy-mapped finding, but it can miss legacy or version-specific representations. The **LLM** can bridge semantic descriptions and suggest a likely family, but it remains observational. The **Full Pipeline** is the component that preserves epistemic discipline by requiring source-grounded confirmation and by abstaining when the required gate is not satisfied.

## 4. Current real-world status

| Case | Status | Metrics inclusion | Immediate interpretation |
|---|---|---:|---|
| Nomad Bridge | Quarantined | No | Taxonomy gap: message/proof validation is not currently represented. |
| BonqDAO | Quarantined | No | Taxonomy gap: oracle/dispute-window enforcement is not currently represented. |
| Parity WalletLibrary | Quarantined | No | Semantic coverage exists, but exact historical detector confirmation is missing. |

All three remain outside Precision, Recall, F1, admitted-case counts, and headline benchmark metrics. This is intentional. The full pipeline’s ability to return `Quarantined` for all three is a positive result because the cases fail for different, explicitly recorded reasons rather than being forced into synthetic categories.

## 5. Decision before Case #4

No detector or architecture change is justified at this point. The evidence now supports three distinct review questions for a future design phase: whether taxonomy expansion is warranted for message-proof validation; whether taxonomy expansion is warranted for oracle/dispute-window enforcement; and whether the existing `Selfdestruct` detector should eventually support legacy Solidity aliases or compiler-aware source normalization. These are separate hypotheses and must not be conflated.

The recommended next step is to pause the case pipeline here and review the three-case evidence as a corpus. If another case is later added, it should be selected for a different class—preferably a current taxonomy family with a modern source spelling—so the corpus can distinguish detector coverage from legacy compatibility without repeating Nomad, BonqDAO, or Parity. Any detector or architecture work should wait until at least three to five diverse adjudicated cases produce a stable pattern.

## References

[1]: rw-003-nomad-bridge.json "Nomad Bridge adjudication"

[2]: rw-003-nomad-pipeline.json "Nomad Bridge pipeline observations"

[3]: rw-004-bonqdao.json "BonqDAO adjudication"

[4]: rw-004-bonqdao-pipeline.json "BonqDAO pipeline observations"

[5]: rw-001-parity-kill.json "Parity WalletLibrary adjudication"

[6]: rw-001-parity-pipeline.json "Parity A/B/C pipeline observations"

[7]: ../../../verification/comparator.py "Current deterministic comparator vocabulary and source matchers"
