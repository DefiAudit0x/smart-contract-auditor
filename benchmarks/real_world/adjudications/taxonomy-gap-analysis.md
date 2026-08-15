# Real-World Taxonomy Gap Analysis: Nomad and BonqDAO

## Purpose

This review compares the first two fully adjudicated real-world cases before selecting Case #3. The goal is not to add a detector or to reinterpret quarantined cases as metric failures. The goal is to distinguish three separate conditions: **insufficient independent evidence**, **a vulnerability family not defined in the current taxonomy**, and **a defined taxonomy family that the implementation fails to detect**.

The current measured Solidity taxonomy contains ten detector families: reentrancy, delegatecall usage, selfdestruct, public mint/burn, `tx.origin` authorization, flash-loan attack vectors, storage collision, unchecked transfer, unbounded loops, and `block.timestamp` usage. The analyzer also emits advisory findings such as `Uninitialized Proxy`, `Arbitrary External Call`, `Unvalidated Address`, `Event Emission`, and `Pragma Fixed`, but an incidental observation is not automatically an admitted Ground Truth mapping. The ten-family list is the controlled comparison vocabulary used by the evaluation protocol [1] [2].

> **Coverage definition:** A case is covered only when an existing detector is semantically equivalent to the independently established vulnerability claim and can be assigned as an expected detector before running the comparator. A syntactic symptom or nearby security concept does not satisfy this definition.

## Gap table

| Case | Independently established real vulnerability | Current taxonomy candidate | Coverage | Reason for result |
|---|---|---|---|---|
| Nomad Bridge | **Message/proof validation flaw:** initialization pre-approved `bytes32(0)`, `acceptableRoot` treated the zero root as valid after time `1`, and `process` accepted an unproven message through that predicate. | No semantically equivalent family. `Uninitialized Proxy` is nearby in wording but concerns an uninitialized delegatecall proxy, not an initialized message-authentication predicate. | ❌ **Not covered** | No detector expresses Merkle/message-proof authentication, zero-root initialization, or “unproven message must not be processable.” Static and LLM runs observed `block.timestamp` only; comparator was `NotApplicable` [3] [4]. |
| BonqDAO | **Oracle price manipulation through immediate spot-price consumption:** TellorFlex allowed a reporter value to be submitted, `getCurrentValue` selected the newest report, and Bonq `TellorPriceFeed.price()` consumed it without enforcing a dispute window before collateral valuation, borrowing, and liquidation. | No semantically equivalent family. `block.timestamp Usage (AST)` detects timestamp syntax, not oracle freshness, dispute windows, or price-manipulation resistance. | ❌ **Not covered** | No detector expresses “collateral price must come from a report older than the dispute window.” Static and LLM runs observed `block.timestamp` only; comparator was `NotApplicable` [5] [6]. |

## What the two cases actually show

Both cases have strong independent evidence, pinned source material, exact affected lines, a narrow invariant, and a passed owned vulnerable/fixed reproduction. Their quarantine status therefore does **not** primarily indicate an evidence failure. The records explicitly mark the evidence and reproduction stages as complete while leaving `covered_by_existing_detector` false [3] [5].

The common reason for non-admission is a **taxonomy definition gap**: the current controlled detector vocabulary does not define either message-proof authentication or oracle dispute-window enforcement as a detector family. The pipeline can still execute static analysis, LLM comparison, invariant evaluation, and PoC verification, but it cannot produce a valid comparator result when no expected detector mapping exists. In that state, `NotApplicable` and `Quarantined` are the correct abstention outcomes.

This evidence does **not** establish architectural inability. We have not performed a fair “detector exists and misses” experiment for either class, because no detector has yet been defined and assigned. The observations show that the existing analyzer can notice a related syntax pattern—`block.timestamp`—but that is a **non-equivalent proxy**. A false positive mapping would test the wrong hypothesis and would contaminate the metric rather than measure detection capability.

| Diagnostic question | Current answer | What would be needed to answer it rigorously |
|---|---|---|
| Is there enough independent evidence? | Yes, for both cases at the adjudication level. | A second independent adjudication remains an admission requirement, but it is not the same as missing incident evidence. |
| Is the vulnerability family defined in the controlled taxonomy? | No for Nomad proof validation; no for Bonq oracle/dispute-window enforcement. | A separate taxonomy design review, not a case-specific detector patch. |
| Did an existing semantically valid detector miss? | Not demonstrated. There was no valid expected detector to run through Comparator. | Define a detector family first, then run an independent positive/negative corpus. |
| Did the pipeline abstain correctly? | Yes. Static/LLM observations were retained, Comparator was `NotApplicable`, and Full Pipeline was `Quarantined`. | Preserve this behavior while expanding evidence and case diversity. |
| Is a new detector justified now? | No. Two cases are insufficient to infer a recurring architectural pattern. | Add diverse Case #3–#5 evidence before deciding whether expansion is warranted. |

## Implication for Case #3

Case #3 should be deliberately different from both current gaps. The preferred candidate should have an independent root cause that maps to one of the existing controlled families—such as reentrancy, unchecked transfer, delegatecall/storage collision, public mint authorization, or unbounded loop—while still requiring source pinning, independent transaction evidence, an owned contrast, an invariant, and an executable PoC. It should not be selected merely because a third-party PoC happens to contain a matching detector label.

The Case #3 experiment will therefore preserve the same abstention discipline while testing positive coverage. Before execution, the expected detector must be declared from independent source analysis. The case will then be run in three isolated views: **A — existing detector only; B — LLM only; and C — full pipeline**. The comparison will report detector presence, LLM prediction, comparator confirmation, invariant status, PoC status, and final admission separately. A successful Case #3 will demonstrate that the current pipeline can move from independent real-world Ground Truth to a confirmed existing detector without broadening the taxonomy.

## Interim conclusion

The first two cases support the following narrow conclusion:

> **Nomad and BonqDAO are currently taxonomy gaps, not demonstrated architecture failures.** The system abstained because it lacked a semantically valid detector mapping, and that abstention was correct. The next useful experiment is not to add a detector; it is to adjudicate a materially different real-world case whose root cause is already represented in the controlled taxonomy.

## References

[1]: ../../evaluation/BASELINE_RESULTS.md "Evaluation baseline and controlled taxonomy boundary"

[2]: ../../run_llm_comparison.py "Allowed detector vocabulary and LLM comparison schema"

[3]: rw-003-nomad-bridge.json "Nomad Bridge adjudication record"

[4]: rw-003-nomad-pipeline.json "Nomad Bridge stage-by-stage pipeline observations"

[5]: rw-004-bonqdao.json "BonqDAO adjudication record"

[6]: rw-004-bonqdao-pipeline.json "BonqDAO stage-by-stage pipeline observations"
