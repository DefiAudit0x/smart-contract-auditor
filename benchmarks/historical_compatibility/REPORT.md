# Historical Compatibility Audit: Selfdestruct

## Scope and rule

This is a **measurement-only** audit of the existing `Selfdestruct` detector and Comparator. No production detector, parser, AST normalizer, compiler-selection logic, Comparator matcher, or architecture was changed. The corpus contains five small fixtures for each of Solidity 0.4.11, 0.5.17, 0.6.12, 0.7.6, and 0.8.25: high-level `selfdestruct`, high-level `suicide`, inline-assembly `selfdestruct`, inline-assembly `suicide`, and a fixed contract with no destructive operation.

Solidity 0.4.11 is used as the reproducible 0.4.x compiler representative because the installed `py-solc-x` version does not expose a 0.4.10 installer. The Parity deployment itself remains pinned separately to Etherscan’s exact-match Solidity `v0.4.10+commit.f0d539ae`; this audit does not rewrite that source or claim that 0.4.11 is the deployment compiler.

## Measurement path

The pipeline measures four separate links:

> **Historical source → historical compiler → AST representation → current analyzer/detector → current Comparator**

The historical compiler stage uses the matching compiler version for each directory. The current analyzer stage is run unchanged and remains fixed at `solc 0.8.25`. The current Comparator is run unchanged with its existing `Selfdestruct` matcher, which searches for the literal `selfdestruct(` pattern. The complete machine-readable output is [`selfdestruct_compatibility_measurement.json`](metadata/selfdestruct_compatibility_measurement.json), and the compact matrix is [`selfdestruct_compatibility_summary.txt`](metadata/selfdestruct_compatibility_summary.txt).

## Results matrix

| Version family | Historical compiler | `selfdestruct` source | `suicide` source | Assembly `selfdestruct` | Assembly `suicide` | Fixed |
|---|---:|---|---|---|---|---|
| Solidity 0.4.x | 0.4.11 | Compile; detector HIT; Comparator Confirmed | Compile; detector MISS; Comparator Rejected | Compile; detector HIT; Comparator Confirmed | Compile; detector MISS; Comparator Rejected | Compile; clean |
| Solidity 0.5.x | 0.5.17 | Compile; detector HIT; Comparator Confirmed | **Compile failed**; detector MISS; Comparator Rejected | Compile; detector HIT; Comparator Confirmed | **Compile failed**; detector MISS; Comparator Rejected | Compile; clean |
| Solidity 0.6.x | 0.6.12 | Compile; detector HIT; Comparator Confirmed | **Compile failed**; detector MISS; Comparator Rejected | Compile; detector HIT; Comparator Confirmed | **Compile failed**; detector MISS; Comparator Rejected | Compile; clean |
| Solidity 0.7.x | 0.7.6 | Compile; detector HIT; Comparator Confirmed | **Compile failed**; detector MISS; Comparator Rejected | Compile; detector HIT; Comparator Confirmed | **Compile failed**; detector MISS; Comparator Rejected | Compile; clean |
| Solidity 0.8.x | 0.8.25 | Compile; detector HIT; Comparator Confirmed | **Compile failed**; detector MISS; Comparator Rejected | Compile; detector HIT; Comparator Confirmed | **Compile failed**; detector MISS; Comparator Rejected | Compile; clean |

The corpus contains 25 rows. All five `selfdestruct` and assembly-`selfdestruct` cases in every version family produce a current detector hit and a deterministic Comparator confirmation. The 0.4.x `suicide` and assembly-`suicide` cases compile successfully but produce a detector miss and Comparator rejection. From Solidity 0.5.x onward, the corresponding `suicide` forms fail at the historical compiler stage, while the modern `selfdestruct` forms continue to compile and pass the current detector/comparator path.

## Parser and AST observation

The historical compiler successfully preserves the destructive keyword in raw AST output for the compiled fixtures. High-level `selfdestruct` and `suicide` appear as historical AST identifier values in Solidity 0.4.11. Inline assembly destructive instructions are present in the raw serialized AST, but the current normalized AST extraction does not consistently expose them as `uses_selfdestruct` across old compiler AST shapes. Despite that normalized AST limitation, the current analyzer’s textual fallback still detects literal `selfdestruct` in the source. It does not detect `suicide` because neither the AST path nor the fallback path maps that legacy alias to the `Selfdestruct` detector.

This produces an important separation. The observed Parity miss is **not** explained solely by a compiler’s inability to parse the source: Solidity 0.4.11 compiles both `selfdestruct` and `suicide`. The exact detector failure occurs later because the current detector and Comparator recognize only the canonical modern spelling. The analyzer’s fixed 0.8.25 compiler is an additional compatibility limitation for exact historical files, but the controlled corpus shows that the decisive reproducible miss is the missing `suicide` semantic mapping.

## HIT/MISS interpretation

| Stage | `selfdestruct` | `suicide` | What this establishes |
|---|---|---|---|
| Historical compiler, Solidity 0.4.x | Compiles | Compiles | The legacy compiler accepts both spellings in the representative 0.4.x environment. |
| Historical compiler, Solidity 0.5.x–0.8.x | Compiles | Fails | Later compiler versions removed or rejected the legacy spelling in this matrix. |
| Current analyzer | HIT | MISS | The current detector recognizes the canonical keyword but not the legacy alias. |
| Current Comparator | Confirmed | Rejected | Deterministic verification has the same lexical boundary. |
| Fixed control | Clean | Clean | The measurement does not turn the absence of a destructive pattern into a false positive. |

## Decision

The first measurement-only conclusion is **detector-specific compatibility gap**, not yet an architecture-wide failure. The current `Selfdestruct` detector and Comparator are modern-spelling aware but not legacy-alias aware. The corpus does not justify changing them in this phase. It also reveals a secondary AST concern for inline assembly across older AST schemas, but that concern should not be generalized beyond this detector without a broader corpus.

The correct next decision is therefore conditional. If later evidence shows that only `Selfdestruct` fails on historical aliases, a narrowly scoped compatibility change can be evaluated and then Parity can be re-run. If the same parser/AST/compiler boundary appears across several existing detector families, the project should stop adding cases and perform the proposed architecture audit. The primary benchmark remains untouched at Precision/Recall/F1 `1.0/1.0/1.0`, and this historical compatibility track remains separate from those headline metrics.

## References

[1]: metadata/selfdestruct_compatibility_measurement.json "Machine-readable measurement artifact"

[2]: metadata/selfdestruct_compatibility_summary.txt "Compact compatibility matrix"

[3]: ../real_world/adjudications/rw-001-parity-kill.json "Parity exact-source adjudication"

[4]: ../real_world/adjudications/rw-001-parity-pipeline.json "Parity A/B/C pipeline observations"

[5]: ../../analyzers/solidity_ast.py "Current AST compiler and normalizer path"

[6]: ../../analyzers/solidity_analyzer.py "Current Selfdestruct detector path"

[7]: ../../verification/comparator.py "Current deterministic Selfdestruct Comparator matcher"
