# Cross-Detector Compatibility Audit

## Scope and non-fix rule

This audit measures three existing detector families only: `Selfdestruct`, `block.timestamp Usage (AST)`, and `DELEGATECALL Usage (AST)`. The selection intentionally spans an opcode-related family, a timing/AST semantic family, and an access-control/AST family. Each family has a canonical modern form, a legacy or historical equivalent where the language provides one, and a fixed control. The matrix covers Solidity 0.4.11, 0.5.17, 0.6.12, 0.7.6, and 0.8.25.

> **Measurement-only rule:** No detector, alias, compiler-selection path, AST normalizer, Comparator matcher, or architecture component was changed. The goal is to locate the break, not to make every historical form pass.

The machine-readable artifact is [`cross_detector_compatibility_measurement.json`](metadata/cross_detector_compatibility_measurement.json), and the compact matrix is [`cross_detector_compatibility_summary.txt`](metadata/cross_detector_compatibility_summary.txt). The corpus generator and runner are stored beside this report so the measurement can be regenerated without importing third-party PoC code.

## Measurement chain

Each row records the following sequence:

> **Historical source → historical compiler/raw AST → current normalized AST (`solc 0.8.25`) → current detector → current Comparator**

The historical compiler is selected per version family. The normalized AST and detector stages use the existing project path unchanged, whose compiler constant is `0.8.25`. The Comparator is also unchanged and uses its existing source matchers.

## Detector selection

| Detector family | Canonical form | Historical/legacy form | Fixed control | Why it was selected |
|---|---|---|---|---|
| `Selfdestruct` | `selfdestruct(_to)` | `suicide(_to)` | No destructive operation | Opcode-related detector already implicated by Parity. |
| `block.timestamp Usage (AST)` | `block.timestamp` | `now` | State flag with no time source | AST semantic detector with a documented Solidity-era spelling change. |
| `DELEGATECALL Usage (AST)` | `.delegatecall(data)` | `.callcode(data)` | Direct `.call(data)` | Access-control/storage-context detector with a historical near-equivalent. |

## Results by family

### Selfdestruct

Solidity 0.4.11 compiles both canonical `selfdestruct` and legacy `suicide`, and the raw AST contains the corresponding token for each. The current normalized AST fails on the historical source because the unchanged project compiler path is `solc 0.8.25`. The detector still reports `Selfdestruct` on canonical source in every version family because its unchanged textual fallback recognizes the literal `selfdestruct`; it does not report the legacy `suicide` form. Comparator behavior is identical: canonical source is `Confirmed`, while `suicide` is `Rejected`.

From Solidity 0.5.17 onward, the high-level `suicide` form fails in the historical compiler matrix, while canonical `selfdestruct` continues to compile. This separates the 0.4.x legacy-alias miss from later compiler rejection. The fixed controls remain clean.

### block.timestamp Usage (AST)

The historical compiler accepts canonical `block.timestamp` across all five version families. It accepts legacy `now` through Solidity 0.6.12 and rejects it from the 0.7.6 matrix onward. The raw AST records `timestamp` for the canonical form and `now` for the legacy form when compilation succeeds.

The current normalized AST succeeds only for the 0.8.25 canonical fixture. The current AST detector therefore reports `block.timestamp Usage (AST)` only for the 0.8.25 canonical source; it misses canonical historical sources even when the historical compiler and raw AST succeed. The Comparator confirms canonical `block.timestamp` text in all five versions, but rejects legacy `now` because its matcher recognizes only `block.timestamp`. This is a two-layer boundary: current compiler/normalized-AST compatibility affects the detector, while the Comparator has an independent lexical vocabulary boundary.

### DELEGATECALL Usage (AST)

The historical compiler accepts canonical `.delegatecall(data)` in all five version families. It accepts the legacy `.callcode(data)` form only in the 0.4.11 representative and rejects it from 0.5.17 onward. Raw AST output preserves `delegatecall` and `callcode` when the relevant source compiles.

The current normalized AST succeeds only for the 0.8.25 canonical fixture. The current AST detector reports `DELEGATECALL Usage (AST)` only for that current-version canonical source, even though historical compilers accept the canonical form in earlier versions. The Comparator confirms canonical `delegatecall(` text in all five versions and rejects `callcode(` because it has no legacy-equivalent matcher. The fixed direct-call controls remain detector-clean and Comparator-rejected.

## Cross-detector matrix

| Detector | Version range | Canonical historical compiler | Canonical raw AST | Canonical normalized AST | Canonical detector | Canonical Comparator | Legacy result |
|---|---|---|---|---|---|---|---|
| Selfdestruct | 0.4.11 | Compiled | `selfdestruct` | Failed under current 0.8.25 path | HIT via textual fallback | Confirmed | 0.4.11 compiles `suicide` but detector MISS/Comparator Rejected; 0.5+ compiler rejects it |
| block.timestamp | 0.4.11–0.8.25 | Compiled | `timestamp` | Only 0.8.25 succeeds | Only 0.8.25 HIT | Confirmed in all versions | `now` compiles through 0.6.12 but detector MISS/Comparator Rejected; 0.7+ compiler rejects it |
| DELEGATECALL | 0.4.11–0.8.25 | Compiled | `delegatecall` | Only 0.8.25 succeeds | Only 0.8.25 HIT | Confirmed in all versions | 0.4.11 `callcode` compiles but detector MISS/Comparator Rejected; 0.5+ compiler rejects it |

The exact row-level artifact contains 45 observations: three detectors × five version families × three forms. All 15 fixed controls compile in their historical compiler and remain target-detector clean. Canonical Comparator evidence is present in all 15 canonical rows, while legacy Comparator evidence is absent in all 15 legacy rows.

## Where the chain breaks

The experiment identifies three different break types rather than one universal failure.

| Break type | Observed evidence | Affected families | Interpretation |
|---|---|---|---|
| Historical language removal | `suicide` fails from 0.5.x; `now` fails from 0.7.x; `callcode` fails from 0.5.x in this matrix | All three legacy forms | The compiler itself rejects some historical equivalents. This is not a detector false negative for those rows. |
| Current compiler/normalized-AST boundary | Canonical 0.4.x–0.7.x forms compile historically but normalized AST fails under unchanged `solc 0.8.25` | `block.timestamp`, `DELEGATECALL`; also canonical `Selfdestruct` normalized signal | The current AST path is effectively modern-version-only for these canonical probes. |
| Detector/Comparator vocabulary boundary | `suicide`, `now`, and `callcode` are absent from target detector/Comparator recognition even when historical compilation succeeds | All three families | Legacy semantic equivalents are not normalized into the existing detector families. |

There is also an implementation asymmetry. `Selfdestruct` has a source-text fallback and therefore hits canonical historical text despite current AST compilation failure. The two AST-only families do not have an equivalent fallback and miss canonical historical source when the current compiler cannot parse it. This is evidence of a shared pipeline boundary, but it is not yet enough to label the architecture defective: the sample contains only three detectors and uses minimal fixtures.

## Decision

The measurement supports a stronger hypothesis than the Selfdestruct-only audit, but not a repair decision. Two AST-only families show the same canonical historical pattern: historical compiler success, current normalized-AST failure under `solc 0.8.25`, detector miss, and Comparator confirmation of the canonical source. All three families also reject legacy equivalents at the Comparator layer.

The correct current classification is therefore **possible shared compiler/AST compatibility boundary, not yet an architecture verdict**. No alias, normalization rule, compiler fallback, Comparator matcher, or detector change should be added from this measurement alone. The next design decision should be based on whether the project wants historical-source support as a product requirement; if so, an isolated architecture audit should examine compiler selection, AST acquisition, normalized AST contracts, detector fallback policy, and evidence representation before any compatibility fix is implemented.

The controlled primary benchmark and real-world metrics remain separate. This audit does not admit Parity, does not alter Nomad or BonqDAO, and does not create Case #4.

## References

[1]: metadata/cross_detector_compatibility_measurement.json "Machine-readable 45-row measurement artifact"

[2]: metadata/cross_detector_compatibility_summary.txt "Cross-detector compact matrix"

[3]: ../REPORT.md "Selfdestruct-only historical compatibility report"

[4]: ../../../analyzers/solidity_ast.py "Current compiler and AST normalizer"

[5]: ../../../analyzers/solidity_analyzer.py "Current detector implementations"

[6]: ../../../verification/comparator.py "Current deterministic Comparator matchers"

[7]: ../../../benchmarks/timestamp/vulnerable.sol "Canonical timestamp benchmark source"

[8]: ../../../benchmarks/delegatecall/vulnerable.sol "Canonical delegatecall benchmark source"
