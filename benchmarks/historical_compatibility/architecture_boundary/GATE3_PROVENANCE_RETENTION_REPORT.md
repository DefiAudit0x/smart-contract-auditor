# Gate 3 — Provenance and Raw-AST Retention Validation

## النطاق

هذا artifact يختبر retention contract داخل isolated Architecture/Compatibility track. لا يربط التخزين أو replay بالـproduction analyzer أو Comparator، ولا يغير production reporting. الهدف هو تحديد ما يُحفظ فعليًا لكل analysis، وربط finding بالمصدر والـcompiler والـraw AST والـCanonical AST والـdetector والـComparator، ثم إثبات replay والتحقق من العبث.

## قرار retention المقترح

| Artifact | السياسة الحالية في Gate 3 |
|---|---|
| Source content | persisted content-addressed artifact لكل `source_id`، مع `content_sha256` وbyte length. |
| Source manifest | persisted داخل `manifest.json`، ويشمل source IDs وartifact paths وsource-set hash. |
| Raw AST | persisted content-addressed JSON artifact باسم raw-AST SHA-256. |
| Canonical AST summary | persisted داخل `canonical_summary.json`. |
| Compiler provenance | persisted داخل manifest، بما في ذلك version وbuild وbinary hash وsettings hash وAST format. |
| Analysis/finding payload | persisted داخل manifest مع finding وprovenance وComparator result. |
| Retention duration | 2,555 يومًا كـproposal default قابل للمراجعة، وليس policy production مفروضة بعد. |
| Replay guarantee | `hash-verified-artifact-replay`. |

## Provenance chain المثبتة

```text
Finding
  ↓ source_id + canonical_expression_id
Source manifest + source hash
  ↓ source-set hash
Raw AST hash + persisted raw AST artifact
  ↓ compiler version/build/binary hash/settings hash
Adapter version + Canonical AST version
  ↓ detector/comparator versions
Analysis result and evidence
```

في Gate 3 fixture، finding source ID هو `Lib.sol`، source set يحتوي `Lib.sol` و`Main.sol`، compiler هو `0.8.25`، raw AST hash هو `305bbfb2b3ce3ee7bb1d34d130c8fda265600de094c4f279fe8d3746020b6203`، adapter هو `canonical-poc-adapter-v2`، Canonical AST هو `canonical-ast-poc-v2`، والـanalysis payload يحتوي detector finding وfinding provenance وComparator evidence.

## Replay and tamper matrix

| الحالة | النتيجة |
|---|---|
| Persisted source + manifest + raw AST + canonical summary | `ReplayVerified`. |
| إعادة التحقق دون تغيير | `ReplayVerified`. |
| تعديل source artifact بعد persistence | `ReplayVerificationFailed` بسبب content hash mismatch. |
| استعادة source artifact الأصلي | `ReplayVerified`. |
| تعديل raw AST artifact | `ReplayVerificationFailed` بسبب raw-AST hash mismatch. |
| Compiled result بلا raw AST أو provenance | `RetentionError`؛ لا bundle قابل لإعادة البناء. |
| Source set فارغ | `RetentionError`؛ لا replayable analysis. |

## Bundle identity

يُشتق `bundle_id` من source-set hash، compiler version، compiler binary hash، compiler settings hash، raw-AST hash، adapter version، Canonical AST version، وanalysis payload. هذا يمنع دمج provenance من تشغيلين مختلفين داخل artifact واحد، ويجعل manifest content-addressed وقابلًا للمقارنة.

## ما أُغلق

> **Gate 3 — Passed as an isolated provenance/retention and replay contract.**

أصبح لدينا قرار محدد لما يُحفظ فعليًا، ومخرجات قابلة للتحقق، وإثبات أن العبث بالمصدر أو raw AST لا يمر كـreplay ناجح.

## ما لم يُنفذ بعد

هذا gate لا ينشئ production artifact store، ولا يحدد backend أو encryption أو access-control أو deletion workflow أو legal retention override، ولا يثبت replay بعد نقل bundle بين machines أو بعد تبديل compiler registry. كما أن مدة 2,555 يومًا proposal default تحتاج مراجعة تشغيلية قبل اعتمادها production.

لذلك يُغلق Gate 3 على مستوى **contract and evidence**، بينما يبقى production storage implementation وoperational policy خارج هذا التغيير.

## Artifacts

| Artifact | الغرض |
|---|---|
| `provenance_retention.py` | Retention contract وbundle verifier. |
| `run_gate3.py` | Runner وtamper/replay matrix. |
| `metadata/gate3_provenance_retention_results.json` | Machine-readable retention/replay evidence. |
| `metadata/gate3_artifacts/bundles/` | Persisted content-addressed Gate 3 evidence bundle. |
| `tests/test_architecture_gates.py` | Regression tests للـretention and replay. |


## مراجعة Gate 3 — v2 hardening

تمت مراجعة retention contract v2 واختباره ضد مصفوفة عبث موسعة. لا تقتصر عملية التحقق على artifact bytes؛ بل تربط أيضًا manifest بالـbundle identity، وcompiler provenance، وadapter version، وCanonical AST hash، وanalysis payload hash. أي اختلاف مادي في هذه الروابط ينتج `ReplayVerificationFailed` بدل نجاح صامت.

| محور الاختبار | النتيجة المثبتة |
|---|---|
| Source artifact mutation | مرفوض مع `source hash mismatch` و`source set hash mismatch`. |
| Raw AST mutation | مرفوض مع `raw AST hash mismatch`. |
| Canonical summary mutation | مرفوض مع `canonical AST hash mismatch` وidentity mismatch. |
| Analysis payload mutation | مرفوض مع `analysis payload hash mismatch` وidentity mismatch. |
| Manifest compiler metadata mutation | مرفوض مع compiler provenance mismatch. |
| Manifest adapter metadata mutation | مرفوض مع adapter provenance mismatch أو bundle identity mismatch. |
| Manifest finding provenance mutation | مرفوض لأن manifest analysis لم يعد يطابق payload المحفوظ. |
| Restore after each tamper | يعود إلى `ReplayVerified` بعد استعادة bytes والmanifest الأصليين. |

## Finding-level provenance

أصبح كل finding في fixture Gate 3 مرتبطًا بسلسلة قابلة لإعادة التفسير: `source_id` و`source_range` و`source_sha256`، ثم `raw_ast_hash` وcompiler version/build/binary hash، ثم adapter وCanonical AST versions، وأخيرًا detector وComparator evidence. في الحالة المثبتة بقي attribution هو `Lib.sol`، ولم يتحول إلى `Main.sol` رغم أن `Main.sol` هو entry point للترجمة.

## Failure semantics

أضيفت تغطية صريحة لحالات `CompilationFailed` و`ASTUnavailable` و`UnsupportedCompiler` و`UnsupportedASTVersion` و`ASTNormalizationFailed` و`Inconclusive`. كل حالة تنتج failure provenance قابلة للتسلسل JSON وتتضمن diagnostics وsource-set hash وcompiler/adapter/Canonical AST metadata، بدل تحويل فشل normalization أو عدم كفاية الدليل إلى zero findings.

## Validation result

Focused Gate 3 tests: **5 passed**. Full regression suite: **344 passed, 70 warnings**. لم تتغير ملفات `analyzers/` أو `verification/`، ولم تتغير Primary Benchmark أو Real-World adjudication tracks. نتيجة Gate 3 هي **Passed within isolated contract/evidence scope**؛ أما production artifact store وoperational retention/access-control policy فما زالت خارج نطاق Stage 1.
