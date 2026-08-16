# Gate 2 — Production Compiler-Resolution Policy Validation

## النطاق

هذا artifact يختبر **قرار** compiler resolution داخل isolated Architecture/Compatibility track، ولا يضيف Production CompilerResolver إلى `analyzers/` أو يغير مسار compilation الحالي في production. الهدف هو إثبات أن selection قابل للتفسير، وأن الرفض صريح، وأن compilation failure لا يتحول إلى compiler fallback أو no findings.

## السياسة المطبقة في الـPOC

| القرار | السياسة |
|---|---|
| Verified deployment metadata | يُستخدم عندما لا يوجد explicit version؛ وإذا تعارض explicit وverified فلا تُطبق أولوية صامتة، بل يُعاد `VersionConflict`. |
| Explicit compiler version | يُستخدم بعد التحقق من توفر binary وتوافقه مع كل pragmas؛ تعارضه مع verified version يُرفض صراحةً. |
| Pragma constraints | تُجمع لكل source unit وتُستخدم لتصفية candidates، لا لتخمين compiler وحيد عند الغموض. |
| Candidate واحد متوافق | `Resolved` بسبب `single-compatible-candidate`. |
| Candidates متعددة | `AmbiguousCandidates` ما لم يطلب caller صراحةً `highest-compatible` policy. |
| لا يوجد candidate متوافق | `PragmaConflict`. |
| Compiler غير متوفر | `UnsupportedCompiler`. |
| لا توجد pragma ولا explicit/verified version | `NoPragmaPolicy`. |
| Compilation بعد resolution يفشل | `CompilationFailed`، ولا يعاد resolution بصمت إلى إصدار آخر. |

## Matrix result

| الحالة | النتيجة | التفسير |
|---|---|---|
| Single file `^0.8.25` + explicit `0.8.25` | `Resolved` | اختيار explicit deterministic. |
| Single file `^0.4.10` + explicit `0.4.10` | `Resolved` | historical binary محدد صراحةً. |
| ملفان بنفس pragma + verified `0.8.25` | `Resolved` | source set كامل، وverified version يحسم القرار. |
| Range متوافق مع عدة candidates + explicit highest policy | `Resolved` إلى `0.8.26` | selection policy صريحة وقابلة لإعادة التفسير. |
| Range متوافق مع عدة candidates دون policy | `AmbiguousCandidates` | لا compiler guess. |
| ملفان بـpragma متعارضة `^0.8.25` و`^0.4.10` | `PragmaConflict` | لا يوجد candidate يرضي كل source units. |
| Compiler `0.6.12` مسجل لكنه غير متوفر | `UnsupportedCompiler` | لا يوجد fallback إلى 0.8.x أو غيره. |
| لا توجد pragma | `NoPragmaPolicy` | يلزم explicit/verified configuration. |
| Explicit `0.4.10` مع pragma `^0.8.25` | `PragmaConflict` | explicit version لا يتجاوز source constraints، و`compatible_candidates` فارغة. |
| Explicit `0.8.26` مع verified `0.8.25` وpragma `^0.8.25` | `VersionConflict` | لا precedence صامتة؛ selected = null وdiagnostic يشرح التعارض. |
| Explicit وverified كلاهما `0.8.25` | `Resolved` | اتفاق موثق عبر `explicit-and-verified-agree`. |
| Compiler `0.8.25` متوفر لكن source malformed | resolution `Resolved` ثم compilation `CompilationFailed` | compilation failure طبقة مستقلة، ولا تتحول إلى no findings. |
| Multi-file `Main.sol → Lib.sol` بنفس pragma | `Resolved` ثم `Compiled` | source manifest and AST source units preserved. |

## Invariants

> **نفس source set + نفس policy + نفس candidate registry ينتج نفس القرار.**

يُحسب `request_source_set_sha256` من source map المرتب، وتُحفظ constraints حسب `source_id`، وقائمة candidates، وselected candidate، وselection reason، وrejection diagnostics، وpolicy version. لذلك يمكن إعادة تفسير سبب الاختيار أو الرفض دون الاعتماد على log خارجي.

> **No compiler guess → no silent fallback → no usable AST claim.**

إذا فشل compilation بعد اختيار compiler، تبقى النتيجة `CompilationFailed` مرتبطة بالإصدار والـbinary hash المستخدمين. لا يعاد الطلب تلقائيًا إلى candidate آخر، ولا يُنشأ `CanonicalASTReady` أو `AnalysisSucceededNoFindings` من source لم يثبت AST الخاص به.

## حدود Gate 2

هذا validation لا يمثل production resolver implementation، ولا يثبت بعد استخراج verified deployment metadata من external registry، أو البحث عن binaries في production artifact store، أو cryptographic attestation للـcompiler build، أو full Solidity pragma grammar لكل إصدار تاريخي. لكنه يغلق contract ambiguity الخاص بتعارض explicit/verified ويثبت أن `compatible_candidates` لا تضم مرشحًا مرفوضًا بسبب pragma. هذه العناصر التشغيلية يجب أن تدخل Production Architecture Proposal قبل Stage 1 implementation.

## النتيجة

> **Gate 2 — Passed as a deterministic policy validation inside the isolated track.**

نجاح Gate 2 لا يصرح ببدء production resolver. بل يثبت أن policy المقترحة يمكن أن تكون deterministic وfail-closed قبل تنفيذها production.

## Artifacts

| Artifact | الغرض |
|---|---|
| `canonical_ast_poc/compiler_resolution_policy.py` | Policy contract المعزول. |
| `run_gate2.py` | Matrix runner. |
| `metadata/gate2_compiler_resolution_results.json` | Machine-readable outcomes والـrejection reasons. |
| `tests/test_architecture_gates.py` | Regression tests للـresolution boundaries. |
