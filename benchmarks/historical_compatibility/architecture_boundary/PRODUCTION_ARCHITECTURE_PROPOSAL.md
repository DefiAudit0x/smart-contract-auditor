# Production Architecture Proposal
## Compiler / Canonical AST Compatibility Boundary

### حالة الوثيقة

هذه الوثيقة هي **Production Architecture Proposal** مبنية على نتائج Revised Compatibility POC، وليست تنفيذًا production ولا موافقة تلقائية على الدمج. لم تُعدّل ملفات `analyzers/` أو `verification/comparator.py`، ولم تتغير Primary Benchmark أو سجلات Nomad وBonqDAO وParity أو Case #4.

> **القرار المطلوب لاحقًا:** Adopt أو Revise أو Reject لهذه المعمارية المقترحة، بعد مراجعة الوثيقة وحدودها. لا يُسمح ببدء production implementation قبل قرار مستقل صريح.

---

## 1. الملخص التنفيذي

أثبت Revised Compatibility POC أن من الممكن بناء حدّ توافق معزول بين compiler-specific raw ASTs وعقد دلالي Canonical AST للعائلات المختبرة، بشرط استخدام version-isolated adapters، والتحقق من شكل AST قبل استخراج المعنى، والفشل الصريح عند فقدان البنية أو عدم اكتمالها. كما أثبت أن النتيجة الخالية من findings لا تصبح موثوقة إلا بعد نجاح compiler وAST وschema validation وnormalization وstructural validation وdetector execution.[1]

تقترح هذه الوثيقة إدخال هذه الفكرة إلى production على مراحل، وليس عبر استبدال مسار التحليل دفعة واحدة. يبدأ التصميم بـ`CompilerResolver` و`CompilationResult` و`VersionedAdapter` و`DetectorInput`، ثم يمر عبر detector واحد مختار، ثم عائلات detectors، ثم إزالة compatibility bridge فقط بعد تحقق مستقل من parity وعدم تدهور الـControlled Track.

يجب تسجيل حد مهم بوضوح: الـmulti-file slice الحالي أثبت **compilation وsource-unit preservation وmanifest وno-findings** فقط. لم يثبت بعد semantic detection عبر imported source أو انتقال finding من source unit مستورد إلى detector ثم Comparator. لذلك لا تُعدّ multi-file semantic analysis محلولة في هذه الوثيقة؛ بل تُعرّف كـproduction gate لاحق.[1]

---

## 2. القرار المعماري الأساسي

المبدأ الحاكم هو:

> **No compiler guess → no silent fallback → no usable AST claim.**

لا يجوز للنظام أن يختار compiler بديلًا لمجرد أن compiler المطلوب فشل، ولا أن يحول AST normalization الفاشل إلى `CanonicalProgram([])`، ولا أن يفسر `finding_count = 0` على أنه غياب vulnerability ما لم تنجح كل الطبقات السابقة وأُنفّذ detector فعليًا.

يفصل التصميم بين أربع مسؤوليات لا ينبغي دمجها:

| المسؤولية | المكوّن | ما لا يفعله |
|---|---|---|
| تحديد مجموعة المصادر والقيود | `SourceManifest` | لا يختار compiler وحده. |
| اختيار compiler وإعداداته | `CompilerResolver` | لا يفسر raw AST ولا يشغل detectors. |
| تحويل raw AST إلى semantic contract | `VersionedAdapter` | لا يخفي schema غير المعروفة ولا يخمّن equivalence. |
| اكتشاف evidence والتحقق منه | Detector وComparator | لا يختاران compiler ولا يقرآن schema خامًا. |

---

## 3. Production Compiler Resolver

### 3.1 التدفق المقترح

```text
SourceManifest
      ↓
CompilerRequest
      ↓
CompilerResolver
      ↓
CompilerCandidate(s)
      ↓
CompilationResult
      ↓
Raw AST + Compiler Provenance
      ↓
VersionedAdapter
      ↓
CanonicalProgram | Explicit Failure
```

### 3.2 `CompilerRequest`

يجب أن يحتوي طلب التحليل على هوية source set، وentrypoint، والـpragma constraints، والـcompiler version الصريح إن وُجد، وverified deployment metadata إن وُجد، وoptimizer/settings المطلوبة أو غير المعروفة، وسياسة multi-file، وسبب اختيار المسار. لا يجوز تمرير source string فقط إلى production boundary لأن ذلك يفقد source identity وimport graph وper-file provenance.

```text
CompilerRequest
├── source_manifest
├── entrypoint
├── explicit_compiler_version?
├── verified_deployment_metadata?
├── pragma_constraints
├── optimizer_settings
├── compilation_settings
└── resolution_policy
```

### 3.3 سياسة اختيار compiler

تُرتب مصادر القرار وفق السياسة التالية:

| الأولوية | مصدر القرار | شرط الاستخدام |
|---:|---|---|
| 1 | Verified deployment metadata | يجب أن تكون مرتبطة بالعقد والعنوان والشبكة والمصدر exact source set، وأن تُحفظ أدلة التحقق. |
| 2 | Explicit compiler version | تُستخدم عندما يحدد المستخدم أو artifact الموثق إصدارًا صريحًا. |
| 3 | Pragma constraints | تُستخدم لتصفية candidates، وليست إذنًا لتخمين compiler وحيد. |
| 4 | Supported compiler policy | تحدد adapters والبinaries المقبولة في production support matrix. |
| 5 | Compilation settings | تشمل optimizer وmetadata وstandard-json settings، وتدخل في provenance. |

عند وجود أكثر من candidate صالح، لا يختار النظام واحدًا بصمت. يجب أن يعيد `Inconclusive` أو `UnsupportedCompiler` مع candidate evidence وrejection reasons، إلا إذا كانت `resolution_policy` تعرّف tie-breaker حتميًا ومراجعًا. وعند عدم وجود candidate صالح، يجب إيقاف التحليل قبل detectors وعدم إصدار no-finding claim.

### 3.4 `CompilationResult`

```text
CompilationResult
├── status
├── raw_ast_artifact
├── source_manifest
├── compiler_resolution
├── diagnostics
└── provenance
```

يجب أن تكون `compiler_resolution` قابلة للتفسير لاحقًا، وتشمل selected compiler، compiler binary hash، settings hash، candidate list، candidate acceptance evidence، وrejection reasons. لا يكفي تسجيل الإصدار النهائي فقط، لأن reproducibility تتطلب تفسير سبب عدم اختيار البدائل.

---

## 4. Canonical AST Contract v1

### 4.1 قاعدة التصميم

Canonical AST ليس Solidity AST ثانية كاملة. كل field يجب أن يرتبط بحاجة detector أو evidence أو reproducibility. إذا لم توجد consumer واضحة، فلا يضاف field لمجرد الاحتياط. وفي الوقت نفسه، لا يجوز حذف field يحتاجه detector ثم تعويضه بتخمين نصي.

### 4.2 العقد المقترح

```text
CanonicalProgram
├── canonical_ast_version
├── compiler_provenance
├── source_units[]
├── diagnostics[]
├── unknown_nodes[]
└── skipped_nodes[]

CanonicalSourceUnit
├── source_id
├── source_range
└── contracts[]

CanonicalContract
├── name
├── kind
├── source_range
├── base_contracts[]
├── state_variables[]
├── modifiers[]
└── functions[]

CanonicalFunction
├── name
├── kind
├── visibility
├── state_mutability
├── modifiers[]
├── parameters[]
├── returns[]
├── expressions[]
└── source_range

CanonicalExpression
├── expression_id
├── kind
├── member
├── arguments[]
└── source_range
```

### 4.3 مصفوفة fields والـconsumers

| Field | الغرض | قاعدة التوسع |
|---|---|---|
| `source_units` و`source_id` | multi-file identity وsource-unit separation | مطلوب للـmanifest وreplay؛ لا يثبت وحده imported semantic detection. |
| `contract.name/kind` | contract-level findings وownership | يبقى جزءًا من v1. |
| `base_contracts` | inheritance/proxy/ownership detectors | يُفعّل عند وجود detector consumer مثبت. |
| `state_variables` | storage/public state detectors | لا يُستخدم كبديل عن storage layout. |
| `function.name/visibility` | access-control وpublic function detectors | مطلوب في v1. |
| `state_mutability` | payable/view/pure semantics | مطلوب لتقليل false positives في بعض العائلات. |
| `parameters/returns` | signature-sensitive detectors | يدخل v1 عندما يثبت detector consumer. |
| `modifiers` | access-control/reentrancy semantics | مطلوب قبل migration لعائلات تعتمد عليها. |
| `expressions` | semantic operations وsource evidence | يجب أن تكون AST-shaped لا token-matched. |
| `source_range` | evidence وComparator lookup | مطلوب لكل expression وfunction قابلين لإنتاج finding. |
| `provenance` | replay والتفسير اللاحق | لا يدخل detector branching؛ يدخل reporting والـaudit trail. |
| `unknown_nodes/skipped_nodes` | منع silent loss | unknown semantic structure يمنع no-finding claim أو ينتج `Inconclusive`. |

### 4.4 ما لا يمثله Canonical AST v1

لا يمثل v1 كل تفاصيل Solidity compiler AST، ولا bytecode، ولا storage layout، ولا complete type system، ولا optimizer internals، ولا control-flow graph كاملًا، ولا source comments أو strings كدلالات أمنية، ولا imported semantic relationships التي لم يُثبت detector contract معالجتها بعد. أي detector يحتاج واحدًا من هذه يجب أن يعلن dependency صريحة ويمنع migration قبل إضافة field أو boundary متخصصة.

---

## 5. Versioned Adapter Contract

```text
RawAST + CompilerMetadata
            ↓
VersionedAdapter
            ↓
CanonicalProgram | Explicit Failure
```

### 5.1 قواعد التصنيف

| المدخل | النتيجة الإلزامية |
|---|---|
| legacy AST مع legacy schema | normalization إلى Canonical AST إذا اكتملت البنية. |
| modern AST مع modern schema | normalization إلى Canonical AST إذا اكتملت البنية. |
| unknown schema | `UnsupportedASTVersion`. |
| malformed known schema | `ASTNormalizationFailed`. |
| partially understood structure | `Inconclusive`. |
| provenance ناقصة | failure صريح؛ لا `CanonicalASTReady`. |
| zero contracts مع source يحتوي contracts | `ASTNormalizationFailed`. |
| structural loss في function-like nodes أو ranges | `ASTNormalizationFailed`. |

لا يجوز أن تعتمد ownership على `ast_format` metadata وحدها؛ يجب فحص raw schema markers نفسها. كما يجب أن تكون alias mappings context-safe: `block.timestamp` لا يُستخرج إلا من `MemberAccess` مع magic `block` receiver، و`delegatecall` لا يُستخرج إلا من member call فعلي، و`suicide` لا يُستخرج إلا من FunctionCall callee مناسب.

---

## 6. Detector Migration Strategy

### Stage 0 — Isolated POC bridge

يبقى الـbridge الحالي في Compatibility Track. وظيفته إثبات semantic projection وstatus/provenance contract، وليس تمثيل production migration. لا تدخل نتائجه في Primary metrics ولا تغيّر Comparator.

### Stage 1 — Detector contract + detector production واحد

يُختار detector واحد محدود الدلالة، ويُعرّف له contract رسمي:

```text
DetectorInput
├── canonical_program
├── source_view
├── analysis_context
└── provenance
```

يجب أن يستقبل detector `DetectorInput` immutable/read-only، وألا يعرف compiler version أو AST schema أو adapter internals. في هذه المرحلة يُشغّل المسار الحالي والمسار Canonical في shadow mode، وتُقارن النتائج دون تغيير القرار للمستخدم.

### Stage 2 — Detector families

بعد نجاح Stage 1، تُنقل family واحدة في كل مرة، مع contract tests وnegative controls وsource-range checks وComparator boundary tests. لا تُنقل detectors التي تعتمد fields غير موجودة في Canonical AST v1.

### Stage 3 — إزالة compatibility bridge

لا يُزال bridge إلا بعد تحقق كل detector migrated، وإغلاق حالات silent loss، ووجود rollback path لا يعيد failure إلى zero findings، ومرور Controlled Track وCompatibility Track وReal-World registry tests. إزالة bridge ليست شرطًا زمنيًا؛ هي نتيجة acceptance gates فقط.

---

## 7. DetectorInput وSourceView

```text
DetectorInput
├── canonical_program
├── source_view
│   ├── source_id
│   ├── source_bytes/text
│   ├── source_hash
│   └── source_manifest_reference
├── analysis_context
│   ├── canonical_ast_version
│   ├── adapter_version
│   └── provenance_reference
└── detector_version
```

`SourceView` مخصص للوصول إلى bytes أو excerpts المرتبطة بـsource range، وليس لإعادة parsing أو compiler fallback داخل detector. إذا احتاج detector معلومة غير موجودة في Canonical AST، يجب أن يفشل contract validation أو يطلب field رسميًا؛ لا يجوز أن يقرأ raw AST أو يستخرج semantics من text coincidence.

---

## 8. Comparator Boundary

يجب أن يبقى الفصل صريحًا:

```text
Detection semantics
        ≠
Evidence confirmation semantics
```

الـPOC أثبت أن historical source يمكن أن يصل إلى detector HIT بعد normalization، ثم يحصل على Comparator `Rejected` لأن source-vocabulary matcher الحالي لا يثبت syntax التاريخية؛ modern source يصل إلى `Confirmed`. هذه ليست نتيجة تسمح بتعديل Comparator تلقائيًا ولا سببًا لإدخال Parity في metrics.

### 8.1 العقد المقترح

```text
Finding + SourceEvidence + ComparatorVersion + Invariant
                    ↓
          Confirmed | Rejected | Inconclusive
```

### 8.2 سياسة historical evidence

| الحالة | التفسير المقترح |
|---|---|
| Detector semantic HIT + Comparator Confirmed | finding مؤكد دلاليًا ومصدريًا. |
| Detector semantic HIT + Comparator Rejected بسبب vocabulary غير مدعومة | لا يُعاد تصنيفه إلى no finding؛ يسجل كـ`semantic_hit_evidence_rejected` أو `Inconclusive` حسب policy المستقبلية. |
| Detector لم يعمل بسبب upstream failure | لا يُنشأ Comparator rejection؛ الحالة upstream failure. |
| Detector clean بعد successful analysis | `AnalysisSucceededNoFindings` فقط إذا اكتملت كل الطبقات. |

أي policy جديدة للـhistorical evidence يجب أن تكون architecture decision مستقلة، مع fixtures exact-source، ولا تُنفذ كـComparator patch داخل هذه الوثيقة.

---

## 9. Provenance Architecture وRetention Policy

### 9.1 سلسلة التتبع

```text
Finding
  ↓ canonical_expression_id
CanonicalExpression
  ↓ source_range + source_id
SourceView / SourceManifest
  ↓ source_hash
Raw AST artifact
  ↓ raw_ast_hash
Compiler result
  ↓ compiler version + binary hash + settings hash
Versioned adapter
  ↓ adapter_version + canonical_ast_version
Detector / Comparator versions
```

### 9.2 الحقول الإلزامية

يجب أن يحمل كل finding أو analysis status، مباشرة أو عبر immutable references، `source_id` و`source_manifest` و`source_hash` و`compiler_version` و`compiler_binary_hash` و`raw_ast_hash` و`adapter_version` و`canonical_ast_version` و`detector_version` و`comparator_version` و`source_range` و`evidence_kind` و`canonical_expression_id` و`analysis_status`.

### 9.3 سياسة الاحتفاظ المقترحة

الاختيار المقترح هو **hybrid retention**:

| Artifact | السياسة |
|---|---|
| Source manifest and per-file content hash | يحتفظ بها مع كل analysis result. |
| Compiler resolution and diagnostics | يحتفظ بها مع result حتى انتهاء retention period الخاص بالتقارير. |
| Raw AST | يُحفظ كـpersisted content-addressed artifact عندما يكون التحليل أدلة أمنية أو قابلًا لإعادة التقييم؛ لا يُضمّن كاملًا داخل finding. |
| Raw AST hash | يبقى دائمًا داخل provenance حتى عندما يُحذف artifact وفق policy. |
| Canonical AST summary | يُحفظ مع result لأنه صغير وقابل للمراجعة. |
| Evidence excerpts | تُحفظ bounded ومربوطة بـsource hash/range، دون اعتبارها بديلًا عن source artifact. |

إذا كان raw AST ephemeral في بعض التشغيلات، فلا يجوز تسمية النتيجة `fully reproducible` بعد انتهاء نافذة الاحتفاظ؛ تُصنف حينها `replay-limited` مع raw-AST hash فقط. أي finding إنتاجي يتطلب replay بعد أشهر يجب أن يحتفظ بالـsource manifest والـcompiler artifact أو بمسار استرجاع موثوق لهما.

---

## 10. Multi-file Production Model

### 10.1 `SourceManifest`

```text
SourceManifest
├── source_id
├── path
├── content_hash
├── pragma_constraints[]
├── import_edges[]
├── source_order
└── entrypoint
```

يجب أن تكون source IDs canonical ومحددة قبل compilation، وأن تُحفظ import edges وentrypoint. لا يجوز اختزال source set في entry source فقط لأن ذلك يفقد provenance ويمنع تفسير imported contracts.

### 10.2 `CompilerResolution`

```text
CompilerResolution
├── selected_compiler
├── compiler_binary_hash
├── settings
├── settings_hash
├── candidate_evidence[]
├── accepted_constraints[]
└── rejection_reasons[]
```

### 10.3 حدود ما أثبته الـPOC

أثبت الـPOC أن `Main.sol` و`Lib.sol` يمكن compiling عبر standard-json، وأن source units وmanifest وpragma constraints يمكن حفظها، وأن entry-source detector no-finding يمكن إصداره بعد نجاح pipeline. لكنه **لم يثبت semantic detection عبر imported source**، ولم يثبت finding reference من imported source unit إلى detector أو Comparator. لذلك يجب إضافة acceptance gate مستقل:

> Imported semantic fixture must produce a finding whose `source_id` و`source_range` يعودان إلى imported file، ثم يمر عبر Comparator دون فقدان provenance.

حتى اجتياز هذا gate، تُعتبر multi-file support في production **compilation-ready فقط** وليست semantic-analysis-ready.

---

## 11. Failure State Machine

```text
SourceManifest
      │
      ▼
CompilerResolver
 ┌────┼───────────────┐
 │    │               │
 ▼    ▼               ▼
UnsupportedCompiler  CompilationFailed  CompilationResult
                                          │
                                          ▼
                                   AST available?
                                  ┌───────┴────────┐
                                  │                │
                                 No               Yes
                                  │                │
                           ASTUnavailable         ▼
                                            Schema valid?
                                           ┌──────┴───────┐
                                           │              │
                                          No             Yes
                                           │              │
                             UnsupportedASTVersion      ▼
                                                    Normalize
                                               ┌──────┼─────────┐
                                               │      │         │
                                            Failed  Partial    Ready
                                               │      │         │
                                               ▼      ▼         ▼
                                    ASTNormalizationFailed  Inconclusive  Detector
                                                                             │
                                                                     ┌───────┴────────┐
                                                                     │                │
                                                                No findings       Findings
                                                                     │                │
                                                                     ▼                ▼
                                                       AnalysisSucceededNoFindings  AnalysisSucceededWithFindings
```

القاعدة الحرجة:

> لا يمكن إنتاج `AnalysisSucceededNoFindings` إلا بعد نجاح compiler وAST availability وschema ownership وnormalization وstructural validation وتنفيذ detector فعليًا.

Rollback أو Comparator لا يجوز أن يحول أي failure state إلى `AnalysisSucceededNoFindings`.

---

## 12. Rollout وRollback

### Production v1 — Current default

يبقى المسار الحالي هو default. يكون Canonical path opt-in خلف feature flag أو detector-specific configuration، ويعمل في shadow mode حيث لا يغيّر قرار المستخدم. تُسجل الفروق بين current وCanonical، ولا تُقبل findings الجديدة أو الإزالات تلقائيًا.

### Production v2 — Selected detectors

يصبح Canonical path active لعائلات detectors التي اجتازت acceptance gates، مع إبقاء current path كمرجع أو rollback path لفترة محددة. يجب أن يكون اختيار المسار observable في كل result عبر `analysis_path` وversions.

### Production v3 — Canonical default

يصبح Canonical path default فقط بعد اكتمال migration للعائلات المشمولة، وإثبات عدم وجود silent analysis loss، والتحقق من source ranges وComparator boundary وtrack baselines. يبقى legacy path محدودًا كمسار مدعوم صراحةً، لا كfallback عشوائي.

### شروط rollback

الـrollback يجب أن يعيد اختيار implementation path، لا أن يغير status semantics. إذا فشل Canonical path، فالنتيجة الصحيحة هي failure/inconclusive visible؛ لا يجوز تشغيل legacy path سرًا ثم إصدار zero findings أو دمج النتائج دون provenance. أي fallback production يجب أن يكون explicit، policy-controlled، ومسجلًا كـseparate analysis attempt.

---

## 13. Observability وSecurity Controls

يجب تسجيل `analysis_path` وcompiler resolution وadapter/canonical versions وstatus transitions وunknown/skipped nodes وsource manifest identity وComparator result. يجب أن تكون هذه السجلات قابلة للربط عبر analysis ID واحد.

من منظور false-positive security، يجب رفض direct-token semantics، والتحقق من receiver/callee/call shape، واستخدام negative controls للأسماء والـstrings والـcomments والـnested expressions، وعدم استخدام textual fallback كدليل detector عندما يكون Canonical AST هو contract المعتمد. ومن منظور silent-loss security، يجب منع empty canonical structures، والتحقق من source-unit completeness، وإيقاف detector عند unknown semantic nodes أو missing provenance.

يجب أيضًا منع compiler artifact substitution: binary hash وsettings hash وraw-AST hash يجب أن تكون جزءًا من provenance، ويجب ألا يستطيع source manifest غير المرتب أو import alias تغيير source identity دون اكتشاف.

---

## 14. Compatibility Support Matrix

> هذه المصفوفة مستقلة عن نجاح POC. لا يجوز صياغة claim بأن Canonical AST يدعم كل Solidity 0.4.x–0.8.x.

| Solidity family | Compiler artifact | AST schema | Adapter | POC tested | Production-supported |
|---|---|---|---|---:|---:|
| 0.4.10 | Installed exact binary | Legacy `ast-json` | Legacy v1/v2 design target | Yes | TBD |
| 0.5.x | Not established in this proposal | TBD | TBD | No | TBD |
| 0.6.x | Not established in this proposal | TBD | TBD | No | TBD |
| 0.7.x | Not established in this proposal | TBD | TBD | No | TBD |
| 0.8.25 | Installed exact binary | Modern compact/standard-json AST | Modern v1/v2 design target | Yes | TBD |
| Other 0.8.x | Candidate-specific | TBD | TBD | No | TBD |

الصياغة المسموح بها حاليًا هي:

> **The POC demonstrates a version-isolated compatibility boundary for the tested 0.4.10 and 0.8.25 schemas and selected semantic families.**

ولا يجوز تحويلها إلى claim أوسع قبل إضافة compiler/AST fixtures وadapters وnegative controls وproduction-support decision لكل family.

---

## 15. Metrics وTrack Preservation

تبقى المقاييس غير قابلة للخلط:

| Track | الحالة المطلوبة |
|---|---|
| Controlled Benchmark | Precision = 1.0، Recall = 1.0، F1 = 1.0؛ لا تُضاف compatibility أو architecture fixtures. |
| Compatibility Benchmark | يشمل historical schemas وadapters وfailure semantics وsupport matrix؛ metrics منفصلة. |
| Real-World Track | Nomad = Quarantined، BonqDAO = Quarantined، Parity = Quarantined؛ لا admission تلقائي. |

نجاح Architecture Proposal أو production migration لا يضيف حالة إلى Primary Benchmark ولا يعيد adjudication لأي Real-World case. Parity لا تُستخدم كسبب لتعديل Comparator في هذه المرحلة.

---

## 16. Measurable Acceptance Gates قبل Production Implementation

| Gate | معيار القبول |
|---|---|
| Compiler resolution | لا fallback صامت؛ كل candidate ورفضه وselected settings قابلة لإعادة التفسير. |
| Canonical AST v1 | كل field له consumer موثق؛ لا توسع إلى AST ثانية بلا detector need. |
| Adapter safety | schema ownership وcontext-safe mapping وmalformed/partial states مثبتة بnegative controls. |
| Structural completeness | source units/contracts/function-like nodes/modifiers/ranges/unknown nodes تتحقق AST-native. |
| Status semantics | الحالات الثماني تظهر end-to-end ولا يتحول failure إلى no findings. |
| Provenance | finding يعيد trace إلى canonical expression وsource manifest وraw AST/compiler artifact. |
| Imported semantic detection | finding من imported source يعود إلى imported `source_id` وrange ويمر عبر Comparator boundary. هذا gate **غير مثبت بعد**. |
| Detector migration | detector production واحد على الأقل يعمل عبر `DetectorInput` في shadow mode مع parity evidence. |
| Comparator policy | evidence identity وhistorical rejection policy موثقتان دون patch غير مبرر. |
| Rollout safety | feature flag وrollback path وfailure visibility مثبتة. |
| Track preservation | Primary metrics ثابتة، Real-World statuses ثابتة، ولا Case #4. |

---

## 17. قرار الوثيقة

هذه الوثيقة تنقل المشروع من Revised POC إلى **Production Architecture Proposal** فقط. وهي لا تعني Adopt ولا تبدأ implementation. القرار المقترح للمراجعة هو:

| القرار | معنى القرار |
|---|---|
| **Adopt** | اعتماد المعمارية للبدء في Stage 1 production detector بعد إغلاق كل gates الإلزامية، مع إبقاء rollout opt-in. |
| **Revise** | بقاء الفكرة صالحة، لكن تعديل resolver أو Canonical Contract أو provenance أو multi-file policy قبل أي implementation. |
| **Reject** | رفض abstraction إذا اتضح أن fields أو adapters تتحول إلى AST ثانية ضخمة أو لا يمكنها الحفاظ على failure/evidence semantics. |

الاقتراح الحالي هو **فتح مراجعة القرار فقط**، وليس تسجيل Adopt مسبقًا. وبالأخص، لا تزال imported-source semantic detection وproduction compiler candidate policy وraw-AST retention implementation مسائل تحتاج قرارًا تفصيليًا.

---

## References

[1]: ../canonical_ast_poc/REVISED_POC_REPORT.md "Revised Compatibility POC Report"

[2]: ../canonical_ast_poc/metadata/revised_poc_results.json "Revised POC machine-readable results"

[3]: ../canonical_ast_poc/tests/test_architecture_poc.py "Revised POC regression tests"

[4]: ARCHITECTURE_DESIGN.md "Compiler / AST Boundary Architecture Design"

[5]: REPORT.md "Read-only Compiler / AST Boundary Audit"

[6]: ../../../../analyzers/solidity_analyzer.py "Current Solidity detector implementation"

[7]: ../../../../verification/comparator.py "Current Comparator implementation"

[8]: ../../../../benchmarks/evaluation/BASELINE_RESULTS.md "Cross-track baseline and metric separation"
