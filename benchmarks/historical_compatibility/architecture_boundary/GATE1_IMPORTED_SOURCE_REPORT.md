# Gate 1 — Imported-Source Semantic Detection

## النطاق

هذا artifact يختبر أول gate بعد Adopt المعماري: `Main.sol` يستورد `Lib.sol`، والثغرة موجودة فقط داخل `Lib.sol`. بقي الاختبار داخل Compatibility/Architecture track، ولم يُعدّل `analyzers/` أو `verification/comparator.py` أو Primary Benchmark أو Real-World adjudications.

## Fixture

| Source unit | المحتوى المتوقع |
|---|---|
| `Lib.sol` | العقد `ImportedLibraryTarget` والدالة `destroyImported()` التي تحتوي `selfdestruct`. |
| `Main.sol` | العقد `ImportedSourceEntry` والدالة `safeEntry()` فقط؛ لا تحتوي selfdestruct. |

## النتيجة end-to-end

| Layer | النتيجة |
|---|---|
| Compiler | `Compiled` عبر standard-json solc 0.8.25. |
| Source units | `Lib.sol` و`Main.sol` محفوظتان منفصلتين. |
| Adapter | `CanonicalASTReady` مع source-unit identity. |
| Detector على `Lib.sol` | `AnalysisSucceededWithFindings`، finding count = 1. |
| Finding file | `Lib.sol`. |
| Finding provenance source ID | `Lib.sol`. |
| Canonical expression ID | يبدأ بـ`Lib.sol:`. |
| Canonical source range | `109:12:0` في raw AST provenance. |
| Comparator | `Confirmed` عبر unchanged Comparator. |
| Comparator hypothesis file | `Lib.sol`. |
| Comparator evidence | kind = `selfdestruct`، location = `line 5`. |
| Detector على `Main.sol` | `AnalysisSucceededNoFindings`، finding count = 0. |

النتيجة تثبت أن detector projection أصبح source-unit-scoped في الـisolated bridge، وأن finding لا يُنسب إلى entrypoint لمجرد أنه source الذي بدأ compilation. كما تثبت أن Comparator يستقبل نص `Lib.sol` نفسه، لا `Main.sol`، فيستطيع إعادة العثور على evidence في المصدر المستورد دون تعديل comparator implementation.

## ما الذي أُغلق

> **Gate 1 — Imported-source semantic detection: Passed داخل نطاق الـPOC.**

السلسلة المثبتة هي:

```text
Main.sol imports Lib.sol
        ↓
standard-json source-unit compilation
        ↓
Lib.sol canonical unit
        ↓
source-scoped DetectorInput(Lib.sol)
        ↓
Selfdestruct finding in Lib.sol
        ↓
Finding provenance source_id = Lib.sol
        ↓
Comparator source evidence in Lib.sol, line 5
```

## ما الذي لم يُثبت

هذا gate يستخدم direct source-unit detector invocation داخل isolated bridge. لم يثبت بعد production analyzer end-to-end multi-file orchestration، ولا imported-source detection لعائلات متعددة، ولا inheritance/using-for/library semantic relationships، ولا production `SourceView` persistence، ولا artifact retention بعد process boundary. لذلك لا يُعتبر Stage 1 production implementation مصرحًا به تلقائيًا.

## Gates المتبقية

| Gate | الحالة |
|---|---|
| Gate 1 — Imported-source semantic detection | **Passed داخل POC**. |
| Gate 2 — Production compiler-resolution policy | **Open**؛ يجب تحديد explicit version، pragma intersection، multiple candidates، missing compiler، compilation failure، وno silent fallback. |
| Gate 3 — Production provenance/raw-AST policy | **Open**؛ يجب تحديد ما يُحفظ فعليًا، retention period، content-addressed raw AST، وreplay guarantees. |

## Artifacts

| Artifact | الغرض |
|---|---|
| `canonical_ast_poc/fixtures/imported_lib_0_8_25.sol` | Vulnerable imported source. |
| `canonical_ast_poc/fixtures/imported_main_0_8_25.sol` | Safe entry source. |
| `canonical_ast_poc/metadata/gate1_imported_source_results.json` | Machine-readable Gate 1 evidence. |
| `tests/test_architecture_poc.py` | Regression test including imported-source attribution. |

## ملاحظة المسارات

لا يدخل هذا النجاح إلى Primary metrics، ولا يغيّر Parity أو Nomad أو BonqDAO، ولا يبرر alias patch أو Comparator patch. إعادة adjudication لـParity تبقى مسارًا مستقلًا بعد Stage 1، إذا وصل المشروع إليه.

## References

[1]: ../canonical_ast_poc/REVISED_POC_REPORT.md "Revised Compatibility POC Report"

[2]: PRODUCTION_ARCHITECTURE_PROPOSAL.md "Production Architecture Proposal"

[3]: ../canonical_ast_poc/metadata/gate1_imported_source_results.json "Gate 1 machine-readable result"

[4]: ../canonical_ast_poc/tests/test_architecture_poc.py "Gate 1 regression tests"
