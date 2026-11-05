"""Mini-Review corpus regression gate (Fix 3).

Runs Mini-Review's auto (reentrancy-evidence) path over every case in
a local 52-case corpus and fails if the pinned counts move. The pins
are the counts as Fix 3 code actually reports them, measured on the
corpus at ~/workspace/auditor-test-corpus/ (manifest commits, same
files) -- see the workflow and README for the bucket definitions.

Bucket definitions (Fix 2 _partition_triaged, auto path only):
- total: every auto-generated item (one per function with an external
  call: a Confirmed reentrancy item or a guard note).
- Critical: items with severity Critical. On the auto path every
  Critical item is in the Confirmed bucket, and every Confirmed item
  is Critical, so Critical == Confirmed here.
- Medium / guard notes: items with evidence "Guard note only", listed
  only in the report appendix and explicitly NOT findings.
- Confirmed findings: the Confirmed bucket only. Guard notes and
  unverified hypotheses are never counted as findings.
- hypotheses / other: 0 on the auto path (no LLM findings are
  supplied, so there is nothing to put in those buckets).

Why the pins are exact, not "at least": a drop in Critical means lost
detection (e.g. SB-RE-01 going back to 0), and a rise means a new
false Critical (e.g. Mandate / REAL-01 returning findings). Either
direction is a regression and must fail, not just a drop.

Why this script fails when the corpus is absent: the corpus is NOT
vendored into this repo (see the workflow header: it mixes public
benchmark code under its own licences with real teams' outreach
contracts, and the local corpus is deliberately local-only). A gate
that passed without the corpus would be a false green, so a missing
corpus directory is exit code 2 with an explicit message, never a
pass. Run it where the corpus is present:

    CORPUS_DIR=/path/to/auditor-test-corpus python3 \\
        scripts/check_corpus_regression.py
    # or: python3 scripts/check_corpus_regression.py --corpus-dir ...

Stdlib only: Mini-Review's evidence path needs no third-party package.
"""
import argparse
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import mini_review as mr

# Pins: measured with Fix 3 code on the 52-case local corpus.
# Total 143 = 19 Critical/Confirmed + 124 Medium/guard notes.
# Confirmed split: 17 in reentrancy-labelled cases + 2 in Parity
# access-control cases (SB-AC-02, NS-AC-02, confirm() only). The
# Parity confirm() Criticals are code-evidence items, NOT verified
# exploits: the labelled Parity flaw is elsewhere in those files.
PINS = {
    "total": 143,
    "critical_sev": 19,
    "medium_sev": 124,
    "confirmed": 19,
    "guard": 124,
    "hyp": 0,
    "other": 0,
}

# Per-case pins for the cases a regression would most plausibly hit.
# (case, field, expected, why)
CASE_PINS = [
    ("LAB-RE-01", "confirmed", 1, "own lab vault must stay Confirmed"),
    ("SB-RE-01", "confirmed", 1, "old-call-syntax detection must not regress"),
    ("SF-RE-01", "confirmed", 5, "SolidiFI reentrancy file, 5 Critical"),
    ("SF-RE-01", "guard", 13, "SolidiFI reentrancy file, 13 guard notes"),
    ("SB-RE-07", "total", 0, "still missed (known gap, must not silently change)"),
    ("NS-RE-03", "confirmed", 0, "SpankChain stays unverified-only"),
    ("NS-RE-03", "guard", 4, "SpankChain guard notes"),
    ("SB-AC-02", "confirmed", 1, "Parity confirm() Critical (not a verified exploit)"),
    ("NS-AC-02", "confirmed", 1, "Parity confirm() Critical (not a verified exploit)"),
    ("REAL-01", "total", 0, "Mandate must stay at 0 findings"),
    ("REAL-02", "total", 0, "StableSettle must stay at 0 findings"),
    ("REAL-03", "total", 0, "Stream Vaults must stay at 0 findings"),
    ("REAL-04", "total", 0, "Seikine ChainlinkGuard must stay at 0 findings"),
]


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus-dir", default=None,
                        help="Corpus root containing corpus/<case>/contract.sol "
                             "(default: $CORPUS_DIR, else ../auditor-test-corpus)")
    args = parser.parse_args(argv)
    root = Path(args.corpus_dir or os.environ.get("CORPUS_DIR", "")
                 or Path(__file__).resolve().parent.parent.parent
                 / "auditor-test-corpus")
    corpus_dir = root / "corpus" if (root / "corpus").is_dir() else root
    if not corpus_dir.is_dir():
        print(f"CORPUS NOT PRESENT: no corpus directory at {root} "
              f"(looked for {corpus_dir}). This gate does NOT pass "
              f"without the corpus: check out the local 52-case corpus "
              f"and re-run with --corpus-dir or $CORPUS_DIR. "
              f"See .github/workflows/corpus-regression.yml.", file=sys.stderr)
        return 2
    cases = sorted(p for p in corpus_dir.iterdir()
                   if p.is_dir() and (p / "contract.sol").is_file())
    if len(cases) != 52:
        print(f"FAIL: expected 52 cases, found {len(cases)} in {corpus_dir}",
              file=sys.stderr)
        return 1
    rows = []
    for case_dir in cases:
        src = (case_dir / "contract.sol").read_text(errors="replace")
        auto = mr._auto_findings(src)
        triaged = mr.triage_findings(auto, src)
        confirmed, hyp, guard, other = mr._partition_triaged(triaged, auto)
        sev = {}
        for item in triaged:
            sev[item["severity"]] = sev.get(item["severity"], 0) + 1
        rows.append({
            "case": case_dir.name, "total": len(triaged),
            "critical_sev": sev.get("Critical", 0),
            "medium_sev": sev.get("Medium", 0),
            "confirmed": len(confirmed), "guard": len(guard),
            "hyp": len(hyp), "other": len(other),
        })
    totals = {k: sum(r[k] for r in rows) for k in PINS}
    print("Mini-Review corpus regression: "
          "total=%d Critical=%d Medium=%d Confirmed-findings=%d "
          "guard-notes(not findings)=%d hypotheses=%d other=%d"
          % (totals["total"], totals["critical_sev"], totals["medium_sev"],
             totals["confirmed"], totals["guard"], totals["hyp"],
             totals["other"]))
    for row in rows:
        print(f"  {row['case']}: total={row['total']} "
              f"Critical={row['critical_sev']} Medium={row['medium_sev']} "
              f"confirmed={row['confirmed']} guard={row['guard']}")
    failures = []
    for key, expected in PINS.items():
        if totals[key] != expected:
            failures.append(f"total {key}: got {totals[key]}, pinned {expected}")
    by_case = {r["case"]: r for r in rows}
    for case, field, expected, why in CASE_PINS:
        got = by_case[case][field]
        if got != expected:
            failures.append(f"{case} {field}: got {got}, pinned {expected} ({why})")
    # Reentrancy-labelled vs Parity split, when the manifest is present.
    manifest = root / "manifest.json"
    if manifest.is_file():
        try:
            entries = json.loads(manifest.read_text())
            classes = {e["case_id"]: e.get("vuln_class") for e in entries}
            re_conf = sum(by_case[c]["confirmed"] for c in by_case
                          if classes.get(c) == "reentrancy")
            print(f"  Confirmed split: reentrancy-labelled={re_conf} "
                  f"(pinned 17), other={totals['confirmed'] - re_conf} (pinned 2, Parity confirm())")
            if re_conf != 17 or totals["confirmed"] - re_conf != 2:
                failures.append(
                    f"confirmed split: reentrancy-labelled={re_conf} "
                    f"(pinned 17), other={totals['confirmed'] - re_conf} (pinned 2)")
        except Exception as exc:  # manifest is advisory, totals are the gate
            print(f"  (manifest split check skipped: {exc})")
    if failures:
        print("FAIL: corpus regression pins violated:", file=sys.stderr)
        for failure in failures:
            print(f"  - {failure}", file=sys.stderr)
        return 1
    print("PASS: all corpus regression pins hold.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
