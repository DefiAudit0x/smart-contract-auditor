"""Executable regression tests for distinct attack variants."""

import json
from pathlib import Path

from analyzers.solidity_analyzer import SolidityAnalyzer
from verification.poc import PocStatus, run_foundry_poc


ROOT = Path(__file__).resolve().parents[1]
VARIANT_ROOT = ROOT / "benchmarks" / "attack_variants"
MANIFEST = json.loads((VARIANT_ROOT / "manifest.json").read_text(encoding="utf-8"))


def test_attack_variant_manifest_is_complete():
    variants = MANIFEST["variants"]
    assert len(variants) == 5
    for variant in variants:
        assert (VARIANT_ROOT / variant["source"]).is_file()
        assert (VARIANT_ROOT / variant["poc_file"]).is_file()
        assert variant["expected_detectors"]


def test_attack_variants_trigger_expected_detectors():
    failures = []
    for variant in MANIFEST["variants"]:
        path = VARIANT_ROOT / variant["source"]
        findings = SolidityAnalyzer().analyze_file(
            path.name,
            path.read_text(encoding="utf-8"),
        )
        observed = {finding.agent_name for finding in findings}
        missing = sorted(set(variant["expected_detectors"]) - observed)
        if missing:
            failures.append({"variant": variant["name"], "missing": missing})
    assert not failures, failures


def test_attack_variant_pocs_pass_with_foundry():
    failures = []
    for variant in MANIFEST["variants"]:
        result = run_foundry_poc(VARIANT_ROOT / variant["poc_file"], ROOT)
        if result.status is not PocStatus.PASSED:
            failures.append({
                "variant": variant["name"],
                "status": result.status.value,
                "reason": result.reason,
            })
    assert not failures, failures
