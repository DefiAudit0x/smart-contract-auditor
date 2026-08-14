"""False-positive regression tests for safe Solidity negative controls."""

import json
from pathlib import Path

from analyzers.solidity_analyzer import SolidityAnalyzer


ROOT = Path(__file__).resolve().parents[1]
CONTROL_ROOT = ROOT / "benchmarks" / "negative_controls"
MANIFEST = json.loads((CONTROL_ROOT / "manifest.json").read_text(encoding="utf-8"))


def test_negative_control_manifest_is_complete():
    controls = MANIFEST["controls"]
    assert len(controls) == 10
    for control in controls:
        path = CONTROL_ROOT / control["file"]
        assert path.is_file(), control["file"]
        assert control["expected_absent_detectors"]


def test_negative_controls_do_not_trigger_expected_detectors():
    failures = []
    for control in MANIFEST["controls"]:
        path = CONTROL_ROOT / control["file"]
        findings = SolidityAnalyzer().analyze_file(
            path.name,
            path.read_text(encoding="utf-8"),
        )
        observed = {finding.agent_name for finding in findings}
        unexpected = sorted(observed & set(control["expected_absent_detectors"]))
        if unexpected:
            failures.append({"file": control["file"], "unexpected": unexpected})
    assert not failures, failures
