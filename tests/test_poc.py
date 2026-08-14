"""Safety and manifest tests for executable PoC verification."""

from pathlib import Path

import pytest

from benchmarks.run_benchmark import discover_cases, load_metadata
from verification.poc import PocStatus, run_foundry_poc


ROOT = Path(__file__).resolve().parents[1]


def test_poc_manifest_files_are_repository_owned():
    for case_dir in discover_cases():
        metadata = load_metadata(case_dir)
        poc_path = case_dir / metadata["poc_file"]
        assert poc_path.is_file()
        assert ROOT.resolve() in poc_path.resolve().parents
        assert poc_path.name.endswith(".t.sol")


def test_poc_runner_reports_missing_forge_as_inconclusive(monkeypatch):
    case_dir = discover_cases()[0]
    metadata = load_metadata(case_dir)
    monkeypatch.setattr("verification.poc.shutil.which", lambda _: None)
    result = run_foundry_poc(case_dir / metadata["poc_file"], ROOT)
    assert result.status is PocStatus.INCONCLUSIVE
    assert "forge" in result.reason.lower()


def test_poc_runner_rejects_path_outside_project():
    result = run_foundry_poc("/tmp/outside.t.sol", ROOT)
    assert result.status is PocStatus.INCONCLUSIVE
    assert "inside the project root" in result.reason


def test_poc_runner_rejects_non_foundry_extension(tmp_path):
    poc = tmp_path / "not_solidity.sol"
    poc.write_text("contract C {}", encoding="utf-8")
    result = run_foundry_poc(poc, tmp_path)
    assert result.status is PocStatus.INCONCLUSIVE
    assert ".t.sol" in result.reason
