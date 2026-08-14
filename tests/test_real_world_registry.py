"""Offline validation for the provenance-first real-world candidate registry."""

import json
import re
from pathlib import Path

from benchmarks.real_world.run_negative_controls import run as run_negative_controls


ROOT = Path(__file__).resolve().parents[1]
REGISTRY_PATH = ROOT / "benchmarks" / "real_world" / "registry.json"
SCHEMA_PATH = ROOT / "benchmarks" / "real_world" / "registry.schema.json"


def test_real_world_registry_is_versioned_and_not_admitted_yet():
    registry = json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))
    assert registry["schema_version"] == 1
    assert registry["track"] == "real_world"
    assert registry["corpus_status"] == "candidate_registry_not_admitted"
    assert len(registry["cases"]) == 10
    assert all(case["status"].startswith("candidate_pending_") for case in registry["cases"])


def test_real_world_candidates_have_commit_and_source_hash_provenance():
    registry = json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))
    for case in registry["cases"]:
        assert re.fullmatch(r"[a-f0-9]{40}", case["source_repository_commit"])
        assert re.fullmatch(r"[a-f0-9]{64}", case["source_sha256"])
        assert case["source_path"].startswith("src/test/")
        assert case["references"] or case["status"] == "candidate_pending_external_incident_validation"


def test_real_world_registry_schema_is_valid_json():
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    assert schema["properties"]["track"]["const"] == "real_world"
    assert schema["properties"]["corpus_status"]["enum"] == ["candidate_registry_not_admitted", "admitted"]


def test_all_real_world_adjudications_are_quarantined_and_metric_neutral():
    adjudication_dir = ROOT / "benchmarks" / "real_world" / "adjudications"
    records = sorted(adjudication_dir.glob("rw-*.json"))
    assert len(records) == 10
    for path in records:
        record = json.loads(path.read_text(encoding="utf-8"))
        assert record["review_status"] == "quarantined"
        assert record["review"]["ground_truth_decision"] == "quarantine"
        assert record["detector_mapping"]["covered_by_existing_detector"] is False
        assert record["reproduction"]["execution_status"] == "not_started"


def test_real_world_negative_controls_have_zero_expected_false_positive_checks():
    report = run_negative_controls()
    assert report["primary_benchmark_affected"] is False
    assert report["metrics"]["controls"] == 5
    assert report["metrics"]["false_positive_checks"] == 0
    assert report["metrics"]["false_positive_rate"] == 0.0
