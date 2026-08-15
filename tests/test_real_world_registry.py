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
    records = sorted(
        path for path in adjudication_dir.glob("rw-*.json")
        if not path.name.endswith("-pipeline.json")
    )
    assert len(records) == 10
    for path in records:
        record = json.loads(path.read_text(encoding="utf-8"))
        assert record["review_status"] == "quarantined"
        assert record["review"]["ground_truth_decision"] == "quarantine"
        assert record["detector_mapping"]["covered_by_existing_detector"] is False
        if record["case_id"] in {"rw-003-nomad-bridge", "rw-004-bonqdao"}:
            assert record["reproduction"]["execution_status"] == "passed"
        else:
            assert record["reproduction"]["execution_status"] == "not_started"


def test_real_world_negative_controls_have_zero_expected_false_positive_checks():
    report = run_negative_controls()
    assert report["primary_benchmark_affected"] is False
    assert report["metrics"]["controls"] == 5
    assert report["metrics"]["false_positive_checks"] == 0
    assert report["metrics"]["false_positive_rate"] == 0.0


def test_nomad_has_pinned_implementation_and_remains_quarantined():
    registry = json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))
    nomad = next(case for case in registry["cases"] if case["id"] == "rw-003-nomad-bridge")
    assert nomad["status"].startswith("candidate_pending_")
    assert nomad["expected_detectors"] == []
    assert nomad["implementation_source"]["commit"] == "7510d54a5cd334d283d84fdff59827abfceb2da7"
    assert nomad["implementation_source"]["sha256"] == "3b6439fe258ffeeec58586e6d21ae3286903409b10b28f46b4b8cb64b4a773d6"
    assert nomad["owned_reproduction"]["status"] == "passed"


def test_bonq_has_pinned_implementation_and_remains_quarantined():
    registry = json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))
    bonq = next(case for case in registry["cases"] if case["id"] == "rw-004-bonqdao")
    assert bonq["status"].startswith("candidate_pending_")
    assert bonq["expected_detectors"] == []
    assert bonq["implementation_source"]["commit"] == "3b3820f2111ec2813cb51455ef68cf0955c51674"
    assert bonq["implementation_source"]["sha256"] == "db633e4080e3e95410e0eec34b17fbacaadca42281bbde5dd6282f61cd40a522"
    assert bonq["owned_reproduction"]["status"] == "passed"
    assert bonq["owned_reproduction"]["invariant_id"] == "bonq.oracle_price_requires_dispute_window"


def test_bonq_adjudication_keeps_ground_truth_independent():
    path = ROOT / "benchmarks" / "real_world" / "adjudications" / "rw-004-bonqdao.json"
    record = json.loads(path.read_text(encoding="utf-8"))
    assert record["review_status"] == "quarantined"
    assert record["review"]["ground_truth_decision"] == "quarantine"
    assert record["detector_mapping"]["covered_by_existing_detector"] is False
    assert record["reproduction"]["execution_status"] == "passed"
    assert record["root_cause"]["affected_contract"] == "0xa1620af6138d2754f7250299dc9024563bd1a5d6"
    assert any(
        entry.startswith("TellorPriceFeed.price:30-32")
        for entry in record["root_cause"]["source_line_ranges"]
    )
    pipeline = record["pipeline_observations"]
    assert pipeline["ground_truth_unchanged"] is True
    assert pipeline["stage_statuses"]["comparator"] == "NotApplicable"
    assert pipeline["stage_statuses"]["full_pipeline"] == "Quarantined"
    assert (ROOT / pipeline["report_path"]).is_file()


def test_nomad_adjudication_keeps_ground_truth_independent():
    path = ROOT / "benchmarks" / "real_world" / "adjudications" / "rw-003-nomad-bridge.json"
    record = json.loads(path.read_text(encoding="utf-8"))
    assert record["review_status"] == "quarantined"
    assert record["review"]["ground_truth_decision"] == "quarantine"
    assert record["detector_mapping"]["covered_by_existing_detector"] is False
    assert record["reproduction"]["execution_status"] == "passed"
    pipeline = record["pipeline_observations"]
    assert pipeline["ground_truth_unchanged"] is True
    assert pipeline["stage_statuses"]["comparator"] == "NotApplicable"
    assert pipeline["stage_statuses"]["full_pipeline"] == "Quarantined"
    assert (ROOT / pipeline["report_path"]).is_file()
