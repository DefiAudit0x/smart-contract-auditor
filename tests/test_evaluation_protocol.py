"""Offline checks for evaluation provenance and benchmark-track separation."""

import json
from hashlib import sha256
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
EVALUATION_ROOT = ROOT / "benchmarks" / "evaluation"


def test_evaluation_protocol_assets_are_versioned():
    prompt = EVALUATION_ROOT / "prompt_v1.txt"
    schema = EVALUATION_ROOT / "evaluation_run.schema.json"
    docs = EVALUATION_ROOT / "README.md"
    assert prompt.is_file()
    assert schema.is_file()
    assert docs.is_file()
    assert prompt.read_text(encoding="utf-8").strip()
    parsed = json.loads(schema.read_text(encoding="utf-8"))
    assert parsed["properties"]["schema_version"]["const"] == 1
    assert set(parsed["required"]) >= {
        "run_id",
        "timestamp_utc",
        "track",
        "corpus",
        "ground_truth",
        "llm",
        "deterministic_metrics",
        "llm_metrics",
        "cases",
    }


def test_prompt_hash_is_stable_for_the_checked_in_prompt():
    prompt = EVALUATION_ROOT / "prompt_v1.txt"
    digest = sha256(prompt.read_bytes()).hexdigest()
    assert len(digest) == 64
    assert digest == sha256(prompt.read_bytes()).hexdigest()


def test_real_world_track_is_not_silently_mixed_into_current_manifests():
    controls = json.loads(
        (ROOT / "benchmarks" / "negative_controls" / "manifest.json").read_text(encoding="utf-8")
    )
    variants = json.loads(
        (ROOT / "benchmarks" / "attack_variants" / "manifest.json").read_text(encoding="utf-8")
    )
    assert all("real_world" not in item.get("kind", "") for item in controls["controls"])
    assert all("real_world" not in item.get("kind", "") for item in variants["variants"])
