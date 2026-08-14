"""Compare targeted deterministic detector outcomes with a structured LLM pass."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests

from analyzers.solidity_analyzer import SolidityAnalyzer

ROOT = Path(__file__).resolve().parents[1]
BENCHMARK_ROOT = Path(__file__).resolve().parent
CONTROL_MANIFEST = BENCHMARK_ROOT / "negative_controls" / "manifest.json"
VARIANT_MANIFEST = BENCHMARK_ROOT / "attack_variants" / "manifest.json"
PROMPT_PATH = BENCHMARK_ROOT / "evaluation" / "prompt_v1.txt"
PROMPT_VERSION = "prompt_v1"
RESPONSE_SCHEMA_VERSION = "targeted_solidity_findings-v1"
MAX_COMPLETION_TOKENS = 800

ALLOWED_DETECTORS = [
    "Reentrancy (AST)",
    "DELEGATECALL Usage (AST)",
    "Selfdestruct",
    "Public Mint/Burn",
    "tx.origin Auth (AST)",
    "Flash Loan Attack Vector",
    "Storage Collision (Delegatecall)",
    "Unchecked Transfer",
    "Unbounded Loop (AST)",
    "block.timestamp Usage (AST)",
]

RESPONSE_SCHEMA = {
    "type": "json_schema",
    "json_schema": {
        "name": "targeted_solidity_findings",
        "strict": True,
        "schema": {
            "type": "object",
            "properties": {
                "findings": {
                    "type": "array",
                    "items": {"type": "string", "enum": ALLOWED_DETECTORS},
                },
                "rationale": {"type": "string"},
            },
            "required": ["findings", "rationale"],
            "additionalProperties": False,
        },
    },
}


def _load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _items() -> list[dict[str, Any]]:
    controls = _load(CONTROL_MANIFEST)["controls"]
    variants = _load(VARIANT_MANIFEST)["variants"]
    items = []
    for item in controls:
        items.append({
            "name": item["file"],
            "kind": "negative_control",
            "source": str(Path("benchmarks") / "negative_controls" / item["file"]),
            "expected_present": [],
            "expected_absent": item["expected_absent_detectors"],
        })
    for item in variants:
        items.append({
            "name": item["name"],
            "kind": "attack_variant",
            "source": str(Path("benchmarks") / "attack_variants" / item["source"]),
            "expected_present": item["expected_detectors"],
            "expected_absent": [],
        })
    return items


def _deterministic_predictions(source_path: Path) -> set[str]:
    findings = SolidityAnalyzer().analyze_file(
        source_path.name,
        source_path.read_text(encoding="utf-8"),
    )
    return {finding.agent_name for finding in findings if finding.agent_name in ALLOWED_DETECTORS}


def _available_models(session: requests.Session) -> list[str]:
    response = session.get(
        f"{os.environ['OPENAI_API_BASE'].rstrip('/')}/models",
        headers={"Authorization": f"Bearer {os.environ['OPENAI_API_KEY']}"},
        timeout=60,
    )
    response.raise_for_status()
    payload = response.json()
    items = payload.get("data", payload if isinstance(payload, list) else [])
    return [item["id"] for item in items if isinstance(item, dict) and item.get("id")]


def _call_llm(
    session: requests.Session,
    source: str,
    name: str,
    model: str,
    system_prompt: str,
) -> dict[str, Any]:
    response = session.post(
        f"{os.environ['OPENAI_API_BASE'].rstrip('/')}/chat/completions",
        headers={
            "Authorization": f"Bearer {os.environ['OPENAI_API_KEY']}",
            "Content-Type": "application/json",
        },
        json={
            "model": model,
            "messages": [
            {
                "role": "system",
                "content": system_prompt,
            },
            {
                "role": "user",
                "content": (
                    f"Analyze benchmark fixture {name}. Select applicable detectors from this exact list:\n"
                    f"{json.dumps(ALLOWED_DETECTORS)}\n\nSolidity source:\n```solidity\n{source}\n```"
                ),
            },
            ],
            "response_format": RESPONSE_SCHEMA,
            "max_completion_tokens": MAX_COMPLETION_TOKENS,
        },
        timeout=180,
    )
    response.raise_for_status()
    payload = response.json()
    choice = payload["choices"][0]
    content = choice.get("message", {}).get("content") or "{}"
    data = json.loads(content)
    usage = payload.get("usage", {})
    return {
        "findings": sorted(set(data.get("findings", [])) & set(ALLOWED_DETECTORS)),
        "rationale": data.get("rationale", ""),
        "usage": {
            "prompt_tokens": usage.get("prompt_tokens"),
            "completion_tokens": usage.get("completion_tokens"),
        },
    }


def run(model: str) -> dict[str, Any]:
    session = requests.Session()
    available_models = _available_models(session)
    if model not in available_models:
        raise ValueError(f"Model {model!r} is not present in live catalog")
    system_prompt = PROMPT_PATH.read_text(encoding="utf-8").strip()
    prompt_sha256 = _sha256(PROMPT_PATH)
    timestamp_utc = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    cases = []
    true_positives = false_positives = false_negatives = 0
    deterministic_true_positives = deterministic_false_positives = deterministic_false_negatives = 0
    for item in _items():
        source_path = ROOT / item["source"]
        source = source_path.read_text(encoding="utf-8")
        deterministic = _deterministic_predictions(source_path)
        expected_present = set(item["expected_present"])
        expected_absent = set(item["expected_absent"])
        deterministic_true_positives += len(deterministic & expected_present)
        deterministic_false_positives += len(deterministic & expected_absent)
        deterministic_false_negatives += len(expected_present - deterministic)
        try:
            llm = _call_llm(session, source, item["name"], model, system_prompt)
            predicted = set(llm["findings"])
            error = None
        except Exception as exc:
            llm = {"findings": [], "rationale": "", "usage": {}}
            predicted = set()
            error = f"{type(exc).__name__}: {exc}"
        true_positives += len(predicted & expected_present)
        false_positives += len(predicted & expected_absent)
        false_negatives += len(expected_present - predicted)
        cases.append({
            **item,
            "deterministic_predictions": sorted(deterministic),
            "llm_predictions": sorted(predicted),
            "llm_rationale": llm["rationale"],
            "usage": llm["usage"],
            "error": error,
        })
    source_sha256 = {
        item["source"]: _sha256(ROOT / item["source"])
        for item in _items()
    }
    return {
        "schema_version": 1,
        "run_id": f"{timestamp_utc}-{model}",
        "timestamp_utc": timestamp_utc,
        "track": "adversarial",
        "corpus": {
            "manifest_paths": [
                "benchmarks/negative_controls/manifest.json",
                "benchmarks/attack_variants/manifest.json",
            ],
            "case_count": len(cases),
            "source_sha256": source_sha256,
        },
        "ground_truth": {
            "definition": "Expected detector presence comes from repository manifests; expected absence comes from negative-control manifests.",
            "provenance_policy": "Ground truth is fixture metadata and must not be inferred from the LLM output or the analyzer output.",
        },
        "llm": {
            "model": model,
            "catalog_checked": True,
            "prompt_version": PROMPT_VERSION,
            "prompt_sha256": prompt_sha256,
            "temperature": None,
            "max_completion_tokens": MAX_COMPLETION_TOKENS,
            "response_schema_version": RESPONSE_SCHEMA_VERSION,
        },
        "model": model,
        "live_catalog_checked": True,
        "scope": "targeted detector assertions on 10 controls and 5 attack variants",
        "cases": cases,
        "llm_metrics": {
            "true_positives": true_positives,
            "false_positives": false_positives,
            "false_negatives": false_negatives,
            "precision": true_positives / (true_positives + false_positives) if true_positives + false_positives else None,
            "recall": true_positives / (true_positives + false_negatives) if true_positives + false_negatives else None,
        },
        "deterministic_metrics": {
            "true_positives": deterministic_true_positives,
            "false_positives": deterministic_false_positives,
            "false_negatives": deterministic_false_negatives,
            "precision": deterministic_true_positives / (deterministic_true_positives + deterministic_false_positives) if deterministic_true_positives + deterministic_false_positives else None,
            "recall": deterministic_true_positives / (deterministic_true_positives + deterministic_false_negatives) if deterministic_true_positives + deterministic_false_negatives else None,
        },
        "failed_calls": sum(case["error"] is not None for case in cases),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Compare deterministic and LLM detector outcomes")
    parser.add_argument("--model", default=os.environ.get("LLM_MODEL", "gpt-5-mini"))
    parser.add_argument("--json-out", type=Path, required=True)
    args = parser.parse_args()
    report = run(args.model)
    rendered = json.dumps(report, indent=2, sort_keys=True)
    print(rendered)
    args.json_out.write_text(rendered + "\n", encoding="utf-8")
    return 0 if report["failed_calls"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
