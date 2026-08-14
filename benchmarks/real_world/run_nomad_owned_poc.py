#!/usr/bin/env python3
"""Run the owned Nomad zero-root PoC through the repository-safe wrapper."""

from pathlib import Path

from verification.poc import run_foundry_poc

ROOT = Path(__file__).resolve().parents[2]
POC = ROOT / "benchmarks" / "real_world" / "owned_reproductions" / "nomad" / "nomad_zero_root_poc.t.sol"

result = run_foundry_poc(POC, ROOT)
print({"status": result.status.value, "reason": result.reason})
raise SystemExit(0 if result.status.value == "Passed" else 1)
