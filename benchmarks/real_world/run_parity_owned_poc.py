#!/usr/bin/env python3
"""Run the repository-owned Parity WalletLibrary kill PoC."""

from pathlib import Path

from verification.poc import PocStatus, run_foundry_poc

ROOT = Path(__file__).resolve().parents[2]
POC = ROOT / "benchmarks" / "real_world" / "owned_reproductions" / "parity" / "parity_library_kill_poc.t.sol"


if __name__ == "__main__":
    result = run_foundry_poc(POC, ROOT)
    print(result.output, end="")
    raise SystemExit(0 if result.status is PocStatus.PASSED else 1)
