# Contributing

Thanks for considering a contribution. This document describes the setup and the checks a
change is expected to pass before review. CI runs the same checks, so passing them locally
saves everyone time.

## Development setup

Prerequisites:

- Python 3.10+
- Solc compiler `0.8.25` on `PATH` (required by the Solidity benchmark)
- Foundry (`forge`) — PoC execution refuses an unisolated fallback, so a local Foundry install
  is expected: `export PATH="$HOME/.foundry/bin:$PATH"`
- Docker (optional — required only for isolated PoC execution mode)

Steps:

```bash
git clone https://github.com/DefiAudit0x/smart-contract-auditor.git
cd smart-contract-auditor

python -m venv venv
source venv/bin/activate

pip install -r requirements.txt
cp .env.example .env   # fill in your API keys
```

For reproducible, hash-verified installs matching CI, use `requirements.lock` with
`pip install --require-hashes -r requirements.lock` (Python `3.10.14`, Foundry `v1.7.1`).

## Checks to run before opening a PR

These mirror the CI pipeline (see `.github/workflows/ci.yml`):

```bash
# Full Python test suite
python -m pytest -q

# Strict deterministic benchmark (requires Foundry on PATH)
PYTHONPATH=. python benchmarks/run_benchmark.py --require-poc

# Extended benchmark and targeted regression tracks
PYTHONPATH=. python benchmarks/run_extended_benchmark.py --json-out extended-benchmark.json
PYTHONPATH=. pytest -q tests/test_negative_controls.py tests/test_attack_variants.py tests/test_adversarial_comparator.py
```

The deterministic benchmark is a regression gate: the primary 10-case corpus must stay at
10/10 true positives with 0 false positives and 0 false negatives. If your change moves these
numbers, explain why in the PR description.

## Pull request guidelines

- One logical change per PR; keep diffs narrow and reviewable.
- New detectors, pre-scan modules, or knowledge-base patterns need tests, and at least one
  benchmark-aligned case demonstrating the behavior.
- Unit tests must be deterministic and offline — use `tests/mock_llm_client.py` instead of
  calling live LLM endpoints.
- Update the relevant docs when behavior changes: `README.md`, `LIMITATIONS.md`,
  `THREAT_MODEL.md`, or `BENCHMARK_METHODOLOGY.md`.
- Never commit real API keys, `.env` contents, or client material.

## Reporting bugs and security issues

- Regular bugs: open an issue with a minimal reproduction and expected versus actual behavior.
- Security issues in this tool itself (sandbox escape, path traversal, auth bypass, SSRF):
  **do not open a public issue** — follow [SECURITY.md](./SECURITY.md).
