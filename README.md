# Smart Contract Auditor

A multi-language smart contract security auditor combining a multi-pass LLM pipeline with deterministic static analysis and verification tooling. Combines hierarchical AI analysis, 9 pre-scan tasks, and a real-time SSE streaming web UI to detect vulnerabilities in Solidity, Vyper, Move, and Chialisp contracts.

## Features

- Multi-pass AI analysis (3-pass: AI → Validation → Gate)
- 9 pre-scan tasks (bug-detector regex, MCP, AI tools, ZKsync, external tools, SBOM, learned patterns, AST, pragma warnings) — see `agents/pre_scan.py` (`_SCAN_TASKS`); they run through a pool of 7 workers, so at most 7 run concurrently; a task failure is reported in the report's Pre-Scan Completeness section, never silently swallowed
- Real-time streaming results via SSE
- CVSS 4.0 scoring
- Gas profiling
- SBOM generation
- SARIF export (GitHub Security Tab compatible)
- Diff Auditor for upgradeable contracts
- VS Code Extension
- Telegram Bot integration
- Dark mode web UI with Chart.js severity charts
- Pattern learner: LLM-mined regex candidates stay inactive until PoC-confirmed (see "Pattern learning" below)
- Cross-session knowledge base with confidence-aware retrieval

## Quick Start (Docker)

```bash
docker build -t smart-contract-auditor .
docker run -p 5000:5000 \
  -v $(pwd)/.env:/app/.env:ro \
  smart-contract-auditor
```

## Manual Setup

### Prerequisites

- Python 3.10+
- Solc compiler 0.8.25

### Installation

```bash
git clone https://github.com/DefiAudit0x/smart-contract-auditor.git
cd smart-contract-auditor

python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

pip install -r requirements.txt

cp .env.example .env  # Edit with your API keys
python web_ui.py
```

Open http://127.0.0.1:5000 in your browser.

### VS Code Extension

Open the `.vscode-auditor/` folder in VS Code and run the extension (F5).

### Telegram Bot

```bash
python run_bot.py
```

## Configuration

| Variable | Description | Default |
|---|---|---|
| `OLLAMA_API_KEY` | API key for Ollama (or OpenRouter/Groq) | — |
| `OLLAMA_MODEL` | LLM model for analysis | `gpt-oss:120b` |
| `AUDITOR_MODEL_VERSION` | Optional cache-version tag for the model behind `OLLAMA_MODEL` / the OpenRouter model id (see below) | — (unset) |
| `OLLAMA_BASE_URL` | Ollama endpoint | `http://localhost:11434` |
| `AUDITOR_API_KEY` | API key for REST endpoint auth | — |
| `API_PROVIDER` | LLM provider (`ollama`, `openrouter`, `groq`) | `ollama` |
| `PORT` | Web UI port | `5000` |
| `RATE_LIMIT_PER_MINUTE` | Max API requests per minute | `5` |
| `KB_USE_ST` | Enable Sentence-Transformer semantic retrieval when installed | `1` |
| `KB_RAG_MIN_CONFIDENCE` | Minimum stored pattern confidence eligible for RAG context | `0.25` |
| `TELEGRAM_BOT_TOKEN` | Telegram bot token | — |
| `TELEGRAM_CHAT_ID` | Telegram target chat ID | — |
| `ETHERSCAN_API_KEY` | Etherscan API key for on-chain fetch | — |

Precedence, stated explicitly (this used to be wrong here): the code default wins when nothing is set. `config.py` defines `OLLAMA_MODEL` as `os.getenv("OLLAMA_MODEL", "gpt-oss:120b")`, so with `OLLAMA_MODEL` unset the model is `gpt-oss:120b`; setting `OLLAMA_MODEL` in the environment or `.env` overrides that default. The `qwen3-coder:480b` value in `.env.example` is only an example for a copied `.env` file — it is not the code default, and an earlier version of this table mistakenly listed it as the default.

Cache versioning: the LLM response cache (`agents/cache.py`) is keyed by model id + prompt hash, and a model id alone does not change when a provider updates the weights behind the same tag. The cache key therefore also carries a model version: callers may pass one explicitly, or operators may set `AUDITOR_MODEL_VERSION` (for example to the Ollama model digest, or to a new tag such as `v2` after re-pulling a model). A cached entry stored under one version is never returned for a different version, and an entry stored with no version is only returned to unversioned lookups, so old entries keep working and a model upgrade cannot silently reuse a stale result. Bump `AUDITOR_MODEL_VERSION` whenever the model behind a fixed name changes.

Copy `.env.example` to `.env` and fill in your values.

## API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/analyze` | Upload a contract file for analysis |
| `POST` | `/api/analyze/stream` | Real-time SSE streaming analysis (JSON body with `code`) |
| `POST` | `/api/analyze/diff` | Diff two contract versions (`old_code`, `new_code`) |
| `POST` | `/api/analyze_chain` | Analyze an on-chain contract by address |
| `POST` | `/api/analyze_github` | Analyze a GitHub repository URL |
| `POST` | `/api/upload_project` | Upload a zip project for batch analysis |
| `POST` | `/api/sarif` | Generate SARIF report from analysis JSON |
| `POST` | `/api/grep-arsenal` | Run regex pattern scan on code |
| `POST` | `/api/mcp-scan` | Run MCP-based analysis |
| `POST` | `/api/ai-detect` | Detect AI-generated code and AI-specific vulnerabilities |
| `POST` | `/api/zksync-analyze` | Run ZKsync-specific pattern analysis |
| `POST` | `/api/poc` | Generate an exploit PoC template |
| `POST` | `/api/hackerone` | Format findings as a HackerOne report |

`POST /api/mcp-scan` requires `code` as a string. It also accepts optional `remappings` (up to 200 strings, each at most 512 characters) and `source_unit_name` (1-512 characters) for Solidity remapping-aware `CUSTOM-018` analysis:

The Flask app enforces an existing 5 MiB request-body limit. This is an app-wide request limit, not a per-field code-size limit.

```json
{
  "code": "import {Initializable} from \"oz/proxy/utils/Initializable.sol\"; contract C is Initializable { function initialize() external initializer {} }",
  "remappings": ["oz/=lib/openzeppelin-contracts-upgradeable/contracts/"],
  "source_unit_name": "src/Example.sol"
}
```

Supply the effective compiler remappings and the exact source-unit name used by Solidity for context-scoped rules. The endpoint does not read `foundry.toml`, `remappings.txt`, environment variables, or project files. Remapping-based suppression is limited to exact allowlisted OpenZeppelin source-unit paths; it is path-identity evidence only and does not verify the target file's contents, dependency origin, or whether a local fork has been modified. Invalid or ambiguous remapping metadata fails closed for this suppression.

The detector only treats recognized named or bare imports as binding evidence; a namespace import does not establish an unqualified `Initializable` symbol. An untrusted bare import or a duplicate local import binding from a non-allowlisted path also prevents suppression, favoring an extra finding over an ambiguous trust decision.

## Ground-Truth Benchmark

The repository includes a deterministic ten-case benchmark covering reentrancy, delegatecall, selfdestruct, unauthorised public minting, `tx.origin` authentication, flash loans, storage collision, unchecked transfers, unbounded loops, and timestamp-dependent gates. Each case pairs `vulnerable.sol` with `fixed.sol` and includes metadata, a comparator evidence path, a declared invariant, and a Foundry PoC fixture. Supplementary negative controls, attack variants, and adversarial comparator fixtures are maintained separately.

The recorded cross-track baseline with Solidity `0.8.25` and Foundry `v1.7.1` reports 340 passed in the full Python suite. This is a historical baseline snapshot; subsequent maintenance commits may add tests without changing the benchmark results.

| Metric | Result |
|---|---:|
| Full Python suite at baseline snapshot | 340 passed |
| Primary benchmark cases | 10 |
| True positives | 10 |
| False positives | 0 |
| False negatives | 0 |
| Precision / Recall / F1 | 1.0 / 1.0 / 1.0 |
| Comparator | 10 Confirmed |
| Invariants | 10 vulnerable Violated; 10 fixed Satisfied |
| PoCs | 10 Passed; 0 Failed; 0 Inconclusive |
| Negative controls | 10 cases; 11 absence checks; 0 FP |
| Attack variants | 5 cases; 7 expected detectors; 5 PoCs Passed |

These are corpus-specific regression measurements, not a guarantee of complete vulnerability coverage. The LLM comparison is separate from the deterministic gate and is documented in [`benchmarks/evaluation/BASELINE_RESULTS.md`](benchmarks/evaluation/BASELINE_RESULTS.md). The Real-World registry currently contains 10 quarantined candidates and 5 incident-inspired negative controls; neither track changes the primary denominator. See [`benchmarks/evaluation/README.md`](benchmarks/evaluation/README.md), [`benchmarks/real_world/README.md`](benchmarks/real_world/README.md), [`BENCHMARK_METHODOLOGY.md`](BENCHMARK_METHODOLOGY.md), and [`LIMITATIONS.md`](LIMITATIONS.md).

To reproduce the strict benchmark locally:

```bash
export PATH="$HOME/.foundry/bin:$PATH"
PYTHONPATH=. python benchmarks/run_benchmark.py --require-poc
python -m pytest -q
PYTHONPATH=. pytest -q tests/test_negative_controls.py tests/test_attack_variants.py tests/test_adversarial_comparator.py
PYTHONPATH=. python benchmarks/run_extended_benchmark.py --json-out extended-benchmark.json
PYTHONPATH=. python benchmarks/real_world/run_negative_controls.py
PYTHONPATH=. python benchmarks/run_track_baseline.py --llm-report /path/to/evaluation_run.json --json-out track-baseline.json
```

## Corpus regression gate (Mini-Review)

Mini-Review's auto (reentrancy-evidence) path is pinned against a
local 52-case corpus by `scripts/check_corpus_regression.py`, run in
CI by `.github/workflows/corpus-regression.yml`. Bucket definitions
(Fix 2): **Confirmed findings** are code-evidence + Critical items
only; **guard notes** (Medium, appendix only) and **unverified LLM
hypotheses** are explicitly not findings and are never counted as
such. On the auto path there are no LLM findings, so hypotheses are 0.

Pinned counts, measured with Fix 3 code on the local corpus (same
files and commits as the corpus manifest): total **143**, Critical
**19**, Medium **124**, Confirmed findings **19**, guard notes (not
findings) **124**, hypotheses **0**, other **0**. Confirmed split:
**17** in reentrancy-labelled cases + **2** Parity `confirm()` items
(SB-AC-02, NS-AC-02) — those two are code-evidence items, not
verified exploits, since the labelled Parity flaw is elsewhere in
those files. Per-case pins include LAB-RE-01 = 1 Confirmed, SB-RE-01
= 1 Confirmed, SF-RE-01 = 5 Confirmed + 13 guard notes, SB-RE-07 = 0
items (known miss), NS-RE-03 = 0 Confirmed, and REAL-01 (Mandate),
REAL-02, REAL-03, REAL-04 = 0 items each. The gate fails if Critical
drops (lost detection) or rises (new false Critical), or if any
per-case pin moves.

Fix 2's bucketing does not change these auto-path counts: before Fix
2 the same run reported total 143 / Critical 19 / Medium 124, and
after Fix 2 those 19 Critical items are exactly the Confirmed bucket
and the 124 Medium items are exactly the guard-notes bucket, so the
before/after comparison is like-for-like. Fix 3 (contract-level-only
`_state_variables`) leaves all 52 per-case counts unchanged, while
the state-variable lists themselves changed in 33 of 52 cases —
locals (e.g. `i`, `to`, `value`, `sig` in the Parity files) removed
and genuine custom-type/constant variables (e.g. `m_owners`,
`MAX_UINT256`, `token`) added — so the narrowing removed
false-evidence surface without moving any corpus verdict.

The corpus is deliberately NOT vendored into this repo: it mixes
public benchmark code under its own licences with real teams'
outreach contracts, and the local corpus is local-only. The workflow
therefore runs only on `workflow_dispatch` where the corpus is
present, and the script exits non-zero — never a silent pass — when
the corpus directory is absent. Run it locally with:

```bash
CORPUS_DIR=/path/to/auditor-test-corpus python3 scripts/check_corpus_regression.py
```

## Reproducible Build and Security

Python dependencies are pinned with hashes in [`requirements.lock`](requirements.lock). Docker uses the pinned Python 3.10.14 Bookworm image tag, installs with `--require-hashes`, runs as a non-root user, and includes a healthcheck. CI runs the full test suite, Python compilation, a strict Foundry benchmark, and a pinned targeted lint gate.

Archive uploads use traversal, symlink, executable-file, member-count, and expansion-size controls. GitHub repository loading accepts only canonical HTTPS `github.com/owner/repository` URLs. PoC execution refuses an unisolated fallback and applies Docker network, capability, filesystem, process, memory, and CPU restrictions when Docker mode is used.

### Docker PoC runs and forge-std (CI note)

A Docker PoC run (`proof_generator.run_foundry_test(..., use_docker=True)`,
the path Mini-Review's opt-in `attempt_poc` uses) mounts a pre-built
project into a container run with `--network none` and a read-only
mount. Nothing can be installed inside that container, so `forge-std`
must be provided **host-side, before the mount**, in this order
(`proof_generator._provide_forge_std`): a `FORGE_STD_PATH` checkout,
a vendored repo `lib/forge-std`, `~/.forge-std`, or a host-side
`forge install foundry-rs/forge-std` (which needs network on the
host step, not inside the container). Having Docker and Foundry on a
CI runner is therefore **not** sufficient on its own: with none of
those sources available the run is `INCONCLUSIVE` with the named
error `forge-std not available: no FORGE_STD_PATH checkout, no repo
lib/forge-std, no ~/.forge-std, and forge is not installed to run
'forge install foundry-rs/forge-std'` (or, if a host install ran but
produced nothing, `forge install ran but lib/forge-std/src/Test.sol
is still missing`) — never a pass and never a disproof. To make a CI
Docker PoC run conclusive, set `FORGE_STD_PATH` to a pre-installed
checkout or run the host-side `forge install` step before the Docker
step. This change deliberately does **not** vendor `forge-std` into
the repo, does not vendor the corpus, and does not change any
workflow trigger. Note also that the legacy unprovisioned helper
`run_foundry_test_docker` was deleted (it had no callers and no
documented use); Docker PoC execution goes through
`run_foundry_test` only.

Read [`THREAT_MODEL.md`](THREAT_MODEL.md) for assets, trust boundaries, threats, and residual risks.

## Pattern learning

The pattern learner mines regex candidates from audit reports
(`agents/pattern_learner.py`, via the pipeline audit path only —
Mini-Review does not mine patterns). A candidate is **inactive** by
default: it appears in no scan and no report until it is confirmed,
and confirmation requires PoC-style evidence, not a text note:

- every regex in the candidate must fire on a supplied vulnerable
  sample, and
- no regex in the candidate may fire on a supplied fixed sample.

Confirm via the admin panel (same admin auth/CSRF treatment as the
KB confirm route — the panel's "Learned Patterns" card lists
candidates and posts the PoC samples) or via the admin API:

- `GET /api/admin/patterns/learned` — list candidates
- `POST /api/admin/patterns/learned/confirm` with `name`,
  `vulnerable_code`, `fixed_code`, and optional `evidence`

A confirmed pattern is stored persistently — `/data/learned_patterns.json`
when the `/data` volume exists, otherwise `instance/learned_patterns.json`
(override with `LEARNED_PATTERNS_PATH`); a legacy repo-root
`learned_patterns.json` is migrated once to the new location and left
intact. The next pre-scan picks up a newly confirmed pattern without a
process restart. Removal is live too: deleting a confirmed pattern
from the file deregisters it from a running process at the next
pre-scan (the registry is reconciled by pattern content, so the
survivors keep firing and the deleted one stops) — no restart is
needed. The admin panel states this where the candidates are shown.

Concurrency limit, stated plainly: PoC checks run through a pool of
4 isolated regex workers shared with live scans, acquired
non-blocking. Under contention a check can time out and the
confirmation fails closed — a timeout is never counted as a pass,
so it can only delay a confirmation, never falsely create one.
Retry the confirmation; the gate is deliberately not weakened to
make a contended confirmation succeed, and no behaviour change
was made here (raising the pool or queueing would change live
scan behaviour).

Limitation, stated plainly: the knowledge-base confirm route
(`/api/admin/patterns/confirm`) is a different store and still accepts
text evidence only. KB patterns are RAG context for confirmed patterns
only — they are never executed as detectors — so that route does not
prove a regex, and must not be presented as PoC confirmation.

## Limitations

The benchmark is a **reproducibility and regression instrument**, not a certification of security or an estimate of real-world detection performance. Results depend on the published corpus, configuration, detectors, compiler/toolchain versions, and ground-truth labels.

An analysis result should be independently validated against the source code and protocol context. False negatives, false positives, novel vulnerability classes, specification errors, and environment-specific behavior remain possible.

## License

[MIT](./LICENSE)
