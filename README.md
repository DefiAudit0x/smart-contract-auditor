# Smart Contract Auditor

An enterprise-grade, multi-language smart contract security auditor powered by a multi-pass LLM pipeline and deep static analysis. Combines hierarchical AI analysis, 7 parallel pre-scan modules, and a real-time SSE streaming web UI to detect vulnerabilities in Solidity, Vyper, Move, and Chialisp contracts.

## Features

- Multi-pass AI analysis (3-pass: AI → Validation → Gate)
- 7 parallel pre-scan modules (regex, AST, MCP, ZKsync, external tools, SBOM, learned patterns)
- Real-time streaming results via SSE
- CVSS 4.0 scoring
- Gas profiling
- SBOM generation
- SARIF export (GitHub Security Tab compatible)
- Diff Auditor for upgradeable contracts
- VS Code Extension
- Telegram Bot integration
- Dark mode web UI with Chart.js severity charts
- Pattern learner for continuous improvement
- Cross-session knowledge base (17,000+ patterns)

## Quick Start (Docker)

```bash
docker run -p 5000:5000 -e OLLAMA_API_KEY=your_key yourname/auditor-bot
```

Or build locally:

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
| `OLLAMA_MODEL` | LLM model for analysis | `qwen3-coder:480b` |
| `OLLAMA_BASE_URL` | Ollama endpoint | `http://localhost:11434` |
| `AUDITOR_API_KEY` | API key for REST endpoint auth | — |
| `API_PROVIDER` | LLM provider (`ollama`, `openrouter`, `groq`) | `ollama` |
| `PORT` | Web UI port | `5000` |
| `RATE_LIMIT_PER_MINUTE` | Max API requests per minute | `5` |
| `KB_USE_ST` | Disable heavy sentence-transformers | `0` |
| `TELEGRAM_BOT_TOKEN` | Telegram bot token | — |
| `TELEGRAM_CHAT_ID` | Telegram target chat ID | — |
| `ETHERSCAN_API_KEY` | Etherscan API key for on-chain fetch | — |

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

## Ground-Truth Benchmark

The repository includes a deterministic ten-case benchmark covering reentrancy, delegatecall, selfdestruct, unauthorised public minting, `tx.origin` authentication, flash loans, storage collision, unchecked transfers, unbounded loops, and timestamp-dependent gates. Each case pairs `vulnerable.sol` with `fixed.sol` and includes metadata, a comparator evidence path, a declared invariant, and a Foundry PoC fixture. Supplementary negative controls, attack variants, and adversarial comparator fixtures are maintained separately.

The latest run with Solidity `0.8.25` and Foundry `v1.7.1` reports:

| Metric | Result |
|---|---:|
| Full Python suite | 286 passed |
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

## Reproducible Build and Security

Python dependencies are pinned with hashes in [`requirements.lock`](requirements.lock). Docker uses the pinned Python 3.10.14 Bookworm image tag, installs with `--require-hashes`, runs as a non-root user, and includes a healthcheck. CI runs the full test suite, Python compilation, a strict Foundry benchmark, and a pinned targeted lint gate.

Archive uploads use traversal, symlink, executable-file, member-count, and expansion-size controls. GitHub repository loading accepts only canonical HTTPS `github.com/owner/repository` URLs. PoC execution refuses an unisolated fallback and applies Docker network, capability, filesystem, process, memory, and CPU restrictions when Docker mode is used.

Read [`THREAT_MODEL.md`](THREAT_MODEL.md) for assets, trust boundaries, threats, and residual risks.

## Screenshots

(Placeholder: add screenshots after deploying)

## License

MIT
