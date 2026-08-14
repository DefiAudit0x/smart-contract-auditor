# Real-World Corpus

This directory is a provenance-first registry for real incidents. The current registry contains ten **candidates**, not admitted benchmark cases. No candidate changes the primary benchmark totals or project Precision/Recall until its source version, incident evidence, affected location, and Ground Truth adjudication are independently verified.

## Candidate sources

The first candidate set was discovered from [SunWeb3Sec/DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs), pinned to repository commit `2c99b565ae24ea2006adf181da20c4419b3edc30`. That repository is used only as a PoC/source discovery index. Its files are not copied into this project, and their presence does not by itself establish the vulnerability label.

The discovery list was cross-checked against the SoK incident index and public incident analyses, including the [SoK repository](https://github.com/HadisRe/SoK-Root-Cause-of-Smart-Contract-Incidents) and its associated [systematic review](https://arxiv.org/abs/2507.20175). The registry retains external incident links, transaction identifiers, contract addresses, source path, source commit, and source SHA-256 where available.

## Admission gate

A candidate may become an admitted Real-World case only when all required fields are complete and independently reviewed:

| Gate | Required evidence |
|---|---|
| Incident identity | Protocol, date, chain, and a stable incident reference |
| On-chain anchor | Full exploit transaction hash or an equivalent immutable event anchor |
| Source provenance | Contract address, verified source or repository path, source commit/block, and SHA-256 |
| Location mapping | Affected contract and function(s), with source lines or an explicit proxy/implementation mapping |
| Root-cause label | Vulnerability family and concise mechanism supported by an external reference |
| Detector mapping | Existing expected detector, or a documented `not_covered` label; no detector is invented during labeling |
| Invariant | A property that can be evaluated on the pinned source or a quarantine reason if unavailable |
| PoC status | Reproduction reference, fork block, dependencies, and safe-run result; a third-party PoC is not silently executed as trusted code |
| Adjudication | Independent reviewer record separate from analyzer and LLM output |

Cases that fail one or more gates remain `candidate_pending_*` in `registry.json`. They must not enter metrics. Disputed or incomplete cases should be moved to a future quarantine file rather than labeled clean.

## First adjudication: Nomad Bridge

`rw-003-nomad-bridge` is the first candidate processed through the full adjudication workflow. Its official `Replica.sol` implementation is pinned to commit `7510d54a5cd334d283d84fdff59827abfceb2da7`, the source SHA-256 and exact line ranges are recorded in the registry, and Etherscan independently verifies the cited `process(bytes)` transaction at block `15259101`. The project-owned zero-root reproduction passes its vulnerable/fixed contrast and its narrow invariant returns `Violated/Satisfied`.

The case remains **quarantined**. The existing detector taxonomy has no semantically valid detector for zero-root message-proof validation, the owned PoC is a minimal model rather than a historical mainnet fork, and a second independent adjudication is still required. The detailed record is [`adjudications/rw-003-nomad-bridge.json`](adjudications/rw-003-nomad-bridge.json), the stage-by-stage observation is [`adjudications/rw-003-nomad-pipeline.json`](adjudications/rw-003-nomad-pipeline.json), and the readable report is [`adjudications/rw-003-nomad-report.md`](adjudications/rw-003-nomad-report.md).

## Current candidate scope

The initial ten candidates span access control and initialization, price/oracle manipulation, business logic and accounting, read-only reentrancy, precision/rounding, and unchecked external calls. The current analyzer does not cover every family. Candidates with an empty `expected_detectors` list are intentionally marked as `not_yet_mapped`; they are useful for coverage planning but cannot contribute to detector metrics until a detector mapping is independently justified.

## Safety and licensing

The project stores metadata and provenance first. It does not import third-party PoC code into the production analyzer or execute external PoCs as part of CI. Any future reproduction must be reduced to a repository-owned, reviewed fixture with bounded execution and an explicit license/provenance record.
