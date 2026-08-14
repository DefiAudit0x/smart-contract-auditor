# Limitations

This project is an analysis and verification tool, not a substitute for a complete independent smart-contract audit. Its outputs are evidence for review and prioritisation; they are not a security guarantee.

## Detector coverage

The current primary ground-truth benchmark contains ten categories: reentrancy, delegatecall, selfdestruct, public mint, `tx.origin` authentication, flash loans, storage collision, unchecked transfers, unbounded loops, and timestamp-dependent gates. The reported precision, recall, F1, false-positive rate, and false-negative rate are measurements on this finite corpus and on the detector named in each case's metadata. They are not estimates for all Solidity vulnerabilities, all compiler versions, or all production contracts. The separate negative-control and attack-variant suites broaden regression coverage but do not turn these numbers into universal analyzer metrics.

The benchmark uses a vulnerable/fixed pair. The fixed file is a controlled comparison fixture, not a proof that every possible repair is safe. A detector may correctly identify additional secondary patterns in either file; those findings are not automatically part of the primary TP/FP/FN denominator.

## Static-analysis limits

Source-pattern and AST evidence can be affected by formatting, inheritance, generated code, compiler changes, proxy boundaries, inline assembly, and semantic behaviour that is not visible from a single source file. A detector finding must be reviewed in its contract, deployment, privilege, and call-graph context.

The deterministic comparator confirms evidence patterns. It does not prove exploitability in every deployment. The invariant engine checks the declared source-level property and can return `Inconclusive` when the input or rule is not sufficient for a conclusion.

## PoC limits

The executable PoCs are repository-owned fixtures designed to demonstrate a narrow behaviour. A passing PoC proves only the assertion encoded by that fixture. The reentrancy fixture is explicitly a `negative_control`: its test passes when checked arithmetic prevents the attempted drain, and this is not reported as a successful exploit.

Foundry execution is isolated as far as the configured runner permits. Docker execution is restricted with no network, read-only mode, dropped capabilities, no-new-privileges, process and resource limits, and read-only fixture mounts. These controls reduce risk but do not make arbitrary Solidity or Foundry code universally safe.

## Metrics limits

`Inconclusive` results are kept separate from FP, FN, and Passed counts. A zero FP/FN result on the ten-case benchmark and zero false positives across the current negative controls mean that no mismatch was observed under this methodology; they do not mean that false positives or false negatives cannot occur outside the corpus. Attack variants test coverage of additional source patterns but are not a complete recall estimate. Runtime coverage is also a property of the available fixtures and environment, not a claim of production-chain coverage.

## Operational limits

The web application accepts source code, archives, repository URLs, and optional external API requests. Upload and archive controls enforce size, path, member-count, and file-type boundaries, while GitHub loading accepts only canonical HTTPS `github.com` repository URLs. The application still requires deployment-level controls such as secret management, TLS termination, authentication configuration, rate-limit storage, dependency patching, logging policy, and network egress policy.

The project should not be deployed with development secrets, unrestricted filesystem access, unrestricted Docker privileges, or a production database exposed to untrusted users. The optional LLM comparison is an experiment whose result depends on model, prompt, and model-version behavior; it is not part of the deterministic CI gate. Operators remain responsible for reviewing generated reports and for validating every finding before acting on it.

## Reproducibility limits

Python dependencies are resolved into `requirements.lock` with hashes for the declared Python 3.10 target. Docker uses a pinned Python image tag and the lockfile. The base image tag and operating-system packages can still change upstream unless an image digest and a fully pinned OS repository snapshot are supplied by the deployment environment. Solidity compiler `0.8.25` and Foundry `v1.7.1` are the benchmark targets; other toolchain versions may produce different results.

## References

[1]: benchmarks/README.md "Ground-truth benchmark overview"

[2]: BENCHMARK_METHODOLOGY.md "Benchmark methodology"

[3]: THREAT_MODEL.md "Application threat model"
