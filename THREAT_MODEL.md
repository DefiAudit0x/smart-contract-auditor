# Threat Model

## Scope

The system accepts smart-contract source code and project archives, may retrieve source from an allowlisted external provider, runs static analysis and optional language-model analysis, generates reports, and can execute repository-owned Foundry PoC fixtures. This model covers the application and its analysis workspace; it does not model the security of an audited contract's deployment.

## Assets

| Asset | Security property | Main concern |
|---|---|---|
| API keys and session secrets | Confidentiality | Leakage through logs, reports, images, exceptions, or untrusted code |
| Uploaded source and archives | Confidentiality and integrity | Path traversal, overwrite, symlink, ZIP bomb, and retention |
| Analysis workspace and reports | Integrity and confidentiality | Cross-user access, filename traversal, and generated content |
| Host process and container | Integrity and availability | Command injection, resource exhaustion, and unsafe PoC execution |
| Benchmark truth labels | Integrity | Accidental changes that inflate metrics or hide regressions |
| External provider requests | Confidentiality and network safety | SSRF, credential forwarding, and excessive egress |

## Trust boundaries

The principal boundaries are the browser/API client to Flask, the uploaded archive to the temporary workspace, the application to GitHub/explorer APIs, the application to model providers, and the PoC runner to the host or Docker runtime. Data crossing a boundary is treated as untrusted unless it is produced by the repository's controlled benchmark fixtures.

## Threats and controls

| Threat | Control in the repository | Residual risk |
|---|---|---|
| Archive path traversal or symlink escape | Normalised relative members, `commonpath`, symlink rejection, safe extraction, member and expansion limits | Parser and filesystem vulnerabilities outside the process remain deployment risks |
| Archive executable or dependency injection | Blocked script/binary extensions and cache/dependency directories | Source-language abuse can still consume analysis resources |
| Upload overwrite and retention | Random temporary upload names and cleanup after source loading | Report and runtime storage still need deployment retention policy |
| SSRF through GitHub URL | HTTPS-only canonical `github.com/owner/repo` validation; no credentials, ports, query, fragment, or subpaths | Other explicitly configured providers still need their own service-level controls |
| SSRF through explorer chain | Fixed chain allowlist and fixed API URLs; strict address validation | Provider-side API behaviour and network egress policy remain external |
| Command injection | `shell=False` with argument lists in environment checks; no shell interpolation in PoC commands | External tools themselves are not assumed trustworthy |
| Arbitrary PoC execution | Foundry runner uses temporary projects; Docker mode disables network, drops capabilities, is read-only, and limits CPU, memory, and PIDs | The runner is not a universal sandbox; untrusted PoCs must not be enabled without stronger isolation |
| Secret leakage in errors | Generic external error responses with internal logging; secrets are not included in URLs | Logs must still be protected and redacted at deployment level |
| Report path traversal | Single basename validation, `secure_filename`, and `commonpath` checks | Reports may contain sensitive source-derived content |
| Benchmark manipulation | Metadata, vulnerable/fixed pairs, comparator, invariants, PoC mode, and metrics are tested together | The corpus is small and requires future independent cases |

## Security assumptions

The deployment supplies secrets through a protected environment or secret manager, enables HTTPS, configures an authentication key, keeps the report and database directories private, and applies outbound network policy. The benchmark assumes Solidity `0.8.25` and Foundry `v1.7.1` for its current runtime target.

## Out of scope

This model does not claim to prove the absence of Solidity vulnerabilities, secure arbitrary model output, secure arbitrary third-party Docker images, secure production infrastructure, or safe handling of private keys. It also does not treat an AI-generated report as a security boundary.

## References

[1]: LIMITATIONS.md "Project limitations"

[2]: security_utils.py "Archive and URL security guards"

[3]: verification/poc.py "PoC execution wrapper"

[4]: proof_generator.py "PoC generation and Docker execution paths"
