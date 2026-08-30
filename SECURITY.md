# Security Policy

This repository is itself a security tool, so vulnerabilities in it are treated seriously.

## Supported versions

| Version | Supported |
| --- | --- |
| `main` branch | Yes |
| Older tags | Best effort — upgrade first |

## Reporting a vulnerability

- **Do not open a public issue** for anything exploitable — in particular: container escape or
  sandbox bypass in the PoC runner, path traversal or symlink issues in archive upload,
  authentication or rate-limit bypass in the API, or SSRF via repository loading.
- Email **[defiaudit@gmail.com](mailto:defiaudit@gmail.com)** with the subject
  `[security] smart-contract-auditor: <short summary>`.
- Include reproduction steps, affected paths or endpoints, and your impact assessment.
- Expect an initial response within 7 days. Coordinated disclosure is the default, and
  reporters are credited unless they prefer otherwise.

## In-scope areas

- PoC execution isolation: Docker network, capability, filesystem, process, memory, and CPU
  restrictions, plus the refusal to run an unisolated fallback.
- Archive upload controls: traversal, symlink, executable-file, member-count, and expansion-
  size checks.
- GitHub repository loading: canonical `github.com/owner/repository` HTTPS URL enforcement.
- API authentication and rate limiting (`AUDITOR_API_KEY`, `RATE_LIMIT_PER_MINUTE`).
- Supply-chain posture: hash-pinned `requirements.lock`, pinned Docker base image, non-root
  container user, and CI gates.

## Out of scope

- The intentionally vulnerable fixtures under `benchmarks/` (for example
  `benchmarks/reentrancy/vulnerable.sol` and its sibling case directories) — they are
  educational corpus material by design.
- Issues that require the attacker to already control the host or the operator's `.env`.

See [THREAT_MODEL.md](./THREAT_MODEL.md) for assets, trust boundaries, and residual risks.
