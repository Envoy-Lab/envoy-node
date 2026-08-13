# Contributing to EnvoyNode

EnvoyNode changes can affect a real Windows host. Treat availability and private-network boundaries as security properties.

## Before proposing a change

1. Read [AGENTS.md](AGENTS.md), [SECURITY.md](SECURITY.md), [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md), and [docs/RUNBOOK.md](docs/RUNBOOK.md).
2. Keep tests and CI non-mutating. Never add `-Apply`, unattended enrollment, a public listener, a router-forwarding step, a self-hosted runner, or a secret-bearing fixture.
3. Use synthetic usernames, hostnames, addresses, SIDs, fingerprints, keys, event records, and paths in tests and documentation.
4. Preserve existing Docker, WSL, firewall, access, encryption, update, and power workloads unless a separately approved lifecycle action owns them.

## Development checks

Run these from Windows PowerShell 5.1:

```powershell
.\tests\Test-Static.ps1
.\envoy.ps1 -Action Audit
.\envoy.ps1 -Action Plan
.\envoy.ps1 -Action Verify
```

`Verify` is expected to fail on a preparation-only host. Explain expected unmet gates; never relabel them as a passing readiness result. `Smoke` and the three preview actions may also be run when their documented prerequisites are satisfied. `Smoke` must leave existing Docker workloads unchanged and no EnvoyNode container running.

## Pull requests

- Keep one coherent safety or maintenance change per pull request.
- Describe the invariant being protected, failure behavior, rollback implications, and checks run.
- Add or update static coverage for every mutation gate or fail-close path.
- Keep local reports, configuration, keys, exports, generated recommendations, client proofs, and credentials out of the diff.
- Link current primary vendor documentation when changing version, platform, or security claims.

Potential vulnerabilities belong in [private vulnerability reporting](https://github.com/Envoy-Lab/envoy-node/security/advisories/new), not a pull request or public issue.
