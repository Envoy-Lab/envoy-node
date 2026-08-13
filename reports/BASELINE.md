# Public pre-activation baseline

This document describes the safe, publishable baseline for EnvoyNode. It intentionally contains no machine snapshot, account identifier, hostname, SID, tailnet address, hardware serial, client key, event record, or local report value.

## Expected starting posture

- Tailscale installation and enrollment are external, interactive operator steps.
- Windows OpenSSH Server and the optional RustDesk adapter are not enabled by project creation or validation.
- The dedicated Ubuntu WSL2 compute distribution does not exist until an explicitly approved bootstrap.
- Existing Docker Desktop workloads are outside EnvoyNode ownership and must remain untouched.
- `Audit`, `Plan`, previews, and `Verify` write ignored local JSON reports. `Smoke` also runs one isolated, uniquely named, auto-removed container from an already cached project image.
- Pre-activation `Verify` is expected to report `acceptanceReady=false`; the exact failed-check count is intentionally not frozen in public documentation.

## Validation contract

- All PowerShell files must parse under Windows PowerShell 5.1.
- `tests/Test-Static.ps1` must pass.
- JSON configuration and Docker Compose must validate.
- The host smoke proof must use the fixed, validly signed Docker Desktop CLI, force the local named pipe, resolve an immutable image ID, run with `--pull=never`, and leave no EnvoyNode container, network, or listener.
- Every non-emergency mutation must require `-Apply` plus the unmodified, unexpired plan artifact and its 64-character review-consistency hash.
- Emergency access and desktop disables remain plan-free but still require an explicit `-Apply` invocation.
- General `Verify` must not start a stopped on-demand WSL distribution or create a compute container.

## Local evidence handling

Machine-readable reports under `reports/*.json`, `config/node.local.json`, `keys/`, `exports/`, `state/`, and `generated/` are ignored. They can contain machine-, account-, network-, workload-, or key-bound details. Git ignore prevents commits but does not prevent cloud synchronization or folder-archive disclosure; publish only the reviewed Git tree and redacted findings that cannot be correlated back to a host or trusted client.

## Activation remains separately gated

Activation requires the operator sequence in [the runbook](../docs/RUNBOOK.md) and [activation checklist](../docs/ACTIVATION_CHECKLIST.md). In particular, installation and interactive enrollment of the official signed Tailscale client precede access preparation, every framework mutation gets a fresh same-context plan, and each layer is verified from a second device before hardening or continuing.
