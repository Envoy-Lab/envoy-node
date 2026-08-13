# Agent operating contract

This repository controls a personal Windows laptop. Preserve the user's existing workloads and treat availability as a safety property.

## Required lifecycle

1. Run `Audit`.
2. Install and enroll the official signed Tailscale client interactively before `AccessPrepare`; the framework never installs it.
3. Immediately before each framework mutation, run `Plan` and inspect all blockers and warnings. The plan and mutator must use the same Windows identity and elevation context: elevated as the same account for Access/Desktop; non-elevated as the same WSL-owning account for Compute/Export.
4. Ask for approval before any action requiring `-Apply`, then pass the unmodified, unexpired artifact through `-ApprovedPlanPath` and its 64-character hash through `-ApprovedPlanHash`. Emergency disables are the only plan-free mutations.
5. Apply one layer at a time: overlay enrollment, SSH, desktop, compute, GPU.
6. Verify each layer from a second device before hardening or continuing.
7. Journal machine/account ownership and prior state before mutation. Roll back connectivity exposure; keep package/distribution work in an explicit resumable state when destructive rollback would be riskier.

## Invariants

- Never create public inbound access or router forwarding.
- Never disable Windows Firewall, Defender, UAC, Secure Boot, disk encryption, Network Level Authentication, or updates.
- Never use Tailscale Serve, Funnel, Services forwarding, Taildrive shares, Taildrop/Send Files, an exit node, subnet routing, public DNS, UPnP, or a router DMZ for this project. Require the fixed signed Tailscale CLI to correlate with the signed registered service executable, require matching CLI/running-daemon versions at or above 1.98.9, require conclusively empty Serve/Funnel/Services configurations, and require zero results from `tailscale drive list`. Services inspection uses `tailscale serve get-config --all`; Taildrop/Send Files must be disabled in the admin console and is not locally attested.
- Never enable Tailscale SSH on Windows. Use native Windows OpenSSH over Tailscale.
- Never place an SSH private key, Tailscale auth key, recovery key, password, or token in the repository, logs, command history, or process arguments.
- Never reuse one SSH private key across client laptops. Enroll and revoke each client independently.
- Never silently change Tailscale node-key expiry. Enforce the configured mode and require at least 30 days remaining when expiry is enabled.
- Never set `StrictHostKeyChecking no`.
- Never disable SSH password login on an existing installation until a new key-only session from a separate client has succeeded.
- Never harden SSH or accept a reboot proof unless exact managed-firewall, listener ownership, Windows port-proxy, Tailscale surface, and global public-exposure checks have just passed.
- Every client proof must sign the host's current printed 64-character challenge and must match a host-observed OpenSSH `Accepted publickey` event for the approved user, source, key fingerprint, and proof window. The helper is portable across Windows, macOS, and Linux when PowerShell and modern OpenSSH with `ssh-keygen -Y sign` are available.
- Treat `access.ssh.publicKeyFiles` as the complete allowlist. Refuse unexpected existing keys; never append around them silently.
- Never overwrite an existing `sshd_config`; preserve bytes and ACLs, edit only a managed block, validate with `sshd.exe -t`, and restore on failure. Require exactly one LocalSystem `sshd` service whose entire command is the fixed signed Windows OpenSSH binary with no arguments; bind any running service to that same live process and listener owner.
- Never bind `sshd` only to a Tailscale IP. Service ordering can make that address unavailable at boot; scope the firewall to the resolved adapter instead.
- Never unregister a WSL distribution, delete a container volume, alter firmware/VRAM, reboot, sign out, or change global `.wslconfig` limits without separate explicit approval.
- Never adopt an existing unmarked WSL distribution from a local journal. Require its live version-2 registration and exact root-owned, machine-and-owner-bound marker; treat journals as informational only.
- Never export while compute containers are active unless the operator explicitly supplies `-AcknowledgeActiveComputeContainers` and accepts a filesystem/crash-consistent artifact recorded as such in the manifest.
- Never run ComputeBootstrap or ExportCompute elevated. Direct export still requires `-Apply`; do not bypass the top-level CLI safety gate.
- Never run ComputeBootstrap until `AccessAcceptRebootProof` has accepted a fresh second-device proof for the current Windows boot; the non-elevated compute action requires an explicit acknowledgment of that completed access-layer gate.
- General `Verify` must not start a stopped on-demand distribution or create a compute container. Use `ComputeVerify` only when the operator deliberately requests the live transient smoke proof.
- Never stop, rename, reconfigure, or reuse the names of pre-existing Docker containers, networks, images, or volumes. All test containers use the `io.envoynode.managed=true` label and a unique name.
- Host `Smoke` must use only the fixed validly signed Docker Desktop CLI, force the local `npipe:////./pipe/docker_engine`, validate the cached image labels/base digest, resolve the immutable image ID, and run that ID with `--pull=never`.
- Never patch Windows Home to host Microsoft RDP.
- Never install or configure RustDesk while network-connected. Download the official signed installer first; disconnect Wi-Fi and Ethernet; install/configure direct-IP, a Tailscale-only whitelist, and a unique password; exit its GUI and stop/startup-disable its service before reconnecting. Do not reopen it or start the service before approved `DesktopEnable` installs and validates the public-egress blocks.
- Never enable RustDesk until its incoming IP whitelist is restricted to Tailscale and EnvoyNode's public-egress block rules validate successfully.
- Treat RustDesk GUI settings as explicit operator attestations: direct-IP only, tailnet whitelist, unique permanent password, LAN discovery/remote configuration and unused permissions off, and public proxy/ID/relay/API/key fields empty. On any lifecycle failure, success requires conclusive proof that the service is stopped/startup-disabled, managed ingress is disabled, and no managed-port endpoint remains; otherwise require local-console investigation.
- Never enable RustDesk until a fresh second-device SSH proof has been accepted after the current Windows boot.
- After every reboot, renew the SSH current-boot proof first, perform a real second-laptop GUI test, then run `DesktopAcceptRebootProof` with both required acknowledgments and a fresh approved plan. Do not rerun `DesktopEnable` merely to renew proof.
- Never claim WSL inference is a pre-login 24/7 service. The Windows pilot compute lifecycle is on-demand; native Linux is the always-on target.

## Mandatory stop conditions

Stop and report instead of guessing if any of the following occurs:

- enterprise/domain/MDM policy manages the target setting;
- an unexpected public listener or router mapping is found;
- more than one possible Tailscale adapter is found;
- the requested target account is an administrator and admin access was not explicitly approved;
- a plan has drifted, a backup is incomplete, or rollback ownership is ambiguous;
- OpenSSH configuration validation fails;
- the signed client proof does not match the host challenge/fingerprint/account/source or lacks a matching host-observed OpenSSH public-key event;
- Tailscale CLI/service correlation or either signature is untrusted; CLI/daemon versions cannot be parsed, differ, or are older than 1.98.9; Serve, Funnel, Services, or Taildrive state cannot be read conclusively; any persistent forwarding configuration is nonempty; or `tailscale drive list` reports a share;
- Taildrop/Send Files is enabled or cannot be confirmed disabled in the admin console;
- the AMD driver, WSL version, Ubuntu release, and ROCm compatibility matrix do not match;
- a command would disturb an existing Docker workload.

The planner must fail closed when domain, Entra ID/workplace join, MDM enrollment, or managed firewall/OpenSSH/RustDesk policy cannot be inspected conclusively. Official-download provenance remains an operator responsibility; the framework binds and rechecks fixed paths, hashes, Authenticode validity, and signer continuity, but does not substitute for obtaining installers from the vendor's official release channel.

## Commands agents may run without further approval

```powershell
.\envoy.ps1 -Action Audit
.\envoy.ps1 -Action Plan
.\envoy.ps1 -Action Smoke
.\envoy.ps1 -Action Verify
.\envoy.ps1 -Action AccessPreview
.\envoy.ps1 -Action DesktopPreview
.\envoy.ps1 -Action ComputePreview
```

Any invocation containing `-Apply` is a machine change and requires explicit user approval in the current conversation. Except emergency disables, direct mutation scripts enforce a fresh reviewed-plan artifact, the planner SID/elevation context, and the resolved public-key manifest. Regenerate the plan if any reviewed input changes.

Read `docs/RUNBOOK.md` before an apply action. Treat blockers, warnings, and checks in the JSON reports as machine-readable local desired-state evidence. `Verify` does not prove Internet reachability or a real client session; any failed check produces a nonzero exit code and forbids an unattended-ready claim.
