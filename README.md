# EnvoyNode

EnvoyNode is a portable, agent-friendly framework for turning a personal Windows machine into a private remote compute node without publicly exposing it.

The temporary Windows design is deliberately layered:

```text
trusted laptop
  -> Tailscale private network
    -> Windows host
       - native OpenSSH for control and recovery
       - RustDesk direct-IP for optional Windows Home desktop control
       - dedicated Ubuntu 24.04 WSL2 compute environment
          -> containers
          -> AMD ROCm GPU adapter
```

The future dedicated-node design keeps the same Linux containers and replaces the Windows/WSL shell with bare-metal Ubuntu. The desktop is an adapter, not part of the compute core.

## Non-negotiable security rules

- No router port forwarding, public TCP 22, public TCP/UDP 3389, public RustDesk port, DMZ, UPnP, Tailscale Serve/Funnel/Services forwarding, Taildrive shares, or Taildrop/Send Files.
- Every client joins the private network through an MFA-protected identity and device approval.
- SSH uses one passphrased Ed25519 key per client. Private keys never enter this project or the host.
- The fixed Program Files Tailscale CLI and its registered service executable must both have valid Windows signatures; the CLI and running daemon must report the same version, at or above 1.98.9.
- The single `sshd` service must be LocalSystem with the signed fixed Windows OpenSSH binary as its entire no-argument command; when running, its live process path and listener ownership must match that registration.
- Windows Firewall admits managed services only through the detected Tailscale adapter.
- SSH password authentication is not disabled until a separate client proves key access.
- Agents never reboot, sign out, change disk encryption, change firmware/VRAM, or remove a WSL distribution without explicit approval.

## Safe starting state

EnvoyNode is designed to begin with remote access and the dedicated compute distribution disabled. `Audit` records the actual operating-system, hardware, firewall, overlay, SSH, WSL, encryption, power, and container state in an ignored local JSON report. Never commit that report: it can contain machine- and account-bound identifiers.

Windows Home cannot host Microsoft's built-in Remote Desktop. This project therefore uses SSH as the base and makes RustDesk direct-IP over Tailscale the optional GUI path. It never uses RDP-enabling patches. The initial AMD adapter targets the `gfx1151` profile, but GPU activation always depends on a fresh compatibility-matrix check for the actual machine.

## Safe quick start

These commands do not enable remote access or install a Linux distribution:

```powershell
# Read-only system audit
.\envoy.ps1 -Action Audit

# Build an indicative plan (each approval plan must match its mutator's context)
.\envoy.ps1 -Action Plan

# Run an isolated, CPU-only container proof without touching existing containers
.\envoy.ps1 -Action Smoke

# Collect strict local desired-state evidence
.\envoy.ps1 -Action Verify

# Preview the still-disabled access, desktop, and compute adapters
.\envoy.ps1 -Action AccessPreview
.\envoy.ps1 -Action DesktopPreview
.\envoy.ps1 -Action ComputePreview
```

Reports are written under `reports/`. Every non-emergency framework mutation requires an explicit action, `-Apply`, and the exact artifact and 64-character review-consistency hash from a fresh `Plan`; `safety.requirePlanReview` cannot be disabled or omitted. The hash is not a signature or a security boundary against a hostile local user; each mutator still performs its own live fail-closed checks. Run the plan under the same Windows identity and elevation context as its mutator: elevated as the same account for Access/Desktop, and non-elevated as the same WSL-owning account for Compute/Export. Plans expire after one hour and are rejected if the planner SID/elevation, configuration, resolved public-key files, or derived safety findings/gates drift. Emergency `AccessDisable` and `DesktopDisable` are the only plan-free mutations.

`Verify` is a strict **local desired-state report**; it does not establish end-to-end availability or Internet reachability. It never starts a stopped on-demand compute distribution and never creates a compute container. For a stopped engine it still validates exact protected Windows state and its machine/owner/version-2 WSL registration binding; missing/drifted state or inconclusive running-state inventory is a failure, while only the deferred live Linux/Docker proof is a warning. An already-running engine receives read-only posture checks. Use the explicit `ComputeVerify` action when you deliberately want to wake compute and run its transient, auto-removed smoke container. Before activation, `Verify` prints `NOT READY`, records locally observable unmet gates, and exits nonzero. It fails closed unless the fixed signed Tailscale CLI and signed registered service are correlated, their parsed `major.minor.patch` releases match at or above 1.98.9, and Serve, public Funnel, and Tailscale Services configurations plus Taildrive shares are conclusively empty. These paths can persist independently of the intended adapter-scoped listener rules. It cannot independently attest current Windows support/update freshness, the Tailscale admin-console policy/MFA settings or whether Taildrop/Send Files is disabled, nor actual ISP and power continuity, a real GUI session, onsite recovery, or later drift; those remain explicit operator checks.

An untouched pre-activation host is expected to report `acceptanceReady=false` because access, desktop, and the dedicated compute distribution are intentionally off or cannot yet be conclusively inspected without elevation. Do not normalize or suppress those failures; they are the gates that prevent an unreviewed activation.

On a newly copied machine, preview and then deliberately build the tiny project-owned probe once before `Smoke`:

```powershell
.\scripts\Build-EnvoySmokeImage.ps1
.\scripts\Build-EnvoySmokeImage.ps1 -Build
```

The helper uses a digest-pinned base and is a separate, deliberate network-capable step. It refuses to replace a same-named image that is not already EnvoyNode-owned, builds under a unique temporary tag, validates the ownership and base-digest labels, and creates no container, network, or volume. `Smoke` does not trust `PATH`, the active Docker context, or the mutable image tag at run time. It requires the fixed Docker Desktop CLI under Program Files to have a valid Windows signature, forces the local `npipe:////./pipe/docker_engine` endpoint, inspects the already-cached tag for the expected ownership and pinned-base labels, resolves its immutable `sha256:` image ID, and runs that ID with `--pull=never`. The transient container has no network, a read-only filesystem, dropped capabilities, explicit resource limits, a unique name, and `--rm` cleanup.

## Activation sequence

1. Run `Audit` and `Smoke`. Generate and review a fresh matching-context `Plan` immediately before every framework mutation.
2. On the second laptop, create a new passphrased Ed25519 SSH key. The proof helper supports Windows, macOS, or Linux when PowerShell and modern OpenSSH (`ssh`, `ssh-keyscan`, and `ssh-keygen -Y sign`) are available. Copy only the `.pub` file to `keys/` locally; that folder is ignored by Git.
3. Install the official signed Tailscale client interactively on both laptops, enroll them, enable MFA and device approval, replace the default allow-all tailnet policy, add concrete positive and negative policy tests, and enable unattended mode on the host. On the Windows host, EnvoyNode binds the fixed CLI and registered service paths, hashes, Authenticode signer continuity, and matching `major.minor.patch` releases at 1.98.9 or newer. Official-download provenance is still an operator responsibility. Prove Serve, Funnel, and Tailscale Services configurations are empty and `tailscale drive list` reports zero Taildrive shares. Disable Taildrop/Send Files in the admin console. EnvoyNode does not install Tailscale.
4. Only after Tailscale is installed and enrolled, prepare Windows OpenSSH, install exactly the configured public-key allowlist, and create only overlay-scoped firewall rules. EnvoyNode accepts only one `sshd` service registered as LocalSystem to the fixed signed Windows OpenSSH binary with no command arguments, and binds a running service to that exact live process and listener owner.
5. Answer the host's one-time challenge from the second laptop with `New-EnvoyClientProof.ps1`. Acceptance requires the signed proof, its pinned host-key and remote-identity evidence, and a matching Windows OpenSSH public-key event. Final hardening rechecks exact service identity, firewall ownership, and global public exposure before password authentication is removed.
6. Reboot deliberately, prove another key-only login from the second laptop, and record that proof for the current boot only after exact firewall and global exposure checks pass again.
7. Add RustDesk direct-IP only if GUI control is needed. Download the official signed installer first, then install it in the native `Program Files\RustDesk` directory and complete every private setting while all network links are disconnected: direct-IP only, a tailnet-only whitelist, a unique permanent password, LAN discovery and remote configuration off, unused permissions/features off, and proxy/rendezvous/relay/API/key fields empty. Stop and startup-disable its service before reconnecting. The GUI settings are operator-acknowledged; the adapter separately requires a non-reparse installation tree not writable by untrusted accounts, a signed executable, an exact quoted `--service` registration under LocalSystem or LocalService, its exact `--server` child, one managed TCP listener, no UDP endpoint on that port, exact firewall posture, and public-egress blocks. Once an authorized managed lifecycle has authenticated its scope/state and begun closure or activation, later activation, reboot-proof, and disable failures attempt to stop/startup-disable the service and close managed ingress on both the reviewed and safely recovered prior port; if closure cannot be proved conclusively, success is refused and local-console investigation is required. Rejected caller, plan, acknowledgment, scope, or unmanaged-state checks make no claim of changing a pre-existing RustDesk service. Test from the second laptop, reboot, test again, and accept the desktop reboot proof.
8. Only after the current-boot SSH proof has been accepted, create the Ubuntu WSL compute layer with `-AcknowledgeCurrentBootAccessProof`. GPU activation is separate because it may require an AMD WSL driver and a reboot.
9. Export containers, manifests, and data when moving to the dedicated Linux machine.

`access.overlay.hostKeyExpiry` makes the availability tradeoff explicit. The default, `keep-enabled`, preserves Tailscale's credential rotation and requires more than 30 days of remaining validity at acceptance. `disable-for-unattended-host` supports a deliberately non-expiring trusted host, but puts prompt manual revocation on the operator if the node is lost or retired.

The exact operator sequence and stop conditions are in [docs/RUNBOOK.md](docs/RUNBOOK.md). The design rationale is in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Why WSL2 instead of a conventional VM

On Windows Home, WSL2 provides a real Linux kernel with substantially less overhead than a traditional VM and is the supported route for GPU compute. It is a good staging shell, but it is not a hard security boundary from Windows and it is not the final 24/7 appliance. Containers are the migration unit.

WSL2 memory/CPU limits are global per Windows user, not per distribution. EnvoyNode generates the ignored, machine-local `generated/wslconfig.recommended` file only during an approved compute bootstrap and never applies it. Individual services still get container-level limits. Dedicated per-VM resource isolation and true pre-login inference belong on the later native-Linux machine (or a conventional hypervisor on an edition that supports one).

Docker Desktop's Windows GPU path supports NVIDIA rather than this AMD GPU. The AMD GPU path therefore uses a dedicated Ubuntu WSL distribution with AMD's ROCm-for-WSL stack, not the existing Docker Desktop GPU runtime.

## Project status

The framework is delivered in preparation mode. Creating or statically validating the project does not install Tailscale, enable SSH, change the firewall, install Ubuntu, modify graphics memory, or reboot the host. `Smoke` deliberately runs one isolated, auto-removed container from an already cached project image; no EnvoyNode container, network, or listener should remain afterward.

The host `Smoke` action validates isolation without touching existing containers. `ComputePreview` does not launch a distro or start Docker. Compute bootstrap and export explicitly reject elevated Windows sessions; direct export invocation also requires `-Apply`. After Ubuntu is deliberately created, `ComputeVerify` requires a live WSL2 registration, exact protected Windows state, an exact root-owned Linux marker, a locked non-system default user with no direct sudoers grant, disabled effective Windows-drive automount/interop, a real non-world-accessible Unix Docker socket, no Docker TCP endpoint, no host-network containers, and no non-loopback published bindings, including stopped containers that would expose ports after restart. Every Docker query is pinned to that distribution's local Unix socket so ambient Docker contexts cannot redirect validation. A journal alone can never authorize adoption of an unmarked distribution. WSL ownership follows the Windows account, so the SSH target and compute owner must match.

The availability contract is deliberately honest: Windows, Tailscale, and native OpenSSH can provide the always-reachable control plane; WSL compute starts on demand after SSH login. If inference itself must run before anyone signs in and survive Windows lifecycle quirks, migrate the same containers to the planned native-Linux node.

## Contributing and support

Read [CONTRIBUTING.md](CONTRIBUTING.md) before proposing a change. Security-sensitive reports belong in GitHub's private vulnerability-reporting flow described in [SECURITY.md](SECURITY.md), never in a public issue. The separately gated operator sequence is summarized in [docs/ACTIVATION_CHECKLIST.md](docs/ACTIVATION_CHECKLIST.md).

Git ignore prevents accidental commits, not cloud synchronization or folder-archive disclosure. Keep local JSON reports, compute state, keys, client proofs, exports, and generated recommendations out of shared/synced workspaces when host privacy requires it, and publish only the reviewed Git tree.
