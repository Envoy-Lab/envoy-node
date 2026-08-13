# Operator runbook

EnvoyNode is currently preparation only. Creating and validating this project does not install Tailscale or Ubuntu, enable OpenSSH or RustDesk, change Windows Firewall, or reboot the host. Keep the local console open through every future connectivity change.

## 0. Safe validation

These actions do not activate remote access or create the compute distribution:

```powershell
.\envoy.ps1 -Action Audit
.\envoy.ps1 -Action Plan
.\envoy.ps1 -Action Smoke
.\envoy.ps1 -Action Verify
.\envoy.ps1 -Action AccessPreview
.\envoy.ps1 -Action DesktopPreview
.\envoy.ps1 -Action ComputePreview
```

An untouched pre-activation host is expected to have `acceptanceReady=false` because Tailscale, SSH, desktop, and the dedicated Ubuntu distribution are intentionally off or cannot yet be conclusively inspected without elevation. The exact check counts can change as controls are added. Those failures are safety evidence, not a framework malfunction.

`Verify` is local desired-state evidence. It does not prove Internet reachability, the Tailscale admin-console policy, a real SSH or GUI session from another network, power continuity, or onsite recovery. Those require the second-laptop tests in this runbook.

`Smoke` is isolated but not purely read-only: it creates one uniquely named `--rm` container and writes its report. It uses only the validly signed Docker Desktop CLI at its fixed Program Files path, forces the local Windows named pipe, refuses an absent cached image, validates the cached EnvoyNode labels and pinned-base digest, resolves the immutable image ID, and runs that ID with `--pull=never`. It never follows `PATH`, an ambient Docker context, or a mutable tag at container start.

## 1. Create a local configuration

Copy the example; the local file is ignored by Git:

```powershell
Copy-Item .\config\node.example.json .\config\node.local.json
```

Review these choices:

- leave `access.overlay.install=false`; the field does not authorize installation and EnvoyNode never installs Tailscale;
- set `access.ssh.targetUser` to the intended local Windows account;
- add every approved client public-key path to `access.ssh.publicKeyFiles`;
- keep `access.overlay.hostKeyExpiry=keep-enabled` for the safer pilot, or choose `disable-for-unattended-host` only after reviewing the revocation tradeoff;
- leave desktop disabled until SSH has passed a current-boot second-laptop proof;
- set `compute.install=true` only when ready to create Ubuntu 24.04;
- leave GPU activation and graphics-memory changes off for the first pass.

Do not put a password, private key, Tailscale key, recovery key, or token in the JSON. Relative public-key paths resolve from the `config` directory; a project-local public key is normally `..\keys\primary-client.pub`. The configured key files form the complete allowlist.

The configuration is the authority for the SSH account. Any `-TargetUser` value shown below must match `access.ssh.targetUser` exactly (a blank configuration resolves to the current Windows account); the command-line argument cannot override it. Changing the account requires a fresh plan.

## 2. Fresh-plan rule

Every non-emergency framework mutation requires a newly generated and reviewed `reports\plan-latest.json` plus its 64-character review-consistency `planHash`. It is a plain SHA-256 consistency token, not a signature or a substitute for the mutator's live fail-closed checks. The artifact expires after one hour and is rejected when its bound configuration, key manifest, planner context, or derived safety findings/gates change.

The plan and mutator must run under the same identity and elevation context:

- Access and Desktop: an elevated PowerShell window opened by the same Windows account;
- Compute and Export: a normal, non-elevated PowerShell window owned by the configured SSH/WSL account.

Immediately before **each** mutating command, rerun this block in the required context:

```powershell
.\envoy.ps1 -Action Plan -Config .\config\node.local.json
$approvedPlanPath = (Resolve-Path .\reports\plan-latest.json).Path
Get-Content -LiteralPath $approvedPlanPath -Raw | Out-Host
$approvedPlanHash = [string]((Get-Content -LiteralPath $approvedPlanPath -Raw | ConvertFrom-Json).planHash)
```

Read every blocker, warning, step, timestamp, public-key manifest entry, and hash. Do not edit the artifact. The guard rejects planner SID/elevation drift and changes to a configured public-key file's resolved path, file hash, or SSH fingerprint. Generate a new plan if any input changes. Do not reuse an earlier plan for the next mutation, and do not copy a plan between elevated and non-elevated consoles. `AccessDisable` and `DesktopDisable` are the only plan-free emergency mutations.

## 3. Enroll one key per client

On each trusted client laptop, create a distinct passphrased Ed25519 key:

```powershell
ssh-keygen -t ed25519 -a 100 -f "$HOME\.ssh\envoy-node" -C "envoy-node-primary-client"
```

A supported FIDO2-backed key is stronger:

```powershell
ssh-keygen -t ed25519-sk -f "$HOME\.ssh\envoy-node-hardware" -C "envoy-node-hardware-key"
```

Transfer only the `.pub` file to the host through a trusted local method. Never copy a private key to the host or reuse one private key across laptops.

## 4. Install and establish Tailscale first

`AccessPrepare` requires an already installed, enrolled, trusted Tailscale client. EnvoyNode deliberately refuses to install it.

1. Download and install the official signed Tailscale Windows client interactively on the host and the official client for the second laptop's OS. On the Windows host, EnvoyNode requires the fixed Program Files CLI and the registered service executable to have valid Windows signatures and to reside in the correlated trusted installation. The CLI version and the running daemon version from `status --json` must match, and both must be 1.98.9 or newer.
2. Sign in with a personal identity protected by a passkey or MFA.
3. Enable device approval and approve only the expected devices.
4. Replace the new tailnet's default allow-all policy with the reviewed template in `config/tailscale-policy.example.hujson`. The template shows the defaults: substitute the configured `access.ssh.port` for TCP 22, and, only much later if RustDesk is enabled, substitute the configured `access.desktop.port` for TCP 21118.
   Add concrete positive and negative policy tests for the stable node and client identities in the Tailscale editor. Do not acknowledge the tailnet controls until those tests pass.
5. Enable unattended mode on the Windows host through the Tailscale tray UI.
6. Keep host node-key expiry enabled for the pilot and maintain more than 30 days remaining, or explicitly choose the documented non-expiring-host policy and accept manual revocation responsibility.
7. Do not enable Tailscale SSH, web client, remote management, exit-node use, subnet routes, Serve, Funnel, Tailscale Services forwarding, Taildrive shares, or Taildrop/Send Files.
8. Confirm every locally enumerable forwarding/sharing surface is empty:

   ```powershell
   tailscale serve status --json
   tailscale funnel status --json
   tailscale serve get-config --all
   tailscale drive list
   ```

   The first two results must contain no Serve or public Funnel mapping, the third must contain no Tailscale Services entry, and `drive list` must report zero Taildrive shares. EnvoyNode repeats these commands through the fixed signed CLI and also checks the matching running-daemon version. If either version is missing, mismatched, or below 1.98.9, or if any surface inspection is inconclusive or nonempty, stop, repair/restart the official installation or remove the persistent surface, and generate a new plan.
9. In the Tailscale admin console, disable Taildrop/Send Files. The framework cannot locally attest this admin-console control, so review it explicitly before acknowledging the tailnet controls.
10. Confirm there is no router forwarding, DMZ entry, or UPnP mapping for the configured SSH port, Windows RDP port 3389, or configured desktop port.

No Tailscale auth key is needed or stored for this interactive personal enrollment.

## 5. Prepare the Windows access layer

Preview the exact target:

```powershell
.\envoy.ps1 -Action AccessPreview `
  -Config .\config\node.local.json `
  -TargetUser <windows-user>
```

The cleaner long-term design uses a dedicated standard Windows account. For this pilot, the existing account makes its user-owned WSL distribution directly reachable, but an administrator-targeted SSH key is a full-control credential.

In an elevated window under that same account, run the fresh-plan block from section 2, review it, then:

```powershell
.\envoy.ps1 -Action AccessPrepare `
  -Config .\config\node.local.json `
  -TargetUser <windows-user> `
  -AcknowledgeAdministratorTarget `
  -ApprovedPlanHash $approvedPlanHash `
  -ApprovedPlanPath $approvedPlanPath `
  -Apply
```

Prepare journals machine/account ownership, installs only the Microsoft OpenSSH capability if needed, disables its broad installer firewall rule, installs exactly the configured public-key allowlist with protected ACLs, and leaves `sshd` stopped. It refuses a missing/untrusted Tailscale installation, an unknown existing key, or an unmanaged OpenSSH installation. The accepted service identity is exactly one `sshd` service running as LocalSystem whose entire expanded command is the fixed, validly signed `%WINDIR%\System32\OpenSSH\sshd.exe` path with no arguments. Whenever the service is running, its service PID must resolve to that same executable.

## 6. Enable overlay-only SSH

Keep the local console open. In the same elevated account context, generate and review another fresh plan, then:

```powershell
.\envoy.ps1 -Action AccessEnable `
  -Config .\config\node.local.json `
  -TargetUser <windows-user> `
  -AcknowledgeAdministratorTarget `
  -AcknowledgeTailnetControls `
  -ApprovedPlanHash $approvedPlanHash `
  -ApprovedPlanPath $approvedPlanPath `
  -Apply
```

The action fails closed unless the fixed Tailscale CLI and registered service executable are bound by path/hash, use valid Authenticode signatures from the same signer certificate, report matching parsed `major.minor.patch` releases at 1.98.9 or newer, and the service is online/automatic/unattended. Official-source provenance is still an operator responsibility. Explicitly inspected SSH/web-client/remote-config/exit/subnet preferences must be off, Serve/Funnel/Services configurations must be conclusively empty, and `tailscale drive list` must report zero Taildrive shares. Taildrop/Send Files remains the separate admin-console check above. The action resolves exactly one live adapter; validates the fixed signed, LocalSystem, no-argument `sshd` service identity, its matching live process, exact SSH configuration, and listener ownership; and creates exact IPv4/IPv6 rules for that adapter. Password authentication remains temporarily available until the signed second-client proof succeeds.

Record the printed Ed25519 host fingerprint and the printed 64-character **client proof challenge**.

## 7. Sign the second-client proof and harden SSH

Copy `scripts/New-EnvoyClientProof.ps1` to the second laptop. The client can be Windows, macOS, or Linux. It needs PowerShell plus modern OpenSSH tools discoverable on `PATH`: `ssh`, `ssh-keyscan`, and an `ssh-keygen` that supports `-Y sign`. Windows can use Windows PowerShell or PowerShell 7; macOS and Linux use PowerShell 7 (`pwsh`). Compare the host fingerprint with the value displayed locally, then answer the current challenge.

On Windows PowerShell or PowerShell 7:

```powershell
.\New-EnvoyClientProof.ps1 `
  -HostName <tailscale-100.x-address-or-magicdns> `
  -Port <configured-ssh-port> `
  -TargetUser <windows-user> `
  -IdentityFile "$HOME\.ssh\envoy-node" `
  -ExpectedHostKeyFingerprint "<fingerprint printed by AccessEnable>" `
  -Challenge "<64-character challenge printed by AccessEnable>" `
  -OutputPath .\envoy-client-proof.json
```

On macOS or Linux, first start PowerShell 7 with `pwsh`, then run the helper at the PowerShell prompt with POSIX paths:

```powershell
./New-EnvoyClientProof.ps1 `
  -HostName <tailscale-100.x-address-or-magicdns> `
  -Port <configured-ssh-port> `
  -TargetUser <windows-user> `
  -IdentityFile "$HOME/.ssh/envoy-node" `
  -ExpectedHostKeyFingerprint "<fingerprint printed by AccessEnable>" `
  -Challenge "<64-character challenge printed by AccessEnable>" `
  -OutputPath ./envoy-client-proof.json
```

The proof helper discovers the three OpenSSH applications without assuming Windows `.exe` names, pins the scanned Ed25519 host key, completes a public-key SSH session to the Windows host, verifies the remote identity/connection tuple and a fresh nonce, and signs a payload containing the host challenge with the approved client key. The host accepts it only when Windows also contains a matching OpenSSH `Accepted publickey` event for the same user, Tailscale source address, key fingerprint, and proof window. Bring back only the generated JSON; never copy the private key.

Bring the JSON back to the host without editing it. Within 30 minutes, generate and review a fresh elevated plan, then:

```powershell
.\envoy.ps1 -Action AccessHarden `
  -Config .\config\node.local.json `
  -TargetUser <windows-user> `
  -ClientProofPath C:\secure\envoy-client-proof.json `
  -AcknowledgeAdministratorTarget `
  -ApprovedPlanHash $approvedPlanHash `
  -ApprovedPlanPath $approvedPlanPath `
  -Apply
```

Before removing password authentication, `AccessHarden` repeats the exact firewall/profile, Windows port-proxy, Tailscale surface, SSH listener/rule ownership, and global public-exposure checks. Any drift aborts the transition. Test a new key-only session, then record the new 64-character **post-reboot proof challenge** printed by `AccessHarden`.

With local recovery available, reboot deliberately. After Windows returns, use that post-reboot challenge to make another proof with the same platform-specific helper form above (the Windows form is shown here):

```powershell
.\New-EnvoyClientProof.ps1 `
  -HostName <tailnet-host> `
  -Port <configured-ssh-port> `
  -TargetUser <windows-user> `
  -IdentityFile "$HOME\.ssh\envoy-node" `
  -ExpectedHostKeyFingerprint "<verified host fingerprint>" `
  -Challenge "<post-reboot challenge printed by AccessHarden>" `
  -OutputPath .\envoy-client-proof-after-reboot.json
```

Bring it to the host, generate and review a fresh elevated plan, then:

```powershell
.\envoy.ps1 -Action AccessAcceptRebootProof `
  -Config .\config\node.local.json `
  -TargetUser <windows-user> `
  -ClientProofPath C:\secure\envoy-client-proof-after-reboot.json `
  -AcknowledgeAdministratorTarget `
  -ApprovedPlanHash $approvedPlanHash `
  -ApprovedPlanPath $approvedPlanPath `
  -Apply
```

This action never reboots the host. Before recording proof, it repeats the exact firewall/profile, Windows port-proxy, Tailscale surface, SSH listener/rule ownership, and global public-exposure checks. It records proof only for the current boot and prints the challenge for the next reboot. After every later reboot or access-layer change, repeat the second-client proof and `AccessAcceptRebootProof` sequence before treating local readiness evidence as current.

## 8. Connect and reach loopback services

Use the Tailscale name or private 100.x address:

```powershell
ssh -p <configured-ssh-port> -i "$HOME\.ssh\envoy-node" <windows-user>@<tailnet-host>
```

Enter the dedicated compute shell when it exists:

```powershell
wsl.exe -d Ubuntu-24.04
```

Tunnel only an allowlisted loopback service:

```powershell
ssh -p <configured-ssh-port> -N -L 11434:127.0.0.1:11434 -i "$HOME\.ssh\envoy-node" <windows-user>@<tailnet-host>
```

Never disable host-key checking.

## 9. Optional Windows Home desktop

Do this only after `AccessAcceptRebootProof` has succeeded for the current boot. Set `access.desktop.enabled=true` and add the configured `access.desktop.port` (TCP 21118 by default) to the tailnet policy only for approved clients.

RustDesk must be configured completely in a fail-closed offline quarantine. Every item below is required before either acknowledgment switch is truthful:

1. While still connected, choose a stable RustDesk Windows release whose exact version, SHA-256, signer, `--service`/`--server` process topology, and direct-IP settings have been validated with this EnvoyNode revision. Download it only from RustDesk's official release source and do not launch it. Do not auto-upgrade; repeat the offline validation for every later version.
2. Disconnect Wi-Fi and Ethernet, including any dock or USB network adapter. Confirm the machine has no network path.
3. Install RustDesk offline in its default native `Program Files\RustDesk` directory. EnvoyNode refuses a portable, per-user, reparse-backed, or untrusted-writable installation. In its GUI, enable direct-IP access, set its direct-access TCP port to the configured `access.desktop.port`, set one long unique permanent password, and set IP Whitelisting to `100.64.0.0/10,fd7a:115c:a1e0::/48` or the smaller exact approved client tailnet IP set.
4. Disable LAN discovery, remote configuration, public-ID/rendezvous use, file transfer, clipboard transfer if unnecessary, audio, camera, TCP tunneling, and hole punching. Disable every other unattended permission that is not explicitly required. Leave proxy, ID server, relay server, API server, and key fields empty.
5. Exit every RustDesk GUI process. In the Windows Services app, stop the RustDesk service and set its startup type to Disabled.
6. Reconnect networking, but do not reopen RustDesk and do not start its service.

Preview it:

```powershell
.\envoy.ps1 -Action DesktopPreview -Config .\config\node.local.json
```

In an elevated window under the same account, generate and review a fresh plan, then:

```powershell
.\envoy.ps1 -Action DesktopEnable `
  -Config .\config\node.local.json `
  -AcknowledgeRustDeskConfigured `
  -AcknowledgeRustDeskTailnetWhitelist `
  -ApprovedPlanHash $approvedPlanHash `
  -ApprovedPlanPath $approvedPlanPath `
  -Apply
```

The two RustDesk acknowledgments are operator attestations of the GUI settings; EnvoyNode does not claim to parse every version-specific private setting. Before starting RustDesk, the adapter proves the native Program Files tree is non-reparse and not writable by untrusted accounts, requires the signed executable and exact quoted `--service` registration under LocalSystem or LocalService, conclusively inspects all Windows Firewall profiles, rejects authenticated outbound allow-bypass rules and unrelated conflicting allow/block rules, and installs exact program-specific public-egress blocks plus Tailscale-adapter-only inbound rules. After starting it, the adapter proves the matching live service root and exact `--server` child, attributes exactly one RustDesk TCP listener to that child, and rejects UDP on the managed port or another RustDesk TCP listener. Once an authorized managed lifecycle has authenticated its scope/state and begun closure or activation, later activation, reboot-proof, or disable errors independently attempt to stop/startup-disable the service, disable managed ingress, and prove that no TCP/UDP endpoint remains on the configured port and any safely recovered prior protected port. It writes a failure journal only when the privileged state path is already exact and non-reparse. Rejected caller, plan, acknowledgment, scope, or unmanaged-state checks intentionally do not alter any pre-existing RustDesk service. If a promised closure cannot be proved conclusively—or the state path is unsafe—it requires local-console investigation and refuses to report success; do not assume fail-close from attempted commands alone.

From the second laptop, connect to the host's Tailscale 100.x address, not its public RustDesk ID, and prove a real GUI session. Reboot deliberately. Renew the SSH proof from section 7 first, then prove another real GUI session after that reboot.

Generate and review a fresh elevated plan, then record both explicit acknowledgments:

```powershell
.\envoy.ps1 -Action DesktopAcceptRebootProof `
  -Config .\config\node.local.json `
  -AcknowledgeRustDeskTailnetWhitelist `
  -AcknowledgeRustDeskPostRebootClientTest `
  -ApprovedPlanHash $approvedPlanHash `
  -ApprovedPlanPath $approvedPlanPath `
  -Apply
```

Every later reboot invalidates both current-boot proofs. Renew SSH first, perform another second-laptop GUI test, generate a fresh elevated plan, and run `DesktopAcceptRebootProof` again. Do **not** rerun `DesktopEnable` merely to renew desktop proof.

RustDesk may call this direct connection "unencrypted" because it cannot see Tailscale's outer WireGuard encryption; verify that the destination is the private Tailscale address.

## 10. Create the Ubuntu 24.04 compute shell

Keep GPU activation off. Preview:

```powershell
.\envoy.ps1 -Action ComputePreview -Config .\config\node.local.json
```

Preview inventories WSL and protected local state only. It does not launch the Ubuntu distribution, start Docker, or rewrite the recommendation file.

Open a **normal, non-elevated** PowerShell window as the exact Windows account configured for SSH and WSL ownership. Generate and review a fresh plan in that same window, then:

```powershell
.\envoy.ps1 -Action ComputeBootstrap `
  -Config .\config\node.local.json `
  -AcknowledgeCurrentBootAccessProof `
  -ApprovedPlanHash $approvedPlanHash `
  -ApprovedPlanPath $approvedPlanPath `
  -Apply
```

Do not use alternate administrator credentials or an elevated plan. The bootstrap script explicitly rejects an elevated process. Pass `-AcknowledgeCurrentBootAccessProof` only after `AccessAcceptRebootProof` has accepted the second-laptop key-only proof for this Windows boot; this is an operator attestation because the protected elevated access journal is intentionally not readable by a standard non-elevated compute owner. WSL distributions are per-user. Bootstrap refuses an existing unmarked distribution, never touches `docker-desktop`, disables Windows-drive automount and Windows executable interop in this distribution, and does not apply global `.wslconfig`, install ROCm, alter graphics memory, install a Windows driver, or reboot.

On a rerun, bootstrap checks the dedicated local Docker socket before both a distribution restart and any package/service transaction. Active compute containers block either operation unless they are stopped cleanly or the operator deliberately adds `-AcknowledgeWorkloadInterruption` to the fresh reviewed apply.

If a managed rerun would interrupt running compute containers, first review that impact and add `-AcknowledgeWorkloadInterruption` to the new approved command. The script never unregisters a distribution.

Verify the dedicated WSL engine:

```powershell
.\envoy.ps1 -Action ComputeVerify -Config .\config\node.local.json
```

`ComputeVerify` is the deliberate live proof: if the distribution is stopped, it starts it and runs one pinned, isolated `--rm` smoke container. The broader `Verify` action does neither. It leaves stopped on-demand compute stopped but still fails closed on missing/drifted protected state, machine/owner/version-2 registration binding, or inconclusive WSL running-state inventory; only the live Linux marker/Docker proof is warning-skipped. If compute is already running, `Verify` performs read-only posture checks and skips the transient smoke.

This is distinct from the existing Docker Desktop engine.

## 11. GPU activation

Follow `GPU_AMD.md` in a separate approved change window. The validated AMD Windows driver, WSL, Ubuntu, ROCm, ROCDXG, and framework combination, plus any Windows driver change, deliberate reboot, or optional graphics-memory reallocation, require their own acceptance proof. Do not use NVIDIA CUDA instructions or assume Docker Desktop supplies AMD GPU compute on Windows.

## 12. Export and later native-Ubuntu migration

For a recovery snapshot, use a normal, non-elevated window under the same WSL-owning account. Stop application writers and compute containers first, then generate and review a fresh plan there:

```powershell
.\envoy.ps1 -Action ExportCompute `
  -Config .\config\node.local.json `
  -Destination D:\Backups\Ubuntu-24.04-YYYYMMDD.tar `
  -AcknowledgeWorkloadInterruption `
  -ApprovedPlanHash $approvedPlanHash `
  -ApprovedPlanPath $approvedPlanPath `
  -Apply
```

Export refuses elevation and requires `-Apply` even when its underlying script is invoked directly. It also refuses a running compute container by default. If stopping it is impossible and you deliberately accept a crash-consistent, not application-consistent, snapshot, add `-AcknowledgeActiveComputeContainers`; the manifest records that exception and the active container IDs. The WSL export is for recovery, not a bare-metal operating system. The later dedicated host should run native Ubuntu with native OpenSSH, Tailscale, the hardware's native GPU stack, and the same pinned containers, manifests, and restored application data.

## 13. Real-world 24/7 test

Do not call the pilot unattended-ready until the operator has proven:

- fresh SSH and optional desktop sessions from the second laptop over a phone hotspot;
- current-boot SSH and desktop proof renewal after a deliberate reboot;
- sign-out and Windows Update recovery;
- compute start/stop behavior;
- plugged-in sleep set to Never and an intentional, safely cooled lid-on-AC posture;
- verified Device Encryption/BitLocker recovery material from another device;
- tested data backup and WSL recovery export;
- acceptable thermals under a multi-hour inference load;
- router/modem/charger power behavior and an onsite fallback.

Finish with an elevated local report:

```powershell
.\envoy.ps1 -Action Verify -Config .\config\node.local.json
```

A passing report means the locally inspectable gates passed at that moment. It does not establish end-to-end reachability, and a reboot invalidates the current-boot proofs.

## Emergency stop

These are deliberately plan-free so a trusted local operator can close managed ingress. Run elevated from the local console:

```powershell
.\envoy.ps1 -Action DesktopDisable -Config .\config\node.local.json -Apply
.\envoy.ps1 -Action AccessDisable -Config .\config\node.local.json -Apply
```

Desktop disable closes managed GUI ingress, stops/startup-disables RustDesk, and preserves existing managed public-egress blocks. Access disable closes managed SSH ingress and stops/startup-disables `sshd`. Both preserve software, keys, backups, and Tailscale enrollment for diagnosis.
