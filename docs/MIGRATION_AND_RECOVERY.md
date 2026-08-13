# Migration and recovery

## Backup layers

1. **Git/source:** scripts, Compose files, tests, configuration schema, and version locks.
2. **Secrets:** a password manager or encrypted removable storage, never Git or reports.
3. **Models and images:** source, license, version, and digest manifests; re-download reproducible caches when practical.
4. **Stateful application data:** application-consistent database dumps and volume backups.
5. **Whole WSL recovery:** a cold WSL export plus SHA-256 manifest.

Disk encryption is not a backup.

## WSL recovery snapshot

The framework requires explicit acknowledgment because export may stop the selected distribution. Stop application writers and compute containers first. In a normal, non-elevated PowerShell window under the same WSL-owning account, generate and review a fresh plan immediately before export:

```powershell
.\envoy.ps1 -Action Plan -Config .\config\node.local.json
$approvedPlanPath = (Resolve-Path .\reports\plan-latest.json).Path
Get-Content -LiteralPath $approvedPlanPath -Raw | Out-Host
$approvedPlanHash = [string]((Get-Content -LiteralPath $approvedPlanPath -Raw | ConvertFrom-Json).planHash)
```

Then use that unmodified artifact and hash:

```powershell
.\envoy.ps1 -Action ExportCompute `
  -Config .\config\node.local.json `
  -Destination D:\Backups\Ubuntu-24.04-YYYYMMDD.tar `
  -AcknowledgeWorkloadInterruption `
  -ApprovedPlanHash $approvedPlanHash `
  -ApprovedPlanPath $approvedPlanPath `
  -Apply
```

Export refuses active compute containers by default. If no application-consistent stop is possible and you intentionally accept a filesystem/crash-consistent recovery artifact, add `-AcknowledgeActiveComputeContainers`; the manifest records the exception and container IDs. Export also requires exact protected project state and a matching live WSL2 registration. When the distribution is already running, it additionally validates the exact root-owned Linux marker. Copying a state JSON file cannot authorize termination of a same-named distribution on another machine.

Test restoration under a new name and new location. Never overwrite or unregister the original during a restore test:

```powershell
wsl.exe --import EnvoyRecoveryTest D:\WSL\EnvoyRecoveryTest D:\Backups\Ubuntu-24.04-YYYYMMDD.tar --version 2
wsl.exe -d EnvoyRecoveryTest -u root -- test -f /etc/envoynode/managed.json
```

After testing, removal of the test distribution is intentionally manual because `wsl --unregister` permanently deletes it.

## Bare-metal migration

Do not install the WSL export as the dedicated machine's operating system. Instead:

1. Inventory and stop application writers.
2. Export application-consistent state and a migration manifest.
3. Install a supported Ubuntu release on the dedicated system.
4. Enable disk encryption, Secure Boot where supported, automatic security updates, an official signed Tailscale installation, and native OpenSSH. Reapply the 1.98.9-or-newer floor to both the CLI and running daemon, require their versions to match, restore the same empty Serve/Funnel/Services/Taildrive posture, and keep Taildrop/Send Files disabled in the admin console.
5. Install the hardware's native GPU stack: `/dev/kfd` and `/dev/dri` for supported AMD hardware, or NVIDIA Container Toolkit for NVIDIA hardware.
6. Install Docker Engine or another reviewed OCI runtime.
7. Clone EnvoyNode and select the native-Linux GPU adapter.
8. Pull images by digest, restore only stateful data, and re-download model caches where practical.
9. Run the same network, identity, container, GPU, model, thermal, reboot, and backup acceptance tests.
10. Keep the laptop node intact until the dedicated node has passed a real failover drill.

## Access recovery order

If remote access fails, diagnose from the local console in this order:

1. Power, AC state, sleep/lid state, router, and Internet.
2. Windows sign-in and pending update/reboot.
3. Tailscale fixed CLI and registered-service path/signatures, matching CLI/running-daemon versions at or above 1.98.9, unattended mode, node approval/expiry, tailnet policy, empty Serve/Funnel/Services state, zero `drive list` shares, and the admin-console Taildrop/Send Files setting.
4. EnvoyNode firewall rules, Windows port-proxy state, global public-exposure checks, and unexpected competing VPN adapters.
5. The single LocalSystem `sshd` service's fixed signed no-argument command, matching live process path/PID listener ownership, `sshd.exe -t`, key-file ACLs, and Event Viewer/OpenSSH logs.
6. WSL distribution state.
7. Container health and loopback binding.
8. ROCm device and real tensor proof.

Use `AccessDisable` locally if the safest response is to close managed ingress while preserving evidence.

After any reboot or access-layer update, sign the host's current 64-character challenge from the second laptop and accept the matching host-observed SSH proof. The helper can run on Windows, macOS, or Linux when PowerShell and modern OpenSSH (`ssh`, `ssh-keyscan`, and `ssh-keygen -Y sign`) are installed. Proof acceptance repeats exact service identity, firewall ownership, and global public-exposure checks and rejects drift. If RustDesk is enabled, then perform a real post-reboot GUI test and run `DesktopAcceptRebootProof` with both acknowledgments and a fresh elevated plan. Renew proof with that action; do not rerun `DesktopEnable`.

## Revocation

- Lost client: revoke it in Tailscale immediately and remove only that client's public key line by fingerprint.
- Suspected SSH key leak: add and prove the replacement key before removing the old key.
- Lost host: revoke the Tailscale node, rotate every client credential it could access, and use the disk recovery inventory.
- Compromised identity provider: recover the IdP first, revoke tailnet sessions/devices, then rotate SSH and desktop credentials.
- RustDesk password leak: disable the owned desktop firewall rule first, then rotate the password locally.

## Storage guardrails

Choose cache budgets and low-space stop thresholds from the current private audit, expected model growth, recovery-export size, and the space needed by existing workloads. Keep a substantial safety margin instead of copying fixed numbers from another host. Dynamic WSL virtual disks may not shrink merely because files were deleted.

Primary Microsoft reference: [WSL export/import commands](https://learn.microsoft.com/en-us/windows/wsl/basic-commands).
