# Architecture and decisions

## Outcome

EnvoyNode separates remote control, compute, GPU enablement, and desktop control so each can be added or removed independently.

```text
                    MFA + device approval
trusted client  -------------------------------+
                                                    |
                                                    v
Internet (no inbound router ports) -> Tailscale private WireGuard network
                                                    |
                         +--------------------------+
                         v
Windows 11 Home host
  - Windows Firewall: managed ports on Tailscale adapter only
  - Windows OpenSSH: host control, file transfer, SSH tunnels
  - RustDesk direct-IP: optional GUI adapter with a tailnet IP whitelist and public-egress block
  - Windows power/update/encryption/GPU driver control
                         |
                         v
Dedicated Ubuntu 24.04 WSL2 compute shell
  - systemd
  - container engine addressed explicitly through wsl.exe
  - projects, models, and state on the Linux ext4 filesystem
                         |
                         v
Containerized services
  - loopback-only published APIs
  - CPU base profile
  - AMD ROCm-for-WSL adapter after acceptance testing
```

## Why this shape

### Private overlay instead of public ports

Tailscale supplies authenticated, end-to-end encrypted private reachability through NAT. SSH still performs its own key authentication. There is no reason for this single-user node to accept Internet-wide connections on port 22, 3389, or 21118.

Tailscale's Personal plan is currently free for non-commercial personal use. Its data-plane components are open source, while its managed coordination plane and Windows GUI are not fully open source. Headscale can replace the coordination plane later, but doing so adds a public control service, TLS/DNS, upgrades, monitoring, backup, and recovery work. It is an adapter, not phase one.

The official signed Windows client is installed and enrolled interactively before `AccessPrepare`; EnvoyNode never performs that installation. Official-source provenance is an operator attestation. The framework does not trust a `tailscale.exe` found on `PATH`: it binds the fixed Program Files CLI and registered service paths and hashes, requires both Authenticode signatures to be valid and use the same signer certificate, and requires their parsed `major.minor.patch` releases to match at 1.98.9 or newer. That security floor incorporates the relevant Serve/Funnel request-handling and Services-isolation fixes. Activation reads only the explicitly supported local preferences and requires Windows unattended mode while refusing Tailscale SSH, the web client, remote configuration, exit-node selection, and advertised subnet routes. It separately requires conclusive, empty status for persistent Serve, public Funnel, and Tailscale Services configurations and zero Taildrive shares. Services are inspected with `tailscale serve get-config --all`; Taildrive is inspected with `tailscale drive list`. Taildrop/Send Files must remain disabled in the admin console, but that control is not locally attestable. MFA, device approval, concrete tailnet policy tests, and Taildrop state remain operator/admin-console attestations.

Tailscale node keys expire by default. EnvoyNode keeps expiry enabled for the safer pilot, requires at least 30 days remaining, and records the exact live state. A future dedicated 24/7 host can explicitly select disabled expiry to avoid reauthentication outages; that is an availability choice with weaker automatic credential rotation, not a hidden default.

### Native Windows SSH instead of Tailscale SSH

Tailscale SSH cannot act as a server on Windows. EnvoyNode therefore uses Microsoft's OpenSSH Server through the tailnet. It accepts exactly one `sshd` service running as LocalSystem whose complete expanded command is the validly signed fixed Windows OpenSSH binary with no alternate configuration or arguments. When running, the service PID must resolve to that same executable, and the expected listener must be owned by that PID with no unexpected UDP or extra SSH port. Firewall rules are scoped to the actual adapter resolved from the active Tailscale IP; the SSH daemon is not bound to a boot-time Tailscale address. The second-client proof helper is client-OS neutral: Windows, macOS, or Linux can run it with PowerShell and modern OpenSSH tools supporting `ssh-keygen -Y sign`.

### RustDesk instead of RDP on this pilot

Windows Home can connect to an RDP host but cannot be an RDP host. RustDesk's direct-IP mode can use the private Tailscale address without a self-hosted server. Because a stock RustDesk client can contact public rendezvous servers as soon as it starts, the installer is downloaded first and installation/configuration occurs while Wi-Fi and Ethernet are disconnected. Official-source provenance and the reviewed version/hash/signer are operator records; the plan binds the default protected executable's path, hash, signer, and version. The operator must install it below the native `Program Files\RustDesk` directory and complete the private GUI posture: direct-IP only on the configured port, tailnet-only IP whitelist, unique permanent password, LAN discovery and remote configuration off, unused permissions and public rendezvous features off, and proxy/ID/relay/API/key fields empty. Those version-specific GUI settings are explicitly acknowledged by the operator rather than claimed as fully machine-parsed. The operator then exits the GUI and stops/startup-disables the service before reconnecting. Before start, `DesktopEnable` rejects a reparse-backed or untrusted-writable Program Files installation tree, requires the signed executable and exact quoted `--service` registration under the built-in LocalSystem or LocalService identity, scans for authenticated outbound allow-bypass rules and conflicting RustDesk firewall rules, installs exact program-specific public-egress blocks, and rejects incomplete or conflicting inspection. After start, it proves the matching live service root and exact `--server` child, attributes the one managed TCP listener to that child, and rejects a managed-port UDP endpoint or any other RustDesk TCP listener. Once an authorized managed lifecycle has authenticated its scope/state and begun closure or activation, later activation, reboot-proof, and disable failures attempt independent closure and prove the service stopped/startup-disabled, managed ingress disabled, and no endpoint on both the current configured port and any safely read prior protected port. A failure journal is written only through an already exact, non-reparse privileged state path. Rejected caller, plan, acknowledgment, scope, or unmanaged-state checks deliberately leave any pre-existing RustDesk service untouched. If a promised closure proof is inconclusive, the result requires local-console investigation and is never labeled successfully fail-closed.

SSH hardening and post-reboot proof acceptance each repeat the exact managed-firewall, Windows port-proxy, Tailscale surface, listener ownership, and global public-exposure gates before recording success. After desktop enablement, the operator must prove a real second-laptop GUI session, reboot, prove the GUI again, and accept the current-boot desktop proof. Every later reboot invalidates that proof; renewal uses `DesktopAcceptRebootProof`, not another enable operation.

### WSL2 instead of a full VM

The full Hyper-V role is not supported on Windows Home. WSL2 provides a Linux kernel and the supported Windows GPU path with less overhead. It is a software and packaging boundary, not a hostile-code security boundary from Windows.

All WSL2 distributions share one managed VM resource envelope. `.wslconfig` is global for the Windows user and also affects Docker Desktop, so EnvoyNode only generates a suggested file. It never applies that file or shuts down all WSL workloads automatically.

Distribution registration is also per Windows user. The SSH target and WSL owner must therefore be the same account for direct `wsl.exe` access. A dedicated standard account remains possible, but its Ubuntu distribution must be registered and bootstrapped from that account's Windows session.

The machine fingerprint hashes the Windows MachineGuid. Access state separately records the target account SID, and compute state plus the Linux marker separately record the WSL-owning account SID. Desktop state is machine-bound and stored with protected privileged ACLs; it is not account-SID-bound. These bindings keep copied state from adopting a local service or distribution merely because its name matches.

### Containers as the migration unit

A WSL export is useful for Windows-to-Windows recovery, but it is not a bootable bare-metal deployment. The portable unit is:

- source and Compose files;
- pinned image digests and model manifests;
- configuration without secrets;
- application-consistent data backups;
- an acceptance test suite.

Moving to the dedicated machine means installing supported Linux and its native GPU driver, restoring state, and using the same container definitions with a native-Linux GPU override.

### Fixed local host smoke path

The Windows host `Smoke` action is deliberately separate from the dedicated WSL engine. It does not trust a Docker command found on `PATH` or the caller's active context. It requires the fixed Docker Desktop CLI under Program Files to have a valid Windows signature, forces `npipe:////./pipe/docker_engine`, and refuses an absent cached image. It validates the cached tag's EnvoyNode ownership/component labels and pinned-base digest, resolves the immutable image ID, and runs that ID with `--pull=never`, no network, read-only root, dropped capabilities, explicit limits, a unique name, and `--rm`. The preceding image build is a separate deliberate operation that can access the network.

### Reviewed plans as a mutation boundary

Every non-emergency framework mutation consumes an unmodified, time-bounded plan artifact and its 64-character hash. The guard validates the artifact hash, expiry, configuration hash, Windows installation, planner SID/elevation, a manifest containing each resolved public-key file hash and SSH fingerprint, and recomputed observable plan state. The plan must therefore run in the same context as the mutator: elevated as the same account for Access/Desktop, and non-elevated as the same WSL-owning account for Compute/Export. `AccessDisable` and `DesktopDisable` remain plan-free so a trusted local operator can close managed ingress during an emergency.

## Trust boundaries

| Boundary | What it protects | What it does not protect |
|---|---|---|
| Tailscale identity/device approval | Reachability from unenrolled devices | A compromised already-approved laptop |
| SSH key and passphrase | Windows shell authentication | Malware on an unlocked client or host |
| Windows Firewall adapter scope | Accidental LAN/public exposure | A bad tailnet access policy |
| WSL distribution | Dependency and filesystem separation | Windows administrators or hostile kernel-level code |
| Container restrictions | Accidental service privilege and blast radius | A perfect sandbox for untrusted code |
| Disk encryption | Offline theft of powered-off storage | Data visible after normal unattended boot/login |

"Any laptop" therefore means any trusted laptop that is patched, disk-encrypted, enrolled, approved, and given its own revocable SSH key. It does not mean an arbitrary borrowed or compromised computer.

## Availability truths

- No software can recover from a power, router, ISP, firmware, thermal, battery, or hardware failure without another path onsite.
- WSL is a pilot runtime, not a true pre-login appliance. Windows remains the availability dependency.
- Strict acceptance is bound to a fresh key-only proof from the second laptop after the current Windows boot. A later reboot requires a new proof before the framework again reports ready.
- `Verify` is local desired-state evidence, not proof of Internet reachability or a real SSH/GUI path. Another-network client tests remain mandatory.
- With Tailscale node-key expiry enabled, reauthentication is a planned maintenance event. Disabling it avoids that outage but makes prompt manual revocation more important.
- The laptop battery is a short UPS for the computer, not for the router and modem.
- Maximum physical security and unattended reboot conflict: a TPM-only disk unlock permits unattended boot; a pre-boot PIN requires someone present.

## Primary references

- [Microsoft: Install WSL](https://learn.microsoft.com/en-us/windows/wsl/install)
- [Microsoft: WSL configuration](https://learn.microsoft.com/en-us/windows/wsl/wsl-config)
- [Microsoft: systemd in WSL](https://learn.microsoft.com/en-us/windows/wsl/systemd)
- [Microsoft: Windows OpenSSH](https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh_install_firstuse)
- [Microsoft: Windows OpenSSH server configuration](https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh-server-configuration)
- [Microsoft: RDP host editions and NLA](https://learn.microsoft.com/en-us/windows-server/remote/remote-desktop-services/remotepc/remote-desktop-allow-access)
- [Tailscale: Windows unattended mode](https://tailscale.com/docs/how-to/run-unattended)
- [Tailscale: security bulletins](https://tailscale.com/security-bulletins)
- [Tailscale: changelog](https://tailscale.com/changelog)
- [Tailscale: pricing](https://tailscale.com/pricing)
- [Tailscale: device approval](https://tailscale.com/docs/features/access-control/device-management/device-approval)
- [Tailscale: node-key expiry](https://tailscale.com/docs/features/access-control/key-expiry)
- [Tailscale: Serve CLI and Services configuration](https://tailscale.com/docs/reference/tailscale-cli/serve)
- [Tailscale: CLI reference, including `drive list`](https://tailscale.com/docs/reference/tailscale-cli)
- [Tailscale: Funnel](https://tailscale.com/docs/features/tailscale-funnel)
- [Tailscale: Taildrive](https://tailscale.com/docs/features/taildrive)
- [Tailscale: Taildrop](https://tailscale.com/docs/features/taildrop)
- [Tailscale: RustDesk direct-IP](https://tailscale.com/docs/solutions/access-remote-desktops-with-rustdesk)
- [AMD: ROCm WSL guide for Ryzen and ROCDXG](https://rocm.docs.amd.com/projects/radeon-ryzen/en/latest/docs/install/installryz/wsl/howto_wsl.html)
- [Docker: Windows GPU support](https://docs.docker.com/desktop/features/gpu/)
