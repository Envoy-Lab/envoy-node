# Security model

## Protected against

- routine Internet scanning and password brute force;
- accidental exposure on home, hotel, or cafe networks;
- coarse key revocation caused by sharing one private key across clients;
- broad default Windows firewall rules;
- accidental operation on unrelated Docker workloads;
- common lockout mistakes during SSH hardening;
- silently treating Windows Home as an RDP server;
- silently changing global WSL, disk encryption, GPU memory, or reboot state.

## Required controls

- supported, fully patched Windows 11;
- Tailscale identity with passkey/MFA and device approval;
- explicit least-privilege tailnet policy with concrete positive and negative tests, not the initial allow-all default;
- one passphrased Ed25519 or hardware-backed key per client;
- pinned SSH host fingerprint;
- tailnet-only Windows Firewall rules, plus RustDesk public-egress blocks when the GUI adapter is enabled;
- no router/UPnP forwarding; a fixed signed Tailscale CLI correlated with the signed registered service executable; bound path/hash/signer continuity and matching parsed `major.minor.patch` releases at or above 1.98.9; conclusively empty persistent Serve, public Funnel, and Tailscale Services configurations; zero Taildrive shares; and Taildrop/Send Files disabled in the admin console;
- exactly one Windows `sshd` service running as LocalSystem with the fixed signed Windows OpenSSH binary as its complete no-argument command, plus matching live process and listener ownership whenever it is running;
- Windows Defender, Firewall, UAC, Secure Boot, and Device Encryption/BitLocker left on;
- no auto-login and a locked local screen;
- versioned backups and offline recovery material;
- separate proof before SSH password removal;
- exact firewall ownership, port-proxy, Tailscale surface, listener, and global public-exposure checks repeated during SSH hardening and current-boot proof acceptance;
- a second fresh key-only proof after the current Windows boot before unattended acceptance;
- a client signature over a host-issued one-time challenge plus pinned host-key, remote identity/connection/nonce evidence, and a matching host OpenSSH public-key acceptance event; the helper works from Windows, macOS, or Linux with PowerShell and modern OpenSSH;
- an unmodified, machine-bound, one-hour reviewed plan before every non-emergency framework mutation, generated under the same Windows identity and elevation context as the mutator;
- complete RustDesk private configuration performed network-disconnected: direct-IP only, tailnet whitelist, unique permanent password, LAN discovery/remote configuration and unused permissions off, public rendezvous features off, and proxy/ID/relay/API/key fields empty; the GUI is exited and the service stopped/startup-disabled before reconnecting;
- RustDesk installed only in a non-reparse, untrusted-nonwritable native Program Files tree, with a signed executable, exact quoted `--service` registration under LocalSystem or LocalService, matching live root and exact `--server` child, exactly one child-owned managed TCP listener, and no managed-port UDP endpoint;
- conclusive RustDesk failure closure: managed ingress disabled, service stopped/startup-disabled, and no TCP/UDP endpoint on the current or safely recovered prior managed port; an inconclusive closure is a local-console-required failure, never a successful fail-close claim, and an unsafe privileged state path is never used for an elevated failure-journal write;
- host `Smoke` execution through only the fixed signed Docker Desktop CLI and local Windows named pipe, using a validated cached image resolved to its immutable ID and run with `--pull=never`;
- a real second-laptop desktop test after enablement and again after each reboot, followed by a current-boot desktop proof;
- an explicit Tailscale host-key expiry policy, with a 30-day minimum remaining window when rotation stays enabled;
- an exact configured public-key allowlist with protected ACLs and refusal of unknown existing keys;
- machine/account-bound lifecycle state and WSL ownership markers;
- stable, reviewed versions for the GPU and model stack.

## Secrets never stored here

- SSH private keys;
- Tailscale auth/API keys;
- Windows, Linux, or RustDesk passwords;
- BitLocker/Device Encryption recovery keys;
- identity-provider recovery codes;
- API tokens or model-service credentials.

The ignored `keys/` directory is for temporary public `.pub` files only.

## Residual risks

- The local Windows host, operator, and project source are trusted. EnvoyNode scripts are user-writable and are not code-signed or application-allowlisted; this framework is not an EDR or application-control boundary against a compromised local account that substitutes code or launches another tunneling tool before elevation.
- An unlocked, malware-infected, or hostile client can capture everything typed or displayed.
- An administrator-targeted SSH key is a full-control credential. Windows administrators normally share `C:\ProgramData\ssh\administrators_authorized_keys`; EnvoyNode therefore refuses any line outside the reviewed allowlist and also restricts `AllowUsers` to the planned account. A dedicated standard account is still the cleaner final design.
- A compromised approved Tailscale node remains dangerous until revoked.
- Tailscale and the identity provider are managed control-plane dependencies.
- RustDesk adds a standing password and unattended desktop service. Its version-specific GUI settings remain operator-attested rather than fully machine-parsed, so the firewall/service/listener fail-close proof is a separate control.
- WSL and containers are not safe sandboxes for malicious code against a Windows administrator.
- Current Tailscale preference verification uses the fixed signed CLI's diagnostic preference output and fails closed if required fields disappear. It also fails if the signed CLI and signed registered service cannot be correlated, if the running daemon version cannot be parsed, if CLI/daemon versions differ, or if either version is below 1.98.9.
- Persistent Tailscale Serve, public Funnel, Services forwarding, or Taildrive shares can create reachability outside the intended adapter-scoped service path. Activation and local verification therefore fail unless Serve/Funnel/Services inspections are conclusive and empty and `tailscale drive list` reports zero shares.
- Taildrop/Send Files is prohibited, but its admin-console state is not locally attested. The operator must confirm it remains disabled before activation and during policy review.
- Disabling Tailscale node-key expiry improves unattended availability but weakens automatic credential rotation; device revocation then becomes an operator-critical control.
- No remote software repairs power, ISP, router, firmware, thermals, disk failure, or a hung machine without an onsite path.
- `Verify` reports locally observable desired state. It cannot prove real Internet reachability, the admin-console policy, or a successful SSH/GUI session from another network; those require operator tests.
- `Verify` does not prove that the installed Windows feature release is still supported or that the latest cumulative/security update is installed. Review Microsoft's current Windows release-health information before acceptance.
- Valid Authenticode and signer continuity do not prove download provenance. Obtain Tailscale and RustDesk only from their official release channels, record the reviewed version/hash/signer, and revalidate upgrades before enabling them.
- Git ignore does not prevent OneDrive or another sync/archive tool from copying ignored machine reports, compute state, client proofs, or generated files. Store or publish only the reviewed Git tree.

## Supported versions

Security fixes are maintained on the default branch. Until tagged releases exist, only the latest commit on `main` is supported.

## Reporting a vulnerability

Use GitHub's [private vulnerability-reporting form](https://github.com/Envoy-Lab/envoy-node/security/advisories/new). Do not open a public issue for a suspected vulnerability and do not attach an unredacted audit, plan, verification report, firewall export, service log, event record, or client proof.

Include the affected commit, script and action, expected security invariant, observed behavior, and a minimal reproduction using synthetic identities and addresses. Remove usernames, hostnames, SIDs, tailnet addresses, keys, tokens, recovery material, machine fingerprints, event records, and absolute personal paths. Maintainers will acknowledge the report in the private advisory and coordinate validation, remediation, and disclosure there.

Ordinary bugs may use the public issue template, but the same redaction rules apply.
