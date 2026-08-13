# Operator-approved activation checklist

This checklist is a handoff, not authorization. Project publication, cloning, `Audit`, `Plan`, static validation, and previews do not approve any `-Apply` action. Read the complete [runbook](RUNBOOK.md) and stop on every condition in [AGENTS.md](../AGENTS.md).

## 1. Recovery and client identity

- [ ] Verify supported Windows updates, Secure Boot, Device Encryption or BitLocker, and recovery material from another device.
- [ ] Keep a working local console and an onsite recovery path.
- [ ] Create one unique passphrased Ed25519 or hardware-backed key on each trusted client; never reuse or copy a private key to the host.
- [ ] Transfer only each public key and configure the complete allowlist.

## 2. Private overlay

- [ ] Install the official signed Tailscale client interactively; EnvoyNode never installs or enrolls it.
- [ ] Protect the identity with MFA or a passkey, enable device approval, and approve only expected devices.
- [ ] Replace the default allow-all policy with least privilege and enable Windows unattended mode.
- [ ] Confirm matching signed CLI/daemon versions at or above the enforced floor, empty Serve/Funnel/Services configurations, zero Taildrive shares, and Taildrop/Send Files disabled in the admin console.
- [ ] Confirm there is no router forwarding, UPnP mapping, DMZ, public DNS exposure, exit-node use, subnet routing, or Tailscale SSH.

## 3. SSH access, hardening, and reboot proof

- [ ] Run `Audit`, then a fresh elevated `Plan` immediately before each Access mutation; inspect every blocker and warning.
- [ ] Run `AccessPrepare`, then `AccessEnable`, one reviewed action at a time while retaining password recovery and the local console.
- [ ] From a second laptop, pin the host fingerprint and sign the current host challenge using the configured SSH port.
- [ ] Accept only a proof that matches the approved user, source, fingerprint, time window, and host-observed OpenSSH public-key event.
- [ ] Run `AccessHarden` only after the separate key-only session succeeds.
- [ ] Reboot deliberately only with separate approval, repeat the second-laptop proof, and run `AccessAcceptRebootProof` for the current boot.

## 4. Optional desktop

- [ ] Download the official signed RustDesk installer before disconnecting all network links.
- [ ] Install and configure it offline for direct-IP only, a tailnet-only whitelist, a unique password, no public rendezvous fields, and only necessary permissions.
- [ ] Exit the GUI and stop/startup-disable the service before reconnecting.
- [ ] After current-boot SSH proof, use a fresh elevated plan for `DesktopEnable`; verify public-egress blocks and Tailscale-only ingress.
- [ ] Test a real GUI session from the second laptop, reboot deliberately, renew SSH proof first, test GUI again, then run `DesktopAcceptRebootProof` with a fresh plan.

## 5. Compute and GPU

- [ ] Use the exact non-elevated Windows account that owns the future WSL distribution.
- [ ] With GPU disabled and current-boot access proof already accepted, use a fresh non-elevated plan and `-AcknowledgeCurrentBootAccessProof` for `ComputeBootstrap`; never adopt an unmarked distribution or interrupt active containers without explicit acknowledgment.
- [ ] Run `ComputeVerify` deliberately against the dedicated engine and confirm existing Docker Desktop workloads remain unchanged.
- [ ] Defer AMD driver, ROCm/ROCDXG, firmware, graphics-memory, and reboot work to a separate approved window using the current compatibility matrix.

## 6. Acceptance and operations

- [ ] Test SSH and optional GUI access from another network, such as a phone hotspot.
- [ ] Test update recovery, sign-out behavior, compute start/stop, backups, WSL export/restore, thermals, storage thresholds, and an onsite fallback.
- [ ] Document monitoring, update cadence, client and node revocation, credential rotation, and recovery ownership.
- [ ] Treat Windows WSL compute as on-demand. Migrate containers and state to native Linux when pre-login 24/7 inference is required.
