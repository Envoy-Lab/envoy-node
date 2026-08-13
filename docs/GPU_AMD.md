# AMD GPU activation gate

## Adapter scope

The example configuration targets an AMD RDNA 3.5 unified-memory APU with expected ROCm architecture `gfx1151`; it is not an NVIDIA CUDA profile. Do not treat that example as evidence about the current host. Record the live adapter, Windows driver, WSL release and kernel, Ubuntu point release, memory posture, and architecture in a private activation report.

AMD documents a WSL route for supported Strix and Strix Halo systems through ROCDXG (`librocdxg`). ROCDXG is independently versioned, but the complete Windows driver, WSL, Ubuntu, ROCm, ROCDXG, and framework combination still needs to be checked against the current compatibility matrix and proven together before acceptance.

## Why activation is not automatic

GPU activation can replace the Windows graphics/compute driver, change Linux packages, require a reboot, and alter the RAM split between Windows and the GPU. A mismatch can leave the desktop unstable or make GPU compute unavailable. Current compatibility must be checked on activation day.

The raw installed driver version is visible to the audit, but its mapping to AMD's Adrenalin package version was not locally provable. Do not infer compatibility from a larger-looking version number.

## Acceptance sequence

1. Save work, verify a local-console recovery path, and create a system restore/backup appropriate for the machine.
2. Check AMD's current WSL compatibility matrix for all of:
   - the exact installed Ryzen/Radeon model;
   - the reported architecture, including `gfx1151` when that is the configured target;
   - the exact Windows AMD Software package;
   - the exact Ubuntu 24.04 point release;
   - the WSL kernel;
   - the chosen ROCm and framework versions.
   AMD currently recommends at least 64 GB of system memory for Ryzen APU ROCm workloads. A host below that recommendation is an experimental profile: record the limitation explicitly and require measured allocation, Windows-headroom, and thermal proof before acceptance.
3. Install only AMD's documented Windows WSL driver. Do not install a Linux display or DKMS kernel driver inside WSL when using ROCDXG.
4. Reboot only with explicit approval and local recovery available.
5. Install the matching ROCm user-space and prebuilt ROCDXG packages inside the dedicated Ubuntu distribution.
6. Verify `/dev/dxg` exists and `rocminfo` reports `gfx1151`.
7. Run a pinned, digest-addressed AMD image with networking disabled. First prove a real tensor/matrix allocation, not just device enumeration.
8. Record framework-visible memory, maximum successful allocation, throughput, thermals, Windows memory pressure, and rollback commands.
9. Add the real inference service only after the acceptance report passes.

ROCDXG-based containers use `/dev/dxg` and version-specific DXCore/ROCDXG mounts. Native Linux AMD later uses `/dev/kfd` and `/dev/dri` instead. Those are separate Compose overrides.

AMD's sample GPU container flags may include relaxed seccomp, `SYS_PTRACE`, host IPC, and a large shared-memory segment. Those weaken isolation. Start with a trusted, network-disabled test image, then remove each relaxation that the chosen inference workload does not demonstrably require.

## Variable Graphics Memory

The audit may identify a conservative graphics-memory reservation that limits larger GPU-resident models. VGM is firmware/driver-level and changing it requires a reboot. A larger reservation also leaves less memory for Windows and WSL, so do not select a value from an example or another machine.

Use measured profiles rather than one permanent maximum:

- `balanced`: current/low VGM, 16 GB WSL recommendation, normal personal use;
- `compute`: a firmware-supported higher VGM value plus a separately reviewed WSL envelope, used only for planned inference sessions.

Do not simultaneously assume 16 GB belongs to WSL and reserve 16 GB for graphics without measuring Windows headroom. The APU uses unified memory, and reported dedicated memory is not the same thing as guaranteed framework-usable memory. Let the acceptance test decide the largest safe model.

## Version policy

- Pin the working Windows driver, ROCm/ROCDXG, framework, image digest, and model digest in the acceptance report.
- Do not track `latest` on a 24/7 node.
- Keep one proven fallback set. Newer ROCm releases can add hardware support and still regress a particular inference workload.
- Re-run the real tensor/model test after every driver, WSL kernel, ROCm, or framework update.

## NPU scope

The Ryzen AI NPU is a separate execution backend and is not a generic ROCm GPU substitute. Treat it as a future adapter after the GPU inference path is stable and only for runtimes/models with documented NPU support.

## Primary references

- [AMD: Ryzen WSL how-to and ROCDXG](https://rocm.docs.amd.com/projects/radeon-ryzen/en/latest/docs/install/installryz/wsl/howto_wsl.html)
- [AMD: Radeon/Ryzen compatibility matrices](https://rocm.docs.amd.com/projects/radeon-ryzen/en/latest/docs/compatibility/compatibility.html)
- [AMD: Ryzen prerequisites](https://rocm.docs.amd.com/projects/radeon-ryzen/en/latest/docs/prerequisites/prerequisitesryz.html)
- [ROCm: official librocdxg repository](https://github.com/ROCm/librocdxg)
- [Docker: Docker Desktop Windows GPU support](https://docs.docker.com/desktop/features/gpu/)
