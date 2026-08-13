# Portable compute core

This directory contains a deliberately tiny API probe. It proves the deployment shape before any model runtime is selected:

- declarative Compose;
- a loopback-only Windows host port;
- a non-root process;
- read-only root filesystem;
- no Linux capabilities;
- bounded CPU, memory, and process count;
- a health endpoint at `http://127.0.0.1:18080/health`.

The probe is not an inference server. Once the AMD ROCm acceptance suite passes, add an inference service as a separate profile and keep its API loopback-only. Reach it remotely with an allowlisted SSH local-forward, not a public bind.

This per-container CPU/memory cap is real. The larger WSL memory/processor recommendation is not applied automatically because `.wslconfig` is shared by every WSL2 distribution for the Windows user, including Docker Desktop.

The base image is locked to a reviewed multi-architecture digest. Refresh that digest deliberately after reviewing upstream changes and rerun the complete smoke/health suite; never change it implicitly during activation. The framework intentionally does not operate on any pre-existing Docker resources.

Do not run a bare fixed-project `docker compose up` or `down`: those commands can collide with and recreate or remove same-named resources. For the residue-free safety proof, preview and run `..\scripts\Build-EnvoySmokeImage.ps1 -Build`, then run `..\envoy.ps1 -Action Smoke`. Both paths require the validly signed Docker Desktop CLI at its fixed Program Files path and force the local Windows named pipe. The builder refuses a non-owned target tag; `Smoke` validates the cached labels and pinned-base digest, resolves the immutable image ID, and runs that ID with `--pull=never` under the documented isolation limits.
