## What changed

Describe the focused change and why it is needed.

## Safety impact

- Security or availability invariant affected:
- Mutation, rollback, or fail-close behavior affected:
- Existing Docker, WSL, firewall, access, encryption, update, and power workloads remain preserved:

## Validation

- [ ] Windows PowerShell 5.1 parser accepted every `.ps1` file.
- [ ] `tests/Test-Static.ps1` passed.
- [ ] Relevant non-mutating actions were run and expected pre-activation failures are explained.
- [ ] No `-Apply` command was added to CI or run without the required approval lifecycle.
- [ ] The diff contains no local reports, configuration, keys, exports, generated recommendations, client proofs, credentials, or unredacted machine data.
- [ ] Documentation claims cite current primary vendor sources where applicable.
