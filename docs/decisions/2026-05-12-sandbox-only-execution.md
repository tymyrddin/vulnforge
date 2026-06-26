# The sandbox is the only execution primitive

Date: 2026-05-12

## Context

If code runs in more than one place, isolation has to be argued in more than one
place. A single execution surface keeps the isolation properties reviewable.

## Decision

`sandbox/run.py` is the canonical isolation surface: rootless podman,
`--network=none`, `--read-only`, `--cap-drop=ALL`,
`--security-opt no-new-privileges`, `--pids-limit`, `--memory`, `--cpus`.
Inference runs through the same sandbox as analysis targets.

## Why

Reviewing isolation amounts to reading that one file. There is no second path
to audit and no way for inference to escape the constraints applied to analysis
targets.

[../architecture/sandbox.md](../architecture/sandbox.md) covers the mechanism.
