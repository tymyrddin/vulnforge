# Run vs Workspace: a design note

Status: not implemented. Deferred until one of the three triggers below
becomes real. This file is the starting point if any does.

## Today

A `Workspace` is a frozen dataclass of paths. `workspace.use(ws)` pins one as
active in a module-level slot. `store/objects`, `store/refs`, `audit/log` all
read `workspace.active()` to know where to write.

`sandbox/run.py` keeps its own process-global `_active: set[str]` for container
names, with `_cleanup` reachable from every exit path. It does not know about
workspaces.

Two global pools, no coupling. This works for a single-process CLI.

## The three triggers

1. Concurrent scans in the same process. Today this is impossible (one active
   workspace, one container set). If two pipelines ran at once, both would
   write to whichever workspace got pinned last, and containers would be
   shared between them.

2. Crash recovery. If a vulnforge process dies with containers running
   (SIGKILL, host reboot, OOM), nothing else can clean them up: the registry
   was process-global and died with the process. A successor process cannot
   know which containers belonged to which (or to any) prior run.

3. Audit-log container provenance. The audit log records stage outputs but
   not the container names that produced them. A confirmed hypothesis cannot
   today be traced back to the specific sandbox invocation that produced it.

## Proposed shape

Introduce a `Run` concept distinct from `Workspace`.

`Workspace` keeps its current job: filesystem locations. Where artefacts live.

`Run` is the active lifecycle. It holds `(workspace, run_id, active_containers,
started_at, status)` and owns the audit-log append cursor. It composes with
`Workspace`; it does not replace it.

`sandbox.run.run(...)` gains an optional `run: Run` parameter. If supplied,
the container name is registered in `run.active_containers` instead of (or in
addition to) the module-level set. Cleanup then walks `run.active_containers`
from a `finally` block in the orchestrator, not from `sandbox.run`. The
module-level set stays as a fallback for code that does not have a `Run`.

For crash recovery, `runs/<run-id>/` gains a `containers.txt` file: one name
per line, written on container creation, removed on cleanup. A new
`vulnforge runs gc` subcommand reads leftover `containers.txt` files from any
run directory and stops/removes the named containers. This is the bit that
makes recovery actually possible across process boundaries.

For audit provenance, `AuditEvent` gains a `container_name` field. A confirmed
hypothesis is then traceable: audit log entry -> container name -> the exact
sandbox invocation that produced the observation.

## What this is not

- A multi-process orchestrator. Single Python process is still the contract.
- A reason to thread `run` through every call. Most code paths can stay on
  `workspace.active()`. `Run` exists only for code that needs lifecycle
  ownership (sandbox launches, audit appends).
- A god object. `Workspace` stays paths-only. `Run` is lifecycle-only. They
  compose.

## Migration sketch (when one of the triggers fires)

1. Add `Run` dataclass alongside `Workspace` (in `workspace.py`, or a new
   `lifecycle.py` if it grows).
2. `workspace.use()` returns a `Run` wrapping the chosen `Workspace`.
3. `sandbox.run.run()` optionally accepts `run`; falls back to the module
   global if absent. Back-compatible.
4. CLI commands create a `Run` on entry and pass it to the orchestrator and
   any sandbox calls.
5. `runs/<run-id>/containers.txt` written on creation, removed on cleanup.
6. Add `vulnforge runs gc`.
7. Test: kill -9 a mid-run vulnforge process; run `vulnforge runs gc`; assert
   `podman ps` is empty. The current cleanup tests cover the in-process
   paths; this test covers the out-of-process path.

## Decision

Defer. The current pattern is small (around fifty lines in `sandbox/run.py`),
testable, and reversible. The three triggers above are all hypothetical
today. If any becomes real, the work starts here.
