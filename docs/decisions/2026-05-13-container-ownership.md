# Container ownership: the run-guard

Date: 2026-05-13

## Context

`podman run` daemonises the container via conmon/runc, so SIGKILLing the client
does not kill the container. Two earlier llama-cli containers survived for
around five hours, eating RAM and CPU until subsequent runs timed out.

## Decision

`sandbox/run.py` treats containers as owned resources. Every container is named
`vulnforge-<uuid>`, registered in a module-level `_active: set[str]` on
creation, and torn down via one idempotent `_cleanup(name)` function. All exit
paths route through `_cleanup`:

- Normal return: `finally` block
- Timeout: `TimeoutExpired` is caught and translated to
  `Result(124, ..., timed_out=True)`; the surrounding `finally` then runs
  clean-up
- KeyboardInterrupt: unwinds through `finally` naturally
- SIGTERM: a custom handler raises `SystemExit(128 + signum)`, which unwinds
- Catastrophic exit: `atexit.register(cleanup_all)` is the safety net

Signal handlers schedule clean-up, they do not perform it. Doing podman work
inside a Python signal handler invites deadlocks; the handler raises, the
`finally` does the work.

`tests/test_sandbox_cleanup.py` asserts no `vulnforge-*` containers survive a
clean exit or a forced timeout.

## Why

Naming every container and routing every exit path through one cleanup function
makes a survivor a named, addressable bug rather than an untraceable leak.

[../architecture/sandbox.md](../architecture/sandbox.md) covers the isolation
surface.
