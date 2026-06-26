# Contributing

A vulnerability research pipeline built around one rule: nothing is a vulnerability until execution says so.

## Where things are

The documentation buckets are mapped in [README.md](README.md). The pipeline and every stage live in
[architecture/overview.md](architecture/overview.md) and [architecture/pipeline.md](architecture/pipeline.md), with the
repo layout in the overview. The reasoning behind the load-bearing choices is in [decisions/](decisions/), and the
threat model in [decisions/threat-model.md](decisions/threat-model.md).

## Invariants to preserve

Four structural commitments hold the design together, each testable in a specific place. A change that breaks one is a
change to the architecture, not a tidy-up:

- The AI does not decide verdicts. Verdict transitions live only in `stages/execute.py` and `stages/verify.py`;
  `git grep "status=Status.CONFIRMED,"` (with the trailing comma) returns the single assignment line. Recorded in
  [decisions/2026-05-12-execution-is-authority.md](decisions/2026-05-12-execution-is-authority.md).
- Code runs only inside the sandbox, one canonical invocation in `sandbox/run.py`. Recorded in
  [decisions/2026-05-12-sandbox-only-execution.md](decisions/2026-05-12-sandbox-only-execution.md).
- Nothing crosses a network boundary during analysis; network code lives only in `bootstrap/`. Recorded in
  [decisions/2026-05-12-network-in-bootstrap.md](decisions/2026-05-12-network-in-bootstrap.md).
- The audit log is tamper-evident end to end. Recorded in
  [decisions/2026-05-12-content-addressed-store-and-audit.md](decisions/2026-05-12-content-addressed-store-and-audit.md).

## Running the tests

```
pytest tests/ -v
```

67 tests across seven files. The unit tests (screen grounding, fact extractors, CVE matching, the probe screen gate,
and the pipeline harness) run without a model or CVE data. `test_plumbing.py` and `test_sandbox_cleanup.py` exercise
the real sandbox and skip on hosts that have not run `vulnforge bootstrap`. `test_pipeline.py` runs the full staged
pipeline against a small target using the `plumbing-check` model, validating wiring and verdict assignment rather than
payload quality.

## Adding documentation

Docs are organised by the question a reader asks, not by when something happened. A new doc goes where its question
lives: what exists in [architecture/](architecture/), why in [decisions/](decisions/) as a dated record, what might
come next in [roadmap/](roadmap/), what a run measured in [metrics/](metrics/). The roadmap makes no claims about
completed work; when something lands, its description moves to architecture and its rationale becomes a decision record.

## Closing note

If the AI layer judges, or the network is open, the system collapses into a confident fiction generator about security.
The design is structural because configuration is too easy to forget.
