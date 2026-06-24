# Contributing

A vulnerability research pipeline built around a single rule: nothing is a vulnerability until execution says so.

## Architecture

```
ingest -> index -> hypothesise -> synthesise -> execute -> verify -> report
                        |             |            |          |
                        v             v            v          v
                    inference     inference     sandbox    (no AI)
```

Each stage reads its inputs from a content-addressed store, writes outputs back, and appends one event to a hash-chained
audit log. Stages communicate by ref (a SHA256), not by in-process state. Any stage can be re-run independently.

For the load-bearing decisions and why they exist, see [design-choices.md](../memory/design-choices.md).

## Trust boundaries

- AI may produce hypotheses and payload suggestions. It may not produce verdicts. Verdict transitions live exclusively
  in `stages/execute.py` (PROPOSED to TESTED) and `stages/verify.py` (TESTED to CONFIRMED or REFUTED).
  `git grep "status=Status.CONFIRMED"` returns the single assignment line.
- The sandbox is the only place untrusted code or untrusted payloads run. Rootless podman with `--network=none`,
  `--read-only`, `--cap-drop=ALL`, `--security-opt no-new-privileges`, and resource limits. One canonical invocation in
  `sandbox/run.py`. Reviewing isolation amounts to reading that file.
- Inference itself runs inside the same sandbox. Defence in depth against weight-level surprises.
- Network access lives only in `bootstrap/`. After bootstrap, the analysis host has no code paths that touch the
  network.
- The audit log is append-only and hash-chained. Each entry references the previous entry's hash; tampering is
  detectable in O(n) via `vulnforge audit-verify`.

For what this design does and does not remove from the trust path, see [trust-path.md](../memory/trust-path.md).

## Repo layout

```
vulnforge/
  bootstrap/           one-time, network-using; outside the analysis pipeline
    fetch_models.py
    fetch_cve.py       downloads OSV.dev / db.gcve.eu CVE dump
    build_sandbox.py
    models.lock        SHA256 pins for each weight
    sandbox.lock       SHA256 of the built image
  cve/                 CVE correlation: CWE map, offline index, OSV loader
  schema/              frozen data types; verdict transitions live in stages/verify.py
  store/               content-addressed object store and named refs
  audit/               hash-chained JSONL log
  sandbox/             canonical podman invocation + Containerfile
  inference/           llama.cpp subprocess wrapper + prompts
  stages/              ingest, index, hypothesise, synthesise, execute, verify, report
  orchestrator/        stage sequencing from configs/pipeline.yaml
  configs/
    pipeline.yaml      which stages, which model per stage
  docs/                design notes
  tests/
  cli.py
```

Runtime state lives outside the framework checkout under `$XDG_DATA_HOME/vulnforge/` (fallback
`~/.local/share/vulnforge/`):

- `weights/` model weights, shared across runs
- `cve/osv-pypi/` CVE data downloaded by bootstrap, shared across runs
- `corpus/` input files to be analysed, persistent and user-curated; the framework reads it, never writes to it
- `runs/<run-id>/` per-scan artefacts: object store, refs, audit log, llama stderr logs, reports, probe artefacts

Override via `--workspace <path>` or `$VULNFORGE_WORKSPACE`.

## Status

All seven stages are implemented and wired into the orchestrator. `vulnforge scan <repo>` runs the full pipeline.

Infrastructure:

- Frozen schema types (`Status`, `EvidenceType`, `VerificationStatus`) with a state machine that refuses bad
  transitions. `Hypothesis.propose` rejects model-supplied CONFIRMED or EXECUTION_OBSERVED at construction.
  `suggested_inputs` is constrained at the schema gate (no expression-shaped strings).
- Content-addressed object store with atomic writes and on-read hash verification.
- Hash-chained audit log with tamper detection.
- Canonical podman sandbox invocation with container ownership: every container named `vulnforge-<uuid>`, registered in
  a module-level set on creation, torn down through one `_cleanup` function reachable from every exit path (normal
  return, timeout, SIGINT, SIGTERM, atexit).
- llama.cpp subprocess runner that passes prompt via stdin so it does not appear in `/proc`.
- Bootstrap fetch with SHA256 verification for weights and CVE data.
- Workspace separation: framework checkout is immutable; runtime artefacts live under `$XDG_DATA_HOME/vulnforge/`.
- `vulnforge probe` for one-shot hypothesis generation with per-failure-layer artefacts. `--function NAME` extracts
  a single function using the same slice format as the pipeline, keeping probe representative of a real scan.
- CVE correlation as the last step inside `verify`: deterministic CWE-based lookup against an offline OSV dump,
  `cve_refs` attached to each confirmed verdict.
- Marker injection in `synthesise`: for `command_injection` payloads, a unique `VULNFORGE_<hex>` string is appended
  to the payload value and stored alongside it. `verify` checks for the marker in sandbox stdout rather than treating
  any non-zero exit as confirmation.

What remains from the verdict pipeline plan: the screening stage between hypothesise and execute, closed-enum failure
modes on `Hypothesis`, and the `vulnforge stats` correlation surface. See
[verdict-pipeline.md](../memory/verdict-pipeline.md). For open design questions (Run vs Workspace separation,
concurrent scans, crash recovery), see [run-concept.md](../memory/run-concept.md).

## Closing note

If the AI layer judges, or the network is open, the system collapses into a confident fiction generator about security.
The design is structural specifically because configuration is too easy to forget.