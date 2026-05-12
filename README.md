# Vulnforge sketch

A vulnerability research pipeline built around a single rule: *nothing is a vulnerability until execution says so.*

AI proposes. Tools test. The system verifies. The model is never the judge of truth.

## Design constraints

Network is something the pipeline cannot do, not something it is configured not to do. One file in the repo touches
the network: `bootstrap/fetch_models.py`. After bootstrap, the analysis host can run fully offline. This is the
load-bearing property of the design: code slices and findings never leave the machine, no external service learns
what you are looking at, and there is no listening service for an attacker to reach.

## Architecture

```
ingest -> index -> hypothesise -> synthesise -> execute -> verify -> report
                        |             |            |          |
                        v             v            v          v
                    inference     inference     sandbox    (no AI)
```

Each stage reads its inputs from a content-addressed store, writes outputs back, and appends one event to a hash-chained
audit log. Stages communicate by ref (a SHA256), not by in-process state. Any stage can be re-run independently.

## Trust boundaries

- AI may produce hypotheses and payload suggestions. It may not produce verdicts. `git grep "status=Status.CONFIRMED"`
  returns exactly the two lines in `stages/verify.py` that create a verdict. That is the entire enforcement of the
  no-AI-judge rule: the only assignment sites for verdict statuses are in one file.
- The sandbox is the only place untrusted code or untrusted payloads run. `--network=none`, read-only filesystem,
  dropped capabilities, no new privileges, rootless podman, no host daemon. One canonical invocation in
  `sandbox/run.py`. Reviewing isolation amounts to reading that file.
- Inference itself runs inside the same sandbox. Defence in depth against weight-level surprises.
- The audit log is append-only and hash-chained. Each entry references the previous entry's hash; tampering is
  detectable in O(n) via `vulnforge audit-verify`.

## Repo layout

```
vulnforge/
  bootstrap/           one-time, network-using; outside the analysis pipeline
    fetch_models.py
    build_sandbox.py
    models.lock        SHA256 pins for each weight (populate before bootstrap)
    sandbox.lock       SHA256 of the built image (written by bootstrap)
  schema/              frozen data types; verdict transitions live in verify.py
  store/               content-addressed object store and named refs
  audit/               hash-chained JSONL log
  sandbox/             canonical podman invocation + Containerfile
  inference/           llama.cpp subprocess wrapper + prompts
  stages/              ingest, index, hypothesise, synthesise, execute, verify, report
  orchestrator/        stage sequencing from configs/pipeline.yaml
  configs/
    pipeline.yaml      which stages, which model per stage
  tests/
  cli.py
```

Runtime data lives under `.vulnforge/` (gitignored): the object store, the audit log, the fetched weights. The
built-image hash sits in `bootstrap/sandbox.lock` (also gitignored, since it is per-machine state).

## Setup

In an activated venv:

```
pip install -e .             # one-off; puts `vulnforge` on PATH
```

Prerequisites: rootless podman on PATH, around 10 GiB free disk, network access for the bootstrap step. After bootstrap
the host can be offline.

## Usage

```
vulnforge bootstrap          # fetch weights, build sandbox image (one-off, online)
vulnforge plumbing           # end-to-end smoke test (after bootstrap)
vulnforge scan path/to/repo  # run the pipeline (offline)
vulnforge audit-verify       # walk the audit log hash chain
```

The pytest version of the smoke test lives at `tests/test_plumbing.py` and skips on hosts that have not bootstrapped:

```
pytest tests/test_plumbing.py -v
```

## What is in place today

Infrastructure: real and runnable.

- Frozen schema types with a state machine that refuses bad transitions.
- Content-addressed object store with atomic writes and on-read hash verification.
- Hash-chained audit log with tamper detection.
- Canonical podman sandbox invocation.
- llama.cpp subprocess runner (passes prompt via stdin so it does not appear in `/proc`).
- Bootstrap fetch with SHA256 verification.

Stages: skeletal. `ingest` walks a repo into the store. `index`, `hypothesise`, `synthesise`, `execute`, `verify`,
`report` raise `NotImplementedError`. The data flow and trust boundaries are wired in; what is missing is the analysis
content.

## A constraint worth restating

If the AI layer judges, or the network is open, the system collapses into a confident fiction generator about security.
The design is structural specifically because configuration is too easy to forget.
