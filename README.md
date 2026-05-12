# Vulnforge sketch (PoC)

A vulnerability research pipeline built around a single rule: *nothing is a vulnerability until execution says so.*

[AI proposes. Tools test. The system verifies. The model is never the judge of truth.](https://broomstick.tymyrddin.dev/posts/model-is-not-system/)

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
  docs/                design notes (design-choices.md, run-concept.md, trust-path.md)
  tests/
  cli.py
```

Runtime data lives outside the framework checkout under `$XDG_DATA_HOME/vulnforge/` (fallback
`~/.local/share/vulnforge/`), in three sibling directories:

- `weights/` model weights fetched by bootstrap, shared across runs.
- `corpus/` input files to be analysed. Persistent and user-curated; the framework reads it, never writes to it.
- `runs/<run-id>/` per-scan artefacts: the object store, refs, audit log, llama stderr logs, reports, and probe
  artefacts. Isolated per run.

Set `VULNFORGE_WORKSPACE` or pass `--workspace` to override the root. The built-image hash sits in
`bootstrap/sandbox.lock` inside the checkout (gitignored, since it is per-machine state).

## Requirements

- Linux with rootless podman on PATH. Ubuntu 24.04 is the tested baseline.
- An x86_64 CPU with AVX2 (llama.cpp needs it).
- Around 10 GiB free disk for weights, the built sandbox image, and the build cache.
- RAM: 8 GiB is enough for the `plumbing-check` smoke test (a 1.1 GiB model). The default Qwen 7B inference runs in
  an 8 GiB cgroup (4.4 GiB weights plus KV cache plus compute buffers land around 5 GiB), so 16 GiB host RAM leaves
  room for the desktop. Swap thrashing during model load is the usual cause of an unresponsive machine; closing
  memory-heavy apps first can avoid it.
- Network access for the bootstrap step only. The analysis host can be offline afterwards.

The cgroup caps live in `inference/runner.py` (the `memory` and `cpus` arguments to `infer`) and `sandbox/run.py`
(defaults for non-inference workloads). Tune if your hardware sits at either end of these numbers.

## Setup

In an activated venv:

```
pip install -e .             # one-off; puts `vulnforge` on PATH
```

Pinning a snapshot of a fast-moving upstream like llama.cpp is a trade-off. The `LLAMA_TAG` default in
`sandbox/Containerfile` names a specific release tag; bumping it is a one-line edit, but doing so with intent matters
because different upstream commits produce different binaries. The pin gives reproducibility within a deployment, not
a guarantee that any specific tag stays available upstream forever.

### A note on podman warnings

Rootless podman prints a block of `can't raise ambient capability CAP_*: operation not permitted` warnings at the
start of every `run` and `build`. They are harmless here. Podman is asking the kernel for capabilities its default
profile would normally grant; the user namespace refuses, which is exactly what we want. The sandbox drops every
capability anyway (`--cap-drop=ALL` in `sandbox/run.py`), so nothing in the pipeline relies on them. Silencing the
warnings, if the noise bothers you, is a one-liner: set `default_capabilities = []` under `[containers]` in
`~/.config/containers/containers.conf`.

### A note on the stderr log

`inference/runner.py` passes `--log-disable` to `llama-cli` so the assistant's reply is the only thing on stdout.
The trade-off is that llama.cpp's own load and timing chatter no longer reaches the per-run stderr log under
the workspace `logs/` directory. Hard failures still surface: the dynamic linker and the kernel write to stderr
regardless, and `infer()` raises on a non-zero exit. If load diagnostics matter for a session, pass `--debug-llama`
to `vulnforge probe`; that flips the flag to `--log-file /dev/stderr` for that one run and the captured stderr log
fills up.

## Usage

```
vulnforge bootstrap                       # fetch weights, build sandbox image (one-off, online)
vulnforge plumbing                        # end-to-end smoke test (after bootstrap)
vulnforge scan path/to/repo               # run the staged pipeline (offline)
vulnforge probe path/to/file              # one-shot hypothesise against a single file
vulnforge audit-verify --workspace <dir>  # walk a run's audit log hash chain
```

`probe` bypasses the staged pipeline and is the fastest way to exercise the prompt and schema layer without the
later stages. Each probe run writes `probe-prompt.txt`, `probe-output.txt`, `probe-extracted.txt`, `probe-parsed.json`,
and (if any) `probe-rejections.jsonl` under its workspace root, so every failure layer leaves a trace.

The pytest suite lives under `tests/`. `test_plumbing.py` is the end-to-end inference smoke test; `test_sandbox_cleanup.py`
asserts that no `vulnforge-*` containers survive a clean exit or a forced timeout. Both skip on hosts that have not
bootstrapped:

```
pytest tests/ -v
```

## Done

Infrastructure: real and runnable.

- Frozen schema types (`Status`, `EvidenceType`, `VerificationStatus`) with a state machine that refuses bad
  transitions. The model cannot propose a hypothesis as `CONFIRMED` or `EXECUTION_OBSERVED`; those values are
  stage-owned. `suggested_inputs` is constrained at the schema gate (no expression-shaped strings).
- Content-addressed object store with atomic writes and on-read hash verification.
- Hash-chained audit log with tamper detection.
- Canonical podman sandbox invocation. Containers are owned resources: each one is named, registered in a
  module-level set on creation, and torn down through one `_cleanup` function reachable from every exit path
  (normal return, timeout, SIGINT, SIGTERM, atexit). `tests/test_sandbox_cleanup.py` enforces the invariant.
- llama.cpp subprocess runner (passes prompt via stdin so it does not appear in `/proc`).
- Bootstrap fetch with SHA256 verification.
- Workspace separation: framework checkout is immutable; runtime artefacts live under `$XDG_DATA_HOME/vulnforge/`.
- `vulnforge probe` for one-shot hypothesis generation with per-failure-layer artefacts.

Stages: skeletal. `ingest` walks a repo into the store. `index`, `hypothesise`, `synthesise`, `execute`, `verify`,
`report` raise `NotImplementedError`. The data flow and trust boundaries are wired in; what is missing is the analysis
content. See `docs/design-choices.md` for the load-bearing decisions and `docs/run-concept.md` for the open forks.

## Another note

If the AI layer judges, or the network is open, the system collapses into a confident fiction generator about security.
The design is structural specifically because configuration is too easy to forget.
