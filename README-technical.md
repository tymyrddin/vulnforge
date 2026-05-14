# vulnforge (technical)

A vulnerability research pipeline built around a single rule: nothing is a vulnerability until execution says so.

For a plain-language overview, see [README.md](README.md). For the conceptual frame,
see [The model is not the system](https://broomstick.tymyrddin.dev/posts/model-is-not-system/).

## Architecture

```
ingest -> index -> hypothesise -> synthesise -> execute -> verify -> report
                        |             |            |          |
                        v             v            v          v
                    inference     inference     sandbox    (no AI)
```

Each stage reads its inputs from a content-addressed store, writes outputs back, and appends one event to a hash-chained
audit log. Stages communicate by ref (a SHA256), not by in-process state. Any stage can be re-run independently.

For the load-bearing decisions and why they exist, see [docs/design-choices.md](docs/design-choices.md).

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

For what this design does and does not remove from the trust path, see [docs/trust-path.md](docs/trust-path.md).

## Repo layout

```
vulnforge/
  bootstrap/           one-time, network-using; outside the analysis pipeline
    fetch_models.py
    build_sandbox.py
    models.lock        SHA256 pins for each weight
    sandbox.lock       SHA256 of the built image
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
- `corpus/` input files to be analysed, persistent and user-curated; the framework reads it, never writes to it
- `runs/<run-id>/` per-scan artefacts: object store, refs, audit log, llama stderr logs, reports, probe artefacts

Override via `--workspace <path>` or `$VULNFORGE_WORKSPACE`.

## Requirements

- Linux with rootless podman on PATH. Ubuntu 24.04 is the tested baseline.
- x86_64 CPU with AVX2 (llama.cpp requirement).
- Around 10 GiB free disk for weights, the built sandbox image, and the build cache.
- 16 GiB RAM recommended. The default Qwen 7B inference runs in an 8 GiB cgroup (around 5 GiB resident); 16 GiB host RAM
  leaves room for the desktop.
- Network for the bootstrap step only. The analysis host can be offline afterwards.

The cgroup caps live in `inference/runner.py` and `sandbox/run.py`, adjustable for the hardware in front of you.

## Setup

In an activated venv:

```
pip install -e .
```

## Usage

```
vulnforge bootstrap                       # fetch weights, build sandbox (online, one-off)
vulnforge plumbing                        # end-to-end smoke test
vulnforge scan path/to/repo               # run the staged pipeline (offline)
vulnforge probe path/to/file              # one-shot hypothesis against a single file
vulnforge audit-verify --workspace <dir>  # walk a run's audit log hash chain
```

`probe` bypasses the staged pipeline and is the fastest way to exercise the prompt and schema layer without the later
stages. Each probe run writes per-failure-layer artefacts under the workspace root: `probe-prompt.txt`,
`probe-output.txt`, `probe-extracted.txt`, `probe-parsed.json`, and (if any) `probe-rejections.jsonl`.

## Tests

```
pytest tests/ -v
```

`test_plumbing.py` is the end-to-end inference smoke test. `test_sandbox_cleanup.py` asserts that no `vulnforge-*`
containers survive a clean exit or a forced timeout. Both skip on hosts that have not bootstrapped.

## Status

Infrastructure is real and runnable:

- Frozen schema types (`Status`, `EvidenceType`, `VerificationStatus`) with a state machine that refuses bad
  transitions. `Hypothesis.propose` rejects model-supplied CONFIRMED or EXECUTION_OBSERVED at construction.
  `suggested_inputs` is constrained at the schema gate (no expression-shaped strings).
- Content-addressed object store with atomic writes and on-read hash verification.
- Hash-chained audit log with tamper detection.
- Canonical podman sandbox invocation with container ownership: every container named `vulnforge-<uuid>`, registered in
  a module-level set on creation, torn down through one `_cleanup` function reachable from every exit path (normal
  return, timeout, SIGINT, SIGTERM, atexit).
- llama.cpp subprocess runner that passes prompt via stdin so it does not appear in `/proc`.
- Bootstrap fetch with SHA256 verification.
- Workspace separation: framework checkout is immutable; runtime artefacts live under `$XDG_DATA_HOME/vulnforge/`.
- `vulnforge probe` for one-shot hypothesis generation with per-failure-layer artefacts.

Stages: skeletal. `ingest` walks a repo into the store. `index`, `hypothesise`, `synthesise`, `execute`, `verify`,
`report` raise `NotImplementedError`. The data flow and trust boundaries are wired in; the analysis content is what
remains.

For the planned verdict pipeline (screening, verification, content addressing, correlation),
see [docs/verdict-pipeline.md](docs/verdict-pipeline.md). For open design questions (Run vs Workspace separation,
concurrent scans, crash recovery), see [docs/run-concept.md](docs/run-concept.md).

## Notes for operators

Rootless podman prints `can't raise ambient capability CAP_*` warnings at the start of every `run` and `build`. They are
harmless: the sandbox drops every capability anyway (`--cap-drop=ALL` in `sandbox/run.py`), so nothing in the pipeline
relies on them. To silence, set `default_capabilities = []` under `[containers]` in
`~/.config/containers/containers.conf`.

`inference/runner.py` passes `--log-disable` to `llama-cli` so the assistant's reply is the only thing on stdout. Hard
failures still surface: the dynamic linker and the kernel write to stderr regardless, and `infer()` raises on a non-zero
exit. To see llama.cpp's own load and timing chatter for a probe run, pass `--debug-llama`; that flips the flag to
`--log-file /dev/stderr` and the captured stderr log fills up.

The `LLAMA_TAG` default in `sandbox/Containerfile` names a specific release tag. Bumping it is a one-line edit;
different upstream commits produce different binaries, so pin with intent.

## Closing note

If the AI layer judges, or the network is open, the system collapses into a confident fiction generator about security.
The design is structural specifically because configuration is too easy to forget.
