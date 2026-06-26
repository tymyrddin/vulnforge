# Architecture overview

The map of what exists. Reasoning behind the load-bearing choices is recorded in
[../decisions/](../decisions/); what is next is in [../roadmap/README.md](../roadmap/README.md).

A vulnerability research pipeline built around a single rule: nothing is a vulnerability until
execution says so.

## The pipeline

Eight stages. The screen sits between hypothesise and synthesise and uses no AI.

```
ingest ─▶ index ─▶ hypothesise ─▶ screen ─▶ synthesise ─▶ execute ─▶ verify ─▶ report
                        │           │            │            │          │
                        ▼           ▼            ▼            ▼          ▼
                    inference    (no AI)     inference     sandbox    (no AI)
```

```
INGEST → INDEX → HYPOTHESISE → SCREEN → SYNTHESISE → EXECUTE → VERIFY → REPORT
```

## Stage table

| Stage       | File             | Owns                                           |
|-------------|------------------|------------------------------------------------|
| Ingest      | `ingest.py`      | File ingestion, hashing, manifest creation     |
| Index       | `index.py`       | AST parsing, slice extraction, call graph      |
| Hypothesise | `hypothesise.py` | AI proposes hypotheses (PROPOSED)              |
| Screen      | `screen.py`      | Grounds hypotheses against facts, no AI        |
| Synthesise  | `synthesise.py`  | AI generates payloads from hypotheses          |
| Execute     | `execute.py`     | Runs payloads in sandbox, marks TESTED         |
| Verify      | `verify.py`      | Compares observations, marks CONFIRMED/REFUTED |
| Report      | `report.py`      | Human-readable output generation               |

## How stages communicate

Each stage reads its inputs from a content-addressed store, writes outputs back, and appends one
event to a hash-chained audit log. Stages communicate by ref (a SHA256), not by in-process state.
Any stage can be re-run independently.

- Content-addressed object store: every blob is keyed by its SHA256. [storage.md](storage.md) covers
  the store.
- Named refs: each stage writes `refs.write("<stage>_latest", ref)` so the next stage can find its
  input. [storage.md](storage.md) covers refs.
- Hash-chained audit: every stage appends one `AuditEvent` (stage, input_refs, output_refs,
  model_hash, seed). Each entry references the previous entry's hash. [storage.md](storage.md) covers
  the audit log.

## Cross-stage patterns

| Pattern                                                            | Location                |
|--------------------------------------------------------------------|-------------------------|
| `run(ref, *, model_alias, seed) -> str`                            | hypothesise, synthesise |
| `run(ref, target_ref, *, timeout_seconds) -> str`                  | execute                 |
| `refs.write("<stage>_latest", ref)`                                | All stages              |
| `AuditEvent` with stage, input_refs, output_refs, model_hash, seed | All stages              |
| `_extract_json()` with `raw_decode()`                              | hypothesise, synthesise |
| `_parse_*()` functions for model output                            | hypothesise, synthesise |
| `logs_dir.mkdir(parents=True, exist_ok=True)`                      | hypothesise, synthesise |
| `except RuntimeError: continue`                                    | hypothesise, synthesise |
| Broad `Exception` catch for sandbox failures                       | execute                 |
| Content-addressed storage (SHA256)                                 | All stages              |

## State transition graph

The "model proposes, code decides" principle, enforced at the code level.

```
                    ┌───────────────────────────────────────┐
                    │                                       │
                    ▼                                       │
    ┌──────────┐  hypothesise.py  ┌───────────┐             │
    │ PROPOSED │─────────────────▶│ PROPOSED  │             │
    └──────────┘                  └───────────┘             │
                        │                                   │
                        │ execute.py                        │
                        │ (mark_tested)                     │
                        ▼                                   │
                   ┌──────────┐                             │
                   │ TESTED   │                             │
                   └──────────┘                             │
                    │       │                               │
         verify.py  │       │  verify.py                    │
         (confirm)  │       │  (refute)                     │
                    ▼       ▼                               │
              ┌──────────┐ ┌──────────┐                     │
              │CONFIRMED │ │ REFUTED  │─────────────────────┘
              └──────────┘ └──────────┘
```

- Only `execute.py` can mark PROPOSED → TESTED.
- Only `verify.py` can mark TESTED → CONFIRMED or TESTED → REFUTED.
- `hypothesise.py` only ever produces PROPOSED.
- Greppable enforcement: `status=Status.TESTED` appears here, only here.

## Trust boundaries

- AI may produce hypotheses and payload suggestions. It may not produce verdicts. Verdict
  transitions live exclusively in `stages/execute.py` (PROPOSED to TESTED) and `stages/verify.py`
  (TESTED to CONFIRMED or REFUTED). `git grep "status=Status.CONFIRMED,"` (with the trailing comma)
  returns the single assignment line.
- The sandbox is the only place untrusted code or untrusted payloads run. [sandbox.md](sandbox.md)
  covers the sandbox.
- Inference itself runs inside the same sandbox. Defence in depth against weight-level surprises.
- Network access lives only in `bootstrap/`. After bootstrap, the analysis host has no code paths
  that touch the network.
- The audit log is append-only and hash-chained; tampering is detectable in O(n) via
  `vulnforge audit-verify`. [storage.md](storage.md) covers the audit log.

## Repo layout

```
vulnforge/
  bootstrap/           one-time, network-using; outside the analysis pipeline
    fetch_models.py
    fetch_cve.py       downloads the db.gcve.eu (CIRCL) PyPA advisory dump
    build_sandbox.py
    models.lock        SHA256 pins for each weight
    sandbox.lock       SHA256 of the built image
  cve/                 CVE correlation: CWE map, offline index, OSV loader
  schema/              frozen data types; verdict transitions live in stages/verify.py
  store/               content-addressed object store and named refs
  audit/               hash-chained JSONL log
  sandbox/             canonical podman invocation + Containerfile
  inference/           llama.cpp subprocess wrapper + prompts
  stages/              ingest, index, hypothesise, screen, synthesise, execute, verify, report
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
- `corpus/` input files to be analysed, persistent and user-curated; the framework reads it, never
  writes to it
- `runs/<run-id>/` per-scan artefacts: object store, refs, audit log, llama stderr logs, reports,
  probe artefacts

Override via `--workspace <path>` or `$VULNFORGE_WORKSPACE`. [storage.md](storage.md) covers the
full resolution order.
