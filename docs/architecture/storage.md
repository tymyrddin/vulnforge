# Storage, refs, audit, and workspace

The substrate every stage shares: a content-addressed object store, named refs, a hash-chained audit
log, and a per-scan workspace.

## Content-addressed object store (`store/`)

Every blob is keyed by its SHA256. `objects.put()` writes a blob and returns its digest; reads verify
the hash on the way out. Writes are atomic. A stage reads its inputs by ref (a SHA256), writes its
outputs back, and never passes in-process state to the next stage. Any stage can be re-run
independently against the same input ref and produce the same output.

## Named refs

A ref is a human-named pointer to a digest. Each stage writes `refs.write("<stage>_latest", ref)` so
the next stage can find its input by name rather than by carrying the digest around:

- `ingest_latest`, `hypotheses_latest`, `screen_accepted_latest`, `tested_hypotheses_latest`, and so
  on.
- The orchestrator feeds `screen_accepted_latest` to synthesise when the screen has run.

## Hash-chained audit log (`audit/`)

The audit log is an append-only JSONL file. Each stage appends one `AuditEvent` carrying stage,
input_refs, output_refs, model_hash, and seed. Each entry references the previous entry's hash, so
tampering is detectable in O(n) via `vulnforge audit-verify`.

Audit events per stage:

| Stage       | model_hash  | seed          |
|-------------|-------------|---------------|
| ingest      | None        | None          |
| index       | None        | None          |
| hypothesise | spec.sha256 | user provided |
| screen      | None        | None          |
| synthesise  | spec.sha256 | user provided |
| execute     | None        | None          |
| verify      | None        | None          |
| report      | None        | None          |

The screen carries `model_hash=None` and `seed=None`: it runs no model and is deterministic.

## Workspace resolution

The workspace root is resolved in order:

1. `--workspace <path>` CLI flag
2. `$VULNFORGE_WORKSPACE` env var
3. `$XDG_DATA_HOME/vulnforge/`
4. `~/.local/share/vulnforge/` (fallback)

Each scan creates a fresh timestamped run directory under `runs/` within that root:

```
~/.local/share/vulnforge/runs/<timestamp>/
```

A run directory holds the per-scan artefacts: object store, refs, audit log, llama stderr logs,
reports, and probe artefacts. Shared, cross-run state (`weights/`, `cve/osv-pypi/`, `corpus/`) lives
at the workspace root, not inside a run.
