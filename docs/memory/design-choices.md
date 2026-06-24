# vulnforge design choices

The load-bearing decisions, why they exist, and where they live in the code.
Things change; this file records what was decided when. If a future commit
contradicts something here, both the code and this note need updating.

## Foundational invariants

These predate this session. They are the constraints the rebuild was organised
around.

### No AI judge

Verdict transitions live exclusively in two files. `stages/execute.py`
(`mark_tested`) owns PROPOSED -> TESTED. `stages/verify.py` (`confirm`,
`refute`) owns TESTED -> CONFIRMED and TESTED -> REFUTED.
`schema/hypothesis.py:Hypothesis.propose` is the only constructor path, and it
only ever yields `Status.PROPOSED`. `git grep "status=Status.CONFIRMED"`
returns the single assignment line in `verify.py`. The rule is in the layout,
not in a comment.

### The sandbox is the only execution primitive

`sandbox/run.py` is the canonical isolation surface: rootless podman,
`--network=none`, `--read-only`, `--cap-drop=ALL`,
`--security-opt no-new-privileges`, `--pids-limit`, `--memory`, `--cpus`.
Inference runs through the same sandbox as analysis targets. Reviewing
isolation amounts to reading that one file.

### Content-addressed store and hash-chained audit log

Every stage output is a content-addressed blob (sha256). `audit/log.py` writes
JSONL records, each carrying `prev_hash` referring to the previous record's
`entry_hash`. Tampering with any entry invalidates every entry after it.
`verify_chain()` walks the file linearly.

### Network access lives only in bootstrap/

`bootstrap/fetch_models.py` and `bootstrap/build_sandbox.py` are the only
modules that touch the network. After `vulnforge bootstrap` runs once, the
analysis host can be fully offline. The pipeline is structurally incapable of
hitting the network because it never holds network code paths.

## May 13

### Workspace separation: immutable framework, mutable XDG

The framework checkout is read-only. All runtime state lives under
`$XDG_DATA_HOME/vulnforge/` (fallback `~/.local/share/vulnforge/`). Three
sibling directories with distinct semantics:

- `weights/` model weights, fetched once by bootstrap, shared across runs.
- `corpus/` input files to be analysed. Persistent, curated, framework
  reads only.
- `runs/<run-id>/` per-scan artefacts: object store, refs, audit log,
  llama stderr logs, reports, probe artefacts. Isolated per scan.

Override via `--workspace <path>` or `$VULNFORGE_WORKSPACE`. The XDG root is
the only place runtime state lives. `.gitignore` keeps a defensive entry for
`.vulnforge/` in the framework checkout so older versions or accidental local
state cannot land in commits.

Why: scans were writing to `.vulnforge/` relative to CWD, so running a scan
from inside the framework checkout silently filled the repo with scan
residue. Making the boundary structural removed the contamination class.
`/tmp` is reserved for truly transient scratch and is explicitly not a
corpus.

### Prompt: certainty, not vocabulary

The hypothesise prompt does not ban words. It bans unverified findings
asserted as fact. The model can discuss vulnerability classes, suspicious
patterns, attack surfaces, and exploit hypotheses. It cannot claim successful
exploitation without execution evidence.

Why: the prior rule "the word 'vulnerable' cannot appear in your output"
forced lexical avoidance instead of epistemic discipline. Models do not become
more truthful when words are banned; they become evasive. Restricting
epistemic claims (not vocabulary) lets the model speak naturally while the
schema and the downstream stages enforce what counts as a verdict.

### Three orthogonal schema axes

`schema/hypothesis.py` exposes three enums:

- `Status` pipeline lifecycle (PROPOSED, TESTED, CONFIRMED, REFUTED)
- `EvidenceType` nature of evidence (static_pattern, behaviour_inferred,
  execution_observed)
- `VerificationStatus` epistemic claim strength (unverified, tested, confirmed)

`Hypothesis.propose` rejects model-supplied `CONFIRMED` or
`EXECUTION_OBSERVED` at construction time. Those values are stage-owned: only
`verify.confirm` sets `CONFIRMED`, only `execute.mark_tested` sets
`EXECUTION_OBSERVED`. `verify.refute` does not promote VerificationStatus
past `TESTED`.

Why: uncertainty needed a place to live. Three orthogonal fields let the
system encode "where in the pipeline" separately from "how strong is the
evidence" separately from "what claim are we willing to make". Without this,
the system tries to encode all three in `Status` alone, which conflates
distinct things.

### Schema constraints over prompt rules

When the model produced `"A" * 20` (a Python expression) inside
`suggested_inputs`, the chosen fix was a regex on the schema, not another
prompt rule. The constraint is `^[^*()]+$` on each `suggested_inputs` string.

Why: prompt rules are advisory and ignorable. Schema rules are enforced at
construction. Moving the constraint from "ask nicely" to "reject loudly"
removes an entire class of model-output silent failure.

This fix does not address the strcpy case, where the model still emits
literally-invalid JSON (`"A" * 20` is not parseable JSON, regardless of
schema). That is a different intervention class, addressed at the JSON layer
rather than the schema layer.

### Type contract: list at the API boundary, tuple in storage

`Hypothesis.propose` accepts `suggested_inputs: list[str]`. The dataclass
field is `tuple[str, ...]`. Conversion happens in exactly one place: the
`cls(...)` call inside `propose`. Callers pass lists; storage is immutable.

Why: JSON has lists, not tuples. Internal storage benefits from immutability.
Doing both clearly avoids "is this expecting a list or a tuple?" friction at
every call site, and avoids subtle bugs from converting at the wrong layer.

### Probe: one-shot inference, bypassing the staged pipeline

`vulnforge probe <file>` runs the hypothesise prompt against a single file,
bypassing the staged pipeline. Useful for tuning the prompt and schema layer
in isolation before committing to a full scan.

`--function NAME` extracts a single function using the same slice format as
the index and hypothesise stages. Without it, probe sends the raw file; the
model sees the full source including docstrings, which can prime the wrong
attack template (a file with a container-related docstring will attract
container security hypotheses regardless of the function). The flag keeps
probe representative of what happens during a real pipeline run and is the
correct form for prompt tuning.

Per-probe artefacts under the workspace root:

- `probe-prompt.txt` the exact prompt sent to the sandbox
- `probe-output.txt` raw post-strip model output
- `probe-extracted.txt` the `{...}` block we attempted to parse
- `probe-parsed.json` extracted JSON object, present only if `json.loads`
  succeeded
- `probe-rejections.jsonl` one line per rejected hypothesis, present only
  if any were rejected

The `--debug-llama` flag swaps `--log-disable` for `--log-file /dev/stderr`,
streaming llama.cpp's own load and timing logs into the captured stderr.

Why: each artefact captures a different failure layer. JSON-not-extracted,
JSON-parse-fail, and schema-reject all leave distinct traces. Debugging
shifts from "guess what went wrong" to "read the artefact that captured the
failure layer".

### Container ownership: the run-guard

`sandbox/run.py` treats containers as owned resources. Every container is
named `vulnforge-<uuid>`, registered in a module-level `_active: set[str]` on
creation, and torn down via one idempotent `_cleanup(name)` function. All exit
paths route through `_cleanup`:

- Normal return: `finally` block
- Timeout: `TimeoutExpired` is caught and translated to `Result(124, ..., timed_out=True)`; the surrounding `finally` then runs clean-up
- KeyboardInterrupt: unwinds through `finally` naturally
- SIGTERM: a custom handler raises `SystemExit(128 + signum)`, which unwinds
- Catastrophic exit: `atexit.register(cleanup_all)` is the safety net

Signal handlers schedule clean-up, they do not perform it. Doing podman work
inside a Python signal handler invites deadlocks; the handler raises, the
`finally` does the work.

Why: `podman run` daemonises the container via conmon/runc, so SIGKILLing the
client does not kill the container. Two earlier llama-cli containers survived
for around five hours, eating RAM and CPU until subsequent runs timed out.
The fix turns "garbage collection problem" into "addressable resource".

`tests/test_sandbox_cleanup.py` asserts no `vulnforge-*` containers survive a
clean exit or a forced timeout.

## Open forks

These are decisions we have not yet made. Listed so the next person reading
this file knows where the live design questions are.

- Verdict pipeline: screening stage between hypothesise and execute, and
  closed-enum failure modes on `Hypothesis`. `stages/verify.py` is implemented;
  the screener and `vulnforge stats` are still pending. See
  [verdict-pipeline.md](verdict-pipeline.md).
- `Run` vs `Workspace` separation: making workspaces own their containers and
  audit cursors. See `run-concept.md`. Deferred until a concrete trigger
  (concurrent scans, crash recovery, audit provenance) shows up.
- Tolerant JSON parsing for the strcpy-shaped failure mode (model emits
  Python expressions inside JSON arrays). The schema cannot help; options
  are prompt restructuring via a chat template, an upstream parse repair, or
  a model change.
- Workspace locking: preventing two concurrent scans from writing to the same
  `run-id`. Not currently possible (each scan creates a fresh timestamped
  run dir), but worth a flag once concurrency arrives.

## Model selection for hypothesise: /no_think required for thinking models on CPU

qwen3-8b is a thinking model: it generates a `<think>...</think>` chain before
any JSON output. On CPU at roughly 1-2 tok/sec, a complex slice can produce
2,000 or more thinking tokens before the JSON answer appears. At that rate,
no slice completes within the 300-second `infer()` default timeout. The failure
is silent: every container runs for exactly 300 seconds, times out, and is skipped;
the scan appears to run but produces zero hypotheses.

The fix: `no_think: true` in `bootstrap/models.lock` for qwen3-8b. When set,
`inference/runner.py` prepends `/no_think` to the prompt before inference.
qwen3-8b respects this in plain completion mode (`--simple-io --single-turn`)
without a chat template, skipping the thinking chain entirely. Output becomes
direct and comparable in speed to qwen2.5-coder-7b.

`configs/pipeline.yaml` uses `qwen3-8b` for hypothesise and `qwen2.5-coder-7b`
for synthesise. `probe` defaults to `qwen3-8b`; the `no_think` flag applies
automatically from `ModelSpec`.

The structural gap that caused the silent failure: `hypothesise.run()` had no
`timeout_seconds` parameter, so the 300-second `infer()` default was invisible
in config. The fix is that `max_tokens` is now wired from `pipeline.yaml` through
the stage; timeout remains the `infer()` default, which is appropriate for
qwen3-8b with `no_think` at max_tokens=512.
