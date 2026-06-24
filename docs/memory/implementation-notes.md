# Implementation notes: vulnforge pipeline

This document captures design decisions, edge cases, patterns, and lessons learned during implementation of the vulnforge pipeline stages.

## Pipeline overview

```
INGEST → INDEX → HYPOTHESISE → SYNTHESISE → EXECUTE → VERIFY → REPORT
```

| Stage       | File             | Status   | Owns                                           |
|-------------|------------------|----------|------------------------------------------------|
| Ingest      | `ingest.py`      | Complete | File ingestion, hashing, manifest creation     |
| Index       | `index.py`       | Complete | AST parsing, slice extraction, call graph      |
| Hypothesise | `hypothesise.py` | Complete | AI proposes hypotheses (PROPOSED)              |
| Synthesise  | `synthesise.py`  | Complete | AI generates payloads from hypotheses          |
| Execute     | `execute.py`     | Complete | Runs payloads in sandbox, marks TESTED         |
| Verify      | `verify.py`      | Complete | Compares observations, marks CONFIRMED/REFUTED |
| Report      | `report.py`      | Complete | Human-readable output generation               |

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

## Stage details

### Ingest (`ingest.py`)

Purpose: Walk a local repo, hash each file into the store, produce a manifest.

Implementation:
- Walks directory tree
- Skips common noise: `.git`, `.venv`, `node_modules`, `.vulnforge`, `__pycache__`, `.idea`
- Each file → SHA256 hash via `objects.put()`
- Manifest: `{file_path: digest}`
- Writes `refs.write("ingest_latest", manifest_ref)`
- Audit log with `stage="ingest"`, `model_hash=None`, `seed=None`

### Index (`index.py`)

Purpose: Parse ingested files into ASTs, extract symbols and call graph, produce per-function slices.

Implementation:

- Only `.py` files are processed
- AST parsing using Python's `ast` module
- Extracts per function: name, parameters, return type, body source, decorators, calls, globals used, imports
- Call graph: intra-file only (`callers` and `callees`)
- Security facts extracted via `extractors.python.extract()` and added to every slice
- Nested functions are skipped (would create slice ID collisions)
- `_body()` includes the `def` line but not decorators
- `_globals_used()` uses set intersection — O(n) on AST size
- Slice ID: `{file_path}::{function_name}`

Slice format:

```json
{
  "function_name": "str",
  "file_path": "str",
  "file_hash": "str",
  "parameters": ["str"],
  "return_type": "str or null",
  "body": "str",
  "decorators": ["str"],
  "calls": ["str"],
  "globals_used": ["str"],
  "imports": ["str"],
  "context": {"callers": ["str"], "callees": ["str"]},
  "security_facts": [{"type": "str", ...}]
}
```

`security_facts` is always a list (empty `[]` when nothing found, never absent). See `extractors/` below.

### Hypothesise (`hypothesise.py`)

Purpose: For each slice, ask the local model to propose attack-relevant hypotheses.

Implementation:

- Loads prompt from `inference/prompts/hypothesise.txt`
- Uses `inference/runner.py` to run llama-cli in sandbox
- `_extract_json()` uses `json.JSONDecoder().raw_decode()` from first `{` — ignores trailing llama.cpp chatter
- `[str(x) for x in ...]` on `suggested_inputs` coerces non-string elements before schema validation
- `logs_dir` created before loop — prevents `infer()` failure on missing directory
- `model_hash` in audit uses `spec.sha256` from lock file (always available even if all slices fail)
- Invalid model output (missing fields, wrong types) is silently discarded
- Only produces `Status.PROPOSED` via `Hypothesis.propose()`

`_format_slice()` renders the slice dict as a `# File: / # Function: / ...` header block. Security facts
are rendered at the end of the header via `_render_fact()`:

```
# Security facts:
#   subprocess(shell=default_false, argv=unknown)
#   file write: path from parameter:stderr_log_path
```

`_render_fact()` is a pure formatting helper; it does not interpret or judge facts.

State transition:

- This stage only produces `Status.PROPOSED`
- Verdict transitions live in `verify.py`
- Enforced via `Hypothesis.propose()`

### Synthesise (`synthesise.py`)

Purpose: For each hypothesis, ask the local model to generate concrete payloads.

Implementation:
- Follows same pattern as `hypothesise.py`
- Prompt from `inference/prompts/seed_payloads.txt`
- Payload format minimal: `{hypothesis_id, value, category, rationale}`
- No schema validation — payloads are plain dicts (intentional)

Payload format:

```json
{
  "hypothesis_id": "str",
  "value": "str",
  "category": "baseline | encoded | oversized | unicode | nested | polyglot",
  "rationale": "str",
  "marker": "VULNFORGE_<16hex>"
}
```

`marker` is only present for `command_injection` payloads. When present, the payload `value` has `; echo {marker}`
appended. `verify` uses the marker to distinguish "injection executed" from "process crashed with an error".

### Execute (`execute.py`)

Purpose: Run each payload against its target inside the sandbox, capture an Observation, and move the corresponding hypothesis from PROPOSED to TESTED.

Implementation:

- `hyp_manifest` loaded via `refs.read("hypotheses_latest")` — execute doesn't take a `hypotheses_ref` parameter
- `tested_hypothesis_ref` added to each observation — verify needs to load the TESTED hypothesis
- Separate `tested_hypotheses_latest` ref written as a manifest
- `_run_payload()` catches `Exception` broadly — podman startup failure records `exit_code=-1` without crashing
- `mark_tested()` silently skips if hypothesis already TESTED (multiple payloads, same hypothesis)

State transition:

- This module owns `PROPOSED → TESTED` transition
- `mark_tested()` is the only function that can set `status=Status.TESTED`
- Grep for `status=Status.TESTED` and you find it here, only here

Observation format:

```json
{
  "payload_id": "str",
  "hypothesis_id": "str",
  "exit_code": 0,
  "stdout": "str",
  "stderr": "str",
  "timed_out": false,
  "duration_seconds": 1.23,
  "tested_hypothesis_ref": "str",
  "marker": "VULNFORGE_<16hex>"
}
```

`marker` is only present when the payload carried one (i.e., the attack type was `command_injection`).
`verify._decide` uses `obs.get("marker", "")` so old observations without the field are handled transparently.

### Verify (`verify.py`)

Purpose: Compare observations against hypotheses without using the AI. CVE
correlation runs as the last step, labelling confirmed findings.

Implementation:
- Uses `observations_ref` and `refs.read("tested_hypotheses_latest")`
- CONFIRMED always wins: if a hypothesis already has a CONFIRMED verdict, subsequent observations skipped
- Existing verdict loaded from store, not just in-memory — survives refactors
- `_decide()` checks `timed_out` before `exit_code` — timed-out processes also have non-zero exit code (124)
- Updated hypothesis blob stored but not included in verdict dict — provenance chain already in hypothesis
- `cve_index.load()` called once before the loop; returns `None` when CVE data has not been bootstrapped
- `cve_refs: list[str]` attached to every verdict; populated for CONFIRMED findings where the attack_type maps to a CWE that has entries in the offline DB

Verdict logic:
| Condition | Verdict | Evidence |
|-----------|---------|----------|
| `timed_out == True` | CONFIRMED | "timed_out: true" |
| marker present AND `marker in stdout` | CONFIRMED | "marker in stdout: {marker}" |
| marker present AND `marker not in stdout` | falls through | (injection did not execute) |
| (no marker) `exit_code != 0` | CONFIRMED | "exit_code: {n}" |
| (no marker) `expected_effect in stdout` | CONFIRMED | "stdout contains expected_effect" |
| `attack_type == "dos" and not timed_out` | REFUTED | "dos attack completed without timeout" |
| `attack_type == "logical" and exit_code == 0` | REFUTED | "logical attack, exit_code: 0, no observable effect" |
| Default | REFUTED | "no confirming evidence" |

When a payload carries a marker, `exit_code != 0` is not enough to confirm: the marker appearing in stdout is the
only confirmation path (besides timeout). This prevents crashes or argument-rejection errors from producing false
positives.

State transition:
- This module owns `TESTED → CONFIRMED` and `TESTED → REFUTED`
- `confirm()` and `refute()` are the only assignment sites
- Grep for `status=Status.CONFIRMED` or `REFUTED` finds exactly two lines
- This is the entire enforcement of "AI cannot be the judge"

### Report (`report.py`)

Purpose: Emit human-readable findings from a verdicts ref.

Implementation:
- Uses `verdicts_ref` and `refs.read("tested_hypotheses_latest")`
- Report format: Markdown, no bold markers
- Output: `<workspace>/reports/report_<timestamp>.md`
- `output_refs` in audit carries file path string, not store digest (report is not content-addressed)
- CVEs line rendered for confirmed findings where `cve_refs` is non-empty

Report structure:

```
# Vulnerability Report
Generated: 2026-05-14T12:34:56Z
Summary: 3 confirmed, 2 refuted, 0 skipped

## Confirmed Findings

### file.py::function - attack_type
- Assumption broken: ...
- Expected effect: ...
- Evidence: ...
- CVEs: CVE-2024-xxxxx, GHSA-xxxx-xxxx-xxxx   (omitted when empty)
- Observation: ref...
- Provenance: hypothesise:...;tested:...;confirmed:...

## Refuted Hypotheses

### file.py::function - attack_type
- Reason: ...
- Provenance: ...
```

## Security fact extractor (`extractors/`)

Two-file package. `__init__.py` defines the shared type alias; `python.py` does the AST work.

```
extractors/
  __init__.py   # SecurityFact = dict[str, Any]; schema docstring only
  python.py     # extract(node) -> list[SecurityFact]
```

`extract()` runs four sub-walkers over the function AST:

| Sub-walker | Detects | Fact type |
|---|---|---|
| Subprocess | `subprocess.run/call/check_output/check_call/Popen`, `os.system`, `os.popen` | `subprocess` |
| File path | `open()`, `.open()`, `.write_text/bytes()`, `.read_text/bytes()` | `file_write` / `file_read` |
| Dangerous sink | `eval`, `exec`, `compile`, `pickle.loads`, `yaml.load`, `marshal.loads`, `os.system`, `os.popen`, `subprocess.*(shell=True)` | `dangerous_sink` |
| Environment access | `os.getenv()`, `os.environ[]`, `os.environ.get()`, `environ.get()` | `environment_access` |

Fact schema:

```
{"type": "subprocess",        "shell": True|False|"default_false"|"unknown", "argv_style": "list"|"string"|"unknown", "arg_source": ARG_SOURCE}
{"type": "file_write",        "path_source": ARG_SOURCE}
{"type": "file_read",         "path_source": ARG_SOURCE}
{"type": "dangerous_sink",    "name": str, "arg_source": ARG_SOURCE}
{"type": "environment_access","call": "os.getenv"|"os.environ[]"|"os.environ.get"|"environ.get"}
```

`shell` semantics:
- `True`/`False`: explicit boolean constant in source
- `"default_false"`: `shell` kwarg absent; relies on stdlib default (weaker than explicit `False`)
- `"unknown"`: dynamic expression; static analysis cannot resolve

`ARG_SOURCE` is the provenance of the value reaching the sink, computed by the shared `_classify_arg` helper:
- `"parameter:NAME"`: a bare parameter, direct identity
- `"parameter-derived"`: a parameter flows in via f-string interpolation or as a collection element
- `"constant"`: a literal; no parameter can reach it
- `"unknown"`: a helper call, a local, or anything the single-function pass cannot follow

`"unknown"` is the honest value when the extractor hits a static analysis limit. It is not the same as absence of a fact, and it is not the same as `"constant"`: a value the pass cannot follow is not proof the attacker has no influence over it. The screen stage relies on exactly this distinction.

Future languages: add `extractors/javascript.py` (same return type); wire into `stages/index.py`'s existing per-extension dispatch. No changes to `extractors/__init__.py` needed.

## Screen stage (`stages/screen.py`)

Sits between hypothesise and synthesise. Grounds each hypothesis against the slice's security facts, in code, before any payload is synthesised or executed. The deterministic answer to static-pattern enthusiasm: the model proposes attack classes by recall, the screen checks whether a parameter actually reaches a sink of the right kind.

`run(hypotheses_ref, slices_ref) -> (accepted_ref, screen_verdicts_ref)`. A hypothesis is mapped back to its slice by id (`<slice_id>::<idx>`, so the slice id is the id with its last segment stripped). The accepted ref is a hypothesis manifest of the same shape hypothesise emits, so synthesise consumes it with no signature change; the orchestrator feeds `screen_accepted_latest` to synthesise when the screen has run.

Grounding (`schema/screen.py`, `Grounding` enum): `grounded` (parameter reaches a matching sink, accept at full confidence), `unknown` (matching sink, provenance unresolved, accept but cap confidence at `UNKNOWN_CONFIDENCE_CAP` = 0.35), `contradicted` (facts rule the mechanism out, reject), `unsupported` (no matching sink, reject). `decide_policy()` maps a state to (accepted, effective_confidence); the cap is a policy constant, not a calibrated value, and the only property that matters is that unknown ranks below grounded.

Two pure functions carry the logic: `_grounding(hyp, facts, imports)` computes the state from an attack-class predicate table plus `arg_source`, resolving multiple matching sinks by precedence (grounded > unknown > contradicted > unsupported); `decide_policy` applies the cap. Verdicts for rejected hypotheses are stored too, not discarded, so a later run can ask how many unknown findings ever verify.

## Inference runner (`inference/runner.py`)

Purpose: llama.cpp subprocess wrapper. Inference runs inside the canonical sandbox.

Design Decisions:
- Prompt passed via stdin, not command line — prevents exposure via `/proc`
- `_extract_assistant_text()` handles llama-cli conversation-mode chrome:
  - Backspaces replayed (kills spinners)
  - ANSI escapes stripped
  - Trailing timings/Exiting block removed
  - Last `> ` prompt-echo line used as boundary
- Weights hash verified before each run
- `--single-turn` prevents multi-turn drift
- `--no-display-prompt` keeps prompt out of stdout
- Stderr logged to workspace `logs_dir` for debugging
- Deterministic: same `(weights_hash, prompt, seed)` → same output

### `no_think` flag

Qwen3-8B emits lengthy reasoning traces by default. When `ModelSpec.no_think=True`,
`/no_think` is prepended to the prompt before inference. This is treated as model
configuration rather than prompt logic.

Set in `bootstrap/models.lock` per model entry. Prompts stay model-agnostic; the
behaviour is documented in one place. Future models can carry other runtime quirks
(`chat_template`, `reasoning_effort`, etc.) the same way, without contaminating
prompt files.

Verified to work in plain completion mode (`--simple-io --single-turn`) without a
chat template: qwen3-8b skips the `<think>` block entirely when `/no_think` appears
at the start of the user turn.

Prompt Files:
- `inference/prompts/hypothesise.txt` — used by hypothesise stage
- `inference/prompts/seed_payloads.txt` — used by synthesise stage

Both prompts enforce the "model proposes, code decides" principle and require valid JSON output.

## Sandbox (`sandbox/run.py`)

Purpose: Canonical sandbox invocation. Rootless podman, no network, read-only root filesystem.

Isolation:
- `--network=none`
- `--read-only`
- `--cap-drop=ALL`
- `--security-opt no-new-privileges`
- `--user 65534:65534` (nobody/nogroup)
- `--pids-limit 256`
- `--memory 2g`
- `--cpus 2`

Lifecycle:
- Containers tracked in `_active` set
- `atexit` registration for clean-up
- SIGTERM translation to SystemExit
- Prevents "zombie container" pattern (container daemonised via conmon/runc)

Containerfile:
- Based on `debian:trixie-slim`
- Includes `llama.cpp` built from pinned tag
- Minimal image: anything inside is something an escaped payload could use

## Testing

### Sandbox clean-up (`test_sandbox_cleanup.py`)
- Enforces no `vulnforge-` containers left behind after normal exit or timeout
- Uses `_live_vulnforge_containers()` to verify

### Plumbing Ttest (`test_plumbing.py`)
- End-to-end smoke test for `vulnforge plumbing` command
- Verifies llama-cli produces output inside sandbox

### Pipeline test (`test_pipeline.py`)
- Full pipeline end-to-end on small test target
- Uses `new_run(base=base)` for isolated workspace
- Uses `plumbing-check` model for speed; tests pipeline wiring, not payload quality
- Harness unit tests (6 tests) run deterministically without a model or CVE data
- Timeout test asserts `timed_out=True` and `exit_code=124` after a 3-second limit

### CVE test (`test_cve.py`)
- CWE map coverage assertion
- Index load and match with a minimal OSV fixture file
- `load()` returns `None` when directory is absent
- `verify.run()` integration: patches `cve_index.load()` and asserts `cve_refs` in confirmed verdicts

## Known edge cases

1. Hypothesis already TESTED — `mark_tested()` silently passes if called twice. Multiple payloads can target same hypothesis; tested blob hash is identical.

2. Podman startup failure — Broad catch records `exit_code=-1` in observation rather than crashing stage.

3. Invalid model output — Skipped silently. Only valid JSON matching schema is stored.

4. Missing hypothesis in manifest — Payload skipped, counter incremented.

5. Target file missing from target manifest — Payload skipped.

6. Non-Python files in index — Skipped. Only `.py` files processed.

7. Nested functions in index — Skipped. Only top-level functions and one level of class methods (`ClassName.method_name`) are indexed.

8. llama.cpp chatter after JSON — `_extract_json()` stops at the end of the first valid JSON object. Trailing text is ignored.

9. CONFIRMED always wins — If a hypothesis already has a CONFIRMED verdict, subsequent observations are skipped (verified via existing verdict blob in store).

10. timed_out before exit_code — Timed-out processes have exit code 124; evidence string says the more informative thing.

## Audit events

All stages append `AuditEvent`:

| Stage       | model_hash  | seed          |
|-------------|-------------|---------------|
| ingest      | None        | None          |
| index       | None        | None          |
| hypothesise | spec.sha256 | user provided |
| synthesise  | spec.sha256 | user provided |
| execute     | None        | None          |
| verify      | None        | None          |
| report      | None        | None          |

## Workspace resolution

Workspace resolved in order:
1. `--workspace <path>` CLI flag
2. `$VULNFORGE_WORKSPACE` env var
3. `$XDG_DATA_HOME/vulnforge/`
4. `~/.local/share/vulnforge/` (fallback)

Each scan creates a fresh timestamped run directory under `runs/` within that root:
`~/.local/share/vulnforge/runs/<timestamp>/`

## Test results

| Test                      | Status    | Tests | Time  |
|---------------------------|-----------|-------|-------|
| `test_cve.py`             | Passing   | 5     | <1s   |
| `test_extractors.py`      | Passing   | 27    | <1s   |
| `test_screen.py`          | Passing   | 16    | <1s   |
| `test_probe_screen.py`    | Passing   | 5     | <1s   |
| `test_pipeline.py`        | Passing   | 13    | ~90s  |
| `test_plumbing.py`        | Passing   | 1     | ~10s  |
| `test_sandbox_cleanup.py` | Passing   | 2     | ~2s   |

## Model selection

| Stage       | Model            | Size   | Why                                                                         |
|-------------|------------------|--------|-----------------------------------------------------------------------------|
| Hypothesise | Qwen3-8B         | ~5GB   | Better reasoning, more capable at pattern recognition; `no_think=true` set  |
| Synthesise  | Qwen2.5-Coder-7B | ~4.7GB | Code-specialised, good at generating working payloads; no thinking overhead |

Qwen3-8B runs with `/no_think` prepended (via `ModelSpec.no_think`). Without it,
the model generates thousands of tokens of internal reasoning before any JSON,
exceeding the per-slice timeout on CPU. With it, output is direct and comparable
in speed to Qwen2.5-Coder-7B.

### Model management

`bootstrap/models.lock` contains pinned model weights:
- `qwen3-8b`: hypothesising (`no_think: true`)
- `qwen2.5-coder-7b`: synthesising
- `plumbing-check`: smoke tests (1.5B)

Run `vulnforge bootstrap` to download all models.

## CVE correlation (`cve/`)

Last step inside `stages/verify.py`. Labels confirmed findings; does not change whether a verdict is CONFIRMED or REFUTED.

### How it works

1. `cve/cwe_map.py`: static dict mapping `attack_type` strings to CWE IDs (e.g. `"code_execution"` → `["CWE-78", "CWE-94", "CWE-95"]`).
2. `cve/index.py`: `load()` walks `$XDG_DATA_HOME/vulnforge/cve/osv-pypi/` and builds a `CWE → [CVE/GHSA IDs]` index. Returns `None` when the directory is absent (safe: `cve_refs` defaults to `[]`).
3. `cve/index.py`: `match(db, attack_type)` returns CVE IDs for the matching CWEs.
4. `verify.run()` calls `load()` once before the verdict loop, then attaches `cve_refs` to each verdict dict.

### Data sources

Primary: OSV.dev PyPI ecosystem dump (`https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip`).
Downloaded by `bootstrap/fetch_cve.py` to `$XDG_DATA_HOME/vulnforge/cve/osv-pypi/`.

db.gcve.eu (CIRCL Luxembourg) is the intended long-term primary. It uses the same OSV format; when a confirmed bulk-download URL is available, it replaces the URL in `fetch_cve.py` with no other changes.

Model fallback (plumbing-check alias) for ambiguous matches: not yet implemented.

## Pipeline Performance

| Stage       | Typical Time     | Notes                                 |
|-------------|------------------|---------------------------------------|
| Ingest      | <1s              | File hashing                          |
| Index       | <1s              | AST parsing                           |
| Hypothesise | 30-60s           | Depends on model size and slice count |
| Synthesise  | 30-60s           | Depends on hypothesis count           |
| Execute     | 1-5s per payload | Sandbox startup overhead              |
| Verify      | <1s              | Deterministic comparison              |
| Report      | <1s              | Markdown generation                   |

Total (qwen3-8b + qwen2.5-7b): ~2-3 minutes for small codebases

## Open items

- Screen grounding effectiveness: the screen now grounds attack classes in code via `arg_source` rather than relying on the model to honour rule 12 in the prompt. Rule 12 stays as a cheap upstream nudge. Grounding versus unknown verify rates want measuring across a few real runs: if unknown findings almost never verify, the policy can tighten; if some confirmed findings come from the unknown bucket, the penalty stays. This is the empirical path the four-state model keeps open.
- Multi-language support: add `extractors/javascript.py` (same `list[SecurityFact]` return type, including `arg_source`); wire into `stages/index.py`'s per-extension dispatch. No other changes needed.
- Payload dispatch: the `category` field from synthesise (`input_string`, `fuzz_seed`, `request_sequence`) is not yet used by `execute._run_payload()`.
- Marker injection for additional attack types: `command_injection` is covered; `code_execution` needs Python-syntax marker embedding (e.g. `; print('MARKER')` inside eval targets).
- CVE model fallback: when the offline DB has no match for a confirmed finding, fall back to plumbing-check for ambiguous linking. Not yet implemented.
- Screening stage: landed as a taint-grounding gate (`stages/screen.py`). The location-resolution, payload-syntax, and reachability checks from the original `verdict-pipeline.md` sketch are not yet built; they can follow as the attack-type predicate table grows.
