# Pipeline: per-stage reference

Eight stages. Each reads a ref, writes a ref, appends one audit event. [overview.md](overview.md)
covers the map and the cross-stage patterns.

## Ingest (`ingest.py`)

Purpose: walk a local repo, hash each file into the store, produce a manifest.

- Walks the directory tree.
- Skips common noise: `.git`, `.venv`, `node_modules`, `.vulnforge`, `__pycache__`, `.idea`.
- Each file is hashed to SHA256 via `objects.put()`.
- Manifest: `{file_path: digest}`.
- Writes `refs.write("ingest_latest", manifest_ref)`.
- Audit log with `stage="ingest"`, `model_hash=None`, `seed=None`.

## Index (`index.py`)

Purpose: parse ingested files into ASTs, extract symbols and call graph, produce per-function slices.

- Only `.py` files are processed.
- AST parsing uses Python's `ast` module.
- Extracts per function: name, parameters, return type, body source, decorators, calls, globals
  used, imports.
- Call graph: intra-file only (`callers` and `callees`).
- Security facts extracted via `extractors.python.extract()` and added to every slice.
  [security.md](security.md) covers security facts.
- Nested functions are skipped (they would create slice ID collisions). Top-level functions and one
  level of class methods (`ClassName.method_name`) are indexed.
- `_body()` includes the `def` line but not decorators.
- `_globals_used()` uses set intersection, O(n) on AST size.
- Slice ID: `{file_path}::{function_name}`.

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

`security_facts` is always a list (empty `[]` when nothing found, never absent).

## Hypothesise (`hypothesise.py`)

Purpose: for each slice, ask the local model to propose attack-relevant hypotheses.

- Loads prompt from `inference/prompts/hypothesise.txt`.
- Uses `inference/runner.py` to run llama-cli in the sandbox. [sandbox.md](sandbox.md) covers the
  runner.
- `_extract_json()` uses `json.JSONDecoder().raw_decode()` from the first `{`, ignoring trailing
  llama.cpp chatter.
- `[str(x) for x in ...]` on `suggested_inputs` coerces non-string elements before schema validation.
- `logs_dir` is created before the loop, which prevents `infer()` failing on a missing directory.
- `model_hash` in the audit uses `spec.sha256` from the lock file (available even if all slices fail).
- Invalid model output (missing fields, wrong types) is silently discarded.
- Only produces `Status.PROPOSED` via `Hypothesis.propose()`.

`_format_slice()` renders the slice dict as a `# File: / # Function: / ...` header block. Security
facts are rendered at the end of the header via `_render_fact()`:

```
# Security facts:
#   subprocess(shell=default_false, argv=unknown, arg=unknown)
#   file write: path from parameter:stderr_log_path
```

`_render_fact()` is a pure formatting helper; it does not interpret or judge facts.

State transition: this stage only produces `Status.PROPOSED`, enforced via `Hypothesis.propose()`.
Verdict transitions live in `verify.py`.

## Screen (`screen.py`)

Sits between hypothesise and synthesise. Grounds each hypothesis against the slice's security facts,
in code, before any payload is synthesised or executed. The model proposes attack classes by recall;
the screen checks whether a parameter actually reaches a sink of the right kind. No AI.

`run(hypotheses_ref, slices_ref) -> (accepted_ref, screen_verdicts_ref)`. A hypothesis is mapped
back to its slice by id (`<slice_id>::<idx>`, so the slice id is the id with its last segment
stripped). The accepted ref is a hypothesis manifest of the same shape hypothesise emits, so
synthesise consumes it with no signature change; the orchestrator feeds `screen_accepted_latest` to
synthesise when the screen has run.

Verdicts for rejected hypotheses are stored too, not discarded, so a later run can ask how many
unknown findings ever verify. The four grounding states, `decide_policy`, and the confidence cap are
described in [security.md](security.md).

## Synthesise (`synthesise.py`)

Purpose: for each hypothesis, ask the local model to generate concrete payloads.

- Follows the same pattern as `hypothesise.py`.
- Prompt from `inference/prompts/seed_payloads.txt`.
- Payload format is minimal: `{hypothesis_id, value, category, rationale}`.
- No schema validation; payloads are plain dicts (intentional).

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

`marker` is only present for `command_injection` payloads. When present, the payload `value` has
`; echo {marker}` appended. `verify` uses the marker to distinguish "injection executed" from
"process crashed with an error".

## Execute (`execute.py`)

Purpose: run each payload against its target inside the sandbox, capture an Observation, and move
the corresponding hypothesis from PROPOSED to TESTED.

- `hyp_manifest` is loaded via `refs.read("hypotheses_latest")`; execute does not take a
  `hypotheses_ref` parameter.
- `tested_hypothesis_ref` is added to each observation; verify needs to load the TESTED hypothesis.
- A separate `tested_hypotheses_latest` ref is written as a manifest.
- `_run_payload()` catches `Exception` broadly; a podman startup failure records `exit_code=-1`
  without crashing.
- `mark_tested()` silently skips if a hypothesis is already TESTED (multiple payloads, same
  hypothesis; the tested blob hash is identical).

State transition: this module owns the `PROPOSED → TESTED` transition. `mark_tested()` is the only
function that can set `status=Status.TESTED`. `status=Status.TESTED` appears here, only here.

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

`marker` is only present when the payload carried one (the attack type was `command_injection`).
`verify._decide` uses `obs.get("marker", "")`, so observations without the field are handled
transparently.

## Verify (`verify.py`)

Purpose: compare observations against hypotheses without using the AI. CVE correlation runs as the
last step, labelling confirmed findings. [cve.md](cve.md) covers correlation.

- Takes `observations_ref`; the hypothesis under test is read from each observation's embedded `tested_hypothesis_ref`, not from a separate named ref.
- CONFIRMED always wins: if a hypothesis already has a CONFIRMED verdict, subsequent observations
  are skipped.
- The existing verdict is loaded from the store, not just in-memory, so it survives refactors.
- `_decide()` checks `timed_out` before `exit_code`; timed-out processes also have a non-zero exit
  code (124).
- The updated hypothesis blob is stored but not included in the verdict dict; the provenance chain
  is already in the hypothesis.
- `cve_index.load()` is called once before the loop; it returns `None` when CVE data has not been
  bootstrapped.
- `cve_refs: list[str]` is attached to every verdict; populated for CONFIRMED findings where the
  attack_type maps to a CWE that has entries in the offline DB.

Verdict decision rule:

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

When a payload carries a marker, `exit_code != 0` is not enough to confirm: the marker appearing in
stdout is the only confirmation path (besides timeout). This prevents crashes or argument-rejection
errors from producing false positives.

State transition: this module owns `TESTED → CONFIRMED` and `TESTED → REFUTED`. `confirm()` and
`refute()` are the only assignment sites. `status=Status.CONFIRMED,` or `status=Status.REFUTED,`
(with the trailing comma) matches exactly the two assignment lines. This is the entire enforcement of
"AI cannot be the judge".

## Report (`report.py`)

Purpose: emit human-readable findings from a verdicts ref.

- Uses `verdicts_ref` and `refs.read("tested_hypotheses_latest")`.
- Report format: Markdown, no bold markers.
- Output: `<workspace>/reports/report_<timestamp>.md`.
- `output_refs` in the audit carries the file path string, not a store digest (the report is not
  content-addressed).
- The CVEs line is rendered for confirmed findings where `cve_refs` is non-empty.

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

## Known edge cases

1. Hypothesis already TESTED: `mark_tested()` silently passes if called twice. Multiple payloads can
   target the same hypothesis; the tested blob hash is identical.
2. Podman startup failure: the broad catch records `exit_code=-1` in the observation rather than
   crashing the stage.
3. Invalid model output: skipped silently. Only valid JSON matching the schema is stored.
4. Missing hypothesis in manifest: payload skipped, counter incremented.
5. Target file missing from the target manifest: payload skipped.
6. Non-Python files in index: skipped. Only `.py` files processed.
7. Nested functions in index: skipped. Only top-level functions and one level of class methods
   (`ClassName.method_name`) are indexed.
8. llama.cpp chatter after JSON: `_extract_json()` stops at the end of the first valid JSON object.
   Trailing text is ignored.
9. CONFIRMED always wins: if a hypothesis already has a CONFIRMED verdict, subsequent observations
   are skipped (verified via the existing verdict blob in the store).
10. timed_out before exit_code: timed-out processes have exit code 124; the evidence string says the
    more informative thing.
