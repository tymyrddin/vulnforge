# Verdict pipeline plan

Status: partially implemented.

What is done: `stages/verify.py` implements a deterministic comparator over
`(Hypothesis, Observation)` pairs, emitting CONFIRMED/REFUTED verdicts. CVE
correlation runs as the last step inside verify: CWE-based lookup against an
offline OSV dump, with `cve_refs` attached to each verdict. `vulnforge
bootstrap` downloads the CVE data. Move 1 (the screening stage) has landed, in
a taint-grounding form described below.

What remains from this plan: the closed-enum failure modes on `Hypothesis`
from Move 2, and Move 4 (correlation loop / `vulnforge stats`). Move 3
(content-addressing) is substantially in place via the object store; the
stricter `_ref`-field verification is not.

## Why this plan exists

vulnforge already settled three things: AI does not judge, the
execution sandbox is the only ground truth, and the audit log is
hash-chained. What it has not yet settled is the layer between
"generator produced a hypothesis" and "execution returned an
observation". That layer can drift into AI theatre fastest, because
every check feels like it benefits from "ask the model one more
time".

The principle this plan locks in: between propose and execute,
everything that can be a deterministic structural check becomes one.
Between execute and verify, the comparison between hypothesis and
observation is also deterministic, and emits a closed-enum verdict
that later runs can be statistically compared against. Models
propose; tools decide.

## What is already in place

Hash gates and storage:

- Content-addressed store under `store/objects/` (`store/objects.py`),
  sha256 atomic writes, hash-verified reads.
- Hash-chained JSONL audit log (`audit/log.py`) with `verify_chain()`.

Schema gates (the proto-verifier):

- `Hypothesis.propose` rejects `EvidenceType.EXECUTION_OBSERVED` and
  `VerificationStatus.CONFIRMED` at construction.
- `suggested_inputs` regex constraint `^[^*()]+$` rejects Python
  expressions masquerading as inputs.
- Three orthogonal schema axes (`Status`, `EvidenceType`,
  `VerificationStatus`) carry uncertainty separately from lifecycle.

No-AI-judge:

- Verdict transitions live in two files and grep for them returns the
  exact line. `stages/verify.py:confirm` and `refute` are
  stage-owned; `stages/execute.py:mark_tested` owns PROPOSED to
  TESTED.

What is missing:

- A pre-execution screening stage that catches structurally invalid
  hypotheses before a container is spawned for them.
- The body of `stages/verify.py:run`, currently `NotImplementedError`.
- A closed-enum predicted outcome on `Hypothesis`, so the verify
  stage has something concrete to compare against.
- A closed enum of verdict failure modes, suitable for grouping
  rejection counts across runs.
- A correlation surface that lets a future run answer "did our
  screening rules actually reduce wasted container launches".

## Move 1: a screening stage (implemented)

`stages/screen.py` sits between hypothesise and synthesise, not hypothesise
and execute: rejecting a hypothesis before synthesise saves the synthesis model
call as well as the container launch. It reads the hypothesis manifest and the
slice manifest, and emits two refs, `screen_accepted_latest` (a hypothesis
manifest, same shape as hypothesise output, so synthesise consumes it unchanged)
and `screen_verdicts_latest` (one `ScreenVerdict` per hypothesis, accepted or
rejected, kept for measurement).

The shape that landed is taint grounding, a refinement of the attack-type
consistency check below. The prompted reason: a reviewer pointed out that the
pipeline classified vulnerability tropes onto sinks without ever checking
whether attacker-controlled data reaches them. The fix is to compute that
source-to-sink relation in code, from the `arg_source` provenance now carried on
every subprocess and dangerous-sink fact (`extractors/python.py`), and make it
consequential for acceptance and confidence rather than leaving it as advice in
the prompt.

Each hypothesis lands in one of four grounding states, defined in
`schema/screen.py`:

- `grounded`: a parameter reaches a sink matching the attack class. Accept at
  the model's confidence.
- `unknown`: a matching sink exists but its argument provenance is unresolved
  (a helper call the single-function AST pass cannot follow). Accept, but cap
  confidence at `UNKNOWN_CONFIDENCE_CAP` (0.35, a policy constant, not a measured
  threshold; the only load-bearing property is that unknown ranks below grounded).
  "Unresolved" is the analysis hitting its limit, not proof the attacker has no
  influence, so the hypothesis survives at a lowered prior rather than being
  discarded.
- `contradicted`: the facts rule the mechanism out, for example shell
  metacharacters under `shell=False`, or a constant sink argument no parameter
  can reach. Reject.
- `unsupported`: no sink matching the attack class exists in the slice. Reject.

The line that this stage exists to hold: never conflate "not tainted"
(constant, contradicted) with "taint unresolved" (unknown). Where several
matching sinks disagree, the strongest claim wins, grounded over unknown over
contradicted over unsupported, so an analysis limit on one sink never
masquerades as proof across the others.

Two honesty rules on the edges. Catch-all reasons (`attack_type_unrecognised`
for a class with no detector, `screen_other`) land in `unknown`, never
`unsupported`, so a novel attack class is penalised rather than silently
rejected. SQL injection has no sink detector, so it is assessed by imports as a
deliberately weak signal: no database import is `unsupported`, a database import
with no detectable query construction is `unknown` (`insufficient_sql_evidence`),
never grounded.

The original Move 1 sketch below also named location-resolution, payload-syntax,
and reachability checks. Those have not landed yet; the grounding gate was the
move that answered the reviewer's critique, and the others can follow as the
attack-type predicate registry grows.

Naming note: the landed reason enum is `ScreenReason` in `schema/screen.py`, not
`ScreenFailure` as the draft below calls it. It carries eight values grouped by
grounding state: `param_reaches_sink` (grounded); `sink_source_unresolved`,
`insufficient_sql_evidence`, `attack_type_unrecognised`, `screen_other` (unknown);
`shell_metachars_under_shell_false`, `constant_sink_arg` (contradicted); and
`no_matching_sink` (unsupported). Every reason carries a grounding state, so a
rejection records why it was rejected, not only that it was. `ScreenFailure` below
is the earlier draft name, kept for the history.

Checks from the original sketch, deterministic and cheap:

- Location resolves. `Hypothesis.location` is a file path with an
  optional line or symbol. The screener confirms the file is in the
  corpus, the line exists, the symbol (if named) is parseable in
  that file. Caught before container spin-up.
- Payload syntax. Where `suggested_inputs` claims to be a parseable
  artefact (URL, JSON, SQL fragment, shell argument), the screener
  parses it. A payload that does not parse cannot be a faithful
  rendering of an exploit.
- Attack-type consistency. Each `attack_type` value maps to a small
  predicate over the rest of the hypothesis: a SQLi hypothesis names
  a query-construction location, a path-traversal hypothesis names a
  filesystem-call location. Predicates live in a registry keyed by
  `attack_type`. Predicate failure is a screen reject.
- Reachability. Where feasible (Python, C with available source), a
  static check that the named location is reachable from at least
  one entry point. Reachability misses are expensive; this check
  can stay optional behind a flag until it earns its keep.

The screen stage emits one audit event per hypothesis, with
`output_refs` pointing at either the accepted hypothesis blob or the
rejection record. Rejections are stored, not discarded, because
"hypotheses we threw away" is a measurement input. A discarded
hypothesis is data; a deleted one is silence.

Closed enum draft for `ScreenFailure`:

- `location_not_in_corpus`
- `location_line_out_of_range`
- `symbol_unparseable`
- `payload_parse_failed`
- `attack_type_predicate_failed`
- `unreachable_from_entry_points`
- `screen_other`: measurement-only catch-all for taxonomy gaps. A
  rising count here is a signal to grow the taxonomy, not to leave
  the bucket open forever.

## Move 2: lock the verify stage

Precondition: the hypothesis needs a closed-enum predicted outcome,
not free-text `expected_effect`. Add `expected_outcome: Outcome` to
`Hypothesis`, populated from the model output via the screening
stage. `expected_effect` stays for human readers as narrative;
`expected_outcome` is what the verifier compares against. A
hypothesis whose `expected_effect` cannot be mapped onto an
`Outcome` value is a screen reject under `attack_type_predicate_failed`,
not an undefined verify case.

`stages/verify.py:run` becomes a deterministic comparator over the
(`Hypothesis`, `Observation`) pair. Output is a `Verdict` with a
closed-enum `VerificationFailure` field (populated only when status
is REFUTED). Reasoning becomes a structured reference, not prose: it
carries the comparison rule that fired and the observation digest,
nothing else.

Closed enum draft for `VerificationFailure`:

- `expected_crash_no_crash`: hypothesis predicted CRASH, observation
  was CLEAN_EXIT or NONZERO_EXIT.
- `expected_exit_no_signal`: hypothesis predicted NONZERO_EXIT,
  observation was CLEAN_EXIT.
- `expected_sanitiser_silent`: hypothesis predicted SANITISER_REPORT,
  observation produced no sanitiser output.
- `timeout_inconclusive`: observation was TIMEOUT, comparison cannot
  conclude either way. A TIMEOUT is a refute-with-doubt, kept
  separate from a clean refute.
- `payload_did_not_execute`: target rejected the payload before any
  vulnerable path could be reached (e.g. parse error in the target
  before the parser-under-test was hit). Refute with low confidence:
  the hypothesis might still be right but this payload did not test
  it.
- `evidence_mismatch_other`: catch-all for cases the taxonomy missed.
  Same rule as `screen_other`: a measurement surface, not a
  permanent escape hatch.

A closed enum is the point. An open enum is prose with extra steps.

## Move 3: confirm content-addressed references end to end

The store is already content-addressed. The remaining check is that
every `_ref` field in the schema resolves to a store digest, not a
wall-clock or path-shaped id:

- `Verdict.hypothesis_ref` and `Verdict.observation_ref`: sha256
  digests of the canonicalised JSON of the underlying object.
- `Observation.payload_ref`: sha256 of the payload bytes.
- `Observation.stdout_hash` and `stderr_hash`: already present and
  hash-shaped.
- `AuditEvent.input_refs` and `output_refs`: sha256 digests, no
  exceptions.

The canonicalisation rule (key-sorted JSON, no whitespace, utf-8)
becomes a helper in `store/objects.py` so callers cannot quietly
disagree on what "the bytes of this hypothesis" means. The
`verify_chain` check gains a stricter form: every `_ref` on every
record is dereferenceable in the store, or the chain is considered
broken.

## Move 4: the correlation loop

Per run, emit two JSONL summaries:

- `runs/<run-id>/screening-report.jsonl`
- `runs/<run-id>/verification-report.jsonl`

Each line is one decision:

```
{"hypothesis_ref": "...", "screen_decision": "accepted",
 "verify_outcome": "confirmed", "failure_mode": null}
```

A `vulnforge stats` subcommand walks any subset of `runs/*/` and
emits counts:

- Per `ScreenFailure`: how many hypotheses were dropped at the
  screen stage, by `attack_type` and by check.
- Per `VerificationFailure`: how many TESTED hypotheses went on to
  be refuted, by failure mode.
- Joint: of hypotheses the screener accepted, what fraction reached
  a CONFIRMED verdict; of hypotheses the screener accepted with a
  given `attack_type` predicate, what fraction reached a CONFIRMED
  verdict.

This is the bit that keeps the rest honest. Without it, the screener
is unfalsifiable, and the comparison rules in verify drift into
folklore. With it, a check that never rejects anything, or a
comparison rule that fires only on `evidence_mismatch_other`,
becomes visible.

The reports stay per-run by default. Aggregation is an opt-in
command and reads only from disk; no global state, no daemon, no
sidecar.

The grounding-distribution metrics in `docs/roadmap.md` ("Measuring the grounding
distribution") are the first concrete consumer of this loop: `vulnforge stats` walks
`runs/*/` for the fact-level provenance coverage and the verdict-level grounding
distribution. The two are read together because each measures a different layer.

## Sequencing

1 first. The screen stage is the cheapest unlocking move and pays
for itself the first time it catches a malformed hypothesis before a
container spin-up.

2 and 3 together. The closed-enum verdict and end-to-end content
addressing are co-dependent: a verdict points at object digests by
contract, so verifying the contract and writing the comparator make
sense as one piece of work.

4 last. The correlation loop has nothing to correlate until 1 and 2
have produced output for a few runs. Building the loop before there
is data to feed it is the same theatre this plan is trying to avoid.

## What this is not

- A reintroduction of an AI judge. The verify stage stays in
  deterministic comparison territory. The screening stage uses
  parsers, registries, and reachability tools; the only model in
  this pipeline is the one that produces the hypothesis in the
  first place.
- A reason to make `stages/screen.py` clever. If a check needs
  prose to explain itself, it does not belong in this stage. It
  belongs in a comment somewhere far away, or in a paper.
- A measurement framework. `vulnforge stats` reads the per-run
  files and counts. It does not score, it does not weight, and it
  does not tell anyone what to think about the numbers.

## Triggers to revisit

Reasons this plan could turn out to be wrong, listed so future-us
knows where to look:

- The closed-enum verdict taxonomy collapses everything into
  `evidence_mismatch_other`. That means the taxonomy missed the
  actual failure shape and needs growing, not that closed enums
  were the wrong call.
- The screener rejects nothing across many runs. Either the
  generator already produces well-formed output (unlikely, given
  the strcpy-shaped failures already seen) or the screener's checks
  are too weak. Inspect the rejections that did fire, and the
  hypotheses that reached execute and then failed; the gap between
  those two sets is where new checks live.
- A check requires more than a screen-full of code to express.
  That is a signal it belongs in `stages/verify.py` or in a
  dedicated module, not buried in screening.