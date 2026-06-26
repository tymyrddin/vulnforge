# Verdict pipeline plan

The unbuilt moves of the verdict pipeline. Move 1, the screening stage, has landed in
a taint-grounding form. [../architecture/](../architecture/) covers what it does and
[../decisions/2026-06-24-grounding-screen.md](../decisions/2026-06-24-grounding-screen.md)
covers why. What remains is Move 2 (closed-enum outcomes), Move 3 (end-to-end `_ref`
verification), and Move 4 (the correlation loop).

## Why this plan exists

vulnforge already settled three things: AI does not judge, the execution sandbox is
the only ground truth, and the audit log is hash-chained. Not yet settled is part of
the layer between "generator produced a hypothesis" and "execution returned an
observation". That layer drifts into AI theatre fastest, because every check appears to
benefit from "ask the model one more time".

The principle this plan locks in: between propose and execute, everything that can be a
deterministic structural check becomes one. Between execute and verify, the comparison
between hypothesis and observation is also deterministic, and emits a closed-enum
verdict that later runs can be statistically compared against. Models propose; tools
decide.

## Move 2: lock the verify stage

Precondition: the hypothesis needs a closed-enum predicted outcome, not free-text
`expected_effect`. Add `expected_outcome: Outcome` to `Hypothesis`, populated from the
model output via the screening stage. `expected_effect` stays for human readers as
narrative; `expected_outcome` is what the verifier compares against. A hypothesis whose
`expected_effect` cannot be mapped onto an `Outcome` value is a screen reject, not an
undefined verify case.

`stages/verify.py:run` becomes a deterministic comparator over the (`Hypothesis`,
`Observation`) pair. Output is a `Verdict` with a closed-enum `VerificationFailure`
field (populated only when status is REFUTED). Reasoning becomes a structured
reference, not prose: it carries the comparison rule that fired and the observation
digest, nothing else.

Closed enum draft for `VerificationFailure`:

- `expected_crash_no_crash`: hypothesis predicted CRASH, observation was CLEAN_EXIT or
  NONZERO_EXIT.
- `expected_exit_no_signal`: hypothesis predicted NONZERO_EXIT, observation was
  CLEAN_EXIT.
- `expected_sanitiser_silent`: hypothesis predicted SANITISER_REPORT, observation
  produced no sanitiser output.
- `timeout_inconclusive`: observation was TIMEOUT, comparison cannot conclude either
  way. A TIMEOUT is a refute-with-doubt, kept separate from a clean refute.
- `payload_did_not_execute`: target rejected the payload before any vulnerable path
  could be reached (e.g. parse error in the target before the parser-under-test was
  hit). Refute with low confidence: the hypothesis might still be right but this
  payload did not test it.
- `evidence_mismatch_other`: catch-all for cases the taxonomy missed. A measurement
  surface, not a permanent escape hatch.

The enum stays closed. An open enum is prose with extra steps.

## Move 3: confirm content-addressed references end to end

The store is already content-addressed. The remaining check is that every `_ref` field
in the schema resolves to a store digest, not a wall-clock or path-shaped id:

- `Verdict.hypothesis_ref` and `Verdict.observation_ref`: sha256 digests of the
  canonicalised JSON of the underlying object.
- `Observation.payload_ref`: sha256 of the payload bytes.
- `Observation.stdout_hash` and `stderr_hash`: already present and hash-shaped.
- `AuditEvent.input_refs` and `output_refs`: sha256 digests, no exceptions.

The canonicalisation rule (key-sorted JSON, no whitespace, utf-8) becomes a helper in
`store/objects.py` so callers cannot quietly disagree on what "the bytes of this
hypothesis" means. The `verify_chain` check gains a stricter form: every `_ref` on
every record is dereferenceable in the store, or the chain is considered broken.

## Move 4: the correlation loop

Per run, emit two JSONL summaries:

- `runs/<run-id>/screening-report.jsonl`
- `runs/<run-id>/verification-report.jsonl`

Each line is one decision:

```
{"hypothesis_ref": "...", "screen_decision": "accepted",
 "verify_outcome": "confirmed", "failure_mode": null}
```

A `vulnforge stats` subcommand walks any subset of `runs/*/` and emits counts:

- Per screen reason: how many hypotheses were dropped at the screen stage, by
  `attack_type` and by check.
- Per `VerificationFailure`: how many TESTED hypotheses went on to be refuted, by
  failure mode.
- Joint: of hypotheses the screener accepted, what fraction reached a CONFIRMED
  verdict; of hypotheses the screener accepted with a given `attack_type` predicate,
  what fraction reached a CONFIRMED verdict.

Without this loop, the screener is unfalsifiable, and the comparison rules in verify
drift into folklore. With it, a check that never rejects anything, or a comparison rule
that fires only on `evidence_mismatch_other`, becomes visible.

The reports stay per-run by default. Aggregation is an opt-in command and reads only
from disk; no global state, no daemon, no sidecar.

The grounding-distribution metrics in [../metrics/README.md](../metrics/README.md) are
the first concrete consumer of this loop: `vulnforge stats` walks `runs/*/` for the
fact-level provenance coverage and the verdict-level grounding distribution. The two
are read together because each measures a different layer.

## Sequencing

2 and 3 together. The closed-enum verdict and end-to-end content addressing are
co-dependent: a verdict points at object digests by contract, so verifying the contract
and writing the comparator make sense as one piece of work.

4 last. The correlation loop has nothing to correlate until 2 has produced output for a
few runs. Building the loop before there is data to feed it is the same theatre this
plan avoids.

## What this is not

- A reintroduction of an AI judge. The verify stage stays in deterministic comparison
  territory. The screening stage uses parsers, registries, and reachability tools; the
  only model in this pipeline is the one that produces the hypothesis in the first
  place.
- A reason to make `stages/screen.py` clever. If a check needs prose to explain itself,
  it does not belong in this stage. It belongs in a comment somewhere far away, or in a
  paper.
- A measurement framework. `vulnforge stats` reads the per-run files and counts. It
  does not score, it does not weight, and it does not tell anyone what to think about
  the numbers.

## Naming note

The landed Move 1 reason enum is `ScreenReason` in `schema/screen.py`. It carries eight
values grouped by grounding state: `param_reaches_sink` (grounded);
`sink_source_unresolved`, `insufficient_sql_evidence`, `attack_type_unrecognised`,
`screen_other` (unknown); `shell_metachars_under_shell_false`, `constant_sink_arg`
(contradicted); and `no_matching_sink` (unsupported). Every reason carries a grounding
state, so a rejection records why it was rejected, not only that it was. The Move 2
`VerificationFailure` enum above follows the same closed-enum discipline.

## Triggers to revisit

Reasons this plan could turn out to be wrong, with where to look:

- The closed-enum verdict taxonomy collapses everything into `evidence_mismatch_other`.
  That means the taxonomy missed the actual failure shape and needs growing, not that
  closed enums were the wrong call.
- The screener rejects nothing across many runs. Either the generator already produces
  well-formed output (unlikely, given the strcpy-shaped failures already seen) or the
  screener's checks are too weak. The rejections that did fire, and the hypotheses that
  reached execute and then failed, mark the gap; that gap between the two sets is where
  new checks live.
- A check requires more than a screen-full of code to express. That is a signal it
  belongs in `stages/verify.py` or in a dedicated module, not buried in screening.
