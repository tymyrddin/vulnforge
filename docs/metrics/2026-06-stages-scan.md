# Grounding metrics: first real scan

A record of the first measured scan on a real corpus, with the data and what it does
and does not show. The corpus is the repository's own pipeline code under `stages/`, a
self-test: vulnforge is asked to find vulnerabilities in the very stages that decide
what counts as a vulnerability.

This is a single data point, not a benchmark. The interpretations below hold for this
corpus and this run; the pinned-corpus plan in
[../roadmap/README.md](../roadmap/README.md) turns points like this into a series. The
two metrics are defined in [README.md](README.md).

## Run identity

| Field             | Value                                          |
|-------------------|------------------------------------------------|
| Run               | `runs/20260625T132915Z/`                       |
| Date              | 2026-06-25                                     |
| Corpus            | `stages/` (this repository)                    |
| Hypothesise model | qwen3-8b (`d98cdcbd03e17ce4…`), seed 1         |
| Synthesise model  | qwen2.5-coder-7b (`509287f78cb4d4cf…`), seed 2 |
| Audit chain       | 8 entries, verified                            |

Reproduce: `vulnforge scan stages/`, then walk the run's `index_latest` slices and
`screen_verdicts_latest` manifest. The audit log carries the model hashes and seeds.

## Pipeline data

| Stage       | Summary                                                               | Model calls          |
|-------------|-----------------------------------------------------------------------|----------------------|
| ingest      | 9 files ingested                                                      | 0                    |
| index       | 44 slices from 9 Python files                                         | 0                    |
| hypothesise | 61 hypotheses from 44 slices                                          | 44 (one per slice)   |
| screen      | 1/61 accepted (grounded=0, unknown=1, contradicted=0, unsupported=60) | 0                    |
| synthesise  | 0 payloads from 1 hypotheses                                          | 1 (one per accepted) |
| execute     | 0 observations, 0 skipped                                             | 0                    |
| verify      | 0 verdicts, 0 skipped                                                 | 0                    |
| report      | 0 confirmed, 0 refuted, 0 skipped                                     | 0                    |

45 model calls total: 44 in hypothesise, 1 in synthesise. Only hypothesise runs the
model once per slice, so it owns nearly all of the roughly two-and-three-quarter-hour
wall clock. Everything downstream is either deterministic code over in-memory manifests
(screen, verify, report run in milliseconds) or scales with accepted hypotheses rather
than slices. The screen gate dropping 61 to 1 cut synthesise from a potential 61 model
calls to 1, and saved the matching container launches in execute.

## Metric 1: fact-level provenance coverage

Deterministic, model-free. Computed over the run's index slices.

```text
provenance-bearing facts: 5   (file_write: 2, file_read: 3)
resolved: 0/5  (0.0%)
unknown:  5/5  (100.0%)
```

`stages/` carries no subprocess and no dangerous-sink facts at all: the stage code
shells out nothing, evals nothing, deserialises nothing untrusted. The only
source-to-sink surface present is five file paths, and all five resolve to `unknown`.
They reach `open()` and Path methods through object-store handles and helper-call
returns, not through a bare or interpolated parameter, which is the frontier the
single-function AST pass does not cross. The resolver reports `unknown` rather than
guessing: analysis stopped, not "no taint".

The question Metric 1 answers: can the extractor resolve provenance on the attack
surface that actually exists? On this corpus, not yet, 0 of 5.

## Metric 2: verdict-level grounding distribution

```text
hypotheses: 61
grounding:  unsupported 60,  unknown 1,  contradicted 0,  grounded 0
reasons:    no_matching_sink 60,  attack_type_unrecognised 1
accepted:   1  (synthesise.py::run, attack_type "data leakage",
                grounding unknown, effective_confidence 0.35)
```

The model proposed roughly fifty distinct free-text `attack_type` strings across the 61
hypotheses, heavily synonymous: "Command injection" four times plus "command injection"
plus "Command injection via shell metacharacters"; "Code injection" in about eight
variants; deserialisation in four spellings. Broad recall, ungrounded in the slice.
This is static-pattern enthusiasm, on a corpus that catalogues every trope by name.

The question Metric 2 answers: can the system stop attack-category pattern matching from
becoming accepted output? On this corpus, yes, 60 of 61 removed.

## What the distribution shape shows

The shape of the result, beyond "1 accepted, 60 rejected":

```text
unsupported  60
contradicted  0
grounded      0
unknown       1
```

A merely sceptical filter would produce a mixture of contradicted and unsupported.
Instead almost everything landed in unsupported. The dominant failure mode is attack
classes proposed where the required attack surface does not exist in the slice facts at
all. The model is not getting the mechanism subtly wrong on a real sink (that would be
contradicted); it is naming sinks that are not there.

## The mapping carries information, not just confidence

The result is stronger than a precision improvement. Before the gate, the system had no
way to distinguish

```text
command injection  proposed against a subprocess sink
```

from

```text
command injection  proposed against code with no subprocess sink at all
```

Now it does. The 60 unsupported verdicts are evidence that the attack-type to sink
mapping is carrying real information, not merely down-ranking a confidence number. A
class with no matching surface is removed, not kept at a lower prior.

## The survivor is unassessable, not supported

The single survivor is an artefact of the "unknown rather than silently reject" policy,
not a hypothesis the evidence backed. Precisely:

```text
61 hypotheses
60 assessable, and unsupported
 1 unassessable attack class  (no detector for "data leakage")
```

The survivor did not survive because anything grounded it. It survived because the
system does not reject a novel class on missing taxonomy coverage alone, and holds it at
a capped 0.35 prior instead. Grounding never fired on it; it was blocked from assessment
one step earlier, at the registry.

## Two orthogonal findings

The two metrics measure almost unrelated things on this corpus.

|             | Metric 1                                                         | Metric 2                                                       |
|-------------|------------------------------------------------------------------|----------------------------------------------------------------|
| Asks        | can the extractor resolve provenance on the surface that exists? | can the system stop category pattern-matching becoming output? |
| Answer here | not yet, 0/5 resolved                                            | yes, 60/61 removed                                             |
| Bounded by  | the extractor's provenance frontier                              | the attack-type to sink registry                               |

The extractor frontier explains the Metric 1 result. The attack-type to sink registry
explains the Metric 2 result. They are separate levers, and this run exercises them
independently.

## Reading for next time

This run is the first evidence that the attack-type registry is part of the system's
effective precision boundary, alongside the extractor. If a later run shows too many
`unknown` survivors, the first place to look is registry coverage, before provenance
extraction: in this run the one survivor was blocked from assessment by taxonomy, not by
provenance.

The data is internally consistent with the architecture:

- extractor coverage is limited on this corpus (5 surfaces, all unknown),
- model recall is extremely broad (about fifty attack-class strings),
- the screen filters primarily via attack-surface presence (60 of 61 unsupported),
- provenance grounding has had little opportunity to fire, because the corpus contains
  very few provenance-bearing attack surfaces for it to act on.

A corpus with real subprocess and deserialisation sinks would put grounded,
contradicted and the provenance resolver to work, the next data point to gather. The
decisions behind these states are recorded in
[../decisions/2026-06-24-grounding-screen.md](../decisions/2026-06-24-grounding-screen.md);
the calibration question is open in [../roadmap/README.md](../roadmap/README.md).
