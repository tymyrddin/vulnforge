# Cookiecutter scan, 2026-06-29

The first end-to-end run on real third-party surface. Target: the `cookiecutter`
package (`cookiecutter/cookiecutter/`, the library, excluding tests and docs). Models:
qwen3-8b (hypothesise, seed 1), qwen2.5-coder-7b (synthesise, seed 2). The audit chain
verified, 8 entries.

Prior runs only covered `stages/` (vulnforge's own code), which has almost no sinks, so
the grounded, contradicted, and confirmed paths had never fired on meaningful code.
Methodology for the two metrics is in [README.md](README.md).

## Metric 1: provenance coverage (model-free)

Computed from the index stage. 76 function-slices, 11 carrying security facts. Fact
types: subprocess 3, file_read 5, file_write 3, environment_access 2.

Provenance on the arg_source-bearing facts (subprocess, dangerous_sink): 1 of 3 resolved
(`parameter:repo_url` on the vcs clone), 2 unknown. Provenance on file-path facts: 3 of 8
resolved to a parameter (`config_path`, `context_file`, `infile`), 5 unknown.

Cross-target comparison, same model-free survey on the other cloned candidates (package
directories, tests excluded):

| Target       | Slices | Slices with facts | arg_source resolved | Notable                                   |
|--------------|--------|-------------------|---------------------|-------------------------------------------|
| cookiecutter | 76     | 11                | 1/3                 | `repo_url` subprocess; 3 parameter paths  |
| celery       | 2809   | 39                | 0/4                 | dangerous sinks all unknown               |
| tox          | 1021   | 54                | 3/5                 | `python_path`, `virtualenv_spec`          |

Sink density by reputation does not predict provenance the extractor can resolve. celery
has 2809 slices but 39 with facts and zero resolved arg_source: its sinks sit behind
layers, the arguments are not direct parameters. tox carries the most resolvable surface.
cookiecutter is the smallest, the only one scannable near-whole at one slice per model
call.

## Metric 2: grounding distribution (model-dependent)

qwen3-8b proposed 123 hypotheses across the 76 slices, spanning more than 50 distinct
`attack_type` strings (path traversal, command injection, template injection, code
execution, and many one-off categories). The grounding distribution:

| Grounding    | Count | Screen reasons                                                   |
|--------------|-------|------------------------------------------------------------------|
| unsupported  | 111   | no_matching_sink 111                                             |
| unknown      | 11    | sink_source_unresolved 7, attack_type_unrecognised 4            |
| grounded     | 1     | param_reaches_sink 1                                             |
| contradicted | 0     |                                                                  |

The screen rejected 111 of 123 (90%) as no_matching_sink: the model proposed an attack
class with no sink of that class in the slice. That is the static-pattern-enthusiasm the
screen exists to absorb, measured on real surface. decide_policy accepted 12 (the 1
grounded plus the 11 unknown). The single grounded hypothesis is a path traversal at
`config.py::get_config`, matching the one parameter-resolved file path from Metric 1.

## Verdicts: zero, and why

The 12 accepted hypotheses produced 0 payloads at synthesise, so execute and verify had
nothing to run and no verdict reached CONFIRMED or REFUTED.

The cause is not grounding or execution. A single synthesise call replayed on the grounded
path-traversal hypothesis showed qwen2.5-coder-7b generating correct payloads
(`../../etc/passwd`, `../etc/hosts`, null-byte variants). The output was truncated mid-JSON
by the token budget (synthesise `max_tokens` is 256; a 512-token replay still truncated
after six payloads), leaving the `{"payloads": [...]}` object unterminated.
`_parse_payloads` cannot decode an unterminated object and returns an empty list, so every
accepted hypothesis yielded zero stored payloads.

This is the tolerant-JSON-parsing open question in [../roadmap/README.md](../roadmap/README.md)
made concrete: the limiting factor for confirmations on real code is the synthesise output
contract (token budget plus strict whole-object JSON parsing), not the grounding gate.

## Reading

- The screen works as designed on real surface: 90% of an enthusiastic model's proposals
  were rejected as unsupported, one parameter-to-sink hypothesis grounded.
- The confirmed path is blocked at synthesise by output truncation. The generated payloads
  were valid, the JSON envelope did not survive the token limit.
- A confirmation on real code is reachable: the grounded path-traversal hypothesis has
  correct payloads. It needs synthesise to emit parseable output (a larger token budget,
  or parsing tolerant of a truncated trailing object, or a capped payload count).

The synthesise contract fix below did exactly this, and the run that followed moved the
bottleneck to verify (Post-fix re-run).

## Post-fix re-run: the synthesise contract

The synthesise stage was given a bounded output contract: the prompt asks for at most 5
payloads of at most 200 characters; the parser enforces those bounds, recovers complete
payload objects from a truncated stream (discarding any cut-off trailing object, never
inventing fields), and reports a categorical status per hypothesis (ok, recovered, empty,
schema_invalid, unparseable, infer_error) with `contract_limit`, `recovered_count`, and
`valid_count`. `max_tokens` was left at 256.

Re-driving synthesise, execute, and verify over the same 12 accepted hypotheses (the
hypothesise and screen output is deterministic at the same seed, so it was reused):

- synthesise: 52 payloads from 12 hypotheses (ok=8, recovered=3, unparseable=1). The
  contract fix alone unblocked the stage at the unchanged 256-token budget; raising the
  budget was not needed.
- execute: 52 observations.
- verify: 11 verdicts.

This is the first successful end-to-end execution on a real codebase: payloads
synthesised, delivered, and run in the sandbox, with observations produced. Fixing one
stage moved the failure downstream, which is what a well-factored pipeline does.

The 11 verdicts are not trustworthy. verify reported 9 CONFIRMED and 2 REFUTED; every
CONFIRMED carries the evidence `exit_code: 1`. Those are functions raising on a malformed
first argument (`get_config` failing to parse a path as YAML, `replay.dump`/`load` erroring
on a bad argument), not exploited vulnerabilities. verify currently asks "did something
happen?" (any nonzero exit confirms) rather than "did the predicted outcome happen?". A
Python exception is an observation, neither confirmation nor refutation until compared
against the hypothesis's expected outcome.

So the next bottleneck is verify, not synthesise. The fix is Move 2 in
[../roadmap/verdict-pipeline.md](../roadmap/verdict-pipeline.md): a hypothesis predicts an
`expected_outcome`, and verify confirms only when an observation satisfies it. Exit codes
become evidence, not verdicts.

## Verify redesign: false positives removed by design

The expected-outcome design ([../decisions/2026-06-29-expected-outcomes.md](../decisions/2026-06-29-expected-outcomes.md))
was built: synthesise attaches expected outcomes to each payload, execute produces purely
factual observations, and verify compares predicted outcomes against observed facts using
the executor's advertised channels, with no exit-code heuristics. Re-driving the same 12
accepted hypotheses:

- before: 9 CONFIRMED, 2 REFUTED. Every CONFIRMED was `exit_code: 1`.
- after: 0 CONFIRMED, 2 REFUTED, 9 INCONCLUSIVE.

The nine false positives are gone as a consequence of the comparison, not a patched rule.
The 2 REFUTED are command-injection witnesses whose predicted marker was observable but
absent (the function raised before reaching a shell). The 9 INCONCLUSIVE all read "expected
outcome not observable by this executor": filesystem-class outcomes whose channel the
Python executor does not produce.

The remaining gap is now named and outside verify: executor capability (observing
filesystem events) and experiment setup (planting a sentinel so a successful traversal
surfaces in output). That INCONCLUSIVE set is the worklist for the next build, the
execution-plan with setup/cleanup and executor-advertised capabilities, at which point
the capability-gap case becomes a pre-execution routing decision rather than a verdict.

## Caveats

First data point on this target, not a pinned corpus, so Metric 1 is not yet comparable
across runs ([README.md](README.md)). Metric 2 is tied to these models and seeds. The
walk over the run was done by hand; `vulnforge stats` and an index-only mode remain
backlog ([../roadmap/README.md](../roadmap/README.md)).
