# Expected outcomes: verify compares predictions to observations

## Context

The verify stage confirmed on heuristics: a nonzero exit code, a timeout, or the
attack-class-specific checks in `_decide`. The first run on real third-party code
(cookiecutter, recorded in [../metrics/2026-06-29-cookiecutter-scan.md](../metrics/2026-06-29-cookiecutter-scan.md))
showed the cost: nine CONFIRMED verdicts, every one carrying the evidence `exit_code: 1`,
each a library function raising on a malformed argument rather than an exploited
vulnerability. "Did something happen?" is the wrong question. The question is "did the
outcome the hypothesis predicted happen?".

## Decision

A hypothesis predicts semantic outcomes. The synthesise stage turns a hypothesis into an
execution plan, and verify compares predicted outcomes against observed ones. Verify holds
no knowledge of attack classes; it evaluates a boolean structure over observations.

Expected outcomes are a closed, implementation-independent vocabulary. Each kind names the
observation channel it needs:

| Kind | Satisfied when | Channel |
|------|----------------|---------|
| `OUTPUT_CONTAINS(token)` | the token appears in stdout or stderr | process |
| `PROCESS_TIMED_OUT` | the run hit its timeout | process |
| `SANITISER_REPORT` | a sanitiser or crash channel fired | process |
| `FILESYSTEM_ACCESS(path_predicate)` | a filesystem event matches | filesystem_events |
| `SUBPROCESS_SPAWNED(cmd_predicate)` | a spawned process matches | subprocess_events |
| `NETWORK_CONNECTION(host_predicate)` | an outbound connection matches | network_events |

An outcome is a predicate over observed state, the same shape used elsewhere in the
substrate: `outcome.satisfied_by(observations)`.

The execution plan from synthesise carries payloads, each with its own expected outcomes.
The success structure is disjunctive normal form: outcomes within one payload are
conjoined, payloads are alternatives.

    (p1.o1 AND p1.o2) OR (p2.o1) OR (p3.o1 AND p3.o2)

A hypothesis is existential: it claims a demonstration exists. The payloads are alternative
witnesses, not independent predictions, so one payload whose outcomes all hold establishes
the hypothesis. Requiring every payload to succeed would tie confirmation to the payload
generator's quality rather than the truth of the claim. The only conjunction is within a
single payload, where the model deliberately predicts more than one consequence (for
example `OUTPUT_CONTAINS(token)` and `SUBPROCESS_SPAWNED("/bin/sh")` together).

The executor advertises a capability set: the channels it can currently observe. Verify
decides each outcome mechanically:

- observable and satisfied: true
- observable and not satisfied: false
- not observable by the current executor: unknown

A payload clause is the conjunction of its outcomes; the plan is the disjunction of its
clauses. The verdict:

- CONFIRMED: some clause evaluates true.
- REFUTED: every clause is fully observable and evaluates false.
- INCONCLUSIVE: no clause is true and at least one clause is unknown, because a channel it
  needs is not observable yet.

Exit codes and exceptions are evidence recorded in observations, never satisfaction
conditions. A raised exception is an observation, neither confirmation nor refutation until
compared against an expected outcome.

Confirmation reduces to the output channel wherever synthesise can make success observable
there, which is what keeps most outcomes verifiable without new instrumentation:

- command injection, code execution, deserialization: the payload causes a planted token to
  be printed, so success is `OUTPUT_CONTAINS(token)`.
- path traversal: synthesise plants a sentinel file outside the root whose content is the
  token and targets it, so a successful traversal surfaces the token in output, again
  `OUTPUT_CONTAINS(token)`, with no filesystem tracing required.

The instrumented channels (`filesystem_events`, `subprocess_events`, `network_events`)
are defined in the vocabulary now and return INCONCLUSIVE until the executor advertises
them. Adding that instrumentation changes only the executor's capability set, not the
vocabulary, the hypotheses, or synthesise.

## Why

Keeping verify free of attack semantics is what makes it stable: it never learns a new
attack, it only evaluates predicates and a boolean structure. Tying the vocabulary to
semantics rather than to today's executor means new instrumentation is an executor change,
not a vocabulary redesign, the dependency points the right way. Existential confirmation
keeps a verdict a statement about the hypothesis, not about how many payload variants the
generator happened to produce. The three-state verdict preserves honesty: an outcome the
backend cannot observe is recorded as unknown rather than silently refuted or wrongly
confirmed.

## Build order

The synthesise execution plan, the verify boolean evaluator, and the executor capability
set are one piece of work. The first observable outcome is `OUTPUT_CONTAINS` (the existing
command-injection marker is its first instance); `PROCESS_TIMED_OUT` and `SANITISER_REPORT`
follow on the process channel; the instrumented channels are deferred behind the capability
set. The immediate first step is the verify correction: stop confirming on exit code,
confirm only on a satisfied observable outcome.
