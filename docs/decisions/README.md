# Decisions

Append-only, ADR-sized, dated, immutable records of why vulnforge is built as it
is. Each one captures the context that forced a choice, the choice itself, and
the reasoning, at the size of a single decision.

The boundary with architecture: a completed roadmap item becomes architecture
because it now exists; a record lives here because it explains why. These files
are not rewritten when the code moves on. If a later commit contradicts one, a
new record supersedes it; the old one stays as the account of what was decided
when.

## Records, in date order

- [2026-05-12-execution-is-authority.md](2026-05-12-execution-is-authority.md): verdict transitions live in code, not in an AI judge.
- [2026-05-12-sandbox-only-execution.md](2026-05-12-sandbox-only-execution.md): one isolation surface; inference and targets run through the same sandbox.
- [2026-05-12-content-addressed-store-and-audit.md](2026-05-12-content-addressed-store-and-audit.md): content-addressed blobs and a hash-chained audit log.
- [2026-05-12-network-in-bootstrap.md](2026-05-12-network-in-bootstrap.md): network code lives only in bootstrap, so the pipeline cannot reach out.
- [2026-05-13-workspace-separation.md](2026-05-13-workspace-separation.md): immutable framework checkout, mutable runtime state under XDG.
- [2026-05-13-certainty-not-vocabulary.md](2026-05-13-certainty-not-vocabulary.md): the prompt bans unverified claims, not words.
- [2026-05-13-orthogonal-schema-axes.md](2026-05-13-orthogonal-schema-axes.md): three orthogonal enums so uncertainty has a place to live.
- [2026-05-13-schema-over-prompt-rules.md](2026-05-13-schema-over-prompt-rules.md): constraints enforced at construction beat advisory prompt rules.
- [2026-05-13-list-at-boundary-tuple-in-storage.md](2026-05-13-list-at-boundary-tuple-in-storage.md): list at the API boundary, immutable tuple in storage.
- [2026-05-13-probe-one-shot.md](2026-05-13-probe-one-shot.md): one-shot inference for tuning, a single file through index, hypothesise, and the grounding screen (amended 2026-06-24).
- [2026-05-13-container-ownership.md](2026-05-13-container-ownership.md): containers are owned resources with one cleanup path.
- [2026-06-18-security-facts.md](2026-06-18-security-facts.md): security facts carry arg_source provenance, so a sink fact holds its source-to-sink link.
- [2026-06-23-no-think-model-config.md](2026-06-23-no-think-model-config.md): /no_think as model config, because thinking traces blow the per-slice timeout on CPU.
- [2026-06-24-grounding-screen.md](2026-06-24-grounding-screen.md): the taint-grounding screen stage and its four grounding states.
- [2026-06-25-two-metrics.md](2026-06-25-two-metrics.md): provenance coverage and grounding distribution kept deliberately apart.
- [2026-06-29-expected-outcomes.md](2026-06-29-expected-outcomes.md): verify compares predicted semantic outcomes to observations over an implementation-independent vocabulary; exit codes are evidence, not verdicts.
- [threat-model.md](threat-model.md): what the design removes from the trust path, and what it does not.
