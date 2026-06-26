# Metrics

What actually happened. This bucket is the methodology index; individual runs are dated
files beside it (for example
[2026-06-stages-scan.md](2026-06-stages-scan.md), the first measured scan).

Measuring the grounding gate uses two numbers, kept deliberately apart. They sit at
different layers, so reading one without the other invites a wrong conclusion.

## Metric 1: fact-level provenance coverage

Model-free. Computed over a run's index slices. It counts provenance-bearing facts
(subprocess and dangerous-sink facts carrying an `arg_source`) and splits them into
resolved versus `unknown`.

Over a fixed corpus, Metric 1 is a pure function of the extractor: no model runs in the
index stage. A falling `unknown` fraction is therefore genuine coverage growth, not a
model or corpus artefact. It answers: can the extractor resolve provenance on the
attack surface that actually exists?

## Metric 2: verdict-level grounding distribution

Model-dependent. Computed over a run's `screen_verdicts_latest` manifest. It counts how
the proposed hypotheses landed across the four grounding states (grounded, unknown,
contradicted, unsupported) and which screen reasons fired.

Metric 2 moves with both the extractor and the model, because the model decides which
attack classes get proposed in the first place. It answers: can the system stop
attack-category pattern matching from becoming accepted output?

## Reading them together

Metric 1 holds the model constant by construction; Metric 2 does not. Together they
separate two questions that otherwise tangle: did `unknown` shrink because the extractor
improved, because the corpus was easier, or because the model proposed differently?
Metric 1 answers the extractor part on its own, so Metric 2 can be read for the rest.

Comparability caveats:

- Metric 1 is only comparable across runs on a pinned corpus. The same code re-scanned
  as the extractor evolves tells coverage growth from corpus luck. `stages/` is a first
  data point, not yet a frozen pin. The pinned-corpus item is in
  [../roadmap/README.md](../roadmap/README.md).
- Metric 2 is only comparable across runs with a fixed model (and seed). A different
  model changes the proposal distribution, which moves the metric for reasons unrelated
  to the gate.

## The tool that automates the walk

Both metrics are computed by walking `runs/*/`. Currently that is done by hand against a
single run. `vulnforge stats`, the Click command that walks `runs/*/`, computes both
metrics per run and aggregated, and counts only, is backlog. It is described in
[../roadmap/README.md](../roadmap/README.md) (measurement tooling) and aligns with Move
4 in [../roadmap/verdict-pipeline.md](../roadmap/verdict-pipeline.md).
