# Two metrics kept deliberately apart

## Context

Measuring the grounding gate could be done with a single end-to-end number, but
that number moves with both the extractor and the model. A change in the
`unknown` fraction would then be ambiguous: extractor improvement, easier
corpus, or the model proposing differently, with no way to tell which.

## Decision

Measuring the grounding gate uses two numbers kept deliberately apart. Metric 1,
fact-level provenance coverage, is model-free: over a fixed corpus it is a pure
function of the extractor, so a falling `unknown` fraction is genuine coverage
growth. Metric 2, the verdict-level grounding distribution, moves with both the
extractor and the model, so it is read alongside Metric 1, not instead of it.

## Why

Separating extractor capability from end-to-end behaviour removes a major source
of ambiguity. "Did unknown shrink because the extractor improved, because the
corpus was easier, or because the model proposed differently" becomes
answerable, because Metric 1 holds the model constant by construction.

The first measured run is recorded in [../metrics/README.md](../metrics/README.md).
The tool that automates the walk (`vulnforge stats`) is backlog, in the roadmap.
