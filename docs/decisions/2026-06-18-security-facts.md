# Security facts carry arg_source provenance

## Context

The model proposes attack classes by recall. A fact that a slice contains a
sink of some kind is not, on its own, evidence that attacker-controlled data
reaches that sink. Without the source-to-sink link, a finding about a sink can
look grounded when it is not. This was the reviewer's central criticism.

## Decision

The extractor in `extractors/python.py` produces security facts where each fact
about a sink carries `arg_source` provenance. The provenance records where the
value reaching the sink comes from, so a fact about a sink also carries the
source-to-sink link. The link is machine-computed at index time, not inferred
later from prose.

The provenance model in `extractors/python.py` returns `list[SecurityFact]` and
today resolves a bare parameter (`parameter:NAME`), a parameter reaching the
sink through an f-string or collection (`parameter-derived`), and a string
literal (`constant`); everything else lands `unknown`. That return type is the
contract a new-language extractor implements, and that frontier is what richer
provenance extends.

## Why

`arg_source` makes the source-to-sink link explicit and machine-computed.
Making the relation a fact attached to the sink, rather than a claim the model
makes in its output, is what lets a later stage check grounding in code. The
fact is the ground truth the screen reads, so the link needs to live in the
fact, not in the hypothesis.
