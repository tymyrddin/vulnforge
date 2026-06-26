# Prompt: certainty, not vocabulary

Date: 2026-05-13

## Context

The prior rule "the word 'vulnerable' cannot appear in your output" forced
lexical avoidance instead of epistemic discipline. Models do not become more
truthful when words are banned; they become evasive.

## Decision

The hypothesise prompt does not ban words. It bans unverified findings asserted
as fact. The model can discuss vulnerability classes, suspicious patterns,
attack surfaces, and exploit hypotheses. It cannot claim successful
exploitation without execution evidence.

## Why

Restricting epistemic claims (not vocabulary) lets the model speak naturally
while the schema and the downstream stages enforce what counts as a verdict.

[../architecture/models.md](../architecture/models.md) covers the prompt design.
