# Schema constraints over prompt rules

Date: 2026-05-13

## Context

The model produced `"A" * 20` (a Python expression) inside `suggested_inputs`.
A prompt rule asking it not to do that is advisory and ignorable.

## Decision

The chosen fix was a regex on the schema, not another prompt rule. The
constraint is `^[^*()]+$` on each `suggested_inputs` string.

## Why

Prompt rules are advisory and ignorable. Schema rules are enforced at
construction. Moving the constraint from advisory request to construction-time
rejection removes an entire class of model-output silent failure.

This fix does not address the strcpy case, where the model still emits
literally-invalid JSON (`"A" * 20` is not parseable JSON, regardless of
schema). That is a different intervention class, addressed at the JSON layer
rather than the schema layer.

## Amended 2026-06-24

The `^[^*()]+$` regex is gone. `schema/hypothesis.py` now rejects template
placeholders instead (`_is_placeholder`: angle-bracket, brace, bracket, and
SCREAMING_SNAKE tokens, plus a bare `...`), and deliberately allows parentheses
and asterisks. A code-execution payload is an expression, so banning `(` and `)`
threw out valid test inputs; the sandbox, not the schema, is what contains an
expression. The decision this record holds, constraints enforced at construction
rather than asked for in a prompt, is unchanged; only the specific constraint
moved from "no expression characters" to "no placeholder tokens".
