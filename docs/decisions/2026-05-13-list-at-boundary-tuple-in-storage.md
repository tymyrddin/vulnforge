# Type contract: list at the API boundary, tuple in storage

Date: 2026-05-13

## Context

JSON has lists, not tuples. Internal storage benefits from immutability. Mixing
the two without a clear rule invites "is this expecting a list or a tuple?"
friction at every call site and subtle bugs from converting at the wrong layer.

## Decision

`Hypothesis.propose` accepts `suggested_inputs: list[str]`. The dataclass field
is `tuple[str, ...]`. Conversion happens in exactly one place: the `cls(...)`
call inside `propose`. Callers pass lists; storage is immutable.

## Why

A single conversion point avoids the call-site friction and the subtle bugs from
converting at the wrong layer. The boundary owns the conversion, so nothing
downstream handles it.
