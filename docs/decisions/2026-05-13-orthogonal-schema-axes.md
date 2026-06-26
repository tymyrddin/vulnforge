# Three orthogonal schema axes

Date: 2026-05-13

## Context

Uncertainty needed a place to live. Without somewhere to put it, the system
tries to encode "where in the pipeline", "how strong is the evidence", and
"what claim is the system willing to make" in `Status` alone, which conflates
distinct things.

## Decision

`schema/hypothesis.py` exposes three enums:

- `Status` pipeline lifecycle (PROPOSED, TESTED, CONFIRMED, REFUTED)
- `EvidenceType` nature of evidence (static_pattern, behaviour_inferred,
  execution_observed)
- `VerificationStatus` epistemic claim strength (unverified, tested, confirmed)

`Hypothesis.propose` rejects model-supplied `CONFIRMED` or
`EXECUTION_OBSERVED` at construction time. Those values are stage-owned: only
`verify.confirm` sets `CONFIRMED`, only `execute.mark_tested` sets
`EXECUTION_OBSERVED`. `verify.refute` does not promote VerificationStatus past
`TESTED`.

## Why

Three orthogonal fields let the system encode "where in the pipeline"
separately from "how strong is the evidence" separately from "what claim is the
system willing to make".

[../architecture/pipeline.md](../architecture/pipeline.md) covers how the axes
move through the stages.
