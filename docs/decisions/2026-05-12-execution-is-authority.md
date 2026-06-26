# Execution is the authority on verdicts

Date: 2026-05-12

## Context

A verdict on a hypothesis needs an owner. If the model that proposes a finding
can also declare it confirmed, the system has no separation between a guess and
a result. There is no AI judge.


## Decision

Verdict transitions live exclusively in two files. `stages/execute.py`
(`mark_tested`) owns PROPOSED -> TESTED. `stages/verify.py` (`confirm`,
`refute`) owns TESTED -> CONFIRMED and TESTED -> REFUTED.
`schema/hypothesis.py:Hypothesis.propose` is the only constructor path, and it
only ever yields `Status.PROPOSED`. `git grep "status=Status.CONFIRMED,"`
(with the trailing comma) returns the single assignment line in `verify.py`.

## Why

The rule is enforced by the layout. Keeping each transition in exactly one place
means a verdict cannot be set anywhere a reviewer has not looked, and the single
grep result confirms it.

[../architecture/pipeline.md](../architecture/pipeline.md) covers how the stages
run.
