"""Execute stage: run each payload against its target inside the sandbox,
capture an Observation, and move the corresponding hypothesis from PROPOSED to
TESTED.

This module owns the PROPOSED -> TESTED transition. Grep for
`status=Status.TESTED` and you find it here, only here.
"""
from __future__ import annotations

import dataclasses

from schema.hypothesis import Hypothesis, Status


def mark_tested(h: Hypothesis, attempts: int) -> Hypothesis:
    if h.status is not Status.PROPOSED:
        raise ValueError(f"cannot mark tested from {h.status.value}")
    return dataclasses.replace(
        h,
        status=Status.TESTED,
        provenance=f"{h.provenance};tested:{attempts}",
    )


def run(payloads_ref: str, target_ref: str, *, timeout_seconds: int) -> str:
    raise NotImplementedError("execute stage: implementation pending")
