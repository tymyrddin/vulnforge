"""Verify stage: compare observations against hypotheses without using the AI.

This module owns the TESTED -> CONFIRMED and TESTED -> REFUTED transitions.
Grep for `status=Status.CONFIRMED` (or REFUTED) and you find exactly the two
lines below. That is the entire enforcement of the "AI cannot be the judge"
rule: the only assignment sites for verdict statuses are in this file.
"""
from __future__ import annotations

import dataclasses

from schema.hypothesis import Hypothesis, Status, VerificationStatus


def confirm(h: Hypothesis, evidence: str) -> Hypothesis:
    if h.status is not Status.TESTED:
        raise ValueError(f"cannot confirm from {h.status.value}")
    return dataclasses.replace(
        h,
        status=Status.CONFIRMED,
        verification_status=VerificationStatus.CONFIRMED,
        provenance=f"{h.provenance};confirmed:{evidence}",
    )


def refute(h: Hypothesis, reason: str) -> Hypothesis:
    if h.status is not Status.TESTED:
        raise ValueError(f"cannot refute from {h.status.value}")
    return dataclasses.replace(
        h,
        status=Status.REFUTED,
        provenance=f"{h.provenance};refuted:{reason}",
    )


def run(observations_ref: str, hypotheses_ref: str) -> str:
    raise NotImplementedError("verify stage: implementation pending")
