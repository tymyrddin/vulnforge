"""Verdict schema. Produced exclusively by `stages/verify.py`."""

from __future__ import annotations

from dataclasses import dataclass

from .hypothesis import Status


@dataclass(frozen=True, slots=True)
class Verdict:
    hypothesis_ref: str
    observation_ref: str
    status: Status  # CONFIRMED or REFUTED at this point
    reasoning: str
    reproductions: int
