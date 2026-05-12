"""Hypothesis schema.

The class has only one constructor path: `Hypothesis.propose(...)`, which sets
`status=Status.PROPOSED`. Verdict transitions to CONFIRMED or REFUTED happen
exclusively in `stages/verify.py`; marking TESTED happens in `stages/execute.py`.
Each of those stages calls `dataclasses.replace` directly, so a single grep for
`status=Status.CONFIRMED` returns exactly the line that creates a confirmed
verdict. The rule lives in the layout, not in a comment.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class Status(str, Enum):
    PROPOSED = "proposed"
    TESTED = "tested"
    CONFIRMED = "confirmed"
    REFUTED = "refuted"


@dataclass(frozen=True, slots=True)
class Hypothesis:
    attack_type: str
    location: str
    assumption_broken: str
    expected_effect: str
    suggested_inputs: tuple[str, ...]
    confidence: float
    status: Status
    provenance: str

    @classmethod
    def propose(
        cls,
        *,
        attack_type: str,
        location: str,
        assumption_broken: str,
        expected_effect: str,
        suggested_inputs: tuple[str, ...],
        confidence: float,
        model_hash: str,
    ) -> "Hypothesis":
        return cls(
            attack_type=attack_type,
            location=location,
            assumption_broken=assumption_broken,
            expected_effect=expected_effect,
            suggested_inputs=suggested_inputs,
            confidence=confidence,
            status=Status.PROPOSED,
            provenance=f"inference:{model_hash}",
        )
