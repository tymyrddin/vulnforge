"""Hypothesis schema.

The class has only one constructor path: `Hypothesis.propose(...)`, which sets
`status=Status.PROPOSED`. Verdict transitions to CONFIRMED or REFUTED happen
exclusively in `stages/verify.py`; marking TESTED happens in `stages/execute.py`.
Each of those stages calls `dataclasses.replace` directly, so a single grep for
`status=Status.CONFIRMED` returns exactly the line that creates a confirmed
verdict. The rule lives in the layout, not in a comment.

Three orthogonal fields carry related-but-distinct information:
  - Status: where this hypothesis sits in the pipeline lifecycle.
  - EvidenceType: the nature of the evidence underpinning it.
  - VerificationStatus: the epistemic claim the system is currently willing to
    make about it. The model can only ever set "unverified"; the verifier is
    the only place "confirmed" appears.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum

_FORBIDDEN_INPUT_CHARS = re.compile(r"[*()]")


class Status(str, Enum):
    PROPOSED = "proposed"
    TESTED = "tested"
    CONFIRMED = "confirmed"
    REFUTED = "refuted"


class EvidenceType(str, Enum):
    STATIC_PATTERN = "static_pattern"
    BEHAVIOUR_INFERRED = "behaviour_inferred"
    EXECUTION_OBSERVED = "execution_observed"


class VerificationStatus(str, Enum):
    UNVERIFIED = "unverified"
    TESTED = "tested"
    CONFIRMED = "confirmed"


@dataclass(frozen=True, slots=True)
class Hypothesis:
    attack_type: str
    location: str
    assumption_broken: str
    expected_effect: str
    suggested_inputs: tuple[str, ...]
    confidence: float
    status: Status
    evidence_type: EvidenceType
    verification_status: VerificationStatus
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
        evidence_type: EvidenceType = EvidenceType.STATIC_PATTERN,
        verification_status: VerificationStatus = VerificationStatus.UNVERIFIED,
    ) -> "Hypothesis":
        if verification_status is VerificationStatus.CONFIRMED:
            raise ValueError(
                "the model cannot propose a hypothesis as CONFIRMED; "
                "confirmation is set only by stages/verify.py"
            )
        if evidence_type is EvidenceType.EXECUTION_OBSERVED:
            raise ValueError(
                "the model cannot claim EXECUTION_OBSERVED evidence at "
                "propose-time; execution evidence comes from stages/execute.py"
            )
        for s in suggested_inputs:
            if _FORBIDDEN_INPUT_CHARS.search(s):
                raise ValueError(
                    f"suggested_inputs must be concrete strings, not "
                    f"expressions: {s!r} contains one of * ( ). "
                    f"Write the literal characters instead."
                )
        return cls(
            attack_type=attack_type,
            location=location,
            assumption_broken=assumption_broken,
            expected_effect=expected_effect,
            suggested_inputs=suggested_inputs,
            confidence=confidence,
            status=Status.PROPOSED,
            evidence_type=evidence_type,
            verification_status=verification_status,
            provenance=f"inference:{model_hash}",
        )
