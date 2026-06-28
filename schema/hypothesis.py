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
from enum import StrEnum

# Matches template tokens rather than concrete attack strings.
# Parentheses and other syntax are NOT banned: for code-execution attacks
# the payload IS an expression, and the sandbox prevents any real harm.
_PLACEHOLDER_RE = re.compile(
    r"""
    <[A-Za-z_]\w*>          # <placeholder> / <type>
    | \{[A-Za-z_]\w*\}      # {placeholder}
    | \[[A-Z][A-Z0-9_]+\]   # [PLACEHOLDER]
    | \.{3}                  # ... standing in for "something"
    """,
    re.VERBOSE,
)


def _is_placeholder(s: str) -> bool:
    """True when s looks like a template token rather than a testable value."""
    if _PLACEHOLDER_RE.search(s):
        return True
    stripped = s.strip()
    if stripped in ("*", "**"):
        return True
    # SCREAMING_SNAKE_CASE with at least one underscore: classic template variable
    return bool(re.fullmatch(r"[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+", stripped))


class Status(StrEnum):
    PROPOSED = "proposed"
    TESTED = "tested"
    CONFIRMED = "confirmed"
    REFUTED = "refuted"


class EvidenceType(StrEnum):
    STATIC_PATTERN = "static_pattern"
    BEHAVIOUR_INFERRED = "behaviour_inferred"
    EXECUTION_OBSERVED = "execution_observed"


class VerificationStatus(StrEnum):
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
        suggested_inputs: list[str],
        confidence: float,
        model_hash: str,
        evidence_type: EvidenceType = EvidenceType.STATIC_PATTERN,
        verification_status: VerificationStatus = VerificationStatus.UNVERIFIED,
    ) -> Hypothesis:
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
        if not isinstance(suggested_inputs, list):
            raise TypeError(
                f"suggested_inputs must be a list of strings, got {type(suggested_inputs).__name__}"
            )
        for s in suggested_inputs:
            if not isinstance(s, str):
                raise TypeError(
                    f"suggested_inputs element must be a string, got {type(s).__name__}: {s!r}"
                )
            if _is_placeholder(s):
                raise ValueError(
                    f"suggested_inputs must be testable values, not template placeholders: {s!r}"
                )
        return cls(
            attack_type=attack_type,
            location=location,
            assumption_broken=assumption_broken,
            expected_effect=expected_effect,
            suggested_inputs=tuple(suggested_inputs),
            confidence=confidence,
            status=Status.PROPOSED,
            evidence_type=evidence_type,
            verification_status=verification_status,
            provenance=f"inference:{model_hash}",
        )
