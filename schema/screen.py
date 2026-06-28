"""Screen schema.

The screen sits between hypothesise and synthesise. It answers one question about
each hypothesis: does the code, as far as a single-function AST pass can tell, ground
the proposed attack? It never decides whether the attack works; execution still owns
that.

Two jobs are kept deliberately separate:
  - Grounding states what the code knows (computed in stages/screen.py from the
    slice's security facts).
  - decide_policy() states how much confidence deserves to survive that grounding.

The split mirrors the rest of the pipeline: facts in one place, the consequence of
those facts in another, so neither quietly absorbs the other's authority.

Four grounding states, and why two of them accept while two reject:

  GROUNDED      a parameter reaches a sink that matches the attack class. Accept.
  UNKNOWN       a matching sink exists but its argument's provenance is unresolved.
                Accept, but cap confidence. "Unresolved" is the AST pass hitting its
                limit, not proof the attacker has no influence, so the hypothesis
                survives at a lowered prior rather than being thrown away.
  CONTRADICTED  the code-derived facts rule the proposed mechanism out (for example
                shell metacharacters under shell=False, or a constant sink argument no
                parameter can reach). Reject.
  UNSUPPORTED   no sink matching the attack class exists in the slice at all. Reject.

The line that matters: never conflate "not tainted" (constant, contradicted) with
"taint unresolved" (unknown). Erasing that distinction is the failure this stage
exists to prevent.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

# Policy constant, not an empirically calibrated number. The only property that
# carries weight is the ordering: an unknown-grounding hypothesis survives at a lower
# prior than a grounded one. The exact value is a starting point to be tuned against
# real verify rates, not a measured threshold. Do not read meaning into 0.35 beyond
# "less than a grounded hypothesis would keep".
UNKNOWN_CONFIDENCE_CAP = 0.35


class Grounding(StrEnum):
    GROUNDED = "grounded"
    UNKNOWN = "unknown"
    CONTRADICTED = "contradicted"
    UNSUPPORTED = "unsupported"


class ScreenReason(StrEnum):
    # grounded
    PARAM_REACHES_SINK = "param_reaches_sink"
    # unknown
    SINK_SOURCE_UNRESOLVED = "sink_source_unresolved"
    INSUFFICIENT_SQL_EVIDENCE = "insufficient_sql_evidence"
    ATTACK_TYPE_UNRECOGNISED = "attack_type_unrecognised"
    SCREEN_OTHER = "screen_other"
    # contradicted
    SHELL_METACHARS_UNDER_SHELL_FALSE = "shell_metachars_under_shell_false"
    CONSTANT_SINK_ARG = "constant_sink_arg"
    # unsupported
    NO_MATCHING_SINK = "no_matching_sink"


# Catch-all reasons land in UNKNOWN, never UNSUPPORTED: an unrecognised state is
# accepted with penalty, never silently rejected, so a novel attack class does not
# quietly collapse recall.
_UNKNOWN_CATCHALLS = frozenset(
    {
        ScreenReason.ATTACK_TYPE_UNRECOGNISED,
        ScreenReason.SCREEN_OTHER,
        ScreenReason.INSUFFICIENT_SQL_EVIDENCE,
        ScreenReason.SINK_SOURCE_UNRESOLVED,
    }
)


@dataclass(frozen=True, slots=True)
class ScreenVerdict:
    hypothesis_id: str
    grounding: Grounding
    screen_reason: ScreenReason
    effective_confidence: float

    @property
    def accepted(self) -> bool:
        return self.grounding in (Grounding.GROUNDED, Grounding.UNKNOWN)


def decide_policy(grounding: Grounding, confidence: float) -> tuple[bool, float]:
    """Map a grounding state and the model's prior to (accepted, effective_confidence).

    grounded      accept, confidence unchanged
    unknown       accept, confidence capped at UNKNOWN_CONFIDENCE_CAP
    contradicted  reject
    unsupported   reject
    """
    if grounding is Grounding.GROUNDED:
        return True, confidence
    if grounding is Grounding.UNKNOWN:
        return True, min(confidence, UNKNOWN_CONFIDENCE_CAP)
    return False, 0.0
