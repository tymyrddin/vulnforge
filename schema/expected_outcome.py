"""Expected outcomes: the semantic vocabulary verify compares against observations.

An outcome is a predicate over observed state (`satisfied_by`) plus the observation
channel it needs. The vocabulary is implementation-independent: the executor advertises
which channels it can observe, and verify decides each outcome as satisfied, unsatisfied,
or unobservable from that. Adding instrumentation changes the executor's channels, not this
vocabulary. Design recorded in docs/decisions/2026-06-29-expected-outcomes.md.

Verify never reasons about attack classes. It evaluates these predicates and the boolean
structure synthesise emits (outcomes AND-ed within a payload, payloads OR-ed).
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any


class OutcomeKind(StrEnum):
    OUTPUT_CONTAINS = "output_contains"
    PROCESS_TIMED_OUT = "process_timed_out"
    SANITISER_REPORT = "sanitiser_report"
    FILESYSTEM_ACCESS = "filesystem_access"
    SUBPROCESS_SPAWNED = "subprocess_spawned"
    NETWORK_CONNECTION = "network_connection"


# The observation channel each outcome kind needs the executor to have observed.
CHANNEL: dict[OutcomeKind, str] = {
    OutcomeKind.OUTPUT_CONTAINS: "process",
    OutcomeKind.PROCESS_TIMED_OUT: "process",
    OutcomeKind.SANITISER_REPORT: "process",
    OutcomeKind.FILESYSTEM_ACCESS: "filesystem_events",
    OutcomeKind.SUBPROCESS_SPAWNED: "subprocess_events",
    OutcomeKind.NETWORK_CONNECTION: "network_events",
}

_SANITISER_SIGNATURES = (
    "AddressSanitizer",
    "UndefinedBehaviorSanitizer",
    "runtime error:",
    "Segmentation fault",
)


@dataclass(frozen=True, slots=True)
class ExpectedOutcome:
    kind: OutcomeKind
    token: str = ""   # OUTPUT_CONTAINS: the string whose presence demonstrates success
    target: str = ""  # event predicate (substring) for filesystem/subprocess/network

    @property
    def channel(self) -> str:
        return CHANNEL[self.kind]

    def satisfied_by(self, obs: dict[str, Any]) -> bool:
        kind = self.kind
        if kind is OutcomeKind.OUTPUT_CONTAINS:
            haystack = (obs.get("stdout") or "") + (obs.get("stderr") or "")
            return bool(self.token) and self.token in haystack
        if kind is OutcomeKind.PROCESS_TIMED_OUT:
            return bool(obs.get("timed_out"))
        if kind is OutcomeKind.SANITISER_REPORT:
            blob = (obs.get("stderr") or "") + (obs.get("stdout") or "")
            return any(sig in blob for sig in _SANITISER_SIGNATURES)
        if kind is OutcomeKind.FILESYSTEM_ACCESS:
            return _event_matches(obs.get("filesystem_events"), self.target)
        if kind is OutcomeKind.SUBPROCESS_SPAWNED:
            return _event_matches(obs.get("subprocess_events"), self.target)
        if kind is OutcomeKind.NETWORK_CONNECTION:
            return _event_matches(obs.get("network_events"), self.target)
        return False

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"kind": self.kind.value}
        if self.token:
            d["token"] = self.token
        if self.target:
            d["target"] = self.target
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> ExpectedOutcome:
        return cls(
            kind=OutcomeKind(d["kind"]), token=d.get("token", ""), target=d.get("target", "")
        )


def _event_matches(events: Any, target: str) -> bool:
    if not events:
        return False
    if not target:
        return True
    return any(target in str(e) for e in events)


def clause_result(
    outcomes: list[ExpectedOutcome], obs: dict[str, Any], observed_channels: set[str]
) -> str:
    """Three-valued AND over a payload's outcomes: "true", "false", or "unknown".

    An outcome on a channel the executor did not observe is unknown. The conjunction is
    false if any outcome is false, otherwise unknown if any is unknown, otherwise true.
    A payload with no declared outcome is unknown: there is no success condition to check.
    """
    if not outcomes:
        return "unknown"
    results = []
    for outcome in outcomes:
        if outcome.channel not in observed_channels:
            results.append("unknown")
        elif outcome.satisfied_by(obs):
            results.append("true")
        else:
            results.append("false")
    if "false" in results:
        return "false"
    if "unknown" in results:
        return "unknown"
    return "true"
