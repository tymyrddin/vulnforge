"""Observation schema. Produced by `stages/execute.py` from a payload + target
run inside the sandbox. Pure data."""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class Outcome(str, Enum):
    CLEAN_EXIT = "clean_exit"
    NONZERO_EXIT = "nonzero_exit"
    CRASH = "crash"
    TIMEOUT = "timeout"
    SANITISER_REPORT = "sanitiser_report"


@dataclass(frozen=True, slots=True)
class Observation:
    hypothesis_ref: str
    payload_ref: str
    outcome: Outcome
    exit_code: int | None
    stdout_hash: str
    stderr_hash: str
    duration_seconds: float
    sandbox_image_hash: str
