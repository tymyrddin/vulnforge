"""Audit event. Appended to a hash-chained JSONL log by `audit/log.py`."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class AuditEvent:
    timestamp: float
    stage: str
    input_refs: tuple[str, ...]
    output_refs: tuple[str, ...]
    model_hash: str | None
    seed: int | None
    summary: str
