"""Report stage: emit human-readable findings from a verdicts ref. Output is a
plain file under .vulnforge/reports/; the audit log retains the canonical
provenance."""
from __future__ import annotations

from pathlib import Path


def run(verdicts_ref: str) -> Path:
    raise NotImplementedError("report stage: implementation pending")
