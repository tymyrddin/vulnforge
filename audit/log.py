"""Hash-chained JSONL log. Each entry references the previous entry's hash.

Tampering with any past entry invalidates every entry after it. Verification
walks the file linearly and is exposed via `verify_chain()`. Field order is
canonicalised (sort_keys=True) so digests are deterministic across runs.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import asdict

from schema.audit_event import AuditEvent
from workspace import active

GENESIS = "0" * 64


def _log_path():
    return active().audit_log


def _canonical(record: dict) -> bytes:
    return json.dumps(record, sort_keys=True, separators=(",", ":")).encode()


def _last_entry_hash() -> str:
    log = _log_path()
    if not log.exists():
        return GENESIS
    with log.open("rb") as f:
        f.seek(0, 2)
        size = f.tell()
        f.seek(max(0, size - 4096))
        tail = f.read()
    lines = [line for line in tail.splitlines() if line.strip()]
    if not lines:
        return GENESIS
    return json.loads(lines[-1])["entry_hash"]


def append(event: AuditEvent) -> str:
    log = _log_path()
    log.parent.mkdir(parents=True, exist_ok=True)
    prev = _last_entry_hash()
    body = asdict(event)
    body["prev_hash"] = prev
    entry_hash = hashlib.sha256(_canonical(body)).hexdigest()
    record = {**body, "entry_hash": entry_hash}
    with log.open("a") as f:
        f.write(json.dumps(record, sort_keys=True) + "\n")
    return entry_hash


def verify_chain() -> int:
    """Walk the log from genesis. Returns the number of valid entries.
    Raises ValueError on the first broken link."""
    log = _log_path()
    if not log.exists():
        return 0
    prev = GENESIS
    count = 0
    with log.open() as f:
        for n, line in enumerate(f, 1):
            entry = json.loads(line)
            stored_hash = entry.pop("entry_hash")
            if entry["prev_hash"] != prev:
                raise ValueError(f"line {n}: prev_hash mismatch")
            actual = hashlib.sha256(_canonical(entry)).hexdigest()
            if actual != stored_hash:
                raise ValueError(f"line {n}: entry_hash mismatch")
            prev = stored_hash
            count += 1
    return count
