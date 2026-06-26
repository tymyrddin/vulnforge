# Content-addressed store and hash-chained audit log

Date: 2026-05-12

## Context

Stage outputs need to be referenced unambiguously, and the record of what
happened needs to resist quiet edits after the fact.

## Decision

Every stage output is a content-addressed blob (sha256). `audit/log.py` writes
JSONL records, each carrying `prev_hash` referring to the previous record's
`entry_hash`. `verify_chain()` walks the file linearly.

## Why

Tampering with any entry invalidates every entry after it. Content addressing
gives a stable identity to each output; the hash chain gives the audit log
integrity that a plain append-only file cannot.

[../architecture/storage.md](../architecture/storage.md) covers the store layout.
