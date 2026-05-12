"""Ingest stage: walk a local repo, hash each file into the store, produce a
manifest blob mapping {path: digest}.

The repo path is local. Cloning, if needed, happens outside the analysis
pipeline so the analysis host can remain offline."""
from __future__ import annotations

import json
import time
from pathlib import Path

from audit.log import append as audit_append
from schema.audit_event import AuditEvent
from store import objects, refs

SKIP_DIRS = {".git", ".venv", "node_modules", ".vulnforge", "__pycache__", ".idea"}


def run(repo_path: Path) -> str:
    if not repo_path.is_dir():
        raise NotADirectoryError(repo_path)
    manifest: dict[str, str] = {}
    for path in sorted(repo_path.rglob("*")):
        if path.is_dir():
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        try:
            data = path.read_bytes()
        except OSError:
            continue
        rel = str(path.relative_to(repo_path))
        manifest[rel] = objects.put(data)
    manifest_bytes = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
    manifest_ref = objects.put(manifest_bytes)
    refs.write("ingest_latest", manifest_ref)
    audit_append(AuditEvent(
        timestamp=time.time(),
        stage="ingest",
        input_refs=(str(repo_path),),
        output_refs=(manifest_ref,),
        model_hash=None,
        seed=None,
        summary=f"{len(manifest)} files ingested",
    ))
    return manifest_ref
