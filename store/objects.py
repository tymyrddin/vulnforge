"""Content-addressed blobs under .vulnforge/store/objects/ab/cd/abcd...

Writes are atomic (tempfile + rename). Reads verify the digest. Nothing here
deletes objects; the store is append-only by convention.
"""
from __future__ import annotations

import hashlib
import os
import tempfile
from pathlib import Path

STORE_ROOT = Path(".vulnforge/store/objects")


def _path_for(digest: str) -> Path:
    return STORE_ROOT / digest[:2] / digest[2:4] / digest[4:]


def put(data: bytes) -> str:
    digest = hashlib.sha256(data).hexdigest()
    dest = _path_for(digest)
    if dest.exists():
        return digest
    dest.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=dest.parent)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        os.replace(tmp, dest)
    except BaseException:
        if Path(tmp).exists():
            os.unlink(tmp)
        raise
    return digest


def get(digest: str) -> bytes:
    data = _path_for(digest).read_bytes()
    actual = hashlib.sha256(data).hexdigest()
    if actual != digest:
        raise IOError(f"store: hash mismatch reading {digest}, got {actual}")
    return data


def exists(digest: str) -> bool:
    return _path_for(digest).exists()
