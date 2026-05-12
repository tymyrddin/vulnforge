"""Named pointers to object digests. Same separation git uses (branches vs
commits): refs are mutable, the objects they point at are not."""
from __future__ import annotations

from pathlib import Path

REF_ROOT = Path(".vulnforge/store/refs")


def write(name: str, digest: str) -> None:
    if "/" in name or name.startswith("."):
        raise ValueError(f"invalid ref name: {name}")
    REF_ROOT.mkdir(parents=True, exist_ok=True)
    (REF_ROOT / name).write_text(digest + "\n")


def read(name: str) -> str:
    return (REF_ROOT / name).read_text().strip()


def exists(name: str) -> bool:
    return (REF_ROOT / name).exists()
