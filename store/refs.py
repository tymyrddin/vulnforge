"""Named pointers to object digests. Same separation git uses (branches vs
commits): refs are mutable, the objects they point at are not. Lives under
the active workspace at ``<workspace>/store/refs/``."""

from __future__ import annotations

from workspace import active


def write(name: str, digest: str) -> None:
    if "/" in name or name.startswith("."):
        raise ValueError(f"invalid ref name: {name}")
    root = active().refs_root
    root.mkdir(parents=True, exist_ok=True)
    (root / name).write_text(digest + "\n")


def read(name: str) -> str:
    return (active().refs_root / name).read_text().strip()


def exists(name: str) -> bool:
    return (active().refs_root / name).exists()
