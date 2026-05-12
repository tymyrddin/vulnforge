"""Where a scan run writes its artefacts.

The framework checkout is immutable. Every run lands in its own directory
under ``$XDG_DATA_HOME/vulnforge/runs/<run-id>/`` (fallback
``~/.local/share/vulnforge/runs/<run-id>/``). Weights are shared across runs
and live separately under the same root at ``weights/``.

Resolution order for the root:
  1. ``$VULNFORGE_WORKSPACE`` (if set)
  2. ``$XDG_DATA_HOME/vulnforge`` (if XDG_DATA_HOME is set)
  3. ``~/.local/share/vulnforge``

A scan acquires a :class:`Workspace` (typically via :func:`new_run`), pins it
as active with :func:`use`, and any module that needs to write artefacts asks
:func:`active` for it. Tests can supply their own via :meth:`Workspace.at`.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path


def _root() -> Path:
    explicit = os.environ.get("VULNFORGE_WORKSPACE")
    if explicit:
        return Path(explicit).expanduser()
    xdg = os.environ.get("XDG_DATA_HOME")
    if xdg:
        return Path(xdg).expanduser() / "vulnforge"
    return Path.home() / ".local" / "share" / "vulnforge"


def weights_dir() -> Path:
    return _root() / "weights"


def runs_root() -> Path:
    return _root() / "runs"


@dataclass(frozen=True, slots=True)
class Workspace:
    root: Path
    store_root: Path
    refs_root: Path
    audit_log: Path
    logs_dir: Path
    reports_dir: Path

    @classmethod
    def at(cls, path: Path) -> "Workspace":
        return cls(
            root=path,
            store_root=path / "store" / "objects",
            refs_root=path / "store" / "refs",
            audit_log=path / "audit" / "log.jsonl",
            logs_dir=path / "logs",
            reports_dir=path / "reports",
        )


def new_run(run_id: str | None = None, base: Path | None = None) -> Workspace:
    if run_id is None:
        run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    base = base if base is not None else runs_root()
    return Workspace.at(base / run_id)


_active: Workspace | None = None


def use(ws: Workspace) -> None:
    global _active
    _active = ws


def clear() -> None:
    global _active
    _active = None


def active() -> Workspace:
    if _active is None:
        raise RuntimeError(
            "no active workspace; call workspace.use() at the entry point"
        )
    return _active