"""Fetch model weights and verify them against pinned SHA256 hashes.

The expected workflow:
  1. Edit bootstrap/models.lock to list each weight (alias, url, sha256).
  2. Run `vulnforge bootstrap`.
  3. The analysis host can now run offline.

If weights are fetched on a different machine and copied across by hand, place
them at .vulnforge/weights/<alias>.gguf and run `vulnforge bootstrap --verify-only`
to confirm hashes match the lock file.
"""
from __future__ import annotations

import hashlib
import urllib.request
from dataclasses import dataclass
from pathlib import Path

import yaml

WEIGHTS_DIR = Path(".vulnforge/weights")
LOCK_FILE = Path("bootstrap/models.lock")


@dataclass(frozen=True)
class ModelSpec:
    alias: str
    url: str
    sha256: str

    @property
    def dest(self) -> Path:
        return WEIGHTS_DIR / f"{self.alias}.gguf"


def load_specs() -> list[ModelSpec]:
    data = yaml.safe_load(LOCK_FILE.read_text()) or {}
    return [ModelSpec(**entry) for entry in (data.get("models") or [])]


def _file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def fetch_all(verify_only: bool = False) -> None:
    WEIGHTS_DIR.mkdir(parents=True, exist_ok=True)
    specs = load_specs()
    if not specs:
        print("bootstrap/models.lock has no entries; nothing to fetch")
        return
    for spec in specs:
        if spec.dest.exists():
            actual = _file_sha256(spec.dest)
            if actual == spec.sha256:
                print(f"ok    {spec.alias} (already present)")
                continue
            print(f"stale {spec.alias} (hash {actual}, expected {spec.sha256})")
            spec.dest.unlink()
        if verify_only:
            raise FileNotFoundError(f"missing weight: {spec.dest}")
        print(f"fetch {spec.alias} from {spec.url}")
        with urllib.request.urlopen(spec.url) as resp, spec.dest.open("wb") as out:
            while True:
                chunk = resp.read(1 << 20)
                if not chunk:
                    break
                out.write(chunk)
        actual = _file_sha256(spec.dest)
        if actual != spec.sha256:
            spec.dest.unlink()
            raise ValueError(
                f"hash mismatch for {spec.alias}: got {actual}, expected {spec.sha256}"
            )
        print(f"ok    {spec.alias}")
