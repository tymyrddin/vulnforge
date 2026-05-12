"""Pipeline runner.

Reads configs/pipeline.yaml and runs stages in order. Each stage knows how to
read its inputs from the store (by ref) and write its outputs back (also by
ref). The orchestrator's only job is sequencing.

If a stage raises NotImplementedError, the pipeline halts with a clear
message; partial progress is durable because every completed stage's output is
already in the content store and the audit log.
"""
from __future__ import annotations

from pathlib import Path

import yaml

from stages import ingest

CONFIG_PATH = Path("configs/pipeline.yaml")


def run(repo_path: Path, config_path: Path = CONFIG_PATH) -> None:
    config = yaml.safe_load(config_path.read_text())
    stages = config.get("stages", [])
    current_ref: str | None = None
    for stage in stages:
        name = stage["name"]
        if name == "ingest":
            current_ref = ingest.run(repo_path)
            print(f"ingest -> {current_ref[:12]}")
            continue
        # Subsequent stages are not yet implemented; halt with context.
        raise NotImplementedError(
            f"stage '{name}' is not yet implemented; last good ref: {current_ref}"
        )
