"""CLI wiring regression tests. The pipeline run is stubbed, so these exercise
command wiring only: no model, no podman, fast.

Guards against the class of regression where a command calls a pipeline entry point
that does not exist (the scan command once called pipeline.run_repo, which had been
removed; the orchestrator's entry is pipeline.run). The full suite missed it because
nothing else drives the scan command end to end.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from click.testing import CliRunner

import orchestrator.pipeline as pipeline
import workspace
from cli import main


def test_scan_invokes_pipeline_run(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[Path] = []
    monkeypatch.setattr(pipeline, "run", lambda repo_path, *a, **k: calls.append(repo_path))

    repo = tmp_path / "repo"
    repo.mkdir()
    try:
        result = CliRunner().invoke(main, ["scan", str(repo), "--workspace", str(tmp_path / "run")])
    finally:
        workspace.clear()

    assert result.exit_code == 0, result.output
    assert calls == [repo]  # scan must call pipeline.run(repo), not a removed entry point
