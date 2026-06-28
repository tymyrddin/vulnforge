"""End-to-end smoke test. Skipped on hosts that have not run `vulnforge
bootstrap`. When podman, the built sandbox image, and the plumbing-check
weights are all present, it invokes the `plumbing` CLI command and confirms
that llama-cli produced output inside the sandbox.

Run after bootstrap completes:

    pytest tests/test_plumbing.py -v
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest
from click.testing import CliRunner

from cli import main
from workspace import weights_dir

ROOT = Path(__file__).resolve().parent.parent

skip_if_unbootstrapped = pytest.mark.skipif(
    shutil.which("podman") is None
    or not (ROOT / "bootstrap/sandbox.lock").exists()
    or not (weights_dir() / "plumbing-check.gguf").exists(),
    reason="vulnforge bootstrap has not run (podman, sandbox image, or weights missing)",
)


@pytest.fixture(autouse=True)
def _chdir_root(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(ROOT)


@skip_if_unbootstrapped
def test_plumbing_runs() -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["plumbing"])
    assert result.exit_code == 0, result.output
    assert "plumbing ok" in result.output
    assert "output:" in result.output
