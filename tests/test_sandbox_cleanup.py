"""Clean-up invariants for sandbox.run.

The containers spawned by ``sandbox.run.run`` are daemonised via conmon/runc,
which means killing the podman client does not kill the container. This test
suite enforces the opposite invariant: every code path through ``run`` leaves
zero ``vulnforge-`` containers behind, whether it completed normally, hit a
timeout, or was interrupted.

Skipped on hosts that have not run ``vulnforge bootstrap`` (podman or the
sandbox image missing).
"""
from __future__ import annotations

import shutil
import subprocess

import pytest

from bootstrap import build_sandbox
from sandbox import run as sandbox_run


def _image_hash() -> str | None:
    try:
        return build_sandbox.current_hash()
    except FileNotFoundError:
        return None


skip_if_no_sandbox = pytest.mark.skipif(
    shutil.which("podman") is None or _image_hash() is None,
    reason="podman or sandbox image missing (run vulnforge bootstrap first)",
)


def _live_vulnforge_containers() -> list[str]:
    out = subprocess.run(
        ["podman", "ps", "--format", "{{.Names}}"],
        capture_output=True, text=True, check=False,
    )
    return [n for n in out.stdout.splitlines() if n.startswith("vulnforge-")]


@skip_if_no_sandbox
def test_clean_exit_tears_down_container() -> None:
    image = _image_hash()
    assert image is not None
    result = sandbox_run.run(image=image, command=["true"], timeout_seconds=10)
    assert result.exit_code == 0
    assert not result.timed_out
    assert _live_vulnforge_containers() == []
    assert sandbox_run._active == set()  # Protected access for test verification


@skip_if_no_sandbox
def test_timeout_tears_down_container() -> None:
    image = _image_hash()
    assert image is not None
    result = sandbox_run.run(image=image, command=["sleep", "60"], timeout_seconds=2)
    assert result.timed_out
    assert result.exit_code == 124
    assert _live_vulnforge_containers() == [], "container leaked after timeout"
    assert sandbox_run._active == set(), "active set leaked after timeout"
