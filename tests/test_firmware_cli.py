"""CLI test for firmware-scan: the vertical driven from the real entry point.

Skipped where capstone or qemu-system-arm is absent. Exercises the command a user
would run, not the orchestrator directly.
"""
import importlib.util
from pathlib import Path

import pytest
from click.testing import CliRunner

import workspace
from sandbox import qemu
from tests.firmware_fixtures import register_write_image

_CONFIG = Path(__file__).resolve().parents[1] / "configs" / "stm32f405.yaml"
_HAVE_FW = importlib.util.find_spec("capstone") is not None and qemu.available()

pytestmark = pytest.mark.skipif(not _HAVE_FW, reason="capstone or qemu-system-arm not installed")


def _run(tmp_path: Path, image_bytes: bytes):
    from cli import main

    image = tmp_path / "fw.bin"
    image.write_bytes(image_bytes)
    runner = CliRunner()
    try:
        return runner.invoke(main, [
            "firmware-scan", str(image),
            "--device", str(_CONFIG),
            "--workspace", str(tmp_path / "run"),
        ])
    finally:
        workspace.clear()


def test_confirmed_run_reports_verdict_and_both_consumers(tmp_path):
    result = _run(tmp_path, register_write_image())
    assert result.exit_code == 0, result.output
    assert "CONFIRMED" in result.output
    assert "watchdog control register written" in result.output
    assert "watchdog_protection_reconfigured" in result.output      # safety consumer
    assert "SR 7.4" in result.output and "candidate_evidence" in result.output  # compliance


def test_non_watchdog_image_is_unsupported(tmp_path):
    result = _run(tmp_path, register_write_image(address=0x20000400))  # SRAM, not a watchdog
    assert result.exit_code == 0, result.output
    assert "UNSUPPORTED" in result.output
