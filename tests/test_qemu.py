"""QEMU backend test: run the fixture image and observe the register write.

Skipped where qemu-system-arm is absent. This is the ground-truth half of the
firmware vertical, so it exercises a real emulator rather than a stub.
"""
from pathlib import Path

import pytest

from sandbox import qemu
from tests.firmware_fixtures import IWDG_KR, IWDG_START_KEY, register_write_image

pytestmark = pytest.mark.skipif(not qemu.available(), reason="qemu-system-arm not installed")


def _run(tmp_path: Path) -> dict:
    image = tmp_path / "fw.bin"
    image.write_bytes(register_write_image())
    return qemu.run(image)


def test_observes_the_register_write(tmp_path):
    result = _run(tmp_path)
    assert any(
        w["address"] == IWDG_KR and w["value"] == IWDG_START_KEY for w in result["writes"]
    )


def test_run_times_out_on_spin_loop(tmp_path):
    # The fixture spins forever; reaching the timeout is the normal exit.
    assert _run(tmp_path)["timed_out"] is True
