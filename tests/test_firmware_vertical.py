"""Firmware vertical: extract -> screen (safety lens) -> execute (QEMU) -> verify.

Pure tests for the safety-lens grounding and the comparator run everywhere. The
end-to-end test drives a real Cortex-M image to a CONFIRMED verdict and is skipped
where capstone or qemu-system-arm is absent.
"""
import importlib.util
from pathlib import Path

import pytest

import workspace
from audit.log import verify_chain
from sandbox import qemu
from stages.screen import ground_safety_operation
from stages.verify import verify_firmware
from tests.firmware_fixtures import IWDG_KR, IWDG_START_KEY, register_write_image
from workspace import Workspace

_CONFIG = Path(__file__).resolve().parents[1] / "configs" / "stm32f405.yaml"
_HAVE_FW = importlib.util.find_spec("capstone") is not None and qemu.available()


# --- pure: safety-lens grounding ---

def _rw(address, role="watchdog"):
    return {"type": "register_write", "address": address, "value": 1, "role": role}


def test_grounds_when_watchdog_write_present():
    grounding, _reason, predicted = ground_safety_operation([_rw(IWDG_KR)], "watchdog")
    assert grounding.value == "grounded"
    assert predicted == [IWDG_KR]


def test_unsupported_when_no_watchdog_write():
    facts = [_rw(0x20000000, role=None)]
    grounding, _reason, predicted = ground_safety_operation(facts, "watchdog")
    assert grounding.value == "unsupported"
    assert predicted == []


# --- pure: comparator ---

def test_verify_confirmed_when_observed():
    obs = {"writes": [{"address": IWDG_KR, "value": IWDG_START_KEY, "size": 4}]}
    result = verify_firmware([IWDG_KR], obs)
    assert result["status"] == "confirmed"
    assert IWDG_KR in result["hits"]


def test_verify_refuted_when_not_observed():
    result = verify_firmware([IWDG_KR], {"writes": []})
    assert result["status"] == "refuted"
    assert result["hits"] == []


# --- end to end ---

@pytest.mark.skipif(not _HAVE_FW, reason="capstone or qemu-system-arm not installed")
def test_vertical_reaches_confirmed(tmp_path):
    from orchestrator import firmware

    workspace.use(Workspace.at(tmp_path / "run"))
    try:
        image = tmp_path / "fw.bin"
        image.write_bytes(register_write_image())
        verdict = firmware.run(image, _CONFIG)

        assert verdict["status"] == "confirmed"
        assert IWDG_KR in verdict["hits"]
        # index, screen, execute, verify all recorded, chain intact
        assert verify_chain() == 4
    finally:
        workspace.clear()


@pytest.mark.skipif(not _HAVE_FW, reason="capstone or qemu-system-arm not installed")
def test_vertical_unsupported_without_watchdog_write(tmp_path):
    from orchestrator import firmware

    workspace.use(Workspace.at(tmp_path / "run"))
    try:
        image = tmp_path / "fw.bin"
        image.write_bytes(register_write_image(address=0x20000400))  # SRAM, not a watchdog
        verdict = firmware.run(image, _CONFIG)

        assert verdict["status"] == "unsupported"
        assert "observation_ref" not in verdict  # never executed
    finally:
        workspace.clear()
