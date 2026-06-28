"""Unit tests for extractors.thumb.extract. No QEMU, no toolchain.

Decodes the hand-encoded fixture image and checks the register-write fact, its
resolved peripheral identity, and provenance.
"""
from pathlib import Path

import pytest

pytest.importorskip("capstone")

from extractors.thumb import extract, load_peripherals  # noqa: E402
from tests.firmware_fixtures import (  # noqa: E402
    FLASH_BASE,
    GPIOA_BASE,
    IWDG_KR,
    IWDG_START_KEY,
    call_reached_write_image,
    clobber_write_image,
    multi_write_image,
    register_write_image,
    unreachable_write_image,
)

_CONFIG = Path(__file__).resolve().parents[1] / "configs" / "stm32f405.yaml"


def _facts():
    peripherals = load_peripherals(_CONFIG)
    return extract(register_write_image(), FLASH_BASE, peripherals)


def test_finds_register_write():
    facts = _facts()
    assert any(f["type"] == "register_write" for f in facts)


def test_resolves_address_and_value():
    fact = next(f for f in _facts() if f["type"] == "register_write")
    assert fact["address"] == IWDG_KR
    assert fact["value"] == IWDG_START_KEY


def test_value_provenance_is_constant():
    fact = next(f for f in _facts() if f["type"] == "register_write")
    assert fact["value_source"] == "constant"


def test_peripheral_named_from_knowledge_layer():
    fact = next(f for f in _facts() if f["type"] == "register_write")
    assert fact["peripheral"] == "IWDG"
    assert fact["register"] == "KR"
    assert fact["role"] == "watchdog"


def test_unmapped_address_has_no_peripheral():
    peripherals = load_peripherals(_CONFIG)
    facts = extract(register_write_image(address=0x20000400), FLASH_BASE, peripherals)
    fact = next(f for f in facts if f["type"] == "register_write")
    assert fact["address"] == 0x20000400
    assert "peripheral" not in fact


def test_finds_write_reached_via_call():
    # The store lives in a function called (bl) from reset; recursive descent follows it.
    peripherals = load_peripherals(_CONFIG)
    facts = extract(call_reached_write_image(), FLASH_BASE, peripherals)
    wd = [f for f in facts if f.get("role") == "watchdog"]
    assert len(wd) == 1
    assert wd[0]["address"] == IWDG_KR


def test_unreachable_write_not_decoded():
    # The store is in an uncalled function. Recursive descent never reaches it, so
    # it is not reported. This is the precision a blind linear sweep cannot give.
    peripherals = load_peripherals(_CONFIG)
    facts = extract(unreachable_write_image(), FLASH_BASE, peripherals)
    assert not any(f.get("role") == "watchdog" for f in facts)


def test_clobbered_base_is_not_reported_as_watchdog():
    # Base register overwritten before the store: no watchdog write may be claimed.
    peripherals = load_peripherals(_CONFIG)
    facts = extract(clobber_write_image(), FLASH_BASE, peripherals)
    assert not any(f.get("role") == "watchdog" for f in facts)


def test_multiple_peripherals_each_resolved():
    peripherals = load_peripherals(_CONFIG)
    facts = extract(multi_write_image(), FLASH_BASE, peripherals)
    addrs = {f["address"]: f for f in facts if f["type"] == "register_write"}
    assert IWDG_KR in addrs and GPIOA_BASE in addrs
    assert addrs[IWDG_KR]["role"] == "watchdog"
    assert "peripheral" not in addrs[GPIOA_BASE]  # GPIOA absent from the minimal map
