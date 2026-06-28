"""Toolchain-free Cortex-M fixtures.

Hand-encoded Thumb, so the test suite builds a real Cortex-M image without an ARM
cross-compiler. The image is a minimal vector table plus four instructions that
store a constant to a memory-mapped register, then spin.

Used by the Thumb extractor test (decode the store) and the QEMU backend test
(observe the store at runtime).
"""
from __future__ import annotations

import struct

FLASH_BASE = 0x08000000
IWDG_KR = 0x40003000   # STM32F405 independent-watchdog key register
IWDG_START_KEY = 0x0000CCCC


def register_write_image(address: int = IWDG_KR, value: int = IWDG_START_KEY) -> bytes:
    """A raw image that does `*(u32*)address = value;` then loops forever.

    Layout (offsets from FLASH_BASE):
      0x00  initial SP
      0x04  reset vector (-> code at 0x08, Thumb bit set)
      0x08  ldr r0,[pc,#4]   load `address` from the literal pool
      0x0a  ldr r1,[pc,#8]   load `value`   from the literal pool
      0x0c  str r1,[r0]      the store under test
      0x0e  b .              spin
      0x10  .word address
      0x14  .word value
    """
    header = struct.pack("<II", 0x20001000, FLASH_BASE + 0x08 + 1)
    code = struct.pack("<HHHH", 0x4801, 0x4902, 0x6001, 0xE7FE)
    literals = struct.pack("<II", address, value)
    return header + code + literals


def unreachable_write_image() -> bytes:
    """A watchdog write that reset never reaches: the reset handler spins, and the
    store lives in an uncalled function. A walk from reset finds nothing here; a
    linear sweep over all code finds it. This is the case real HAL firmware creates,
    where the write sits behind calls rather than on the straight-line path.

      0x08  b .            reset stub spins, never reaching the function
      0x0a  nop            pad to 4-align
      0x0c  ldr r0,[pc,#4] IWDG base
      0x0e  ldr r1,[pc,#8] value
      0x10  str r1,[r0]
      0x12  bx lr
      0x14  .word IWDG_KR / .word value
    """
    header = struct.pack("<II", 0x20001000, FLASH_BASE + 0x08 + 1)
    code = struct.pack("<HHHHHH", 0xE7FE, 0xBF00, 0x4801, 0x4902, 0x6001, 0x4770)
    literals = struct.pack("<II", IWDG_KR, IWDG_START_KEY)
    return header + code + literals


def call_reached_write_image() -> bytes:
    """The watchdog write lives in a function reached by a call (bl) from reset,
    the shape real HAL firmware has. Recursive descent follows the call and finds
    it; a write in code reachable only this way is the realistic positive.

      0x08  bl 0x10        (4-byte Thumb call)
      0x0c  b .
      0x0e  pad
      0x10  ldr r0,[pc,#4] / ldr r1,[pc,#8] / str r1,[r0] / bx lr
      0x18  .word IWDG_KR / .word value
    """
    header = struct.pack("<II", 0x20001000, FLASH_BASE + 0x08 + 1)
    code = struct.pack(
        "<HHHHHHHH",
        0xF000, 0xF802,                  # bl 0x08000010
        0xE7FE, 0x0000,                  # b . ; pad
        0x4801, 0x4902, 0x6001, 0x4770,  # ldr r0; ldr r1; str r1,[r0]; bx lr
    )
    literals = struct.pack("<II", IWDG_KR, IWDG_START_KEY)
    return header + code + literals


def clobber_write_image() -> bytes:
    """The IWDG base is loaded, then overwritten before the store. The store targets
    whatever r0 now holds, not the watchdog, so no watchdog write may be reported.
    Exercises constant invalidation on register clobber (precision).

      0x08  ldr r0,[pc,#8]  IWDG base
      0x0a  movs r0,#0       clobber r0
      0x0c  ldr r1,[pc,#8]   value
      0x0e  str r1,[r0]      r0 no longer the base
      0x10  b .
    """
    header = struct.pack("<II", 0x20001000, FLASH_BASE + 0x08 + 1)
    code = struct.pack("<HHHHHH", 0x4802, 0x2000, 0x4902, 0x6001, 0xE7FE, 0x0000)
    literals = struct.pack("<II", IWDG_KR, IWDG_START_KEY)
    return header + code + literals


# A non-watchdog peripheral, present in no minimal device map: GPIOA on STM32F4.
GPIOA_BASE = 0x40020000


def multi_write_image() -> bytes:
    """Two register writes in sequence: IWDG (watchdog) then GPIOA (unmapped here).
    Both are reported; only the watchdog one carries a role.

      0x08  ldr r0,[pc,#c] / ldr r1,[pc,#10] / str r1,[r0]   IWDG
      0x0e  ldr r0,[pc,#10]/ ldr r1,[pc,#10] / str r1,[r0]   GPIOA
      0x14  b .
      0x18  .word IWDG_KR / .word val / .word GPIOA / .word val
    """
    header = struct.pack("<II", 0x20001000, FLASH_BASE + 0x08 + 1)
    code = struct.pack(
        "<HHHHHHHH",
        0x4803, 0x4904, 0x6001,   # r0=IWDG, r1=val1, *r0=r1
        0x4804, 0x4904, 0x6001,   # r0=GPIOA, r1=val2, *r0=r1
        0xE7FE, 0x0000,
    )
    literals = struct.pack("<IIII", IWDG_KR, IWDG_START_KEY, GPIOA_BASE, 0x00000001)
    return header + code + literals
