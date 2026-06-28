"""Cortex-M Thumb extractor for security facts.

The firmware sibling of extractors/python.py. Where the Python extractor walks an
AST, this one decodes a raw Cortex-M image with Capstone and reports stores to
memory-mapped registers. It honours the same contract: extract(...) ->
list[SecurityFact], each a dict with a "type" key.

The decoder reports a store to an address. It does not decide which peripheral
that address is; that is the knowledge layer (configs/<device>.yaml, loaded by
:func:`load_peripherals`). Capstone preserves the raw operand and address, so the
peripheral identity is added here rather than lost to a normalising IR. That split
is the reason the decision record gives for a native decoder over a borrowed IR.

Provenance is as honest as a linear single-function pass can be, mirroring the
Python extractor's arg_source:

  constant   the stored value was loaded from a PC-relative literal pool
  unknown    the stored value's register could not be followed to a constant

The pass is a recursive-descent disassembly from the vector table. Each exception
handler, and the reset handler, is a root; the decoder follows direct branches and
calls, decoding only bytes reached as code. Literal pools and data are never
decoded as instructions, which a whole-image linear sweep could not avoid: on real
firmware a blind sweep fabricated phantom stores out of data. The trade is recall,
code reached only through computed jumps or function pointers is not followed.

Within a basic block, registers loaded from PC-relative literal pools are tracked,
dropped when an instruction clobbers them, and the caller-saved set is dropped
across a call. A store to an address held in a tracked register is reported, and
the peripheral identity is added from the knowledge layer.
"""
from __future__ import annotations

import struct
from pathlib import Path
from typing import Any

import yaml
from capstone import (
    CS_ARCH_ARM,
    CS_GRP_CALL,
    CS_GRP_JUMP,
    CS_GRP_RET,
    CS_MODE_LITTLE_ENDIAN,
    CS_MODE_THUMB,
    Cs,
)
from capstone.arm import ARM_OP_IMM, ARM_OP_MEM, ARM_OP_REG, ARM_REG_PC

from extractors import SecurityFact


def load_peripherals(config_path: str | Path) -> list[dict[str, Any]]:
    """Load a device peripheral map. Bases and offsets are ints (YAML hex)."""
    data = yaml.safe_load(Path(config_path).read_text())
    return list(data.get("peripherals", []))


def _resolve(address: int, peripherals: list[dict[str, Any]]) -> dict[str, Any]:
    """Name an address against the peripheral map. Empty dict if unmapped."""
    for p in peripherals:
        base = int(p["base"])
        if base <= address < base + int(p.get("size", 0)):
            offset = address - base
            register = next(
                (r["name"] for r in p.get("registers", []) if int(r["offset"]) == offset),
                None,
            )
            return {"peripheral": p["name"], "register": register, "role": p.get("role")}
    return {}


def _u32(image: bytes, offset: int) -> int | None:
    if offset < 0 or offset + 4 > len(image):
        return None
    return struct.unpack_from("<I", image, offset)[0]


def infer_load_addr(image: bytes) -> int:
    """Infer the flash base from the reset vector. A .bin's pointers are absolute,
    so an OTA app linked above a bootloader is not at 0x08000000."""
    reset = _u32(image, 4)
    if reset is None:
        return 0x08000000
    target = reset & ~1
    for base in (0x08100000, 0x08080000, 0x08060000, 0x08040000, 0x08020000,
                 0x08010000, 0x08008000, 0x08004000, 0x08000000):
        if base <= target < base + len(image):
            return base
    return target & ~0xFFFF


def _entry_points(image: bytes, load_addr: int) -> list[int]:
    """Vector-table handler addresses, the roots for recursive descent. The table
    runs from offset 4 up to the reset handler (the first code byte); each entry
    pointing into the image with the Thumb bit set is a root."""
    reset = _u32(image, 4)
    if reset is None:
        return []
    code_start = reset & ~1
    end = code_start - load_addr
    if not 0 < end <= len(image):
        end = min(0x400, len(image))
    hi = load_addr + len(image)
    entries = {code_start}
    off = 4
    while off + 4 <= min(end, 0x400):
        w = _u32(image, off)
        if w is not None and w & 1 and load_addr <= w & ~1 < hi:
            entries.add(w & ~1)
        off += 4
    return sorted(entries)


# Registers a callee may change under AAPCS; not trusted as constants across a call.
_CALLER_SAVED = ("r0", "r1", "r2", "r3", "r12", "ip", "lr")


def extract(
    image: bytes, load_addr: int | None = None, peripherals: list[dict[str, Any]] | None = None
) -> list[SecurityFact]:
    """Decode a raw Cortex-M image and report register-write facts.

    image      raw bytes as loaded at load_addr (vector table first)
    load_addr  the address the image is mapped at; inferred from the reset vector
               when None
    """
    peripherals = peripherals or []
    if load_addr is None:
        load_addr = infer_load_addr(image)
    facts: list[SecurityFact] = []
    seen: set[tuple[int, int | None]] = set()

    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)
    md.detail = True

    lo, hi = load_addr, load_addr + len(image)
    worklist = _entry_points(image, load_addr)
    visited: set[int] = set()

    while worklist:
        start = worklist.pop()
        if start in visited or not lo <= start < hi:
            continue
        reg_const: dict[str, int] = {}
        for insn in md.disasm(image[start - load_addr:], start):
            if insn.address in visited:
                break
            visited.add(insn.address)
            _emit(insn, image, load_addr, peripherals, reg_const, seen, facts)

            if not _follow(insn, lo, hi, visited, worklist, reg_const):
                break  # end of basic block

    return facts


def _emit(
    insn: Any, image: bytes, load_addr: int, peripherals: list[dict[str, Any]],
    reg_const: dict[str, int], seen: set[tuple[int, int | None]], facts: list[SecurityFact],
) -> None:
    """Record a register write, then update tracked constants for this instruction."""
    ops = insn.operands
    mnemonic = insn.mnemonic

    # str Rt, [Rn{, #disp}]: a write to a fixed address when Rn is a tracked constant.
    # Read reg_const before any clobber invalidation below (writeback str changes Rn).
    if (mnemonic.startswith("str") and len(ops) >= 2 and ops[0].type == ARM_OP_REG
            and ops[1].type == ARM_OP_MEM):
        base = insn.reg_name(ops[1].mem.base)
        if base in reg_const:
            address = reg_const[base] + ops[1].mem.disp
            value = reg_const.get(insn.reg_name(ops[0].reg))
            key = (address, value)
            if key not in seen:
                seen.add(key)
                fact: SecurityFact = {
                    "type": "register_write",
                    "address": address,
                    "value": value,
                    "value_source": "constant" if value is not None else "unknown",
                }
                fact.update(_resolve(address, peripherals))
                facts.append(fact)

    # ldr Rd, [pc, #imm]: Rd becomes the literal-pool constant (computed pre-clobber).
    lit: tuple[str, int | None] | None = None
    if (mnemonic.startswith("ldr") and len(ops) == 2 and ops[0].type == ARM_OP_REG
            and ops[1].type == ARM_OP_MEM and ops[1].mem.base == ARM_REG_PC):
        literal_addr = ((insn.address + 4) & ~0b11) + ops[1].mem.disp
        lit = (insn.reg_name(ops[0].reg), _u32(image, literal_addr - load_addr))

    _read, written = insn.regs_access()
    for reg in written:
        reg_const.pop(insn.reg_name(reg), None)
    if lit is not None and lit[1] is not None:
        reg_const[lit[0]] = lit[1]


def _follow(
    insn: Any, lo: int, hi: int, visited: set[int], worklist: list[int],
    reg_const: dict[str, int],
) -> bool:
    """Queue branch/call targets and report whether the basic block continues."""
    is_call = bool(insn.group(CS_GRP_CALL))
    is_jump = bool(insn.group(CS_GRP_JUMP))

    if is_call or is_jump:
        target = next((o.imm for o in insn.operands if o.type == ARM_OP_IMM), None)
        if target is not None and lo <= target < hi and target not in visited:
            worklist.append(target)

    if is_call:
        for r in _CALLER_SAVED:          # callee may clobber these
            reg_const.pop(r, None)
        return True                      # a call returns to the next instruction

    if insn.group(CS_GRP_RET):
        return False
    if is_jump:
        # unconditional (plain b) or indirect (bx/tbb/tbh, no immediate) ends the block
        return not (insn.mnemonic in ("b", "b.w")
                    or not any(o.type == ARM_OP_IMM for o in insn.operands))
    # pop {pc}, ldr pc, mov pc, ... leave the block
    return "pc" not in (insn.reg_name(r) for r in insn.regs_access()[1])
