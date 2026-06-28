# OT/ICS direction: a semantic evidence substrate

The architectural calls behind this direction are settled in
[../decisions/2026-06-26-semantic-evidence-substrate.md](../decisions/2026-06-26-semantic-evidence-substrate.md):
one fact substrate with security, safety, and compliance as lenses; the same
substrate-and-lens shape on the observation side; a plug-in per pipeline layer
with execute and verify as the hard seam; the IR dependency-inversion trade; and
thin-vertical-before-ontology. This note holds the build order, not the why.

## The first vertical

One play, end to end, before any ontology generalisation. Built 2026-06-28:

STM32 firmware image writing a watchdog control register
→ recursive-descent Thumb decoder (Capstone) producing facts
→ one predicate: watchdog control register written
→ QEMU (netduinoplus2, STM32F405) observing the memory-mapped write
→ verify comparing predicted against observed
→ CONFIRMED

This produced the first positive CONFIRMED verdict on real surface. The only prior
end-to-end run is `stages/`, which has almost no sinks, so no grounded,
contradicted, or confirmed verdict had landed on a meaningful artefact (Immediate
priorities in [README.md](README.md) records the same gap). The vertical doubles
as the first real-surface run the policy-calibration question needs.

A second step tests the whole thesis: another consumer reads the same watchdog
fact and asks a different question of it, adding nothing to the fact. Until a
second consumer pulls on the interface, a neutral fact substrate is unproven and
any neutrality is vulnerability-shaped. Built: safety and compliance consumers
both read the same fact, so three consumers now pull on it.

As built, two substitutions from the sketch above:

- QEMU stands in for Renode. QEMU reports the MMIO write, absolute address and
  value, through its `memory_region_ops_write` trace, enough to confirm the
  register was written. It does not model the watchdog as a device, so the
  watchdog's peripheral state is not observable in this backend. Renode is the
  deferred upgrade for peripheral-state properties.
- The predicate is "watchdog control register written", not "disabled". An STM32
  independent watchdog cannot be disabled once started, so the write to its
  control register is the observable operation.

The decoder is Capstone in recursive descent from the vector table, not a
hand-rolled instruction decoder. This meets the native-decoder intent of the
[decision record](../decisions/2026-06-26-semantic-evidence-substrate.md): Capstone
preserves the raw store address and operand, so the peripheral identity comes from
the knowledge layer rather than being lost to a normalising IR.

## Front-end priority

European industrial coverage orders the front ends:

1. ARM Cortex-M, Thumb decoder. STMicroelectronics STM32 first, then NXP and
   Infineon Cortex-M families. One decoder covers much of the Cortex-M segment of
   European industrial controllers; the segment is one part of a field that still
   runs PLC CPUs, x86, PowerPC, TriCore, and proprietary DSPs.
2. Infineon AURIX/TriCore. A fresh decoder, disproportionately important for
   automotive and safety-critical industrial systems.
3. IEC 61131-3 Structured Text. Block-structured, maps onto the existing slice
   model. Ahead of ladder logic, which wants a graph representation rather than
   an AST and lands later.

The decoder layer and the knowledge layer stay separate: `thumb_decoder.py`,
`riscv_decoder.py`, `avr_decoder.py` feed peripheral and standard knowledge
(`cmsis_svd.py`, `stm32.py`, `aurix.py`, `iec62443.py`), because the knowledge
accumulates independently of the instruction set.

## Domain vocabularies

The substrate stays fixed; only the vocabulary grows, rebuilt per architecture.

- Source vocabulary beyond the parameter-shaped model: MMIO register reads, DMA
  buffers, comms ring buffers (UART, CAN), NVM, interrupt vectors, the PLC input
  image. The grounding discipline transfers unchanged (unknown is not
  not-tainted); the source set does not.
- Sink vocabulary for safety-critical operations: watchdog control, secure boot
  configuration, MPU reconfiguration, clock source, interrupt vector table,
  firmware-update unlock, DMA into executable memory.
- Outcome predicates for emulated state: register-state, memory-state, and
  peripheral-state assertions. Some properties are emulation-verifiable (register
  and memory state) and some are not in this backend (timing, clock-glitch,
  analogue), though they remain safety properties. The verdict states already
  carry the unverifiable case.

## Deferred

- Binary lifting through a third-party IR. The expressiveness ceiling is the
  reason, recorded in
  [../decisions/2026-06-26-semantic-evidence-substrate.md](../decisions/2026-06-26-semantic-evidence-substrate.md).
  Native decoders first.
- Ladder logic. Graph representation, after Structured Text.
- The Evidence consumer abstraction as a built layer. Deferred until two
  consumers disagree, the point at which the interface gets constrained by
  something other than the first consumer's shape.

Every step above preserves the same invariant: front ends translate language into
semantics, and consumers interpret semantics without changing the substrate.