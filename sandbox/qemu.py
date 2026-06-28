"""QEMU execution backend for Cortex-M firmware.

The firmware sibling of sandbox/run.py. Where that runs Python payloads in a
podman container, this runs a firmware image in qemu-system-arm and reports the
memory-mapped writes the guest performed. It is the ground-truth half of the
firmware vertical: the static fact says a store to a register should happen, this
says whether it did at runtime.

QEMU's STM32 peripheral map is approximate and mislabels regions, so the trace
line's region name is ignored. The absolute address and value are what count; the
peripheral identity comes from the knowledge layer (extractors.thumb), not here.

The guest spins forever by design, so the run always reaches its timeout; that is
the normal exit, not a failure. The process is a foreground child killed on
timeout, no daemonised state to track.
"""
from __future__ import annotations

import hashlib
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

DEFAULT_MACHINE = "netduinoplus2"  # STM32F405, Cortex-M4

# memory_region_ops_write cpu 0 mr 0x.. addr 0x40003000 value 0xcccc size 4 name '..'
_WRITE_RE = re.compile(r"addr (0x[0-9a-fA-F]+) value (0x[0-9a-fA-F]+) size (\d+)")


def available() -> bool:
    return shutil.which("qemu-system-arm") is not None


def run(
    image_path: str | Path, machine: str = DEFAULT_MACHINE, timeout: float = 3.0
) -> dict[str, Any]:
    """Run a firmware image and return the memory-mapped writes it performed.

    Returns {"writes": [{"address": int, "value": int, "size": int}, ...],
             "timed_out": bool, "image_sha256": str}.
    """
    image_path = Path(image_path)
    image_sha256 = hashlib.sha256(image_path.read_bytes()).hexdigest()

    with tempfile.TemporaryDirectory() as tmp:
        trace = Path(tmp) / "trace.log"
        cmd = [
            "qemu-system-arm", "-M", machine, "-kernel", str(image_path),
            "-nographic", "-no-reboot",
            "--trace", "memory_region_ops_write", "-D", str(trace),
        ]
        timed_out = False
        try:
            subprocess.run(
                cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                timeout=timeout, check=False,
            )
        except subprocess.TimeoutExpired:
            timed_out = True  # expected: the guest spin-loops

        writes: list[dict[str, int]] = []
        if trace.exists():
            for line in trace.read_text().splitlines():
                m = _WRITE_RE.search(line)
                if m:
                    writes.append({
                        "address": int(m.group(1), 16),
                        "value": int(m.group(2), 16),
                        "size": int(m.group(3)),
                    })

    return {"writes": writes, "timed_out": timed_out, "image_sha256": image_sha256}
