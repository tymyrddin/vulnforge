"""Canonical sandbox invocation. Used uniformly for inference, fuzzing, and PoC
execution. Rootless podman, no network, read-only root filesystem, no caps, no
new privileges, no host daemon. Reviewing isolation amounts to reading this
file.
"""
from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Mount:
    source: Path
    target: str
    mode: str = "ro"  # "ro" or "rw"


@dataclass(frozen=True)
class Result:
    exit_code: int
    stdout: bytes
    stderr: bytes
    timed_out: bool


def run(
    image: str,
    command: list[str],
    mounts: tuple[Mount, ...] = (),
    stdin: bytes = b"",
    timeout_seconds: int = 60,
    memory: str = "2g",
    cpus: str = "2",
    pids_limit: int = 256,
) -> Result:
    args: list[str] = [
        "podman", "run",
        "--rm",
        "-i",
        "--network=none",
        "--read-only",
        "--tmpfs", "/tmp:size=128m,mode=1777",
        "--user", "65534:65534",
        "--cap-drop=ALL",
        "--security-opt", "no-new-privileges",
        "--pids-limit", str(pids_limit),
        "--memory", memory,
        "--cpus", cpus,
    ]
    for m in mounts:
        ro = "true" if m.mode == "ro" else "false"
        args += [
            "--mount",
            f"type=bind,src={m.source.resolve()},dst={m.target},ro={ro}",
        ]
    args.append(image)
    args.extend(command)

    try:
        proc = subprocess.run(
            args,
            input=stdin,
            capture_output=True,
            timeout=timeout_seconds,
            check=False,
        )
        return Result(proc.returncode, proc.stdout, proc.stderr, False)
    except subprocess.TimeoutExpired as e:
        return Result(124, e.stdout or b"", e.stderr or b"", True)
