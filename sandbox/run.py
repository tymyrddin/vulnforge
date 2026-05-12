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
    stderr_log_path: Path | None = None,
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

    if stderr_log_path is None:
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

    # stderr streamed straight to disk so a crash mid-run still leaves a trace.
    stderr_log_path.parent.mkdir(parents=True, exist_ok=True)
    with stderr_log_path.open("wb+") as log_f:
        try:
            proc = subprocess.run(
                args,
                input=stdin,
                stdout=subprocess.PIPE,
                stderr=log_f,
                timeout=timeout_seconds,
                check=False,
            )
            log_f.flush()
            log_f.seek(0)
            return Result(proc.returncode, proc.stdout, log_f.read(), False)
        except subprocess.TimeoutExpired as e:
            log_f.flush()
            log_f.seek(0)
            return Result(124, e.stdout or b"", log_f.read(), True)
