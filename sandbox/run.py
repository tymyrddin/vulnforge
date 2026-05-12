"""Canonical sandbox invocation. Used uniformly for inference, fuzzing, and PoC
execution. Rootless podman, no network, read-only root filesystem, no caps, no
new privileges, no host daemon. Reviewing isolation amounts to reading this
file.

Containers are owned resources, not subprocess side-effects. Every container
gets a name and joins the module-level :data:`_active` set on creation; every
exit path (normal, timeout, signal, atexit) drains that set through one
:func:`_cleanup` function. The zombie pattern we want to prevent: ``podman run``
daemonises the container via conmon/runc, so SIGKILLing the client does not
kill the container. The container is therefore tracked explicitly and torn
down explicitly.
"""
from __future__ import annotations

import atexit
import signal
import subprocess
import uuid
from dataclasses import dataclass
from pathlib import Path

_active: set[str] = set()


def _cleanup(name: str) -> None:
    """Stop and remove a named container. Idempotent; never raises."""
    subprocess.run(
        ["podman", "stop", "--time", "1", name],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    subprocess.run(
        ["podman", "rm", "-f", name],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    _active.discard(name)


def cleanup_all() -> None:
    """Drain every tracked container. Called from atexit and signal paths."""
    for name in list(_active):
        _cleanup(name)


def _on_term(signum: int, frame: object) -> None:
    """Translate SIGTERM into a clean unwind. SIGINT already raises
    KeyboardInterrupt which unwinds through the finally blocks naturally."""
    raise SystemExit(128 + signum)


atexit.register(cleanup_all)
signal.signal(signal.SIGTERM, _on_term)


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
    name = f"vulnforge-{uuid.uuid4().hex[:12]}"
    args: list[str] = [
        "podman", "run",
        "--rm",
        "--name", name,
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

    _active.add(name)
    try:
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
    finally:
        _cleanup(name)
