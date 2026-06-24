"""llama.cpp subprocess wrapper.

Inference runs inside the canonical sandbox. The prompt is passed via stdin so
it does not appear in the process command line (which is readable via /proc).
Output for a given (weights_hash, prompt, seed) is deterministic.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from sandbox.run import Mount, run

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]")
_TIMINGS_RE = re.compile(r"\n*\[\s*Prompt:.*", re.DOTALL)


def _process_backspaces(text: str) -> str:
    out: list[str] = []
    for ch in text:
        if ch == "\x08":
            if out:
                out.pop()
        else:
            out.append(ch)
    return "".join(out)


def _extract_assistant_text(raw_stdout: bytes) -> str:
    """Strip llama-cli's conversation-mode chrome from a stdout capture.

    Removes ANSI escape sequences, replays backspaces (kills the loading and
    generation spinners), drops the trailing timings/Exiting block, and returns
    what comes after the last '> ' prompt-echo line. Falls back to the cleaned
    text if no prompt echo is present.
    """
    text = raw_stdout.decode("utf-8", errors="replace")
    text = _process_backspaces(text)
    text = _ANSI_RE.sub("", text)
    text = _TIMINGS_RE.sub("", text)
    lines = text.splitlines()
    last_echo = -1
    for i, line in enumerate(lines):
        if line.startswith("> "):
            last_echo = i
    if last_echo >= 0:
        text = "\n".join(lines[last_echo + 1:])
    return text.strip()


@dataclass(frozen=True)
class InferenceResult:
    output_text: str
    stdout_hash: str
    stderr_hash: str
    seed: int
    weights_hash: str


def _file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def infer(
    *,
    prompt: str,
    weights_path: Path,
    weights_hash: str,
    sandbox_image: str,
    seed: int,
    max_tokens: int = 1024,
    temperature: float = 0.2,
    timeout_seconds: int = 300,
    memory: str = "8g",
    cpus: str = "4",
    ctx_size: int = 4096,
    log_dir: Path | None = None,
    debug_llama: bool = False,
    no_think: bool = False,
) -> InferenceResult:
    if no_think:
        prompt = "/no_think\n\n" + prompt
    actual = _file_sha256(weights_path)
    if actual != weights_hash:
        raise ValueError(
            f"weights hash mismatch: expected {weights_hash}, got {actual}"
        )
    stderr_log_path: Path | None = None
    if log_dir is not None:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        stderr_log_path = log_dir / f"llama-{stamp}-seed{seed}.log"
    log_args = ["--log-file", "/dev/stderr"] if debug_llama else ["--log-disable"]
    result = run(
        image=sandbox_image,
        command=[
            "llama-cli",
            "--model", "/weights/model.gguf",
            "--seed", str(seed),
            "--n-predict", str(max_tokens),
            "--ctx-size", str(ctx_size),
            "--temp", str(temperature),
            "--no-display-prompt",
            "--single-turn",
            *log_args,
            "--simple-io",
            "--no-warmup",
            "--file", "/dev/stdin",
        ],
        mounts=(Mount(source=weights_path, target="/weights/model.gguf", mode="ro"),),
        stdin=prompt.encode("utf-8"),
        timeout_seconds=timeout_seconds,
        memory=memory,
        cpus=cpus,
        stderr_log_path=stderr_log_path,
    )
    if result.exit_code != 0:
        log_hint = f" (stderr log: {stderr_log_path})" if stderr_log_path else ""
        raise RuntimeError(
            f"llama-cli exited {result.exit_code}"
            f"{' (timed out)' if result.timed_out else ''}"
            f"{log_hint}"
        )
    return InferenceResult(
        output_text=_extract_assistant_text(result.stdout),
        stdout_hash=hashlib.sha256(result.stdout).hexdigest(),
        stderr_hash=hashlib.sha256(result.stderr).hexdigest(),
        seed=seed,
        weights_hash=weights_hash,
    )
