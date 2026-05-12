"""llama.cpp subprocess wrapper.

Inference runs inside the canonical sandbox. The prompt is passed via stdin so
it does not appear in the process command line (which is readable via /proc).
Output for a given (weights_hash, prompt, seed) is deterministic.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path

from sandbox.run import Mount, run


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
) -> InferenceResult:
    actual = _file_sha256(weights_path)
    if actual != weights_hash:
        raise ValueError(
            f"weights hash mismatch: expected {weights_hash}, got {actual}"
        )
    result = run(
        image=sandbox_image,
        command=[
            "llama-cli",
            "--model", "/weights/model.gguf",
            "--seed", str(seed),
            "--n-predict", str(max_tokens),
            "--temp", str(temperature),
            "--no-display-prompt",
            "--file", "/dev/stdin",
        ],
        mounts=(Mount(source=weights_path, target="/weights/model.gguf", mode="ro"),),
        stdin=prompt.encode("utf-8"),
        timeout_seconds=timeout_seconds,
    )
    return InferenceResult(
        output_text=result.stdout.decode("utf-8", errors="replace"),
        stdout_hash=hashlib.sha256(result.stdout).hexdigest(),
        stderr_hash=hashlib.sha256(result.stderr).hexdigest(),
        seed=seed,
        weights_hash=weights_hash,
    )
