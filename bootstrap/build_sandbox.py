"""Build the sandbox container image and record its content hash.

The recorded hash is what `sandbox/run.py` refers to when invoking stages; this
guarantees every stage runs against a known image rather than whatever
`vulnforge-sandbox:latest` happens to resolve to at the time.
"""
from __future__ import annotations

import subprocess
from pathlib import Path

CONTAINERFILE = Path("sandbox/Containerfile")
LOCK_FILE = Path("bootstrap/sandbox.lock")
IMAGE_TAG = "vulnforge-sandbox:latest"


def build() -> str:
    if not CONTAINERFILE.exists():
        raise FileNotFoundError(CONTAINERFILE)
    subprocess.run(
        ["podman", "build", "-f", str(CONTAINERFILE), "-t", IMAGE_TAG, "."],
        check=True,
    )
    raw = subprocess.check_output(
        ["podman", "inspect", "--format={{.Id}}", IMAGE_TAG],
    ).decode().strip()
    image_hash = raw.split(":", 1)[-1]
    LOCK_FILE.write_text(image_hash + "\n")
    return image_hash


def current_hash() -> str:
    if not LOCK_FILE.exists():
        raise FileNotFoundError(LOCK_FILE)
    return LOCK_FILE.read_text().strip()
