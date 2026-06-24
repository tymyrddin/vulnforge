# Installation

## Requirements

- Linux with rootless podman on PATH. Ubuntu 24.04 is the tested baseline.
- x86_64 CPU with AVX2 (llama.cpp requirement).
- Around 11 GiB free disk: weights (~10 GiB), sandbox image and build cache, CVE data (~200 MB for the OSV PyPI dump).
- 16 GiB RAM works well here. The default Qwen 7B inference runs in an 8 GiB cgroup (around 5 GiB resident); 16 GiB host RAM leaves room for the desktop.
- Network for the bootstrap step only. The analysis host can be offline afterwards.

The cgroup caps live in `inference/runner.py` and `sandbox/run.py`, adjustable for the hardware in front of you.

## Setup

In an activated venv:

```
pip install -e .
```