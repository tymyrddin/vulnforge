# Vulnforge

A tool that uses local AI models to look for security vulnerabilities in code, built so that the AI never decides on its
own whether something is actually a vulnerability, and so that nothing the tool sees ever leaves the machine.

## Four claims

The AI proposes, code decides. The AI suggests where a vulnerability might be. Whether the suggestion is actually a
vulnerability is decided by running the code in an isolated environment and observing what happens, not by asking the AI
to grade itself.

Nothing leaves the host. Once the tool is set up, the machine running it does not need internet. No prompts go to
OpenAI, Anthropic, or any other vendor. No third party logs what you investigated, what you found, or what you tried.

Every decision is recorded and verifiable. The tool keeps a tamper-evident record of every step, so any finding can be
traced back to exactly what produced it.

It runs on what you already have. Local open-source models on a normal workstation. No cloud bill, no vendor dependency,
no API key.

## Install

Requirements:

- Linux with rootless podman on PATH. Ubuntu 24.04 is the tested baseline.
- x86_64 CPU with AVX2 (a llama.cpp requirement).
- Around 11 GiB free disk: weights (~10 GiB), the sandbox image and build cache, and the CVE data (the PyPA advisory
  dump from db.gcve.eu).
- 16 GiB RAM works well. The default Qwen 7B inference runs in an 8 GiB cgroup (around 5 GiB resident).
- Network for the bootstrap step only. The analysis host can be offline afterwards.

In an activated venv:

```
pip install -e .
vulnforge bootstrap        # fetch weights, build the sandbox image (online, one-off)
```

The cgroup caps live in `inference/runner.py` and `sandbox/run.py`, adjustable for the hardware in front of you.

## Usage

```
vulnforge scan path/to/repo                    # run the staged pipeline (offline)
vulnforge probe path/to/file --function NAME   # one-shot hypothesis against a single function
vulnforge plumbing                             # end-to-end smoke test
vulnforge audit-verify --workspace <dir>       # walk a run's audit log hash chain
```

`probe` runs one file through index, hypothesise, and the grounding screen, the same stages a scan uses up to that
point, and skips synthesise, execute, verify, and report. It exercises the prompt, schema, and grounding layers
without spending a payload synthesis or a container launch, and writes per-failure-layer artefacts (prompt, raw output,
parsed JSON, rejections, and the grounding per hypothesis). `--function NAME` focuses on one function and keeps it
representative of a real run; without it, probe runs each function in the file, and falls back to the raw file only when
no functions are found. Rootless podman prints harmless `can't raise ambient capability` warnings (the sandbox drops
every capability anyway). To see llama.cpp's own load and timing logs for a probe run, pass `--debug-llama`. The
`LLAMA_TAG` in `sandbox/Containerfile` pins the llama.cpp release, so bump it with intent.

## Docs

- [architecture/](docs/architecture/): what exists, the stages, schema, sandbox, and how a scan flows.
- [decisions/](docs/decisions/): why it is built this way, one dated record each.
- [roadmap/](docs/roadmap/): what might come next.
- [metrics/](docs/metrics/): what real runs measured.

To contribute, see [docs/contributing.md](docs/contributing.md).

## Context

AI reasoning research is converging on arrangements of subsystems rather than single models. vulnforge is one worked
example of that convergence, applied to vulnerability research, with fewer models. Three non-technical articles in
[articles/](articles/README.md) hold the longer version.
