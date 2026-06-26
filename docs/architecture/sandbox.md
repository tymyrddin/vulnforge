# Sandbox and inference

The only place untrusted code or untrusted payloads run, plus the llama.cpp runner that lives inside
it. Why container ownership is built this way is recorded in
[../decisions/2026-05-13-container-ownership.md](../decisions/2026-05-13-container-ownership.md); the
no_think model config is recorded in
[../decisions/2026-06-23-no-think-model-config.md](../decisions/2026-06-23-no-think-model-config.md).

## Sandbox (`sandbox/run.py`)

Canonical sandbox invocation: rootless podman, no network, read-only root filesystem. One canonical
invocation; isolation review amounts to reading that one file.

Isolation flags:

- `--network=none`
- `--read-only`
- `--cap-drop=ALL`
- `--security-opt no-new-privileges`
- `--user 65534:65534` (nobody/nogroup)
- `--pids-limit 256`
- `--memory 2g`
- `--cpus 2`

## Container ownership and lifecycle

Every container is named `vulnforge-<uuid>` and registered in a module-level `_active` set on
creation. Teardown runs through one `_cleanup` function reachable from every exit path: normal
return, timeout, SIGINT, SIGTERM, and atexit.

- Containers tracked in the `_active` set.
- `atexit` registration for clean-up.
- SIGTERM is translated to `SystemExit` so the same teardown path runs.
- This prevents the "zombie container" pattern, where the container is daemonised via conmon/runc and
  outlives the process that started it.

## Inference runner (`inference/runner.py`)

A llama.cpp subprocess wrapper. Inference runs inside the canonical sandbox, defence in depth against
weight-level surprises.

- The prompt is passed via stdin, not the command line, so it does not appear in `/proc`.
- `_extract_assistant_text()` handles llama-cli conversation-mode chrome:
  - backspaces replayed (kills spinners),
  - ANSI escapes stripped,
  - trailing timings/Exiting block removed,
  - the last `> ` prompt-echo line used as the boundary.
- The weights hash is verified before each run.
- `--single-turn` prevents multi-turn drift.
- `--no-display-prompt` keeps the prompt out of stdout.
- Stderr is logged to the workspace `logs_dir` for debugging.
- Deterministic: the same `(weights_hash, prompt, seed)` produces the same output.

### no_think mechanism

Qwen3-8B emits lengthy reasoning traces by default. When `ModelSpec.no_think=True`, `/no_think` is
prepended to the prompt before inference. This is treated as model configuration, not prompt logic.

It is set in `bootstrap/models.lock` per model entry, so prompts stay model-agnostic and the
behaviour lives in one place. Future models can carry other runtime quirks (`chat_template`,
`reasoning_effort`, and so on) the same way, without contaminating prompt files.

It works in plain completion mode (`--simple-io --single-turn`) without a chat template: qwen3-8b
skips the `<think>` block entirely when `/no_think` appears at the start of the user turn.

Prompt files:

- `inference/prompts/hypothesise.txt`, used by the hypothesise stage.
- `inference/prompts/seed_payloads.txt`, used by the synthesise stage.

Both prompts enforce the "model proposes, code decides" principle and require valid JSON output.

## Containerfile

- Based on `debian:trixie-slim`.
- Includes `llama.cpp` built from a pinned tag.
- Minimal image: anything inside is something an escaped payload could use.
