# /no_think is model configuration, not a prompt detail

## Context

qwen3-8b is a thinking model: it generates a `<think>...</think>` chain before
any JSON output. On CPU at roughly 1-2 tok/sec, a complex slice can produce
2,000 or more thinking tokens before the JSON answer appears. At that rate, no
slice completes within the 300-second `infer()` default timeout. The failure is
silent: every container runs for exactly 300 seconds, times out, and is skipped;
the scan appears to run but produces zero hypotheses.

## Decision

`/no_think` is treated as model configuration. `ModelSpec.no_think` is set via
`no_think: true` in `bootstrap/models.lock` for qwen3-8b. When set,
`inference/runner.py` prepends `/no_think` to the prompt before inference.
qwen3-8b respects this in plain completion mode (`--simple-io --single-turn`)
without a chat template, skipping the thinking chain entirely. Output becomes
direct and comparable in speed to qwen2.5-coder-7b.

`configs/pipeline.yaml` uses `qwen3-8b` for hypothesise and `qwen2.5-coder-7b`
for synthesise. `probe` defaults to `qwen3-8b`; the `no_think` flag applies
automatically from `ModelSpec`.

## Why

The thinking trace blows the per-slice timeout on CPU, and the failure is
invisible because it looks like a slow scan rather than a misconfiguration.
Putting the flag in `ModelSpec` ties it to the model it belongs to, so any stage
or probe that runs that model inherits the setting without restating it.

The structural gap that caused the silent failure: `hypothesise.run()` had no
`timeout_seconds` parameter, so the 300-second `infer()` default was invisible
in config. The fix is that `max_tokens` is now wired from `pipeline.yaml`
through the stage; timeout remains the `infer()` default, which is appropriate
for qwen3-8b with `no_think` at max_tokens=512.
