# Probe: one-shot inference, bypassing the staged pipeline

Date: 2026-05-13

## Context

Tuning the prompt and schema layer inside a full scan is slow and noisy. The
failure layers (JSON-not-extracted, JSON-parse-fail, schema-reject) leave
distinct traces that are hard to read mid-pipeline.

## Decision

`vulnforge probe <file>` runs the hypothesise prompt against a single file,
bypassing the staged pipeline. This tunes the prompt and schema layer in
isolation before a full scan.

`--function NAME` extracts a single function using the same slice format as the
index and hypothesise stages. Without it, probe sends the raw file; the model
sees the full source including docstrings, which can prime the wrong attack
template (a file with a container-related docstring will attract container
security hypotheses regardless of the function). The flag keeps probe
representative of a real pipeline run and is the correct form for prompt tuning.

Per-probe artefacts under the workspace root:

- `probe-prompt.txt` the exact prompt sent to the sandbox
- `probe-output.txt` raw post-strip model output
- `probe-extracted.txt` the `{...}` block parsing was attempted on
- `probe-parsed.json` extracted JSON object, present only if `json.loads`
  succeeded
- `probe-rejections.jsonl` one line per rejected hypothesis, present only
  if any were rejected

The `--debug-llama` flag swaps `--log-disable` for `--log-file /dev/stderr`,
streaming llama.cpp's own load and timing logs into the captured stderr.

## Why

Each artefact captures a different failure layer. JSON-not-extracted,
JSON-parse-fail, and schema-reject all leave distinct traces, so a failure is
diagnosed by reading the artefact that captured its layer rather than by
guesswork.

## Amended 2026-06-24

Probe no longer stops at the schema layer. It now also runs the grounding screen
on each parsed hypothesis, the same gate the scan pipeline applies, and writes a
`probe-screen.jsonl` recording the grounding per hypothesis. Probe also defaults
to one inference per function in the file (the raw-file path is a fallback for
files with no functions). Probe exercises the prompt, schema, and grounding
layers, while still skipping synthesise, execute, verify, and report.
[2026-06-24-grounding-screen.md](2026-06-24-grounding-screen.md) covers the
screen.
