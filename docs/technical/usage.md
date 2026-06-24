# Usage

```
vulnforge bootstrap                             # fetch weights, build sandbox (online, one-off)
vulnforge plumbing                              # end-to-end smoke test
vulnforge scan path/to/repo                    # run the staged pipeline (offline)
vulnforge probe path/to/file                   # one-shot hypothesis against a single file (raw)
vulnforge probe path/to/file --function NAME   # hypothesis against a single function (pipeline-faithful slice)
vulnforge audit-verify --workspace <dir>        # walk a run's audit log hash chain
```

`probe` bypasses the staged pipeline and is the fastest way to exercise the prompt and schema layer without the later
stages. Each probe run writes per-failure-layer artefacts under the workspace root: `probe-prompt.txt`,
`probe-output.txt`, `probe-extracted.txt`, `probe-parsed.json`, and (if any) `probe-rejections.jsonl`.

Without `--function`, probe sends the raw file. The model sees the full source, including docstrings and module-level
context, which can prime the wrong template. `--function NAME` extracts a single function using the same slice format
the index and hypothesise stages use; this keeps probe representative of what happens in a real pipeline run and is the
right form for prompt tuning.

## Tests

```
pytest tests/ -v
```

`test_plumbing.py` is the end-to-end inference smoke test. `test_sandbox_cleanup.py` asserts that no `vulnforge-*`
containers survive a clean exit or a forced timeout. Both skip on hosts that have not bootstrapped.

`test_pipeline.py` runs the full staged pipeline against a small target. Uses `plumbing-check` for speed; validates
pipeline wiring and verdict assignment, not payload quality. Includes harness unit tests that run without a model.

`test_cve.py` covers the CVE module: CWE map coverage, index load and match with a fixture file, and an integration
test that calls `verify.run()` with a patched CVE DB and asserts `cve_refs` appears in confirmed verdicts.

## Notes for operators

Rootless podman prints `can't raise ambient capability CAP_*` warnings at the start of every `run` and `build`. They are
harmless: the sandbox drops every capability anyway (`--cap-drop=ALL` in `sandbox/run.py`), so nothing in the pipeline
relies on them. To silence, set `default_capabilities = []` under `[containers]` in
`~/.config/containers/containers.conf`.

`inference/runner.py` passes `--log-disable` to `llama-cli` so the assistant's reply is the only thing on stdout. Hard
failures still surface: the dynamic linker and the kernel write to stderr regardless, and `infer()` raises on a non-zero
exit. To see llama.cpp's own load and timing chatter for a probe run, pass `--debug-llama`; that flips the flag to
`--log-file /dev/stderr` and the captured stderr log fills up.

The `LLAMA_TAG` default in `sandbox/Containerfile` names a specific release tag. Bumping it is a one-line edit;
different upstream commits produce different binaries, so pin with intent.