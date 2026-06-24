# Updated Development Roadmap

Three phases: solidify the core, expand capabilities and integration, then deepen autonomy and analysis.

### Phase 1: Core Stabilisation and Usability (COMPLETE)

| Task                           | Status     | Notes                                                                                                                                                                             |
|--------------------------------|------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| 1.1. Productionise the sandbox | ✅ Complete | Rootless podman, no network, read-only root, resource limits, active container tracking, atexit cleanup. Containerfile built from `debian:trixie-slim` with llama.cpp pinned tag. |
| 1.2. Expand static analysis    | ✅ Complete | AST parsing via Python's `ast` module, function-level slices, call graph extraction. `index.py` handles `.py` files.                                                              |
| 1.3. Formalise the audit log   | ✅ Complete | `AuditEvent` schema, `audit.log.append()` across all stages, content-addressed storage, provenance chains in hypotheses.                                                          |
| 1.4. Implement a UI/CLI        | ✅ Complete | `cli.py` with `scan <repo>` (full pipeline), `probe` (single-file hypothesise), `plumbing` (smoke test), `audit-verify`, `bootstrap`. `scan` accepts `--workspace`.               |
| 1.5. Write comprehensive tests | ✅ Complete | `test_sandbox_cleanup.py`, `test_plumbing.py`, `test_pipeline.py` all passing. 11 tests including harness unit tests; pipeline end-to-end runs in ~73s.                           |
| 1.6. Inference runner          | ✅ Complete | `inference/runner.py` with llama-cli wrapper, sandbox execution, stdout cleanup (ANSI, backspaces, timings).                                                                      |
| 1.7. Prompt files              | ✅ Complete | `inference/prompts/hypothesise.txt` and `seed_payloads.txt` written, enforce "model proposes, code decides" principle.                                                            |
| 1.8. Orchestrator wiring       | ✅ Complete | All 7 stages wired into `orchestrator/pipeline.py`. `vulnforge scan <repo>` runs the full pipeline.                                                                               |

### Phase 2: Feature Expansion and Integration

| Task                        | Description & Priority | Notes                                                                                                                                                                                                                |
|-----------------------------|------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| 2.1. Model management       | High                   | `bootstrap/fetch_models.py` works with `models.lock`. Need: `vulnforge model list`, `vulnforge model use <alias>`, automatic model selection. Currently supports qwen3-8b (hypothesise) and qwen2.5-7b (synthesise). |
| 2.2. CVE integration        | High                   | OSV.dev (PyPI) and db.gcve.eu offline dumps. CWE-based lookup. Last step inside `verify` (labels findings, does not change truth value). Model used only as fallback for ambiguous matches.                          |
| 2.3. Multi-language support | Medium                 | Extend `index.py` beyond Python. Use tree-sitter for JavaScript, Go, Rust, C/C++. Each language gets its own AST → slice converter.                                                                                  |
| 2.4. Payload dispatch       | Medium                 | Use `category` field from synthesise: `input_string` (stdin), `fuzz_seed` (file or mutation), `request_sequence` (simulated network). `execute.py` dispatches accordingly.                                           |
| 2.5. Correlation loop       | Med-High               | Implement from `docs/memory/verdict-pipeline.md`. Correlate findings across multiple hypotheses to identify multi-stage vulnerabilities.                                                                             |
| 2.6. Plugin architecture    | Medium                 | Allow custom checkers: `cargo-audit` (Rust), `pip-audit` (Python), `semgrep` rules, `CodeQL` queries. Run before or alongside AI stages.                                                                             |
| 2.7. Sandbox fidelity       | Low                    | Firmware analysis: QEMU emulation for ARM, RISC-V, MIPS. Allows running firmware images in sandbox. Currently out of scope.                                                                                          |

### Phase 3: Advanced Capabilities and Research

| Task                            | Description & Priority | Notes                                                                                                                                           |
|---------------------------------|------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------|
| 3.1. Interactive mode           | Low                    | Analyst guides investigation: ask model for explanations, refine hypotheses, mark false positives, add context. All interactions logged.        |
| 3.2. Verdict confidence scoring | Low                    | Formal framework for confidence based on combined evidence: static patterns, AI confidence, sandbox results, correlation strength, CVE matches. |
| 3.3. Semantic search            | Low                    | Query audit log: "show me all previous proposals for format string bugs in network drivers." Uses embeddings stored alongside audit events.     |
| 3.4. Web UI                     | Low                    | Simple web interface for viewing reports, browsing audit trail, comparing runs. Local-only, not SaaS.                                           |
| 3.5. Research publication       | Low                    | Package vulnforge as worked example of "The model is not the system." Publish paper or detailed blog post on architecture and findings.         |

## Immediate Priorities

1. Run on real projects — `vulnforge scan ./project` should work
2. CVE integration — OSV.dev (PyPI), db.gcve.eu dumps, last step inside verify
3. Model management CLI — `vulnforge model list` and `vulnforge model use`
4. Tune prompts — based on real results, improve hypothesise and synthesise prompts
5. Add language support — start with JavaScript (most common alongside Python)

## Open design questions

### Slice role field

The index stage could annotate each slice with a `role` field: `target`, `library`,
`infrastructure`, or `sandbox`. The hypothesise prompt could then restrict the
attacker model per role: for `sandbox` files, the model is told not to assume the
attacker can change runtime flags, only what flows through the function's own
parameters.

This would fix a current failure mode where the model pattern-matches "container code"
to "container security checklist" instead of reasoning about the actual function interface.
Detection heuristic: files importing subprocess and calling podman/docker/runc get
`role=sandbox`; test files get `role=test`; everything else defaults to `role=target`.

Not implemented yet. Prompt rules 8-11 in `hypothesise.txt` address the same failure
mode with less machinery, and prompt tuning data is needed before adding structure.

### Parameter type annotations in slices

Each parameter in a slice could carry a type annotation: `atomic`, `structured`,
`file`, or `env`. The hypothesise prompt could then ground suggested_inputs against
the actual type: a string-typed atomic parameter cannot encode a mount spec; a
structured parameter (e.g. a list or dataclass) names its fields explicitly.

This is the point where prompt engineering for attacker-model grounding terminates
and becomes a typed intermediate representation. The current prompt rules (8-11) are
building that type system manually in natural language. Formalising it in the index
stage output would make it enforceable and model-agnostic.

Trigger for implementation: when prompt tuning reaches diminishing returns and
suggested_inputs quality is still inconsistent across slice types.

### Security fact extraction in slices

Implemented. `extractors/python.py` runs four AST sub-walkers (subprocess, file path,
dangerous sink, environment access) and adds a `security_facts` list to every slice.
`_format_slice()` in `hypothesise.py` renders the facts as `# Security facts:` header
lines so the model sees them as stated ground truth, not something to infer from code.

Prompt rule 12 in `hypothesise.txt` instructs the model to treat `shell=False` /
`shell=default_false` as ruling out shell-metacharacter injection. Effectiveness
confirmed for "Arbitrary File Write" (new hypothesis driven by the file-write fact);
command injection suppression is pending a second probe run post-rule-12 addition.

Future languages: add `extractors/javascript.py` with the same `list[SecurityFact]`
return type; wire into `stages/index.py`'s per-extension dispatch. No other changes.

