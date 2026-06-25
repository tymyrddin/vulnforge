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
| 1.8. Orchestrator wiring       | ✅ Complete | All 8 stages wired into `orchestrator/pipeline.py` (the screen stage sits between hypothesise and synthesise). `vulnforge scan <repo>` runs the full pipeline.                    |

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

Each subprocess and dangerous-sink fact also carries an `arg_source`: the provenance
of the value reaching the sink (`parameter:NAME`, `parameter-derived`, `constant`,
`unknown`). This is the source-to-sink link a reviewer found missing: facts about a
sink are not the same as evidence that attacker-controlled data reaches it.

That link is now made consequential in code by the screen stage (`stages/screen.py`),
between hypothesise and synthesise. It grounds each hypothesis against the slice facts:
a parameter reaching a matching sink is grounded; a matching sink with unresolved
provenance is unknown (kept, confidence capped); a mechanism the facts rule out is
contradicted (rejected); no matching sink is unsupported (rejected). Acceptance and
confidence depend on the computed grounding, not on the model honouring a prompt rule.
Prompt rule 12 stays as a cheap upstream nudge.

The provenance resolver (`_classify_arg` in `extractors/python.py`) is a
single-function AST pass, and its coverage frontier is worth naming because it is
exactly what later sections mean by "extractor coverage". It resolves a bare parameter
(`parameter:NAME`), a parameter flowing in through an f-string or a collection element
(`parameter-derived`), and a string literal (`constant`). Everything else lands
`unknown`: a value reaching the sink through a helper-call return, an attribute access,
or a local variable the pass cannot trace back to a parameter. `unknown` means the
analysis stopped, not that the attacker has no influence, and `constant` is a resolved
outcome (no parameter can reach the sink), not a coverage gap. Growing coverage means
converting `unknown` into one of the three resolved outcomes.

The attack-class predicate registry lives in `stages/screen.py`: the synonym sets
(`_COMMAND`, `_CODE`, `_DESERIALIZATION`, `_PATH`, `_SQL`) and the sink-name sets they
map onto (`_CODE_SINK_NAMES`, `_DESERIALIZATION_SINK_NAMES`, `_OS_SHELL_SINK_NAMES`).
Adding a new attack class is a one-place edit: add its synonyms to a class set, add the
sink names that count as a matching sink, and extend `_matching_sinks` to return them.
A class with no detector returns `None` there and lands `unknown` rather than
`unsupported`, so a novel class is penalised, never silently dropped.

Future languages: add `extractors/javascript.py` with the same `list[SecurityFact]`
return type (including `arg_source`); wire into `stages/index.py`'s per-extension
dispatch. No other changes.

### Measuring the grounding distribution

The grounding gate is in place; the next informative signal is what the distribution
across grounded, unknown, contradicted and unsupported looks like on a larger corpus,
and whether the unknown bucket shrinks as the extractor's provenance resolver improves.
Two metrics answer two different questions, and they are kept separate on purpose. This
is a measurement plan, not built yet; it is the first concrete consumer of Move 4
(`vulnforge stats`) in `docs/memory/verdict-pipeline.md`.

The first measured run, a scan of this repository's own `stages/`, is recorded with
its data and interpretation in `docs/metrics.md`: 0/5 fact-level provenance resolved,
and 60 of 61 hypotheses removed at the screen (almost all `unsupported`). It doubles
as a worked example of the two metrics before the tool that automates them exists.

Metric 1, fact-level provenance coverage. Deterministic and model-free. Walk a run's
`index_latest` slice manifest, load each slice, and tally the provenance field over
every fact that carries one: `arg_source` on `subprocess` and `dangerous_sink` facts,
`path_source` on `file_read` and `file_write` facts. The denominator is "facts carrying
`arg_source` or `path_source`", phrased that way rather than "sink facts" so a future
fact type that carries provenance without being a sink still counts; `environment_access`
facts carry no provenance and stay out of it. Coverage is the fraction not `unknown`:
`parameter:*`, `parameter-derived` and `constant` all count as resolved, because
`constant` is a successful classification (no parameter reaches the sink), not a gap.
Counting it as a miss would make an extractor improvement that turns `unknown` into
`constant` look like no improvement at all. Because this metric never touches the model,
over a fixed corpus it is a pure function of the extractor, so a falling `unknown`
fraction is genuine coverage growth rather than model noise. This is the clean answer to
"does the unknown bucket shrink as coverage grows".

Metric 2, verdict-level grounding distribution. The user-facing screen output. Walk a
run's `screen_verdicts_latest` manifest (or the `screen` audit event), tally the four
`Grounding` states and the eight `ScreenReason` values, optionally grouped by
`attack_type`. `stages/report.py` already aggregates these counts for one run's markdown
report (`_load_screen_verdicts`); the measurement reuses that loader shape across runs.
This distribution moves with both the extractor and what the model proposed, so it is
read alongside Metric 1, not instead of it.

The command. A planned `vulnforge stats` walks any subset of `runs/*/`, computes both
metrics per run and aggregated, and prints counts. It reads only from disk and counts
only: no scoring, no weighting (the same discipline Move 4 sets). It slots in as a new
Click command after `audit-verify` in `cli.py`, taking one or more run directories and
defaulting to everything under `runs_root()`.

Comparability caveats, so the numbers mean something. Metric 1's `unknown` fraction only
compares across runs of the same corpus; across different corpora it conflates corpus
composition with extractor capability. Metric 2 has a second axis: the grounding
distribution depends on the hypothesise model too, so its comparisons are only
meaningful within a fixed model, or with a model change called out alongside the figures.
The model identity is already recorded (`model_hash` on the audit event), so this is a
reading discipline, not new instrumentation.

What the coverage-growth question needs to be answerable at all: a pinned benchmark
corpus, re-scanned as the extractor evolves (the repo's own `stages/`, or a small
curated fixtures set, are reasonable starting pins), and an extractor fingerprint
recorded per run so a data point is attributable to an extractor version. Today the
index and screen audit events carry `model_hash` but no code version
(`schema/audit_event.py`). The one small piece of new instrumentation is to stamp an
extractor fingerprint, a content hash or a version identifier, into the index audit
event; the exact mechanism is left open here, since a directory content hash also moves
on comments and formatting and so measures tree state rather than provenance capability.

A scan of `stages/` is a useful first data point on a real corpus, not yet a benchmark:
the repository evolves, so `stages/` is only a fixed pin if it is deliberately frozen as
one. The pinned-corpus requirement above is what turns first data points into a series.

