# Roadmap

What
already exists is in [../architecture/](../architecture/); why those things were
built the way they were is in [../decisions/](../decisions/); what a real scan
produced is in [../metrics/README.md](../metrics/README.md).

Three forward-looking design notes live beside this index:

- [ot-ics-direction.md](ot-ics-direction.md): the OT/ICS direction, facts as a
  semantic evidence substrate, and the first firmware vertical to build. Its
  architectural calls are settled in
  [../decisions/2026-06-26-semantic-evidence-substrate.md](../decisions/2026-06-26-semantic-evidence-substrate.md).
- [verdict-pipeline.md](verdict-pipeline.md): the unbuilt moves of the verdict
  pipeline (closed-enum outcomes, end-to-end ref verification, the correlation loop).
- [run-concept.md](run-concept.md): a deferred `Run` vs `Workspace` separation.

## Backlog

These items are scoped but not built. Priority is a rough ordering, not a commitment.

### Feature expansion and integration

| Task                   | Priority | Notes                                                                                                                                                                                                                                                                        |
|------------------------|----------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Model management       | High     | `bootstrap/fetch_models.py` works with `models.lock`. Wanted: `vulnforge model list`, `vulnforge model use <alias>`, automatic model selection. Currently supports qwen3-8b (hypothesise) and qwen2.5-coder-7b (synthesise).                                                 |
| CVE model fallback     | Low      | CWE-based lookup is built and deterministic on `attack_type`. The model fallback for ambiguous matches is not built.                                                                                                                                                         |
| Multi-language support | Medium   | Extend `index.py` beyond Python. Tree-sitter for JavaScript, Go, Rust, C/C++. Each language gets its own AST to slice converter, and implements the same `list[SecurityFact]` contract so the screen stage works unchanged.                                                  |
| Payload dispatch       | Medium   | synthesise tags each payload with a variant `category` (baseline, encoded, oversized, unicode, nested, polyglot), but `execute.py` passes every payload as the function's first argument. Dispatch by delivery channel (stdin, file, network) is a separate idea, not built. |
| Correlation loop       | Med-High | Correlate confirmed findings across hypotheses into multi-stage exploit chains. The measurement half of this is Move 4 in [verdict-pipeline.md](verdict-pipeline.md), tracked under measurement tooling below.                                                               |
| Plugin architecture    | Medium   | Allow custom checkers: `cargo-audit` (Rust), `pip-audit` (Python), `semgrep` rules, CodeQL queries. Run before or alongside AI stages.                                                                                                                                       |
| Sandbox fidelity       | Low      | Firmware analysis: QEMU emulation for ARM, RISC-V, MIPS, to run firmware images in the sandbox. Currently out of scope.                                                                                                                                                      |

### Advanced capabilities and research

| Task                       | Priority | Notes                                                                                                                                                       |
|----------------------------|----------|-------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Interactive mode           | Low      | Analyst guides the investigation: ask the model for explanations, refine hypotheses, mark false positives, add context. All interactions logged.            |
| Verdict confidence scoring | Low      | A formal framework for confidence over combined evidence: static patterns, AI confidence, sandbox results, correlation strength, CVE matches.               |
| Semantic search            | Low      | Query the audit log: "show me all previous proposals for format string bugs in network drivers." Uses embeddings stored alongside audit events.             |
| Web UI                     | Low      | A local-only interface for viewing reports, browsing the audit trail, comparing runs. Not SaaS.                                                             |
| Research publication       | Low      | Package vulnforge as a worked example of "the model is not the system." A paper or detailed write-up on architecture and findings.                          |

## Immediate priorities

The OT/ICS direction in [ot-ics-direction.md](ot-ics-direction.md) sets the lead: one
firmware vertical driven to CONFIRMED. The numbered items below are the
language-neutral spine that direction builds on.

1. Run on code with real surface. The only end-to-end run so far is `stages/`, which
   has almost no sinks, so the grounded, contradicted, and confirmed paths have never
   fired. A corpus with real command-running, file-handling, and untrusted-input
   parsing exercises them, and produces the confirmations the policy-calibration
   question (Open questions) needs. The firmware vertical is the chosen concrete form.
2. Model management CLI (Backlog: High).
3. Tune the hypothesise and synthesise prompts against real results.
4. First new-language extractor, JavaScript (Backlog: Multi-language support).

## Future directions

Forward-looking engineering that builds on settled architecture. The decisions behind
the grounding gate are in [../decisions/](../decisions/).

### Slice role field

The index stage could annotate each slice with a `role` field: `target`, `library`,
`infrastructure`, or `sandbox`. The hypothesise prompt could then restrict the
attacker model per role: for `sandbox` files, the model is told not to assume the
attacker can change runtime flags, only what flows through the function's own
parameters.

This would address a failure mode where the model pattern-matches "container code" to
"container security checklist" instead of reasoning about the actual function
interface. Detection heuristic: files importing subprocess and calling
podman/docker/runc get `role=sandbox`; test files get `role=test`; everything else
defaults to `role=target`.

Not built. Prompt rules 8-11 in `hypothesise.txt` address the same failure mode with
less machinery, and prompt-tuning data is needed before adding structure.

### Parameter type annotations in slices

Each parameter in a slice could carry a type annotation: `atomic`, `structured`,
`file`, or `env`. The hypothesise prompt could then ground suggested_inputs against
the actual type: a string-typed atomic parameter cannot encode a mount spec; a
structured parameter (e.g. a list or dataclass) names its fields explicitly.

This is the point where prompt engineering for attacker-model grounding becomes a typed
intermediate representation. The current prompt rules (8-11) build that type system
manually in natural language. Formalising it in the index stage output would make it
enforceable and model-agnostic.

Trigger: when prompt tuning reaches diminishing returns and suggested_inputs quality
is still inconsistent across slice types.

### Grounding gate: backlog only

The security-fact extraction and the screen stage are built and settled; the decisions
are in [../decisions/](../decisions/). What remains is engineering.

- Richer provenance in `_classify_arg` (`extractors/python.py`): follow local
  assignments, attribute chains, and eventually interprocedural flow, converting
  `unknown` into resolved outcomes.
- Additional attack classes in the `stages/screen.py` registry. SQL currently has only
  a weak imports signal and no sink detector; other classes land `unknown` for want of
  a detector.

### Measurement tooling

The two-metric measurement design is settled, covered in [../metrics/README.md](../metrics/README.md);
the first run is recorded in [../metrics/2026-06-stages-scan.md](../metrics/2026-06-stages-scan.md).
The build is backlog:

- `vulnforge stats`: a Click command after `audit-verify` in `cli.py` that walks
  `runs/*/`, computes both metrics per run and aggregated, and counts only. Aligns
  with Move 4 in [verdict-pipeline.md](verdict-pipeline.md).
- Extractor fingerprint: stamp a content hash or version identifier into the index
  audit event, so a data point is attributable to an extractor version. Today the
  audit event carries `model_hash` but no code version.
- Pinned benchmark corpora: a fixed body of code re-scanned as the extractor evolves,
  so coverage growth can be told apart from corpus luck. `stages/` is a first data
  point, not yet a frozen pin.

## Open questions

These are genuinely open. Everything above is backlog with an obvious home.

### Provenance granularity

The provenance lattice is deliberately coarse: `parameter`, `parameter-derived`,
`constant`, `unknown`. Whether it stays coarse or grows richer (multiple sources,
sanitised, environment-derived, return-value-derived) is a future choice. There is no
pressure to answer it yet; formalising waits until experience shows the four-way split
limiting.

### Policy calibration

The architecture is fixed; the policy numbers are provisional. Unknown is accepted,
with confidence capped at 0.35 (`schema/screen.py`), a starting point whose only
load-bearing property is that unknown ranks below grounded. The open question is
empirical, not architectural: given real verification outcomes, is 0.35 the right cap,
and does unknown deserve acceptance at all. The instrumentation to answer it with data
is in [verdict-pipeline.md](verdict-pipeline.md) (Move 4, the joint of
screen-accepted to confirmed) and the metrics in
[../metrics/README.md](../metrics/README.md). It needs a run on code with real surface,
which produces the confirmations to calibrate against.

### Tolerant JSON parsing for the strcpy-shaped failure

The model sometimes emits Python expressions inside JSON arrays (`"A" * 20`), which is
not parseable JSON regardless of schema. The schema cannot help here. Options are
prompt restructuring via a chat template, an upstream parse repair, or a model change.
Open, no decision yet.

### Workspace locking

Two concurrent scans could write to the same `run-id`. Not currently possible (each
scan creates a fresh timestamped run dir), but a candidate for a flag once concurrency
arrives. This is the same trigger family as the deferred `Run` concept in
[run-concept.md](run-concept.md).
