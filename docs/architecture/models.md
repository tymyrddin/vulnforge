# Models

Which model runs where, how they are pinned, and what the pipeline costs. The no_think rationale is
recorded in [../decisions/2026-06-23-no-think-model-config.md](../decisions/2026-06-23-no-think-model-config.md).

## Model selection

| Stage       | Model            | Size   | Why                                                                         |
|-------------|------------------|--------|-----------------------------------------------------------------------------|
| Hypothesise | Qwen3-8B         | ~5GB   | Better reasoning, more capable at pattern recognition; `no_think=true` set  |
| Synthesise  | Qwen2.5-Coder-7B | ~4.7GB | Code-specialised, good at generating working payloads; no thinking overhead |

Qwen3-8B runs with `/no_think` prepended (via `ModelSpec.no_think`). Without it, the model generates
thousands of tokens of internal reasoning before any JSON, exceeding the per-slice timeout on CPU.
With it, output is direct and comparable in speed to Qwen2.5-Coder-7B. [sandbox.md](sandbox.md)
covers how the flag works.

## Model management (`bootstrap/models.lock`)

`bootstrap/models.lock` contains pinned model weights:

- `qwen3-8b`: hypothesising (`no_think: true`)
- `qwen2.5-coder-7b`: synthesising
- `plumbing-check`: smoke tests (1.5B)

`vulnforge bootstrap` downloads all models. Each entry carries a SHA256 pin; the runner verifies the
weights hash before each run.

## Pipeline performance

| Stage       | Typical Time     | Notes                                 |
|-------------|------------------|---------------------------------------|
| Ingest      | <1s              | File hashing                          |
| Index       | <1s              | AST parsing                           |
| Hypothesise | 30-60s           | Depends on model size and slice count |
| Synthesise  | 30-60s           | Depends on hypothesis count           |
| Execute     | 1-5s per payload | Sandbox startup overhead              |
| Verify      | <1s              | Deterministic comparison              |
| Report      | <1s              | Markdown generation                   |

Total (qwen3-8b + qwen2.5-coder-7b): around 2-3 minutes for small codebases.
