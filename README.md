# vulnforge

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

## Verifying claims

For installation, usage, repo layout, and architecture detail, see [README-technical.md](README-technical.md).

For the load-bearing design decisions and the reasoning behind them, the design notes live in `docs/`:

- [docs/design-choices.md](docs/design-choices.md): load-bearing decisions and why they were made
- [docs/trust-path.md](docs/trust-path.md): what this design removes from the trust path, and what it does not
- [docs/verdict-pipeline.md](docs/verdict-pipeline.md): a plan for screening, verification, content addressing, and
  a correlation loop
- [docs/run-concept.md](docs/run-concept.md): open design forks (Run vs Workspace separation)

## Architecture

The conceptual frame is in [The model is not the system](https://broomstick.tymyrddin.dev/posts/model-is-not-system/).
The short version: AI reasoning research is increasingly converging on arrangements of subsystems rather than single
models. vulnforge is one worked example of that convergence, applied to vulnerability research, but with fewer models.
