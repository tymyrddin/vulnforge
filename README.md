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

## Docs

- For installation, usage, repo layout, and architecture detail, see [technical docs](docs/technical/README.md).
- For the load-bearing design decisions and the reasoning behind them, see [the project's institutional memory](docs/memory/)
- What we're building next can be found in the [roadmap](docs/roadmap.md)

## Context

AI reasoning research is converging on arrangements of subsystems rather than single models. vulnforge is one worked
example of that convergence, applied to vulnerability research, with fewer models. Three plain-language articles in
[articles/](articles/README.md) tell the longer version, from the idea to the machinery to what changed, with no
security or AI background assumed.
