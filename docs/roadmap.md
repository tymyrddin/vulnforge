# Development roadmap

Three phases: solidify the core, expand capabilities and integration, then deepen autonomy and analysis.

## Phase 1: Core stabilisation and usability

|                                | Description & priority (High/Med)                                                                                                                                                            |
|:-------------------------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| 1.1. Productionise the sandbox | High: Move from a basic sandbox to a well-isolated, containerised environment (e.g., Docker) with strict resource limits, network blocking, and configurable timeouts for any executed code. |
| 1.2. Expand static analysis    | High: Integrate with existing SAST tools like `semgrep` or `CodeQL` to generate a baseline of findings without relying solely on the AI model.                                               |
| 1.3. Formalise the audit log   | Medium: Define a strict, append-only, cryptographically signed log format (as in the `audit/` subsystem), covering every event: model input, proposal, execution result, verdict.            |
| 1.4. Implement a UI/CLI        | Medium: A proper CLI with clear subcommands (e.g., `vulnforge analyze ./my-project`), so nobody has to hand-drive the orchestrator.                                                          |
| 1.5. Write comprehensive tests | High: Unit and integration tests for all subsystems (`sandbox`, `inference`, `orchestrator`). The `tests/` directory exists; it needs filling out.                                           |

## Phase 2: Feature expansion and integration

|                               | Description & priority (High/Med)                                                                                                                                                                                                             |
|:------------------------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| 2.1. Model management         | Medium: Develop a system to download, version, and swap different local models. The `bootstrap/` subsystem is a starting point, but a command like `vulnforge model list` and `vulnforge model use <model>` would be powerful.                |
| 2.2. Plugin architecture      | Medium: Create a plugin system to allow users to add custom vulnerability checkers. This could integrate with tools like `cargo-audit` for Rust projects or `pip-audit` for Python, aligning with the goal of using "what you already have".  |
| 2.3. Advanced correlation     | Med-High: Implement the "correlation loop" described in `docs/memory/verdict-pipeline.md`. This would allow the system to correlate findings from multiple sources (SAST, AI, sandbox) to identify more complex, multi-stage vulnerabilities. |
| 2.4. Improve sandbox fidelity | Medium: For firmware analysis, enhance the sandbox to support emulation (e.g., QEMU) to run and test firmware images for different architectures (e.g., ARM, RISC-V).                                                                         |

## Phase 3: Advanced capabilities and research

|                               | Description & priority (High/Med)                                                                                                                                                                                                                    |
|:------------------------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| 3.1. Interactive mode         | Low: Develop an interactive mode where an analyst can ask the model for explanations about its proposals or guide the investigation, with all interactions logged.                                                                                   |
| 3.2. Refined verdict pipeline | Low: Further refine the verdict pipeline described in `docs/memory/verdict-pipeline.md`. Create a formal mathematical framework for how confidence scores are calculated based on combined evidence from static analysis, AI, and sandbox execution. |
| 3.3. Semantic search          | Low: Build a system to semantically search the audit log. An analyst could query "show me all previous proposals for format string bugs in network drivers" to leverage past analyses.                                                               |
| 3.4. Contribute to research   | Low: Package `vulnforge` as a worked example of "The model is not the system" and write it up, whether as a paper or a detailed post. The academic discussion on AI and security could use a concrete case.                                          |
