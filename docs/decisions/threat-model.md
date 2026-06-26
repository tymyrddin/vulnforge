# Threat model

## What this design removes from the trust path

- No data leaves the host during analysis. Code slices, hypotheses, payloads, findings: none of it traverses an
  external boundary. The bootstrap fetches weights and image once, optionally on a different machine, and
  produces hashed artefacts. The analysis host can run with no network interface at all.
- No third-party logs of what was investigated. A cloud model vendor learns, at minimum: "this customer investigated
  this codebase, asked about these functions, produced these payload classes." That log exists regardless of
  the vendor's intent, and it survives subpoenas and breaches. Local inference erases that log because it was
  never created.
- No listening services for an attacker to reach. Ollama's REST API, the Docker daemon socket, an embedding service:
  all gone. llama.cpp is a subprocess. Podman is rootless and spawns per-container with no persistent
  daemon. The host's exposed surface from this tool, in steady state, is zero processes listening on anything.
- Compromised payloads cannot phone home. --network=none on the execution sandbox means a successful exploit of the
  target still has no egress. Findings remain on the host.
- Compromised analysis code (orchestrator bugs, dependency CVEs) cannot exfiltrate either, because there is no outbound
  path configured. Damage stays local.

## What it does not remove from the trust path

- The model weights themselves. A poisoned weight file could nudge hypotheses to mislead a human reviewer, or seed
  payloads designed to manipulate downstream tooling. bootstrap/models.lock pins by SHA256, which fixes
  what was run, but does not establish that the pinned weights are trustworthy. Mitigation is provenance:
  fetch from trusted upstream once, verify, then freeze.
- Sandbox escapes. Any tool that executes untrusted code carries this risk. Rootless podman + --network=none +
  --read-only + non-root user inside is a strong posture but not a zero. This risk is intrinsic to the
  problem, not introduced by this design.
- Supply chain for binaries (llama.cpp, podman, Python deps). Pinning helps, building from source helps more,
  distribution review helps most. The same risk exists for any tool run on the host.
- Human disclosure. If a reviewer copies a finding into a cloud LLM "to help write it up", the tool's local-only
  guarantee is gone. That is a process problem, not solvable by architecture.

## Further thoughts

A cloud-AI vulnerability finder is, in practice, an outbound disclosure pipe with a UI on top: every query is a
third-party log event. This design inverts that. The pipeline is a closed system, and the only thing
that crosses any trust boundary is the human-readable report, on the reviewer's terms.

This substantially reduces the pipeline's contribution to the host's attack surface. The remaining risks (weights
provenance, sandbox escape, supply chain) are inherent to running a vulnerability tool at
all, not artefacts of the design.
