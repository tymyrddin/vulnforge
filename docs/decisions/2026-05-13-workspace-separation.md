# Workspace separation: immutable framework, mutable XDG

Date: 2026-05-13

## Context

Scans were writing to `.vulnforge/` relative to CWD, so running a scan from
inside the framework checkout silently filled the repo with scan residue.

## Decision

The framework checkout is read-only. All runtime state lives under
`$XDG_DATA_HOME/vulnforge/` (fallback `~/.local/share/vulnforge/`). Three
sibling directories with distinct semantics:

- `weights/` model weights, fetched once by bootstrap, shared across runs.
- `corpus/` input files to be analysed. Persistent, curated, framework
  reads only.
- `runs/<run-id>/` per-scan artefacts: object store, refs, audit log,
  llama stderr logs, reports, probe artefacts. Isolated per scan.

Override via `--workspace <path>` or `$VULNFORGE_WORKSPACE`. The XDG root is
the only place runtime state lives. `.gitignore` keeps a defensive entry for
`.vulnforge/` in the framework checkout so older versions or accidental local
state cannot land in commits.

## Why

Making the boundary structural removed the contamination class. `/tmp` is
reserved for truly transient scratch and is explicitly not a corpus.

[../architecture/storage.md](../architecture/storage.md) covers the runtime
layout.
