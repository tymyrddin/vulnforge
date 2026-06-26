# Network access lives only in bootstrap/

Date: 2026-05-12

## Context

An analysis tool that can reach the network during a scan carries a standing
egress risk. The cleaner property is a host that can be fully offline once set
up.

## Decision

`bootstrap/fetch_models.py` and `bootstrap/build_sandbox.py` are the only
modules that touch the network. After `vulnforge bootstrap` runs once, the
analysis host can be fully offline.

## Why

The pipeline is structurally incapable of hitting the network because it never
holds network code paths. The property is enforced by where the code lives, not
by a runtime check that could be bypassed.

[../architecture/security.md](../architecture/security.md) covers the offline
posture.
