"""Compliance consumer: maps register facts to candidate IEC 62443 controls.

The third reading of the same substrate. It asks "which control does this
operation bear on?", and produces evidence for a reviewer, not a verdict. A
watchdog is a resource-availability and recovery mechanism, so a write that
reconfigures it bears on IEC 62443-3-3 FR 7 (Resource Availability).

The disposition is always "candidate_evidence". The consumer never declares a
breach: that adjudication belongs to a human reviewer, the same way execution,
not the model, owns a CONFIRMED verdict in the vulnerability path. Claiming a
breach automatically would be the overclaim the rest of the pipeline is built to
avoid.

Reads only existing fact keys; nothing is added to the fact.
"""
from __future__ import annotations

from typing import Any

from consumers import ComplianceFinding

# Seed of the IEC 62443 knowledge layer: a peripheral role maps to the control a
# write to it bears on. Grows per role; the fact substrate does not change for it.
_CONTROL_BY_ROLE = {
    "watchdog": {
        "standard": "IEC 62443-3-3",
        "foundational_requirement": "FR 7: Resource Availability",
        "candidate_control": "SR 7.4",
        "control_title": "Control system recovery and reconstitution",
    },
}


def assess(facts: list[dict[str, Any]]) -> list[ComplianceFinding]:
    findings: list[ComplianceFinding] = []
    for f in facts:
        if f.get("type") != "register_write":
            continue
        control = _CONTROL_BY_ROLE.get(f.get("role"))
        if control is None:
            continue
        findings.append({
            **control,
            "operation": "register_write",
            "peripheral": f.get("peripheral"),
            "register": f.get("register"),
            "address": f.get("address"),
            "disposition": "candidate_evidence",
            "rationale": (
                f"write to {f.get('peripheral')}.{f.get('register')} bears on "
                f"{control['candidate_control']} ({control['control_title']}); "
                f"surfaced as evidence for reviewer adjudication, not an automated "
                f"breach determination"
            ),
        })
    return findings
