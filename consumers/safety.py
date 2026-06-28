"""Safety consumer: reports safety-relevant state changes from register facts.

It asks "did an operation occur on a protection mechanism?", not "can an attacker
cause it?". So it needs no taint predicate and no execution: a write to a
safety-critical register is a finding on the static fact alone. A constant-valued
write, which the vulnerability lens rules out as not attacker-controlled, is still
a safety finding here, because reconfiguring a protection mechanism matters
regardless of who supplied the value.

The facts read here are the same ones the firmware pipeline produced and verified
for behaviour. Nothing is added to them; only existing keys are read. That is the
point of the module: a second consumer over the same substrate, unchanged.
"""
from __future__ import annotations

from typing import Any

from consumers import SafetyFinding

# A peripheral role maps to the protection a write to it reconfigures. The map
# grows per role; the fact substrate does not change to accommodate it.
_SAFETY_PROPERTY = {
    "watchdog": "watchdog_protection_reconfigured",
}


def assess(facts: list[dict[str, Any]]) -> list[SafetyFinding]:
    findings: list[SafetyFinding] = []
    for f in facts:
        if f.get("type") != "register_write":
            continue
        prop = _SAFETY_PROPERTY.get(f.get("role"))
        if prop is None:
            continue
        findings.append({
            "property": prop,
            "operation": "register_write",
            "peripheral": f.get("peripheral"),
            "register": f.get("register"),
            "address": f.get("address"),
            "rationale": (
                f"write to {f.get('peripheral')}.{f.get('register')} "
                f"reconfigures a {f.get('role')} protection mechanism"
            ),
        })
    return findings
