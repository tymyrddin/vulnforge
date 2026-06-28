"""Consumers read the fact substrate and ask their own question of it.

The pipeline that produces facts is itself one consumer: it asks whether an
operation actually executes, and reaches a CONFIRMED verdict. A consumer here
reads the same facts and asks a different question, needing nothing added to the
fact.

This package exists to keep the substrate honest. An interface is only neutral
once a second consumer pulls on it and the fact does not have to change shape;
with one consumer, anything called neutral is just that consumer's shape renamed.
The vulnerability, safety, and compliance readings of the same register-write fact
are the first consumers, and they are meant to disagree.

SafetyFinding and ComplianceFinding, like SecurityFact, are dicts. A SafetyFinding
always has a "property" key; a ComplianceFinding always has a "candidate_control"
key.
"""
from __future__ import annotations

from typing import Any

SafetyFinding = dict[str, Any]
ComplianceFinding = dict[str, Any]
