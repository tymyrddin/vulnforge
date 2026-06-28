"""Verify stage: compare observations against hypotheses without using the AI.

This module owns the TESTED -> CONFIRMED and TESTED -> REFUTED transitions.
Grep for `status=Status.CONFIRMED` (or REFUTED) and you find exactly the two
lines below. That is the entire enforcement of the "AI cannot be the judge"
rule: the only assignment sites for verdict statuses are in this file.
"""
from __future__ import annotations

import dataclasses
import json
import time
from typing import Any

from audit.log import append as audit_append
from cve import index as cve_index
from schema.audit_event import AuditEvent
from schema.hypothesis import (
    EvidenceType,
    Hypothesis,
    Status,
    VerificationStatus,
)
from store import objects, refs


def confirm(h: Hypothesis, evidence: str) -> Hypothesis:
    if h.status is not Status.TESTED:
        raise ValueError(f"cannot confirm from {h.status.value}")
    return dataclasses.replace(
        h,
        status=Status.CONFIRMED,
        verification_status=VerificationStatus.CONFIRMED,
        provenance=f"{h.provenance};confirmed:{evidence}",
    )


def refute(h: Hypothesis, reason: str) -> Hypothesis:
    if h.status is not Status.TESTED:
        raise ValueError(f"cannot refute from {h.status.value}")
    return dataclasses.replace(
        h,
        status=Status.REFUTED,
        provenance=f"{h.provenance};refuted:{reason}",
    )


def run(observations_ref: str, hypotheses_ref: str) -> str:  # noqa: ARG001
    obs_manifest: dict[str, str] = json.loads(objects.get(observations_ref))
    _cve_db = cve_index.load()

    verdicts: dict[str, str] = {}
    skipped = 0

    for payload_id, obs_ref in sorted(obs_manifest.items()):
        obs: dict[str, Any] = json.loads(objects.get(obs_ref))

        tested_hyp_ref = obs.get("tested_hypothesis_ref")
        if not tested_hyp_ref:
            skipped += 1
            continue

        try:
            hyp_data: dict[str, Any] = json.loads(objects.get(tested_hyp_ref))
            h = _load_hypothesis(hyp_data)
        except Exception:
            skipped += 1
            continue

        hyp_id = obs.get("hypothesis_id", hyp_data.get("location", payload_id))
        verdict_str, evidence = _decide(obs, h)

        # CONFIRMED always wins: don't overwrite a confirmed verdict with a refute
        if hyp_id in verdicts:
            existing = json.loads(objects.get(verdicts[hyp_id]))
            if existing.get("verdict") == "CONFIRMED":
                continue

        try:
            if verdict_str == "CONFIRMED":
                final_h = confirm(h, evidence)
            else:
                final_h = refute(h, evidence)
        except ValueError:
            skipped += 1
            continue

        hyp_blob = json.dumps(
            dataclasses.asdict(final_h), sort_keys=True, separators=(",", ":")
        ).encode()
        objects.put(hyp_blob)

        verdict = {
            "hypothesis_id": hyp_id,
            "verdict": verdict_str,
            "evidence": evidence,
            "observation_ref": obs_ref,
            "cve_refs": cve_index.match(_cve_db, h.attack_type) if _cve_db else [],
        }
        verdict_blob = json.dumps(verdict, sort_keys=True, separators=(",", ":")).encode()
        verdicts[hyp_id] = objects.put(verdict_blob)

    manifest_bytes = json.dumps(verdicts, sort_keys=True, separators=(",", ":")).encode()
    verdicts_ref = objects.put(manifest_bytes)
    refs.write("verdicts_latest", verdicts_ref)
    audit_append(AuditEvent(
        timestamp=time.time(),
        stage="verify",
        input_refs=(observations_ref,),
        output_refs=(verdicts_ref,),
        model_hash=None,
        seed=None,
        summary=f"{len(verdicts)} verdicts, {skipped} skipped",
    ))
    return verdicts_ref


def _decide(obs: dict[str, Any], h: Hypothesis) -> tuple[str, str]:
    exit_code: int = obs.get("exit_code", 0)
    timed_out: bool = obs.get("timed_out", False)
    stdout: str = obs.get("stdout", "")
    marker: str = obs.get("marker", "")
    attack_type: str = h.attack_type.lower()

    if timed_out:
        return "CONFIRMED", "timed_out: true"
    if marker:
        if marker in stdout:
            return "CONFIRMED", f"marker in stdout: {marker}"
        # Marker was embedded but absent: the injection did not execute
    else:
        if exit_code != 0:
            return "CONFIRMED", f"exit_code: {exit_code}"
        if h.expected_effect and h.expected_effect in stdout:
            return "CONFIRMED", "stdout contains expected_effect"
    if attack_type == "dos" and not timed_out:
        return "REFUTED", "dos attack completed without timeout"
    if attack_type == "logical" and exit_code == 0:
        return "REFUTED", "logical attack, exit_code: 0, no observable effect"
    return "REFUTED", "no confirming evidence"


def _load_hypothesis(data: dict[str, Any]) -> Hypothesis:
    return Hypothesis(
        attack_type=data["attack_type"],
        location=data["location"],
        assumption_broken=data["assumption_broken"],
        expected_effect=data["expected_effect"],
        suggested_inputs=tuple(data["suggested_inputs"]),
        confidence=float(data["confidence"]),
        status=Status(data["status"]),
        evidence_type=EvidenceType(data["evidence_type"]),
        verification_status=VerificationStatus(data["verification_status"]),
        provenance=data["provenance"],
    )