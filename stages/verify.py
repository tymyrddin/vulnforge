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
from schema.expected_outcome import ExpectedOutcome, clause_result
from schema.hypothesis import (
    EvidenceType,
    Hypothesis,
    Status,
    VerificationStatus,
)
from store import objects, refs

# Channels a default executor observes; the pipeline passes the real executor's set.
_DEFAULT_CAPABILITIES = frozenset({"process"})


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


def run(
    observations_ref: str,
    payloads_ref: str,
    *,
    capabilities: frozenset[str] = _DEFAULT_CAPABILITIES,
) -> str:
    """Compare each hypothesis's predicted outcomes (from the plan) against the observed
    facts (from execute), using the executor's advertised channels. Verify holds no attack
    knowledge: it evaluates outcome predicates and the boolean structure synthesise emits
    (outcomes AND-ed within a payload, payloads OR-ed as alternative witnesses).

    A nonzero exit code or an exception is an observation, never a verdict on its own.
    """
    obs_manifest: dict[str, str] = json.loads(objects.get(observations_ref))
    payload_manifest: dict[str, str] = json.loads(objects.get(payloads_ref))
    cve_db = cve_index.load()
    channels = set(capabilities)

    # Group payload-level clause results per hypothesis (payloads are alternative witnesses).
    groups: dict[str, dict[str, Any]] = {}
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
        outcomes: list[ExpectedOutcome] = []
        plan_ref = payload_manifest.get(payload_id)
        if plan_ref:
            plan = json.loads(objects.get(plan_ref))
            outcomes = [ExpectedOutcome.from_dict(d) for d in plan.get("expected_outcomes", [])]
        result = clause_result(outcomes, obs, channels)

        group = groups.setdefault(hyp_id, {"h": h, "results": [], "witness": obs_ref})
        group["results"].append(result)
        if result == "true":
            group["witness"] = obs_ref

    verdicts: dict[str, str] = {}
    tally: dict[str, int] = {}
    for hyp_id, group in sorted(groups.items()):
        results = group["results"]
        if "true" in results:
            verdict_str, evidence = "CONFIRMED", "an expected outcome was observed"
        elif "unknown" in results:
            verdict_str = "INCONCLUSIVE"
            evidence = "expected outcome not observable by this executor"
        else:
            verdict_str, evidence = "REFUTED", "no expected outcome was observed"
        tally[verdict_str] = tally.get(verdict_str, 0) + 1

        h = group["h"]
        try:
            if verdict_str == "CONFIRMED":
                final_h = confirm(h, evidence)
            elif verdict_str == "REFUTED":
                final_h = refute(h, evidence)
            else:
                final_h = h  # INCONCLUSIVE: the hypothesis stays TESTED, untested by this run
        except ValueError:
            skipped += 1
            continue
        objects.put(
            json.dumps(dataclasses.asdict(final_h), sort_keys=True, separators=(",", ":")).encode()
        )

        verdict = {
            "hypothesis_id": hyp_id,
            "verdict": verdict_str,
            "evidence": evidence,
            "observation_ref": group["witness"],
            "cve_refs": (
                cve_index.match(cve_db, h.attack_type)
                if cve_db and verdict_str == "CONFIRMED"
                else []
            ),
        }
        verdicts[hyp_id] = objects.put(
            json.dumps(verdict, sort_keys=True, separators=(",", ":")).encode()
        )

    manifest_bytes = json.dumps(verdicts, sort_keys=True, separators=(",", ":")).encode()
    verdicts_ref = objects.put(manifest_bytes)
    refs.write("verdicts_latest", verdicts_ref)
    tally_str = ", ".join(f"{k.lower()}={v}" for k, v in sorted(tally.items()))
    audit_append(
        AuditEvent(
            timestamp=time.time(),
            stage="verify",
            input_refs=(observations_ref, payloads_ref),
            output_refs=(verdicts_ref,),
            model_hash=None,
            seed=None,
            summary=f"{len(verdicts)} verdicts ({tally_str}), {skipped} skipped",
        )
    )
    return verdicts_ref


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
