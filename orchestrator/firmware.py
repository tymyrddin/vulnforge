"""Firmware vertical orchestrator: extract -> screen (safety lens) -> execute
(QEMU) -> verify, through the same content-addressed store and hash-chained audit
log as the Python pipeline.

The point of this module is the arrangement, not the analysis. Each per-stage
backend differs from the Python path (a Thumb decoder, a safety-lens grounding, a
QEMU run, a register-write comparator), but the orchestration and the store/audit
discipline are the same. It is the first end-to-end play on a real Cortex-M image:
a static fact predicts a watchdog register write, execution shows whether it
happened, and verify, alone, decides CONFIRMED.
"""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from audit.log import append as audit_append
from extractors import thumb
from sandbox import qemu
from schema.audit_event import AuditEvent
from schema.screen import ScreenVerdict, decide_policy
from stages.screen import ground_safety_operation
from stages.verify import verify_firmware
from store import objects, refs


def _put(obj: Any) -> str:
    return objects.put(json.dumps(obj, sort_keys=True, separators=(",", ":")).encode())


def run(
    image_path: str | Path,
    device_config: str | Path,
    *,
    load_addr: int = 0x08000000,
    role: str = "watchdog",
    predicate: str = "watchdog control register written",
) -> dict[str, Any]:
    image = Path(image_path).read_bytes()
    image_ref = objects.put(image)  # content-address the artefact under test
    peripherals = thumb.load_peripherals(device_config)

    # extract (index stage): firmware facts from the image
    facts = thumb.extract(image, load_addr, peripherals)
    facts_ref = _put(facts)
    audit_append(AuditEvent(
        timestamp=time.time(), stage="index", input_refs=(image_ref,), output_refs=(facts_ref,),
        model_hash=None, seed=None, summary=f"{len(facts)} firmware facts",
    ))

    # screen (safety lens): ground the predicate against the facts
    grounding, reason, predicted = ground_safety_operation(facts, role)
    accepted, eff_conf = decide_policy(grounding, 1.0)
    sv = ScreenVerdict(
        hypothesis_id=predicate, grounding=grounding,
        screen_reason=reason, effective_confidence=eff_conf,
    )
    screen_ref = _put({
        "hypothesis_id": sv.hypothesis_id, "grounding": sv.grounding.value,
        "screen_reason": sv.screen_reason.value, "effective_confidence": sv.effective_confidence,
        "predicted_addresses": predicted, "accepted": sv.accepted,
    })
    refs.write("firmware_screen_latest", screen_ref)
    audit_append(AuditEvent(
        timestamp=time.time(), stage="screen", input_refs=(facts_ref,),
        output_refs=(screen_ref,), model_hash=None, seed=None,
        summary=f"{predicate}: {grounding.value}",
    ))

    base = {
        "kind": "firmware_register_write", "predicate": predicate,
        "facts_ref": facts_ref, "screen_ref": screen_ref,
    }
    if not accepted:
        verdict = {**base, "status": grounding.value, "evidence": reason.value}
        verdict_ref = _put(verdict)
        refs.write("firmware_verdict_latest", verdict_ref)
        return verdict

    # execute (QEMU): observe the writes the guest actually performs
    if not qemu.available():
        raise RuntimeError("qemu-system-arm not available; firmware execution backend missing")
    observation = qemu.run(image_path)
    obs_ref = _put(observation)
    audit_append(AuditEvent(
        timestamp=time.time(), stage="execute", input_refs=(image_ref,),
        output_refs=(obs_ref,), model_hash=None, seed=None,
        summary=f"{len(observation['writes'])} writes, timed_out={observation['timed_out']}",
    ))

    # verify: deterministic comparison; the only firmware CONFIRMED site
    result = verify_firmware(predicted, observation)
    verdict = {**base, "observation_ref": obs_ref, **result}
    verdict_ref = _put(verdict)
    refs.write("firmware_verdict_latest", verdict_ref)
    audit_append(AuditEvent(
        timestamp=time.time(), stage="verify", input_refs=(screen_ref, obs_ref),
        output_refs=(verdict_ref,), model_hash=None, seed=None,
        summary=f"{predicate}: {result['status']}",
    ))
    return verdict
