"""Synthesise stage: for each hypothesis, ask the local model to generate
concrete payloads. The model proposes what to try; execution decides whether
any of it worked."""
from __future__ import annotations

import hashlib
import json
import time
from importlib.resources import files
from typing import Any

from audit.log import append as audit_append
from bootstrap.build_sandbox import IMAGE_TAG as SANDBOX_IMAGE
from bootstrap.fetch_models import load_specs
from inference.runner import infer
from schema.audit_event import AuditEvent
from store import objects, refs
from workspace import active as active_workspace

_PROMPT_PATH = files("inference") / "prompts" / "seed_payloads.txt"

_MARKER_INJECT_TYPES = frozenset({"command_injection"})


def _make_marker(payload_id: str) -> str:
    return "VULNFORGE_" + hashlib.sha256(payload_id.encode()).hexdigest()[:16]


def run(hypotheses_ref: str, *, model_alias: str, seed: int, max_tokens: int = 512) -> str:
    specs = {s.alias: s for s in load_specs()}
    if model_alias not in specs:
        raise ValueError(f"unknown model alias: {model_alias!r}")
    spec = specs[model_alias]

    prompt_template = _PROMPT_PATH.read_text()
    logs_dir = active_workspace().logs_dir
    logs_dir.mkdir(parents=True, exist_ok=True)

    hyp_manifest: dict[str, str] = json.loads(objects.get(hypotheses_ref))
    payloads: dict[str, str] = {}
    total = len(hyp_manifest)

    for n, (hyp_id, hyp_ref) in enumerate(sorted(hyp_manifest.items()), 1):
        print(f"  synthesise [{n}/{total}] {hyp_id}", flush=True)
        hyp_data: dict[str, Any] = json.loads(objects.get(hyp_ref))
        prompt = prompt_template + "\n\n" + _format_hypothesis(hyp_id, hyp_data)

        try:
            result = infer(
                prompt=prompt,
                weights_path=spec.dest,
                weights_hash=spec.sha256,
                sandbox_image=SANDBOX_IMAGE,
                seed=seed,
                max_tokens=max_tokens,
                log_dir=logs_dir,
                no_think=spec.no_think,
            )
        except RuntimeError:
            continue

        attack_type_key = hyp_data.get("attack_type", "").lower().replace(" ", "_")
        for idx, payload in enumerate(_parse_payloads(result.output_text, hyp_id)):
            payload_id = f"{hyp_id}::{idx}"
            if attack_type_key in _MARKER_INJECT_TYPES:
                marker = _make_marker(payload_id)
                payload["marker"] = marker
                payload["value"] = f"{payload['value']}; echo {marker}"
            blob = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
            payloads[payload_id] = objects.put(blob)

    manifest_bytes = json.dumps(payloads, sort_keys=True, separators=(",", ":")).encode()
    payloads_ref = objects.put(manifest_bytes)
    refs.write("payloads_latest", payloads_ref)
    audit_append(AuditEvent(
        timestamp=time.time(),
        stage="synthesise",
        input_refs=(hypotheses_ref,),
        output_refs=(payloads_ref,),
        model_hash=spec.sha256,
        seed=seed,
        summary=f"{len(payloads)} payloads from {len(hyp_manifest)} hypotheses",
    ))
    return payloads_ref


def _format_hypothesis(hyp_id: str, h: dict[str, Any]) -> str:
    lines = [
        f"hypothesis_id: {hyp_id}",
        f"attack_type: {h.get('attack_type', '')}",
        f"location: {h.get('location', '')}",
        f"assumption_broken: {h.get('assumption_broken', '')}",
        f"expected_effect: {h.get('expected_effect', '')}",
    ]
    inputs = h.get("suggested_inputs") or []
    if inputs:
        lines.append("suggested_inputs:")
        for inp in inputs:
            lines.append(f"  - {inp}")
    return "\n".join(lines)


def _extract_json(text: str, required_key: str) -> dict[str, Any] | None:
    decoder = json.JSONDecoder()
    result = None
    pos = 0
    while True:
        start = text.find("{", pos)
        if start == -1:
            break
        try:
            obj, _ = decoder.raw_decode(text, start)
            if isinstance(obj, dict) and required_key in obj:
                result = obj
        except json.JSONDecodeError:
            pass
        pos = start + 1
    return result


def _parse_payloads(text: str, hyp_id: str) -> list[dict[str, Any]]:
    data = _extract_json(text, "payloads")
    if data is None:
        return []
    raw_list = data.get("payloads")
    if not isinstance(raw_list, list):
        return []
    out = []
    for item in raw_list:
        if not isinstance(item, dict) or not isinstance(item.get("value"), str):
            continue
        out.append({
            "hypothesis_id": hyp_id,
            "value": item["value"],
            "category": str(item.get("category", "")),
            "rationale": str(item.get("rationale", "")),
        })
    return out