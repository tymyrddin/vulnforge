"""Hypothesise stage: for each slice, ask the local model to propose
attack-relevant hypotheses. Output is validated against the Hypothesis schema.

Inference runs inside the canonical sandbox. The model can only ever produce
Status.PROPOSED; verdict transitions live in verify.py."""
from __future__ import annotations

import dataclasses
import json
import time
from pathlib import Path
from typing import Any

from audit.log import append as audit_append
from bootstrap.build_sandbox import IMAGE_TAG as SANDBOX_IMAGE
from bootstrap.fetch_models import load_specs
from inference.runner import infer
from schema.audit_event import AuditEvent
from schema.hypothesis import EvidenceType, Hypothesis, VerificationStatus
from store import objects, refs
from workspace import active as active_workspace

_PROMPT_PATH = Path("inference/prompts/hypothesise.txt")


def run(slices_ref: str, *, model_alias: str, seed: int, max_tokens: int = 512) -> str:
    specs = {s.alias: s for s in load_specs()}
    if model_alias not in specs:
        raise ValueError(f"unknown model alias: {model_alias!r}")
    spec = specs[model_alias]

    prompt_template = _PROMPT_PATH.read_text()
    logs_dir = active_workspace().logs_dir
    logs_dir.mkdir(parents=True, exist_ok=True)

    slice_manifest: dict[str, str] = json.loads(objects.get(slices_ref))
    hypotheses: dict[str, str] = {}
    total = len(slice_manifest)

    for n, (slice_id, slice_ref) in enumerate(sorted(slice_manifest.items()), 1):
        print(f"  hypothesise [{n}/{total}] {slice_id}", flush=True)
        slice_data: dict[str, Any] = json.loads(objects.get(slice_ref))
        prompt = prompt_template + "\n\n" + _format_slice(slice_data)

        try:
            result = infer(
                prompt=prompt,
                weights_path=spec.dest,
                weights_hash=spec.sha256,
                sandbox_image=SANDBOX_IMAGE,
                seed=seed,
                max_tokens=max_tokens,
                ctx_size=8192,
                log_dir=logs_dir,
                no_think=spec.no_think,
            )
        except RuntimeError:
            continue

        for idx, hypothesis in enumerate(_parse_hypotheses(result.output_text, slice_id, result.weights_hash)):
            hyp_id = f"{slice_id}::{idx}"
            blob = json.dumps(dataclasses.asdict(hypothesis), sort_keys=True, separators=(",", ":")).encode()
            hypotheses[hyp_id] = objects.put(blob)

    manifest_bytes = json.dumps(hypotheses, sort_keys=True, separators=(",", ":")).encode()
    hypotheses_ref = objects.put(manifest_bytes)
    refs.write("hypotheses_latest", hypotheses_ref)
    audit_append(AuditEvent(
        timestamp=time.time(),
        stage="hypothesise",
        input_refs=(slices_ref,),
        output_refs=(hypotheses_ref,),
        model_hash=spec.sha256,
        seed=seed,
        summary=f"{len(hypotheses)} hypotheses from {len(slice_manifest)} slices",
    ))
    return hypotheses_ref


def _render_fact(f: dict[str, Any]) -> str:
    t = f.get("type", "")
    if t == "subprocess":
        return f"subprocess(shell={f['shell']}, argv={f['argv_style']})"
    if t in ("file_write", "file_read"):
        return f"{t.replace('_', ' ')}: path from {f['path_source']}"
    if t == "dangerous_sink":
        return f"dangerous sink: {f['name']}"
    if t == "environment_access":
        return f"environment access: {f['call']}"
    return str(f)


def _format_slice(s: dict[str, Any]) -> str:
    lines = [
        f"# File: {s['file_path']}",
        f"# Function: {s['function_name']}",
    ]
    if s.get("parameters"):
        lines.append(f"# Parameters: {', '.join(s['parameters'])}")
    if s.get("return_type"):
        lines.append(f"# Returns: {s['return_type']}")
    if s.get("decorators"):
        lines.append(f"# Decorators: {', '.join(s['decorators'])}")
    if s.get("imports"):
        lines.append("# Imports:")
        for imp in s["imports"]:
            lines.append(f"#   {imp}")
    if s.get("calls"):
        lines.append(f"# Calls: {', '.join(s['calls'])}")
    ctx = s.get("context", {})
    if ctx.get("callers"):
        lines.append(f"# Called by: {', '.join(ctx['callers'])}")
    if ctx.get("callees"):
        lines.append(f"# Intra-file callees: {', '.join(ctx['callees'])}")
    if s.get("security_facts"):
        lines.append("# Security facts:")
        for fact in s["security_facts"]:
            lines.append(f"#   {_render_fact(fact)}")
    lines.append("")
    lines.append(s.get("body", ""))
    return "\n".join(lines)


def _extract_json(text: str, required_key: str) -> dict[str, Any] | None:
    # Scan for every { and return the last valid dict containing required_key.
    # The model often echoes the prompt (including the schema example) before
    # emitting its actual response, so the first { is the wrong one.
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


def _parse_hypotheses(text: str, slice_id: str, model_hash: str) -> list[Hypothesis]:
    data = _extract_json(text, "hypotheses")
    if data is None:
        return []
    raw_list = data.get("hypotheses")
    if not isinstance(raw_list, list):
        return []
    out = []
    for item in raw_list:
        if not isinstance(item, dict):
            continue
        try:
            h = Hypothesis.propose(
                attack_type=str(item["attack_type"]),
                location=str(item.get("location", slice_id)),
                assumption_broken=str(item["assumption_broken"]),
                expected_effect=str(item["expected_effect"]),
                suggested_inputs=[str(x) for x in (item.get("suggested_inputs") or [])],
                confidence=float(item.get("confidence", 0.5)),
                model_hash=model_hash,
                evidence_type=EvidenceType(item.get("evidence_type", "static_pattern")),
                verification_status=VerificationStatus(item.get("verification_status", "unverified")),
            )
        except (KeyError, ValueError, TypeError):
            continue
        out.append(h)
    return out