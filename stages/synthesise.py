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
from schema.expected_outcome import ExpectedOutcome, OutcomeKind
from store import objects, refs
from workspace import active as active_workspace

_PROMPT_PATH = files("inference") / "prompts" / "seed_payloads.txt"

_MARKER_INJECT_TYPES = frozenset({"command_injection"})

# Output contract bounds, enforced regardless of what the model emits. They keep the
# payload set small enough to fit the token budget as valid JSON, and cap any single
# value so one runaway string cannot blow the budget on its own.
_MAX_PAYLOADS = 5
_MAX_VALUE_LEN = 200
# The placeholder value in the prompt's schema example; never a real payload.
_SCHEMA_PLACEHOLDER = "the concrete input string"

# Attack classes whose success surfaces on a non-output channel. Synthesise predicts the
# semantic outcome; verify decides it observable or not from the executor's capabilities.
_FS_OUTCOME_TYPES = frozenset({
    "path_traversal", "directory_traversal", "arbitrary_file_read", "arbitrary_file_write",
    "file_read", "file_write", "arbitrary_file_access", "file_disclosure", "path_manipulation",
})
_NET_OUTCOME_TYPES = frozenset({"ssrf", "server_side_request_forgery"})


def _expected_outcomes(attack_type_key: str, marker: str) -> list[ExpectedOutcome]:
    """The semantic outcomes whose observation would demonstrate this payload's success.

    Command-style payloads carry a planted marker, so success is the marker appearing in
    output. Filesystem and network classes predict their own channel. Anything else gets
    no success condition yet, which verify reads as inconclusive rather than refuted.
    """
    if marker:
        return [ExpectedOutcome(OutcomeKind.OUTPUT_CONTAINS, token=marker)]
    if attack_type_key in _FS_OUTCOME_TYPES:
        return [ExpectedOutcome(OutcomeKind.FILESYSTEM_ACCESS)]
    if attack_type_key in _NET_OUTCOME_TYPES:
        return [ExpectedOutcome(OutcomeKind.NETWORK_CONNECTION)]
    return []


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
    # Per-hypothesis parse outcome, so the audit distinguishes "model produced zero
    # payloads" from "model output did not parse / was truncated".
    status_counts: dict[str, int] = {}
    total_recovered = 0  # complete payload objects salvaged, before schema validation
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
            status_counts["infer_error"] = status_counts.get("infer_error", 0) + 1
            continue

        items, status, recovered = _parse_payloads(result.output_text, hyp_id)
        status_counts[status] = status_counts.get(status, 0) + 1
        total_recovered += recovered
        attack_type_key = (
            hyp_data.get("attack_type", "").lower().replace(" ", "_").replace("-", "_")
        )
        for idx, payload in enumerate(items):
            payload_id = f"{hyp_id}::{idx}"
            marker = ""
            if attack_type_key in _MARKER_INJECT_TYPES:
                marker = _make_marker(payload_id)
                payload["value"] = f"{payload['value']}; echo {marker}"
            # the prediction lives on the plan (payload), never on the observation
            payload["expected_outcomes"] = [
                o.to_dict() for o in _expected_outcomes(attack_type_key, marker)
            ]
            blob = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
            payloads[payload_id] = objects.put(blob)

    manifest_bytes = json.dumps(payloads, sort_keys=True, separators=(",", ":")).encode()
    payloads_ref = objects.put(manifest_bytes)
    refs.write("payloads_latest", payloads_ref)
    status_str = ", ".join(f"{k}={v}" for k, v in sorted(status_counts.items()))
    audit_append(
        AuditEvent(
            timestamp=time.time(),
            stage="synthesise",
            input_refs=(hypotheses_ref,),
            output_refs=(payloads_ref,),
            model_hash=spec.sha256,
            seed=seed,
            summary=(
                f"synthesise over {total} hypotheses: "
                f"contract_limit={_MAX_PAYLOADS}, recovered_count={total_recovered}, "
                f"valid_count={len(payloads)}"
                + (f" ({status_str})" if status_str else "")
            ),
        )
    )
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


def _extract_payload_items(text: str) -> tuple[list[Any], str]:
    """Recover the payload array even when the surrounding JSON is truncated.

    The model often echoes the prompt schema and then emits its real answer, which the
    token budget can cut off mid-array. So this scans every ``"payloads"`` array, decodes
    its elements one at a time (salvaging the complete ones before any truncation point),
    and keeps the last array that yielded elements (the model's answer, not the echoed
    schema). Returns the items and a status: "ok" (array closed cleanly), "recovered"
    (array truncated, complete items salvaged), "empty" (a valid but empty array), or
    "unparseable" (no payload array found).
    """
    decoder = json.JSONDecoder()
    best: tuple[list[Any], bool] | None = None  # last array that yielded items
    saw_empty_closed = False  # a payloads array that closed with zero elements
    saw_truncated = False  # a payloads array that opened but never closed
    search = 0
    while True:
        key = text.find('"payloads"', search)
        if key == -1:
            break
        search = key + 1
        bracket = text.find("[", key)
        if bracket == -1:
            continue
        i = bracket + 1
        items: list[Any] = []
        complete = False
        while True:
            while i < len(text) and text[i] in " \t\r\n,":
                i += 1
            if i >= len(text):
                break  # truncated before the array closed
            if text[i] == "]":
                complete = True
                break
            try:
                obj, end = decoder.raw_decode(text, i)
            except json.JSONDecodeError:
                break  # truncated or malformed element: stop, keep the complete ones
            items.append(obj)
            i = end
        if items:
            best = (items, complete)  # last array with content wins (the real answer)
        elif complete:
            saw_empty_closed = True
        else:
            saw_truncated = True

    if best is not None:
        items, complete = best
        return items, ("ok" if complete else "recovered")
    if saw_truncated:
        return [], "recovered"  # an array opened and was cut off with nothing salvageable
    if saw_empty_closed:
        return [], "empty"  # the model genuinely produced no payloads
    return [], "unparseable"  # no payload array at all


def _parse_payloads(text: str, hyp_id: str) -> tuple[list[dict[str, Any]], str, int]:
    """Return (payloads, status, recovered). `recovered` is the number of complete
    payload objects salvaged before validation; len(payloads) is how many then passed
    it, so the two distinguish "recovered 1/5" from "5/5" without new statuses. Bounds
    are enforced here, not trusted to the model: at most _MAX_PAYLOADS items, each value
    at most _MAX_VALUE_LEN characters."""
    items, status = _extract_payload_items(text)
    recovered = len(items)
    if not items:
        return [], status, 0  # "empty", "recovered" (nothing salvaged), or "unparseable"
    out: list[dict[str, Any]] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        value = item.get("value")
        if not isinstance(value, str):
            continue
        value = value.strip()
        if not value or value == _SCHEMA_PLACEHOLDER or len(value) > _MAX_VALUE_LEN:
            continue
        out.append(
            {
                "hypothesis_id": hyp_id,
                "value": value,
                "category": str(item.get("category", ""))[:32],
                "rationale": str(item.get("rationale", ""))[:200],
            }
        )
        if len(out) >= _MAX_PAYLOADS:
            break
    if not out:
        # The JSON parsed and held elements, but none passed validation (non-string
        # value, placeholder, or over-length). Distinct from the model emitting none.
        return [], "schema_invalid", recovered
    return out, status, recovered
