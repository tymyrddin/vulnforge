"""Execute stage: run each payload against its target inside the sandbox,
capture an Observation, and move the corresponding hypothesis from PROPOSED to
TESTED.

This module owns the PROPOSED -> TESTED transition. Grep for
`status=Status.TESTED` and you find it here, only here.
"""
from __future__ import annotations

import dataclasses
import json
import tempfile
import time
from pathlib import Path
from typing import Any

from audit.log import append as audit_append
from bootstrap.build_sandbox import IMAGE_TAG as SANDBOX_IMAGE
from sandbox.run import Mount
from sandbox.run import run as sandbox_run
from schema.audit_event import AuditEvent
from schema.hypothesis import (
    EvidenceType,
    Hypothesis,
    Status,
    VerificationStatus,
)
from store import objects, refs
from workspace import active as active_workspace


def mark_tested(h: Hypothesis, attempts: int) -> Hypothesis:
    if h.status is not Status.PROPOSED:
        raise ValueError(f"cannot mark tested from {h.status.value}")
    return dataclasses.replace(
        h,
        status=Status.TESTED,
        evidence_type=EvidenceType.EXECUTION_OBSERVED,
        verification_status=VerificationStatus.TESTED,
        provenance=f"{h.provenance};tested:{attempts}",
    )


def run(payloads_ref: str, target_ref: str, *, timeout_seconds: int) -> str:
    target_manifest: dict[str, str] = json.loads(objects.get(target_ref))
    payload_manifest: dict[str, str] = json.loads(objects.get(payloads_ref))
    hyp_manifest: dict[str, str] = json.loads(objects.get(refs.read("hypotheses_latest")))

    active_workspace().root.mkdir(parents=True, exist_ok=True)

    observations: dict[str, str] = {}
    tested_hypotheses: dict[str, str] = {}
    skipped = 0

    for payload_id, payload_ref in sorted(payload_manifest.items()):
        payload: dict[str, Any] = json.loads(objects.get(payload_ref))
        hyp_id = payload.get("hypothesis_id", "")

        hyp_ref = hyp_manifest.get(hyp_id)
        if hyp_ref is None:
            skipped += 1
            continue

        hyp_data: dict[str, Any] = json.loads(objects.get(hyp_ref))
        # hyp_id is "file::function::idx" — use it rather than the model's
        # location field, which may echo the schema example verbatim.
        file_path = hyp_id.split("::")[0]
        file_hash = target_manifest.get(file_path)
        if file_hash is None:
            skipped += 1
            continue

        target_bytes = objects.get(file_hash)
        payload_value = payload.get("value", "")
        marker = payload.get("marker", "")

        start = time.monotonic()
        obs = _run_payload(target_bytes, payload_value, payload_id, hyp_id, timeout_seconds)
        obs["duration_seconds"] = round(time.monotonic() - start, 3)
        if marker:
            obs["marker"] = marker

        try:
            h = _load_hypothesis(hyp_data)
            tested = mark_tested(h, attempts=1)
            tested_blob = json.dumps(
                dataclasses.asdict(tested), sort_keys=True, separators=(",", ":")
            ).encode()
            tested_ref = objects.put(tested_blob)
            obs["tested_hypothesis_ref"] = tested_ref
            tested_hypotheses[hyp_id] = tested_ref
        except (ValueError, KeyError):
            pass

        obs_blob = json.dumps(obs, sort_keys=True, separators=(",", ":")).encode()
        observations[payload_id] = objects.put(obs_blob)

    observations_manifest = json.dumps(
        observations, sort_keys=True, separators=(",", ":")
    ).encode()
    observations_ref = objects.put(observations_manifest)
    refs.write("execution_latest", observations_ref)

    if tested_hypotheses:
        tested_manifest = json.dumps(
            tested_hypotheses, sort_keys=True, separators=(",", ":")
        ).encode()
        refs.write("tested_hypotheses_latest", objects.put(tested_manifest))

    audit_append(AuditEvent(
        timestamp=time.time(),
        stage="execute",
        input_refs=(payloads_ref, target_ref),
        output_refs=(observations_ref,),
        model_hash=None,
        seed=None,
        summary=f"{len(observations)} observations, {skipped} skipped",
    ))
    return observations_ref


def _make_harness(func_name: str) -> bytes:
    return f"""\
import inspect, json, sys, traceback

_FUNC = {func_name!r}

with open('/work/payload.json') as _f:
    _payload = json.load(_f)

_ns = {{}}
exec(compile(open('/work/target.py').read(), 'target.py', 'exec'), _ns)

_fn = _ns.get(_FUNC)
if _fn is None and '.' in _FUNC:
    _cls_name, _attr = _FUNC.split('.', 1)
    _cls = _ns.get(_cls_name)
    if _cls is not None:
        _fn = getattr(_cls, _attr, None)

if _fn is None:
    print(f'function {{_FUNC!r}} not found in target', file=sys.stderr)
    sys.exit(2)

try:
    _params = list(inspect.signature(_fn).parameters)
    _args = [_payload] + ['' for _ in _params[1:]]
    _result = _fn(*_args)
    print(repr(_result))
except SystemExit as _exc:
    sys.exit(_exc.code)
except Exception:
    traceback.print_exc()
    sys.exit(1)
""".encode()


def _run_payload(
    target_bytes: bytes,
    payload_value: str,
    payload_id: str,
    hyp_id: str,
    timeout_seconds: int,
) -> dict[str, Any]:
    obs: dict[str, Any] = {
        "payload_id": payload_id,
        "hypothesis_id": hyp_id,
        "exit_code": -1,
        "stdout": "",
        "stderr": "",
        "timed_out": False,
    }
    try:
        parts = hyp_id.split("::")
        func_name = parts[1] if len(parts) >= 2 else ""
        with tempfile.TemporaryDirectory(prefix="vulnforge-exec-") as tmpdir:
            target_path = Path(tmpdir) / "target.py"
            target_path.write_bytes(target_bytes)
            payload_path = Path(tmpdir) / "payload.json"
            payload_path.write_text(json.dumps(payload_value))
            harness_path = Path(tmpdir) / "harness.py"
            harness_path.write_bytes(_make_harness(func_name))
            result = sandbox_run(
                image=SANDBOX_IMAGE,
                command=["python3", "/work/harness.py"],
                mounts=(
                    Mount(source=target_path, target="/work/target.py", mode="ro"),
                    Mount(source=payload_path, target="/work/payload.json", mode="ro"),
                    Mount(source=harness_path, target="/work/harness.py", mode="ro"),
                ),
                timeout_seconds=timeout_seconds,
            )
        obs["exit_code"] = result.exit_code
        obs["stdout"] = result.stdout.decode("utf-8", errors="replace")
        obs["stderr"] = result.stderr.decode("utf-8", errors="replace")
        obs["timed_out"] = result.timed_out
    except Exception as exc:
        obs["stderr"] = str(exc)
    return obs


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