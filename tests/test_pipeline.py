"""Pipeline tests: unit-level parsing checks plus an end-to-end smoke test.

Run with pytest -s to see stage-by-stage output from the integration test.
The unit tests run without podman or weights and should always pass quickly.
"""
from __future__ import annotations

import json
import shutil
import tempfile
from pathlib import Path

import pytest

from bootstrap import build_sandbox
from stages import execute, hypothesise, index, ingest, report, synthesise, verify
from store import objects
from workspace import new_run, use as use_workspace


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _image_hash() -> str | None:
    try:
        return build_sandbox.current_hash()
    except FileNotFoundError:
        return None


skip_if_not_bootstrapped = pytest.mark.skipif(
    shutil.which("podman") is None or _image_hash() is None,
    reason="podman or sandbox image missing (run vulnforge bootstrap first)",
)


# ---------------------------------------------------------------------------
# Unit tests: parsing, independent of the model and sandbox
# ---------------------------------------------------------------------------

def test_extract_json_picks_last_valid_blob():
    """When the model echoes the prompt schema before its own response,
    _extract_json returns the last valid dict, not the template."""
    from stages.hypothesise import _extract_json

    template = '{"hypotheses": [{"evidence_type": "static_pattern | behaviour_inferred"}]}'
    actual = '{"hypotheses": [{"attack_type": "sql_injection", "evidence_type": "static_pattern"}]}'
    text = f"Hard rules: do not ...\n\n{template}\n\nSlice:\n\n```json\n{actual}\n```"

    result = _extract_json(text, "hypotheses")
    assert result is not None
    assert result["hypotheses"][0]["attack_type"] == "sql_injection"


def test_parse_hypotheses_fenced_json():
    """Model output that wraps JSON in markdown code fences parses correctly."""
    from stages.hypothesise import _parse_hypotheses

    output = """\
Hard rules:
1. Do not present unverified findings as confirmed.

```json
{
  "hypotheses": [
    {
      "attack_type": "code_execution",
      "location": "app.py::vulnerable_eval",
      "assumption_broken": "eval is safe on untrusted input",
      "expected_effect": "arbitrary code executed",
      "suggested_inputs": ["__import__('os').system('id')", "1+1"],
      "confidence": 0.9,
      "evidence_type": "static_pattern",
      "verification_status": "unverified"
    }
  ]
}
```"""

    result = _parse_hypotheses(output, "app.py::vulnerable_eval", "deadbeef")
    assert len(result) == 1, f"expected 1 hypothesis, got {len(result)}"
    h = result[0]
    assert h.attack_type == "code_execution"
    assert h.evidence_type.value == "static_pattern"
    assert h.confidence == pytest.approx(0.9)


def test_placeholder_gate_accepts_expressions():
    """Payloads with parentheses, dots, slashes are accepted."""
    from schema.hypothesis import _is_placeholder
    for value in [
        "__import__('os').system('id')",
        "$(id)",
        "`whoami`",
        "../../etc/passwd",
        "' OR 1=1 --",
        "AAAAAAAAAAAAAAAAAAAAAA",
        "1+1",
        "admin",
        "ADMIN",
    ]:
        assert not _is_placeholder(value), f"should accept: {value!r}"


def test_placeholder_gate_rejects_templates():
    """Template tokens are rejected."""
    from schema.hypothesis import _is_placeholder
    for value in [
        "<payload>",
        "{command}",
        "[PLACEHOLDER]",
        "...",
        "*",
        "USER_INPUT",
        "SQL_QUERY",
        "MY_PAYLOAD_VALUE",
    ]:
        assert _is_placeholder(value), f"should reject: {value!r}"


def test_parse_hypotheses_invalid_evidence_type_skipped():
    """Items with invalid enum values are silently dropped rather than crashing."""
    from stages.hypothesise import _parse_hypotheses

    output = """\
```json
{
  "hypotheses": [
    {
      "attack_type": "sql_injection",
      "location": "app.py::query",
      "assumption_broken": "inputs are sanitised",
      "expected_effect": "extra rows returned",
      "suggested_inputs": ["' OR 1=1"],
      "confidence": 0.7,
      "evidence_type": "static_pattern | behaviour_inferred",
      "verification_status": "unverified"
    },
    {
      "attack_type": "path_traversal",
      "location": "app.py::read_file",
      "assumption_broken": "path is restricted to app root",
      "expected_effect": "reads /etc/passwd",
      "suggested_inputs": ["../../../etc/passwd"],
      "confidence": 0.6,
      "evidence_type": "static_pattern",
      "verification_status": "unverified"
    }
  ]
}
```"""

    result = _parse_hypotheses(output, "app.py::mixed", "deadbeef")
    assert len(result) == 1, f"expected 1 (bad enum dropped), got {len(result)}"
    assert result[0].attack_type == "path_traversal"


# ---------------------------------------------------------------------------
# Execute harness: deterministic sandbox tests, no model inference
# ---------------------------------------------------------------------------

_HARNESS_TARGET = b"""\
def echo(value):
    return value

def add(a, b=''):
    return a + b

def vulnerable_eval(user_input):
    return eval(user_input)

def always_raises(value):
    raise RuntimeError("deliberate failure")

def infinite_loop(value):
    import time
    while True:
        time.sleep(0.05)
"""


@skip_if_not_bootstrapped
def test_execute_harness_captures_return_value() -> None:
    """Harness calls the named function and prints repr() of its return value."""
    with tempfile.TemporaryDirectory() as tmpdir:
        use_workspace(new_run(base=Path(tmpdir)))
        obs = execute._run_payload(_HARNESS_TARGET, "hello", "p0", "target.py::echo::0", 30)
    assert obs["exit_code"] == 0, obs["stderr"]
    assert "'hello'" in obs["stdout"]


@skip_if_not_bootstrapped
def test_execute_harness_code_execution_payload() -> None:
    """A real code-execution payload against eval() produces observable output."""
    with tempfile.TemporaryDirectory() as tmpdir:
        use_workspace(new_run(base=Path(tmpdir)))
        obs = execute._run_payload(
            _HARNESS_TARGET, "1+1", "p0", "target.py::vulnerable_eval::0", 30
        )
    assert obs["exit_code"] == 0, obs["stderr"]
    assert "2" in obs["stdout"]


@skip_if_not_bootstrapped
def test_execute_harness_exception_captured() -> None:
    """An exception inside the target function → exit=1 and traceback in stderr."""
    with tempfile.TemporaryDirectory() as tmpdir:
        use_workspace(new_run(base=Path(tmpdir)))
        obs = execute._run_payload(
            _HARNESS_TARGET, "x", "p0", "target.py::always_raises::0", 30
        )
    assert obs["exit_code"] == 1
    assert "RuntimeError" in obs["stderr"]
    assert "deliberate failure" in obs["stderr"]


@skip_if_not_bootstrapped
def test_execute_harness_missing_function() -> None:
    """A hyp_id that names a non-existent function exits with code 2."""
    with tempfile.TemporaryDirectory() as tmpdir:
        use_workspace(new_run(base=Path(tmpdir)))
        obs = execute._run_payload(
            _HARNESS_TARGET, "x", "p0", "target.py::no_such_fn::0", 30
        )
    assert obs["exit_code"] == 2


@skip_if_not_bootstrapped
def test_execute_harness_multi_param_function() -> None:
    """A function with multiple parameters gets the payload as the first arg."""
    with tempfile.TemporaryDirectory() as tmpdir:
        use_workspace(new_run(base=Path(tmpdir)))
        obs = execute._run_payload(
            _HARNESS_TARGET, "hello", "p0", "target.py::add::0", 30
        )
    assert obs["exit_code"] == 0, obs["stderr"]
    assert "'hello'" in obs["stdout"]


@skip_if_not_bootstrapped
def test_execute_harness_timeout() -> None:
    """A function that loops forever hits the timeout; timed_out is True and exit_code is 124."""
    with tempfile.TemporaryDirectory() as tmpdir:
        use_workspace(new_run(base=Path(tmpdir)))
        obs = execute._run_payload(
            _HARNESS_TARGET, "x", "p0", "target.py::infinite_loop::0", 3
        )
    assert obs["timed_out"] is True
    assert obs["exit_code"] == 124


# ---------------------------------------------------------------------------
# Integration test: full pipeline with real model and sandbox
# ---------------------------------------------------------------------------

@skip_if_not_bootstrapped
def test_pipeline_end_to_end() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        base = Path(tmpdir)
        ws = new_run(base=base)
        use_workspace(ws)

        target = base / "target"
        target.mkdir()
        (target / "app.py").write_text("""\
def vulnerable_eval(user_input):
    return eval(user_input)

def safe_function(data):
    return data.upper()
""")

        # ingest
        manifest_ref = ingest.run(target)
        assert manifest_ref

        # index
        slices_ref = index.run(manifest_ref)
        slices = json.loads(objects.get(slices_ref))
        print(f"\nindex: {len(slices)} slices")
        for sid in sorted(slices):
            print(f"  {sid}")
        assert slices, "no slices extracted"

        # hypothesise
        hyp_model = "plumbing-check"   # production: qwen3-8b
        syn_model = "plumbing-check"   # production: qwen2.5-coder-7b
        hypotheses_ref = hypothesise.run(slices_ref, model_alias=hyp_model, seed=42)
        hyp_manifest = json.loads(objects.get(hypotheses_ref))
        print(f"\nhypothesise: {len(hyp_manifest)} hypotheses")
        for hyp_id, hyp_ref in sorted(hyp_manifest.items()):
            h = json.loads(objects.get(hyp_ref))
            print(f"  {hyp_id}")
            print(f"    attack_type : {h.get('attack_type')}")
            print(f"    confidence  : {h.get('confidence')}")
            print(f"    evidence    : {h.get('evidence_type')}")
        assert hyp_manifest, (
            f"0 hypotheses from {len(slices)} slices — "
            f"check model logs in {ws.logs_dir}"
        )

        # synthesise
        payloads_ref = synthesise.run(hypotheses_ref, model_alias=syn_model, seed=42)
        payload_manifest = json.loads(objects.get(payloads_ref))
        print(f"\nsynthesize: {len(payload_manifest)} payloads")
        for pid, pref in sorted(payload_manifest.items()):
            p = json.loads(objects.get(pref))
            print(f"  {pid}: {p.get('value')!r}")
        assert payload_manifest, "0 payloads generated"

        # execute
        observations_ref = execute.run(payloads_ref, manifest_ref, timeout_seconds=30)
        obs_manifest = json.loads(objects.get(observations_ref))
        print(f"\nexecute: {len(obs_manifest)} observations")
        for oid, oref in sorted(obs_manifest.items()):
            o = json.loads(objects.get(oref))
            stdout_preview = (o.get("stdout") or "")[:80]
            print(
                f"  {oid}: exit={o.get('exit_code')} "
                f"timeout={o.get('timed_out')} "
                f"stdout={stdout_preview!r}"
            )
        assert obs_manifest, "0 observations recorded"
        assert len(obs_manifest) == len(payload_manifest), (
            "every payload must produce an observation"
        )
        # safe_function returns its argument — harness captures the return value
        safe_obs = [
            json.loads(objects.get(oref))
            for oid, oref in obs_manifest.items()
            if "safe_function" in oid
        ]
        for o in safe_obs:
            assert o["exit_code"] == 0, (
                f"safe_function raised unexpectedly: {o['stderr']}"
            )
            assert o["stdout"].strip(), "safe_function returned nothing to stdout"

        # verify
        verdicts_ref = verify.run(observations_ref, hypotheses_ref)
        verdict_manifest = json.loads(objects.get(verdicts_ref))
        confirmed = []
        refuted = []
        for hid, vref in sorted(verdict_manifest.items()):
            v = json.loads(objects.get(vref))
            label = v.get("verdict", "?")
            (confirmed if label == "CONFIRMED" else refuted).append(hid)
        print(f"\nverify: {len(confirmed)} confirmed, {len(verdict_manifest) - len(confirmed)} refuted")
        for hid in confirmed:
            vref = verdict_manifest[hid]
            v = json.loads(objects.get(vref))
            print(f"  {hid}: CONFIRMED ({v.get('evidence', '')})")
        assert len(verdict_manifest) == len(hyp_manifest), (
            "every hypothesis must receive a verdict"
        )
        safe_verdicts = [
            json.loads(objects.get(vref))
            for hid, vref in verdict_manifest.items()
            if "safe_function" in hid
        ]
        for v in safe_verdicts:
            assert v.get("verdict") == "REFUTED", (
                "safe_function should be refuted — any payload to .upper() exits cleanly "
                "with no expected effect"
            )

        # report
        report_path = report.run(verdicts_ref)
        assert report_path.exists()
        content = report_path.read_text()
        assert "Vulnerability Report" in content
        assert "app.py" in content
        print(f"\nreport: {report_path}\n")
        print(content)
