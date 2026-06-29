"""Verify as a generic comparator: predicted outcomes vs observed facts, with no
exit-code heuristics. No model, no podman.

The token lives only in the expected outcome (the plan); the observation is purely
factual. A nonzero exit or an exception is an observation, never a verdict on its own.
"""
from __future__ import annotations

import dataclasses
import json
from pathlib import Path

import workspace
from schema.expected_outcome import ExpectedOutcome, OutcomeKind, clause_result
from schema.hypothesis import EvidenceType, Hypothesis, Status, VerificationStatus
from stages import verify
from store import objects
from workspace import Workspace

_PROCESS = {"process"}


def test_output_contains_searches_observation_facts():
    o = ExpectedOutcome(OutcomeKind.OUTPUT_CONTAINS, token="MARK")
    assert o.satisfied_by({"stdout": "x MARK y", "stderr": ""})
    assert o.satisfied_by({"stdout": "", "stderr": "boom MARK"})
    assert not o.satisfied_by({"stdout": "nope", "stderr": ""})


def test_clause_three_valued_logic():
    hit = ExpectedOutcome(OutcomeKind.OUTPUT_CONTAINS, token="M")
    miss = ExpectedOutcome(OutcomeKind.OUTPUT_CONTAINS, token="X")
    fs = ExpectedOutcome(OutcomeKind.FILESYSTEM_ACCESS)  # unobserved channel
    obs = {"stdout": "M"}
    assert clause_result([hit], obs, _PROCESS) == "true"
    assert clause_result([miss], obs, _PROCESS) == "false"
    assert clause_result([fs], obs, _PROCESS) == "unknown"   # channel not observed
    assert clause_result([], obs, _PROCESS) == "unknown"     # no success condition
    assert clause_result([hit, fs], obs, _PROCESS) == "unknown"  # true AND unknown
    assert clause_result([hit, miss], obs, _PROCESS) == "false"  # true AND false


def _tested_hyp_ref() -> str:
    h = Hypothesis(
        attack_type="code_execution", location="t.py::f", assumption_broken="a",
        expected_effect="e", suggested_inputs=("x",), confidence=0.9,
        status=Status.TESTED, evidence_type=EvidenceType.EXECUTION_OBSERVED,
        verification_status=VerificationStatus.TESTED, provenance="p;tested:1",
    )
    blob = json.dumps(dataclasses.asdict(h), sort_keys=True, separators=(",", ":")).encode()
    return objects.put(blob)


def _verdicts(tmp_path: Path, payload: dict, obs_extra: dict) -> list[str]:
    workspace.use(Workspace.at(tmp_path / "run"))
    try:
        pid = "t.py::f::0"
        pref = objects.put(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode())
        pman = objects.put(json.dumps({pid: pref}, sort_keys=True, separators=(",", ":")).encode())
        obs = {
            "payload_id": pid, "hypothesis_id": "t.py::f::0",
            "tested_hypothesis_ref": _tested_hyp_ref(),
            "stdout": "", "stderr": "", "exit_code": 0, "timed_out": False,
            **obs_extra,
        }
        oref = objects.put(json.dumps(obs, sort_keys=True, separators=(",", ":")).encode())
        oman = objects.put(json.dumps({pid: oref}, sort_keys=True, separators=(",", ":")).encode())
        vman = json.loads(objects.get(verify.run(oman, pman)))
        return [json.loads(objects.get(r))["verdict"] for r in vman.values()]
    finally:
        workspace.clear()


_OUTPUT_PLAN = {
    "hypothesis_id": "t.py::f::0",
    "value": "x",
    "expected_outcomes": [{"kind": "output_contains", "token": "MARK"}],
}


def test_confirmed_on_observed_token(tmp_path):
    assert _verdicts(tmp_path, _OUTPUT_PLAN, {"stdout": "MARK\n"}) == ["CONFIRMED"]


def test_refuted_when_token_absent(tmp_path):
    assert _verdicts(tmp_path, _OUTPUT_PLAN, {"stdout": "nothing here"}) == ["REFUTED"]


def test_exit_code_alone_does_not_confirm(tmp_path):
    # The cookiecutter false-positive shape: the function raised, no outcome observed.
    assert _verdicts(tmp_path, _OUTPUT_PLAN, {"exit_code": 1, "stderr": "Traceback"}) == ["REFUTED"]


def test_inconclusive_when_channel_unobservable(tmp_path):
    plan = {"hypothesis_id": "t.py::f::0", "value": "x",
            "expected_outcomes": [{"kind": "filesystem_access"}]}
    assert _verdicts(tmp_path, plan, {"exit_code": 1}) == ["INCONCLUSIVE"]
