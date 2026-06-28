"""Unit tests for the probe's schema-gate-plus-grounding helper. No model, no sandbox.

`vulnforge probe` runs the same taint-grounding gate the scan pipeline applies. These
tests drive `_screen_probe_hypotheses` directly, so the probe's grounding path stays
correct without needing a live model run to exercise it.
"""

from __future__ import annotations

from cli import _screen_probe_hypotheses


def _hyp(attack_type, inputs, confidence=0.8, **over):
    item = {
        "attack_type": attack_type,
        "location": "run.py::run",
        "assumption_broken": "x",
        "expected_effect": "y",
        "suggested_inputs": inputs,
        "confidence": confidence,
    }
    item.update(over)
    return item


# Facts mirroring what the real extractor produces for sandbox/run.py's `run`:
# a subprocess call with shell off and an unresolved argv, plus a file write whose
# path is a parameter.
_RUN_FACTS = [
    {
        "type": "subprocess",
        "shell": "default_false",
        "argv_style": "unknown",
        "arg_source": "unknown",
    },
    {"type": "file_write", "path_source": "parameter:stderr_log_path"},
]


def test_schema_gate_runs_before_grounding():
    # A non-string suggested_input is refused by the schema gate; the grounding gate
    # never sees it. This is the _on_term int case from the live probe run.
    outcomes, accepted, kept = _screen_probe_hypotheses(
        [_hyp("command_injection", [15])], [], [], "deadbeef"
    )
    assert accepted == 0
    assert kept == 0
    assert outcomes[0]["kind"] == "rejected"
    assert "suggested_inputs" in outcomes[0]["rejection"]


def test_command_injection_metachars_contradicted_and_dropped():
    outcomes, accepted, kept = _screen_probe_hypotheses(
        [_hyp("command_injection", ["; rm -rf /"])], _RUN_FACTS, ["import subprocess"], "deadbeef"
    )
    assert accepted == 1
    assert kept == 0
    o = outcomes[0]
    assert o["kind"] == "screened"
    assert o["grounding"] == "contradicted"
    assert o["screen_reason"] == "shell_metachars_under_shell_false"
    assert o["kept"] is False
    assert o["effective_confidence"] == 0.0


def test_path_traversal_grounded_keeps_full_confidence():
    outcomes, accepted, kept = _screen_probe_hypotheses(
        [_hyp("path_traversal", ["../../etc/passwd"], confidence=0.6)],
        _RUN_FACTS,
        ["import subprocess"],
        "deadbeef",
    )
    assert accepted == 1
    assert kept == 1
    o = outcomes[0]
    assert o["grounding"] == "grounded"
    assert o["screen_reason"] == "param_reaches_sink"
    assert o["kept"] is True
    assert o["effective_confidence"] == 0.6


def test_unrecognised_class_with_sink_is_unknown_and_capped():
    outcomes, accepted, kept = _screen_probe_hypotheses(
        [_hyp("Container name injection", ["evil"], confidence=0.7)],
        _RUN_FACTS,
        ["import subprocess"],
        "deadbeef",
    )
    assert accepted == 1
    assert kept == 1
    o = outcomes[0]
    assert o["grounding"] == "unknown"
    assert o["screen_reason"] == "attack_type_unrecognised"
    assert o["effective_confidence"] == 0.35


def test_outcomes_preserve_input_order_and_counts():
    hyps = [
        _hyp("command_injection", ["; rm -rf /"]),  # contradicted, dropped
        _hyp("path_traversal", ["../x"], confidence=0.6),  # grounded, kept
        _hyp("sql_injection", ["' OR 1=1"]),  # no db import: unsupported, dropped
    ]
    outcomes, accepted, kept = _screen_probe_hypotheses(
        hyps, _RUN_FACTS, ["import subprocess"], "deadbeef"
    )
    assert [o["index"] for o in outcomes] == [0, 1, 2]
    assert accepted == 3
    assert kept == 1
    groundings = {o["index"]: o["grounding"] for o in outcomes}
    assert groundings == {0: "contradicted", 1: "grounded", 2: "unsupported"}
