"""Unit tests for the screen stage grounding logic and policy. No podman, no weights.

The four worked examples come straight from the reviewer's critique of static-pattern
enthusiasm: a system that mapped vulnerability tropes onto sinks without checking
whether attacker data reaches them. Each example below is a case the screen must now
resolve in code rather than by model intuition.
"""
from __future__ import annotations

from schema.screen import (
    UNKNOWN_CONFIDENCE_CAP,
    Grounding,
    ScreenReason,
    ScreenVerdict,
    decide_policy,
)
from stages.screen import _grounding


def _hyp(attack_type: str, inputs=None, confidence: float = 0.8) -> dict:
    return {
        "attack_type": attack_type,
        "suggested_inputs": inputs or [],
        "confidence": confidence,
    }


def _subprocess(shell, arg_source, argv_style="unknown") -> dict:
    return {
        "type": "subprocess", "shell": shell,
        "argv_style": argv_style, "arg_source": arg_source,
    }


def _sink(name: str, arg_source: str) -> dict:
    return {"type": "dangerous_sink", "name": name, "arg_source": arg_source}


# The reviewer's four examples

def test_sqli_in_container_cleanup_is_unsupported():
    # SQL payloads in a cleanup function with subprocess/file sinks and no db import.
    facts = [_subprocess(False, "parameter:name", "list"), {"type": "file_write", "path_source": "constant"}]
    grounding, reason = _grounding(
        _hyp("SQL injection", ["' OR '1'='1", "admin'--"]), facts, ["import os", "import shutil"]
    )
    assert grounding is Grounding.UNSUPPORTED
    assert reason is ScreenReason.NO_MATCHING_SINK


def test_signal_hijacking_with_no_sinks_is_unsupported():
    grounding, reason = _grounding(_hyp("signal hijacking", ["SIGTERM"]), [], ["import signal"])
    assert grounding is Grounding.UNSUPPORTED
    assert reason is ScreenReason.NO_MATCHING_SINK


def test_command_injection_metachars_under_shell_false_is_contradicted():
    facts = [_subprocess(False, "parameter:name", "list")]
    grounding, reason = _grounding(_hyp("command_injection", ["; rm -rf /"]), facts, [])
    assert grounding is Grounding.CONTRADICTED
    assert reason is ScreenReason.SHELL_METACHARS_UNDER_SHELL_FALSE


def test_command_injection_unresolved_provenance_is_unknown():
    # The build_cmd(x) case: a real sink, but the AST cannot follow the argument.
    # Analysis limit, not proof of safety, so accepted at a penalty rather than rejected.
    facts = [_subprocess("unknown", "unknown", "unknown")]
    grounding, reason = _grounding(_hyp("command_injection", ["; rm -rf /"]), facts, [])
    assert grounding is Grounding.UNKNOWN
    assert reason is ScreenReason.SINK_SOURCE_UNRESOLVED


# Grounded and contradicted by argument provenance

def test_eval_of_parameter_is_grounded():
    grounding, reason = _grounding(_hyp("code_execution", ["1+1"]), [_sink("eval", "parameter:x")], [])
    assert grounding is Grounding.GROUNDED
    assert reason is ScreenReason.PARAM_REACHES_SINK


def test_eval_of_constant_is_contradicted():
    grounding, reason = _grounding(_hyp("code_execution", ["1+1"]), [_sink("eval", "constant")], [])
    assert grounding is Grounding.CONTRADICTED
    assert reason is ScreenReason.CONSTANT_SINK_ARG


# Multi-sink resolution: strongest claim wins

def test_multi_sink_any_grounded_wins():
    facts = [
        _subprocess(True, "constant"),
        _subprocess(True, "unknown"),
        _subprocess(True, "parameter:name"),
    ]
    grounding, _ = _grounding(_hyp("command_injection", ["whoami"]), facts, [])
    assert grounding is Grounding.GROUNDED


def test_multi_sink_unknown_beats_contradicted():
    facts = [_subprocess(True, "constant"), _subprocess(True, "unknown")]
    grounding, reason = _grounding(_hyp("command_injection", ["whoami"]), facts, [])
    assert grounding is Grounding.UNKNOWN
    assert reason is ScreenReason.SINK_SOURCE_UNRESOLVED


# SQL handling: imports are a weak signal landing in unknown, not grounded

def test_sqli_with_db_import_is_insufficient_evidence():
    grounding, reason = _grounding(_hyp("SQL injection", ["' OR 1=1"]), [], ["import sqlite3"])
    assert grounding is Grounding.UNKNOWN
    assert reason is ScreenReason.INSUFFICIENT_SQL_EVIDENCE


# Unrecognised attack class preserves recall when there is attack surface

def test_unrecognised_attack_type_with_sink_is_unknown():
    facts = [_subprocess(True, "unknown", "string")]
    grounding, reason = _grounding(_hyp("quantum entanglement attack"), facts, [])
    assert grounding is Grounding.UNKNOWN
    assert reason is ScreenReason.ATTACK_TYPE_UNRECOGNISED


# Policy: how much confidence survives a grounding state

def test_policy_grounded_keeps_confidence():
    accepted, conf = decide_policy(Grounding.GROUNDED, 0.9)
    assert accepted is True
    assert conf == 0.9


def test_policy_unknown_caps_confidence():
    accepted, conf = decide_policy(Grounding.UNKNOWN, 0.9)
    assert accepted is True
    assert conf == UNKNOWN_CONFIDENCE_CAP
    assert conf < 0.9


def test_policy_unknown_does_not_raise_low_confidence():
    # The cap is a ceiling, not a floor.
    _, conf = decide_policy(Grounding.UNKNOWN, 0.1)
    assert conf == 0.1


def test_policy_contradicted_and_unsupported_reject():
    assert decide_policy(Grounding.CONTRADICTED, 0.9)[0] is False
    assert decide_policy(Grounding.UNSUPPORTED, 0.9)[0] is False


def test_screen_verdict_accepted_property():
    grounded = ScreenVerdict("h::0", Grounding.GROUNDED, ScreenReason.PARAM_REACHES_SINK, 0.8)
    rejected = ScreenVerdict("h::1", Grounding.UNSUPPORTED, ScreenReason.NO_MATCHING_SINK, 0.0)
    assert grounded.accepted is True
    assert rejected.accepted is False
