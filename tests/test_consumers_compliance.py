"""The third consumer: a compliance reading of the same fact substrate.

Checks the compliance consumer references a named control, stays in the
evidence register rather than adjudicating a breach, and that three consumers can
read one fact and each reach their own conclusion without the fact changing shape.
"""
import copy

from consumers import compliance, safety
from schema.screen import Grounding
from stages.screen import _grade_by_source
from tests.firmware_fixtures import IWDG_KR


def _watchdog_fact(value_source="constant"):
    return {
        "type": "register_write", "address": IWDG_KR, "value": 0xCCCC,
        "value_source": value_source, "peripheral": "IWDG",
        "register": "KR", "role": "watchdog",
    }


def test_references_named_control():
    findings = compliance.assess([_watchdog_fact()])
    assert len(findings) == 1
    f = findings[0]
    assert f["standard"] == "IEC 62443-3-3"
    assert f["candidate_control"] == "SR 7.4"
    assert f["foundational_requirement"].startswith("FR 7")


def test_stays_in_evidence_register_not_breach():
    f = compliance.assess([_watchdog_fact()])[0]
    assert f["disposition"] == "candidate_evidence"
    assert "breach" not in f["disposition"]


def test_ignores_non_register_and_unmapped_roles():
    facts = [
        {"type": "register_write", "address": 0x20000000, "role": None},
        {"type": "subprocess", "shell": True},
    ]
    assert compliance.assess(facts) == []


def test_adds_nothing_to_the_fact():
    facts = [_watchdog_fact()]
    snapshot = copy.deepcopy(facts)
    compliance.assess(facts)
    assert facts == snapshot


def test_three_consumers_one_fact_each_its_own_conclusion():
    fact = _watchdog_fact(value_source="constant")

    # Vulnerability: constant value, not attacker-controlled -> contradicted.
    vuln_grounding, _ = _grade_by_source(fact["value_source"])
    assert vuln_grounding is Grounding.CONTRADICTED

    # Safety: a protection mechanism is reconfigured -> flagged.
    assert len(safety.assess([fact])) == 1

    # Compliance: bears on a named control -> candidate evidence.
    comp = compliance.assess([fact])
    assert len(comp) == 1 and comp[0]["candidate_control"] == "SR 7.4"

    # One fact served three consumers; none of them reshaped it.
    assert "property" not in fact and "candidate_control" not in fact
