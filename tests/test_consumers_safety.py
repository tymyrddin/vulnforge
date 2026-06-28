"""The second consumer: a safety reading of the same fact substrate.

The load-bearing claim under test is that the safety consumer reads the same facts
the firmware pipeline produced, needs nothing added to them, and reaches a
different conclusion from the vulnerability lens on the same fact.
"""
import copy
import importlib.util
import json
from pathlib import Path

import pytest

import workspace
from consumers import safety
from sandbox import qemu
from schema.screen import Grounding
from stages.screen import _grade_by_source
from store import objects
from tests.firmware_fixtures import IWDG_KR, register_write_image
from workspace import Workspace

_CONFIG = Path(__file__).resolve().parents[1] / "configs" / "stm32f405.yaml"
_HAVE_FW = importlib.util.find_spec("capstone") is not None and qemu.available()


def _watchdog_fact(value_source="constant"):
    return {
        "type": "register_write", "address": IWDG_KR, "value": 0xCCCC,
        "value_source": value_source, "peripheral": "IWDG",
        "register": "KR", "role": "watchdog",
    }


# --- pure consumer behaviour ---

def test_flags_watchdog_write():
    findings = safety.assess([_watchdog_fact()])
    assert len(findings) == 1
    assert findings[0]["property"] == "watchdog_protection_reconfigured"
    assert findings[0]["address"] == IWDG_KR


def test_ignores_non_register_and_unmapped_roles():
    facts = [
        {"type": "subprocess", "shell": True, "arg_source": "parameter:x"},
        {"type": "register_write", "address": 0x20000000, "role": None},
    ]
    assert safety.assess(facts) == []


# --- the demonstration: same fact, two consumers disagree, nothing added ---

def test_two_lenses_disagree_on_the_same_fact():
    fact = _watchdog_fact(value_source="constant")

    # Vulnerability lens: a constant value is not attacker-controlled -> contradicted.
    vuln_grounding, _ = _grade_by_source(fact["value_source"])
    assert vuln_grounding is Grounding.CONTRADICTED

    # Safety lens: a protection mechanism is reconfigured regardless of the value.
    assert len(safety.assess([fact])) == 1


def test_consumer_adds_nothing_to_the_fact():
    facts = [_watchdog_fact()]
    snapshot = copy.deepcopy(facts)
    safety.assess(facts)
    assert facts == snapshot  # the substrate is read, never mutated


# --- strongest form: read the exact facts the pipeline stored ---

@pytest.mark.skipif(not _HAVE_FW, reason="capstone or qemu-system-arm not installed")
def test_reads_the_facts_the_pipeline_produced(tmp_path):
    from orchestrator import firmware

    workspace.use(Workspace.at(tmp_path / "run"))
    try:
        image = tmp_path / "fw.bin"
        image.write_bytes(register_write_image())
        verdict = firmware.run(image, _CONFIG)

        # Load the very blob the pipeline wrote, no re-extraction.
        stored_facts = json.loads(objects.get(verdict["facts_ref"]))
        findings = safety.assess(stored_facts)

        assert any(f["property"] == "watchdog_protection_reconfigured" for f in findings)
        # The pipeline baked no safety field into the fact; the consumer derives it.
        assert all("property" not in f and "safety" not in f for f in stored_facts)
    finally:
        workspace.clear()
