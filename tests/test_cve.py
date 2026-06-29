"""Unit tests for the CVE correlation module."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from unittest import mock


def test_cwe_map_covers_common_types():
    from cve.cwe_map import ATTACK_TYPE_TO_CWES

    for attack_type in ("sql_injection", "code_execution", "path_traversal", "xss"):
        cwes = ATTACK_TYPE_TO_CWES.get(attack_type)
        assert cwes, f"no CWE mapping for {attack_type!r}"
        assert all(c.startswith("CWE-") for c in cwes), f"malformed CWE in {cwes}"


def test_cve_index_match_with_fixture():
    from cve import index as cve_index

    fixture = {
        "id": "GHSA-test-0001-xxxx",
        "aliases": ["CVE-2024-99999"],
        "database_specific": {"cwe_ids": ["CWE-89"]},
    }

    with tempfile.TemporaryDirectory() as tmpdir:
        osv_dir = Path(tmpdir) / "osv-pypi"
        osv_dir.mkdir()
        (osv_dir / "GHSA-test-0001-xxxx.json").write_text(json.dumps(fixture), encoding="utf-8")

        with mock.patch("cve.index.cve_dir", return_value=Path(tmpdir)):
            db = cve_index.load()

    assert db is not None, "load() returned None despite fixture data being present"
    refs = cve_index.match(db, "sql_injection")
    assert "CVE-2024-99999" in refs, f"expected CVE-2024-99999 in {refs}"


def test_cve_index_load_returns_none_when_absent():
    from cve import index as cve_index

    with (
        tempfile.TemporaryDirectory() as tmpdir,
        mock.patch("cve.index.cve_dir", return_value=Path(tmpdir)),
    ):
        db = cve_index.load()

    assert db is None, "load() should return None when osv-pypi dir is missing"


def test_cve_index_match_unknown_attack_type():
    from cve import index as cve_index

    db: cve_index.CveDb = {"CWE-89": ["CVE-2024-99999"]}
    refs = cve_index.match(db, "unknown_attack_type")
    assert refs == [], f"expected [] for unknown attack type, got {refs}"


def test_verify_attaches_cve_refs_to_confirmed_verdict():
    """verify.run() wires cve_refs into confirmed verdicts when the DB is present."""
    import dataclasses
    from unittest import mock

    from schema.hypothesis import EvidenceType, Hypothesis, Status, VerificationStatus
    from stages import verify
    from store import objects
    from workspace import new_run
    from workspace import use as use_workspace

    fixture_db: dict[str, list[str]] = {"CWE-94": ["CVE-2024-EVAL"]}

    with tempfile.TemporaryDirectory() as tmpdir:
        use_workspace(new_run(base=Path(tmpdir)))

        h = Hypothesis(
            attack_type="code_execution",
            location="app.py::vulnerable_eval",
            assumption_broken="eval is safe on untrusted input",
            expected_effect="arbitrary code executed",
            suggested_inputs=("1+1",),
            confidence=0.9,
            status=Status.TESTED,
            evidence_type=EvidenceType.EXECUTION_OBSERVED,
            verification_status=VerificationStatus.TESTED,
            provenance="inference:abc;tested:1",
        )
        tested_hyp_ref = objects.put(
            json.dumps(dataclasses.asdict(h), sort_keys=True, separators=(",", ":")).encode()
        )

        # The plan predicts a marker in output; the observation shows it. That is the
        # positive evidence that confirms, not a nonzero exit code.
        token = "VULNFORGE_TESTMARKER"
        payload_id = "app.py::vulnerable_eval::0::0"
        payload = {
            "hypothesis_id": "app.py::vulnerable_eval::0",
            "value": "1+1",
            "expected_outcomes": [{"kind": "output_contains", "token": token}],
        }
        payload_ref = objects.put(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        )
        payloads_manifest_ref = objects.put(
            json.dumps({payload_id: payload_ref}, sort_keys=True, separators=(",", ":")).encode()
        )

        obs = {
            "payload_id": payload_id,
            "hypothesis_id": "app.py::vulnerable_eval::0",
            "exit_code": 0,
            "stdout": f"{token}\n",
            "stderr": "",
            "timed_out": False,
            "tested_hypothesis_ref": tested_hyp_ref,
        }
        obs_ref = objects.put(json.dumps(obs, sort_keys=True, separators=(",", ":")).encode())
        obs_manifest_ref = objects.put(
            json.dumps({payload_id: obs_ref}, sort_keys=True, separators=(",", ":")).encode()
        )

        with mock.patch("stages.verify.cve_index.load", return_value=fixture_db):
            verdicts_ref = verify.run(obs_manifest_ref, payloads_manifest_ref)

        verdict_manifest = json.loads(objects.get(verdicts_ref))
        assert verdict_manifest, "no verdicts produced"

        confirmed = [
            json.loads(objects.get(vref))
            for vref in verdict_manifest.values()
            if json.loads(objects.get(vref))["verdict"] == "CONFIRMED"
        ]
        assert confirmed, "expected at least one CONFIRMED verdict"
        for v in confirmed:
            assert "CVE-2024-EVAL" in v.get("cve_refs", []), (
                f"CVE ref missing from confirmed verdict: {v}"
            )
