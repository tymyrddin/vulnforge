"""CVE index: load the offline OSV dump and match findings by CWE.

The primary data source is the OSV.dev PyPI ecosystem dump, downloaded by
bootstrap/fetch_cve.py. db.gcve.eu (CIRCL Luxembourg) uses the same OSV
format and slots in as the primary source once a confirmed bulk-download URL
is available.

Each .json file in the dump follows the OSV schema:
  {
    "id": "GHSA-xxxx-xxxx-xxxx",
    "aliases": ["CVE-2022-12345"],
    "database_specific": {"cwe_ids": ["CWE-89"]}
  }

load() builds a CWE -> [CVE/GHSA IDs] index in memory. It returns None when
the data directory does not exist so callers can skip the lookup gracefully on
a machine that has not run bootstrap.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from cve.cwe_map import ATTACK_TYPE_TO_CWES
from workspace import cve_dir

CveDb = dict[str, list[str]]


def load() -> CveDb | None:
    data_dir = cve_dir() / "osv-pypi"
    if not data_dir.exists():
        return None

    db: CveDb = {}
    for path in data_dir.glob("*.json"):
        try:
            entry: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue

        primary_id: str = entry.get("id", "")
        aliases: list[str] = entry.get("aliases") or []
        cve_id = next((a for a in aliases if a.startswith("CVE-")), None)
        ref = cve_id or primary_id
        if not ref:
            continue

        cwe_ids: list[str] = (
            (entry.get("database_specific") or {}).get("cwe_ids") or []
        )
        for cwe in cwe_ids:
            db.setdefault(cwe, []).append(ref)

    return db


def match(db: CveDb, attack_type: str) -> list[str]:
    cwes = ATTACK_TYPE_TO_CWES.get(attack_type.lower(), [])
    seen: set[str] = set()
    result: list[str] = []
    for cwe in cwes:
        for ref in db.get(cwe, []):
            if ref not in seen:
                seen.add(ref)
                result.append(ref)
    return result
