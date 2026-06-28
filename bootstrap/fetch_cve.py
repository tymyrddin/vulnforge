"""Download the offline CVE database used by the verify stage.

Source: db.gcve.eu (CIRCL, Luxembourg), the European Global CVE database. Its
bulk dumps are served at https://vulnerability.circl.lu/dumps/; vulnforge pulls
`pysec.ndjson`, the PyPA Python advisory database in OSV format, EU-hosted. This
is deliberate: no dependency on a Big Tech mirror for the CVE bootstrap.

The file is newline-delimited JSON, one OSV record per line. We split it into
one `<id>.json` per record so the loader (`cve/index.py`) reads it unchanged.

Workflow:
  1. Run `vulnforge bootstrap` once (the only network step).
  2. The analysis host can then run fully offline.

Data lands at $XDG_DATA_HOME/vulnforge/cve/osv-pypi/ (outside the repo,
alongside weights/ per the workspace separation policy).
"""

from __future__ import annotations

import json
import urllib.request

from workspace import cve_dir

_PYSEC_URL = "https://vulnerability.circl.lu/dumps/pysec.ndjson"


def fetch_all(verify_only: bool = False) -> None:
    dest_dir = cve_dir() / "osv-pypi"
    existing = list(dest_dir.glob("*.json")) if dest_dir.exists() else []

    if existing:
        print(f"ok    cve/osv-pypi ({len(existing)} entries already present)")
        # Re-download only on explicit refresh (future: add --refresh flag).
        return

    if verify_only:
        raise FileNotFoundError(
            f"CVE data missing at {dest_dir}; run `vulnforge bootstrap` to fetch"
        )

    print(f"fetch cve/osv-pypi from {_PYSEC_URL}")
    dest_dir.mkdir(parents=True, exist_ok=True)

    with urllib.request.urlopen(_PYSEC_URL) as resp:
        raw = resp.read()

    count = 0
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        rec_id = record.get("id")
        if not isinstance(rec_id, str) or not rec_id:
            continue
        (dest_dir / f"{rec_id}.json").write_bytes(line)
        count += 1

    print(f"ok    cve/osv-pypi ({count} entries)")
