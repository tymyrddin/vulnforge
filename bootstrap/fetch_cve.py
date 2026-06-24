"""Download the offline CVE database used by the verify stage.

Primary source: OSV.dev PyPI ecosystem dump (well-documented bulk download,
OSV format, EU mirror available). db.gcve.eu (CIRCL Luxembourg) is the
intended long-term primary; it uses the same OSV format and replaces the URL
below once a confirmed bulk-download endpoint is published.

Workflow:
  1. Run `vulnforge bootstrap` once (the only network step).
  2. The analysis host can then run fully offline.

Data lands at $XDG_DATA_HOME/vulnforge/cve/osv-pypi/ (outside the repo,
alongside weights/ per the workspace separation policy).
"""
from __future__ import annotations

import io
import urllib.request
import zipfile
from pathlib import Path

from workspace import cve_dir

_OSV_PYPI_URL = "https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip"


def fetch_all(verify_only: bool = False) -> None:
    dest_dir = cve_dir() / "osv-pypi"
    existing = list(dest_dir.glob("*.json")) if dest_dir.exists() else []

    if existing:
        print(f"ok    cve/osv-pypi ({len(existing)} entries already present)")
        if verify_only:
            return
        # Re-download only on explicit refresh (future: add --refresh flag).
        return

    if verify_only:
        raise FileNotFoundError(
            f"CVE data missing at {dest_dir}; run `vulnforge bootstrap` to fetch"
        )

    print(f"fetch cve/osv-pypi from {_OSV_PYPI_URL}")
    dest_dir.mkdir(parents=True, exist_ok=True)

    with urllib.request.urlopen(_OSV_PYPI_URL) as resp:
        data = resp.read()

    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        json_members = [m for m in zf.namelist() if m.endswith(".json")]
        for member in json_members:
            target: Path = dest_dir / Path(member).name
            target.write_bytes(zf.read(member))

    print(f"ok    cve/osv-pypi ({len(json_members)} entries)")
