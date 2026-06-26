# CVE correlation

The last step inside `stages/verify.py`. It labels confirmed findings; it does not change whether a
verdict is CONFIRMED or REFUTED.

## How it works

1. `cve/cwe_map.py`: a static dict mapping `attack_type` strings to CWE IDs (for example,
   `"code_execution"` maps to `["CWE-78", "CWE-94", "CWE-95"]`).
2. `cve/index.py`: `load()` walks `$XDG_DATA_HOME/vulnforge/cve/osv-pypi/` and builds a
   `CWE → [CVE/GHSA IDs]` index. It returns `None` when the directory is absent, so `cve_refs`
   defaults to `[]`.
3. `cve/index.py`: `match(db, attack_type)` returns CVE IDs for the matching CWEs.
4. `verify.run()` calls `load()` once before the verdict loop, then attaches `cve_refs` to each
   verdict dict.

## Verify integration

`cve_refs: list[str]` is attached to every verdict, populated for CONFIRMED findings where the
attack_type maps to a CWE that has entries in the offline DB. The labels ride along with the verdict;
they do not enter the decision. The report renders a CVEs line for confirmed findings where
`cve_refs` is non-empty. [pipeline.md](pipeline.md) covers the verify decision rule.

## Data source

db.gcve.eu (CIRCL, Luxembourg), the European Global CVE database. Its bulk dumps are served at
`https://vulnerability.circl.lu/dumps/`; `bootstrap/fetch_cve.py` pulls `pysec.ndjson`, the PyPA
Python advisory database in OSV format. The file is newline-delimited JSON, one OSV record per line,
split into one `<id>.json` per record under `$XDG_DATA_HOME/vulnforge/cve/osv-pypi/` so the loader
reads it unchanged.

The source is European on purpose: the CVE bootstrap takes no dependency on a Big Tech mirror. Because
`pysec` is the PyPA advisory set rather than the broader OSV.dev aggregation, CWE coverage is narrower,
so some confirmed findings may carry no `cve_refs`. The match degrades to an empty list, never an
error.

A model fallback (the plumbing-check alias) for ambiguous matches is not built. Recorded in
[../roadmap/README.md](../roadmap/README.md).
