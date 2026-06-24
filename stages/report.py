"""Report stage: emit human-readable findings from a verdicts ref. Output is a
plain file under ``<workspace>/reports/``; the audit log retains the canonical
provenance."""
from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from audit.log import append as audit_append
from schema.audit_event import AuditEvent
from store import objects, refs
from workspace import active as active_workspace


def run(verdicts_ref: str) -> Path:
    verdicts_manifest: dict[str, str] = json.loads(objects.get(verdicts_ref))

    try:
        tested_hyp_manifest: dict[str, str] = json.loads(
            objects.get(refs.read("tested_hypotheses_latest"))
        )
    except Exception:
        tested_hyp_manifest = {}

    confirmed: list[tuple[dict[str, Any], dict[str, Any]]] = []
    refuted: list[tuple[dict[str, Any], dict[str, Any]]] = []
    skipped = 0

    for hyp_id, verdict_ref in sorted(verdicts_manifest.items()):
        try:
            verdict: dict[str, Any] = json.loads(objects.get(verdict_ref))
        except Exception:
            skipped += 1
            continue

        hyp_ref = tested_hyp_manifest.get(hyp_id)
        if not hyp_ref:
            skipped += 1
            continue

        try:
            hyp: dict[str, Any] = json.loads(objects.get(hyp_ref))
        except Exception:
            skipped += 1
            continue

        if verdict.get("verdict") == "CONFIRMED":
            confirmed.append((verdict, hyp))
        else:
            refuted.append((verdict, hyp))

    now = datetime.now(timezone.utc)
    timestamp = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    report_content = _render(timestamp, confirmed, refuted, skipped)

    reports_dir = active_workspace().reports_dir
    reports_dir.mkdir(parents=True, exist_ok=True)
    report_path = reports_dir / f"report_{now.strftime('%Y%m%dT%H%M%SZ')}.md"
    report_path.write_text(report_content, encoding="utf-8")

    audit_append(AuditEvent(
        timestamp=time.time(),
        stage="report",
        input_refs=(verdicts_ref,),
        output_refs=(str(report_path),),
        model_hash=None,
        seed=None,
        summary=f"{len(confirmed)} confirmed, {len(refuted)} refuted, {skipped} skipped",
    ))
    return report_path


def _render(
    timestamp: str,
    confirmed: list[tuple[dict[str, Any], dict[str, Any]]],
    refuted: list[tuple[dict[str, Any], dict[str, Any]]],
    skipped: int,
) -> str:
    lines: list[str] = [
        "# Vulnerability Report",
        f"Generated: {timestamp}",
        f"Summary: {len(confirmed)} confirmed, {len(refuted)} refuted, {skipped} skipped",
        "",
    ]

    lines.append("## Confirmed Findings")
    lines.append("")
    if confirmed:
        for verdict, hyp in confirmed:
            lines.append(f"### {hyp.get('location', 'unknown')} - {hyp.get('attack_type', 'unknown')}")
            lines.append(f"- Assumption broken: {hyp.get('assumption_broken', '')}")
            lines.append(f"- Expected effect: {hyp.get('expected_effect', '')}")
            lines.append(f"- Evidence: {verdict.get('evidence', '')}")
            cve_refs = verdict.get("cve_refs", [])
            if cve_refs:
                lines.append(f"- CVEs: {', '.join(cve_refs)}")
            lines.append(f"- Observation: {verdict.get('observation_ref', '')}")
            lines.append(f"- Provenance: {hyp.get('provenance', '')}")
            lines.append("")
    else:
        lines.append("No confirmed findings.")
        lines.append("")

    if refuted:
        lines.append("## Refuted Hypotheses")
        lines.append("")
        for verdict, hyp in refuted:
            lines.append(f"### {hyp.get('location', 'unknown')} - {hyp.get('attack_type', 'unknown')}")
            lines.append(f"- Reason: {verdict.get('evidence', '')}")
            lines.append(f"- Provenance: {hyp.get('provenance', '')}")
            lines.append("")

    return "\n".join(lines)