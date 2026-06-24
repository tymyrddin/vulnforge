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

    screen_verdicts = _load_screen_verdicts()

    confirmed: list[tuple[str, dict[str, Any], dict[str, Any]]] = []
    refuted: list[tuple[str, dict[str, Any], dict[str, Any]]] = []
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
            confirmed.append((hyp_id, verdict, hyp))
        else:
            refuted.append((hyp_id, verdict, hyp))

    now = datetime.now(timezone.utc)
    timestamp = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    report_content = _render(timestamp, confirmed, refuted, skipped, screen_verdicts)

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


def _load_screen_verdicts() -> dict[str, dict[str, Any]]:
    """Map hypothesis_id -> screen verdict dict. Empty when no screen stage ran."""
    try:
        manifest: dict[str, str] = json.loads(objects.get(refs.read("screen_verdicts_latest")))
    except Exception:
        return {}
    out: dict[str, dict[str, Any]] = {}
    for hyp_id, ref in manifest.items():
        try:
            out[hyp_id] = json.loads(objects.get(ref))
        except Exception:
            continue
    return out


def _render(
    timestamp: str,
    confirmed: list[tuple[str, dict[str, Any], dict[str, Any]]],
    refuted: list[tuple[str, dict[str, Any], dict[str, Any]]],
    skipped: int,
    screen_verdicts: dict[str, dict[str, Any]],
) -> str:
    lines: list[str] = [
        "# Vulnerability Report",
        f"Generated: {timestamp}",
        f"Summary: {len(confirmed)} confirmed, {len(refuted)} refuted, {skipped} skipped",
        "",
    ]

    if screen_verdicts:
        counts: dict[str, int] = {}
        for v in screen_verdicts.values():
            counts[v.get("grounding", "?")] = counts.get(v.get("grounding", "?"), 0) + 1
        rejected = counts.get("contradicted", 0) + counts.get("unsupported", 0)
        lines.append("## Screening")
        lines.append("")
        lines.append(
            f"Of {len(screen_verdicts)} hypotheses, the screen grounded "
            f"{counts.get('grounded', 0)}, marked {counts.get('unknown', 0)} unknown "
            f"(provenance unresolved, accepted at a capped prior), and rejected "
            f"{rejected} before execution ({counts.get('contradicted', 0)} contradicted "
            f"by the facts, {counts.get('unsupported', 0)} with no matching sink)."
        )
        lines.append("")

    lines.append("## Confirmed Findings")
    lines.append("")
    if confirmed:
        for hyp_id, verdict, hyp in confirmed:
            lines.append(f"### {hyp.get('location', 'unknown')} - {hyp.get('attack_type', 'unknown')}")
            lines.append(f"- Assumption broken: {hyp.get('assumption_broken', '')}")
            lines.append(f"- Expected effect: {hyp.get('expected_effect', '')}")
            lines.append(f"- Evidence: {verdict.get('evidence', '')}")
            _append_grounding(lines, screen_verdicts.get(hyp_id))
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
        for hyp_id, verdict, hyp in refuted:
            lines.append(f"### {hyp.get('location', 'unknown')} - {hyp.get('attack_type', 'unknown')}")
            lines.append(f"- Reason: {verdict.get('evidence', '')}")
            _append_grounding(lines, screen_verdicts.get(hyp_id))
            lines.append(f"- Provenance: {hyp.get('provenance', '')}")
            lines.append("")

    return "\n".join(lines)


def _append_grounding(lines: list[str], sv: dict[str, Any] | None) -> None:
    if not sv:
        return
    lines.append(
        f"- Grounding: {sv.get('grounding', '?')} ({sv.get('screen_reason', '?')}), "
        f"effective confidence {sv.get('effective_confidence', '?')}"
    )