"""Screen stage: ground each hypothesis against the slice's security facts before
any payload is synthesised or executed.

This is the deterministic answer to static-pattern enthusiasm. The hypothesise model
proposes attack classes by recall; this stage checks, in code, whether the slice
actually grounds the proposed class: does a parameter reach a sink of the right kind,
is the proposed mechanism contradicted by the facts, or is there no such sink at all.

The grounding is computed here from the security facts attached at index time. The
policy that turns a grounding state into accept/reject and a confidence cap lives in
schema/screen.py, kept separate so neither absorbs the other's authority. Truth about
whether an accepted hypothesis actually works is still decided downstream by execution;
this stage only decides whether it is worth carrying forward, and at what prior.

A hypothesis is mapped back to its slice by id: hypothesise keys each hypothesis
``<slice_id>::<idx>``, so the slice id is the hypothesis id with its last segment
stripped.
"""
from __future__ import annotations

import dataclasses
import json
import time
from typing import Any

from audit.log import append as audit_append
from schema.audit_event import AuditEvent
from schema.screen import (
    Grounding,
    ScreenReason,
    ScreenVerdict,
    decide_policy,
)
from store import objects, refs

# Attack-class synonyms, normalised to lower_snake_case (spaces -> underscores).
_COMMAND = frozenset({
    "command_injection", "os_command_injection", "shell_injection",
    "argument_injection", "command_execution",
})
_CODE = frozenset({
    "code_execution", "code_injection", "arbitrary_code_execution",
    "remote_code_execution", "rce",
})
_DESERIALIZATION = frozenset({
    "deserialization", "insecure_deserialization", "unsafe_deserialization",
    "pickle_injection",
})
_PATH = frozenset({
    "path_traversal", "directory_traversal", "arbitrary_file_read",
    "arbitrary_file_write", "file_read", "file_write",
    "arbitrary_file_access", "file_disclosure",
})
_SQL = frozenset({"sql_injection", "sqli", "sql"})

_CODE_SINK_NAMES = frozenset({"eval", "exec", "compile"})
_DESERIALIZATION_SINK_NAMES = frozenset({
    "pickle.loads", "pickle.load", "yaml.load", "marshal.loads", "marshal.load",
})
_OS_SHELL_SINK_NAMES = frozenset({"os.system", "os.popen"})

# Substrings that hint a slice imports a database or SQL library. Deliberately a weak
# signal: a hit only lifts a SQL hypothesis to UNKNOWN, never to grounded.
_DB_IMPORT_HINTS = (
    "sqlite3", "sqlalchemy", "psycopg", "pymysql", "mysql", "asyncpg",
    "aiosqlite", "sqlmodel", "peewee", "pyodbc", "cx_oracle", "mariadb",
    "django.db", "sql",
)

# Characters whose effect depends on a shell interpreting the command line.
_SHELL_METACHARS = ";&|`$<>\n"


def run(hypotheses_ref: str, slices_ref: str) -> tuple[str, str]:
    hyp_manifest: dict[str, str] = json.loads(objects.get(hypotheses_ref))
    slice_manifest: dict[str, str] = json.loads(objects.get(slices_ref))

    accepted: dict[str, str] = {}
    verdicts: dict[str, str] = {}
    counts = {g: 0 for g in Grounding}

    for hyp_id, hyp_ref in sorted(hyp_manifest.items()):
        hyp: dict[str, Any] = json.loads(objects.get(hyp_ref))
        facts, imports = _slice_context(hyp_id, slice_manifest)

        grounding, reason = _grounding(hyp, facts, imports)
        is_accepted, effective_confidence = decide_policy(
            grounding, float(hyp.get("confidence", 0.5))
        )

        verdict = ScreenVerdict(
            hypothesis_id=hyp_id,
            grounding=grounding,
            screen_reason=reason,
            effective_confidence=effective_confidence,
        )
        blob = json.dumps(_verdict_dict(verdict), sort_keys=True, separators=(",", ":")).encode()
        verdicts[hyp_id] = objects.put(blob)
        counts[grounding] += 1
        if is_accepted:
            accepted[hyp_id] = hyp_ref

    accepted_ref = objects.put(
        json.dumps(accepted, sort_keys=True, separators=(",", ":")).encode()
    )
    verdicts_ref = objects.put(
        json.dumps(verdicts, sort_keys=True, separators=(",", ":")).encode()
    )
    refs.write("screen_accepted_latest", accepted_ref)
    refs.write("screen_verdicts_latest", verdicts_ref)
    audit_append(AuditEvent(
        timestamp=time.time(),
        stage="screen",
        input_refs=(hypotheses_ref, slices_ref),
        output_refs=(accepted_ref, verdicts_ref),
        model_hash=None,
        seed=None,
        summary=(
            f"{len(accepted)}/{len(hyp_manifest)} accepted "
            f"(grounded={counts[Grounding.GROUNDED]}, unknown={counts[Grounding.UNKNOWN]}, "
            f"contradicted={counts[Grounding.CONTRADICTED]}, unsupported={counts[Grounding.UNSUPPORTED]})"
        ),
    ))
    return accepted_ref, verdicts_ref


def _verdict_dict(v: ScreenVerdict) -> dict[str, Any]:
    d = dataclasses.asdict(v)
    d["grounding"] = v.grounding.value
    d["screen_reason"] = v.screen_reason.value
    return d


def _slice_context(
    hyp_id: str, slice_manifest: dict[str, str]
) -> tuple[list[dict[str, Any]], list[str]]:
    slice_id = hyp_id.rsplit("::", 1)[0]
    slice_ref = slice_manifest.get(slice_id)
    if not slice_ref:
        return [], []
    slice_data: dict[str, Any] = json.loads(objects.get(slice_ref))
    return slice_data.get("security_facts", []), slice_data.get("imports", [])


def _grounding(
    hyp: dict[str, Any], facts: list[dict[str, Any]], imports: list[str]
) -> tuple[Grounding, ScreenReason]:
    klass = str(hyp.get("attack_type", "")).lower().replace(" ", "_").replace("-", "_")
    inputs = [str(x) for x in (hyp.get("suggested_inputs") or [])]
    has_metachars = _relies_on_shell_metacharacters(inputs)

    if klass in _SQL:
        # No SQL sink detector exists. Imports are a weak signal: their absence is
        # treated as no surface, their presence as surface we cannot resolve, never as
        # grounded.
        if _imports_db(imports):
            return Grounding.UNKNOWN, ScreenReason.INSUFFICIENT_SQL_EVIDENCE
        return Grounding.UNSUPPORTED, ScreenReason.NO_MATCHING_SINK

    matching = _matching_sinks(klass, facts)
    if matching is None:
        # Unrecognised attack class: no detector to prove the sink absent. With any
        # sink present, keep the hypothesis at a penalty rather than collapse recall;
        # with no sink of any kind, there is no parameter-to-sink surface to exploit.
        if facts:
            return Grounding.UNKNOWN, ScreenReason.ATTACK_TYPE_UNRECOGNISED
        return Grounding.UNSUPPORTED, ScreenReason.NO_MATCHING_SINK

    if not matching:
        return Grounding.UNSUPPORTED, ScreenReason.NO_MATCHING_SINK

    graded = [_grade_sink(klass, fact, has_metachars) for fact in matching]
    return _resolve(graded)


def _matching_sinks(
    klass: str, facts: list[dict[str, Any]]
) -> list[dict[str, Any]] | None:
    """Facts that count as a sink for this attack class. None means the class is
    unrecognised (no detector), distinct from [] meaning recognised but no such sink."""
    if klass in _COMMAND:
        return [
            f for f in facts
            if f.get("type") == "subprocess"
            or (f.get("type") == "dangerous_sink"
                and (f.get("name") in _OS_SHELL_SINK_NAMES or "shell=True" in str(f.get("name", ""))))
        ]
    if klass in _CODE:
        return [
            f for f in facts
            if f.get("type") == "dangerous_sink" and f.get("name") in _CODE_SINK_NAMES
        ]
    if klass in _DESERIALIZATION:
        return [
            f for f in facts
            if f.get("type") == "dangerous_sink" and f.get("name") in _DESERIALIZATION_SINK_NAMES
        ]
    if klass in _PATH:
        return [f for f in facts if f.get("type") in ("file_read", "file_write")]
    return None


def _grade_sink(
    klass: str, fact: dict[str, Any], has_metachars: bool
) -> tuple[Grounding, ScreenReason]:
    source = fact.get("arg_source", fact.get("path_source", "unknown"))

    if klass in _COMMAND and fact.get("type") == "subprocess":
        shell = fact.get("shell")
        # Under shell=False, a payload that relies on shell metacharacters cannot work:
        # there is no shell to interpret them. That is a contradiction of the proposed
        # mechanism, regardless of whether a parameter reaches the call.
        if shell in (False, "default_false") and has_metachars:
            return Grounding.CONTRADICTED, ScreenReason.SHELL_METACHARS_UNDER_SHELL_FALSE

    return _grade_by_source(source)


def _grade_by_source(source: str) -> tuple[Grounding, ScreenReason]:
    if source.startswith("parameter:") or source == "parameter-derived":
        return Grounding.GROUNDED, ScreenReason.PARAM_REACHES_SINK
    if source == "constant":
        return Grounding.CONTRADICTED, ScreenReason.CONSTANT_SINK_ARG
    return Grounding.UNKNOWN, ScreenReason.SINK_SOURCE_UNRESOLVED


def _resolve(
    graded: list[tuple[Grounding, ScreenReason]]
) -> tuple[Grounding, ScreenReason]:
    """Strongest claim across matching sinks: grounded > unknown > contradicted >
    unsupported. One parameter-reachable sink grounds the hypothesis; an analysis
    limit on one sink never masquerades as proof across the others."""
    for target in (Grounding.GROUNDED, Grounding.UNKNOWN, Grounding.CONTRADICTED):
        for grounding, reason in graded:
            if grounding is target:
                return grounding, reason
    return Grounding.UNSUPPORTED, ScreenReason.NO_MATCHING_SINK


def _relies_on_shell_metacharacters(inputs: list[str]) -> bool:
    return any(any(c in s for c in _SHELL_METACHARS) for s in inputs)


def _imports_db(imports: list[str]) -> bool:
    blob = " ".join(imports).lower()
    return any(hint in blob for hint in _DB_IMPORT_HINTS)
