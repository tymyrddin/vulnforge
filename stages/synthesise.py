"""Synthesise stage: turn hypotheses into concrete payloads, request sequences,
and fuzz seeds. The model may suggest seeds; it does not decide whether a
payload worked."""
from __future__ import annotations


def run(hypotheses_ref: str, *, model_alias: str, seed: int) -> str:
    raise NotImplementedError("synthesise stage: implementation pending")
