"""Hypothesise stage: for each slice, ask the local model to propose
attack-relevant hypotheses. Output is validated against the Hypothesis schema;
free-form prose or anything containing the word "vulnerable" is rejected.

Inference runs inside the canonical sandbox. The model can only ever produce
Status.PROPOSED; verdict transitions live in `verify.py`.
"""
from __future__ import annotations


def run(slices_ref: str, *, model_alias: str, seed: int) -> str:
    raise NotImplementedError("hypothesise stage: implementation pending")
