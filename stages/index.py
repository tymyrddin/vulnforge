"""Index stage: parse ingested files into ASTs, extract symbols and call graph,
produce per-function attack-relevant slices.

Input: manifest ref produced by `ingest`.
Output: slices ref (a manifest of slice blobs).
"""
from __future__ import annotations


def run(manifest_ref: str) -> str:
    raise NotImplementedError("index stage: implementation pending")
