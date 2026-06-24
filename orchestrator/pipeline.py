"""Pipeline runner.

Reads configs/pipeline.yaml and runs stages in order. Each stage knows how to
read its inputs from the store (by ref) and write its outputs back (also by
ref). The orchestrator's only job is sequencing.

Refs that are needed by more than one downstream stage (ingest_ref, hypotheses_ref)
are retained explicitly rather than assuming a purely linear chain.
"""
from __future__ import annotations

from pathlib import Path

import yaml

from stages import execute, hypothesise, index, ingest, report, screen, synthesise, verify

CONFIG_PATH = Path("configs/pipeline.yaml")


def run(repo_path: Path, config_path: Path = CONFIG_PATH) -> None:
    config = yaml.safe_load(config_path.read_text())
    stages_cfg = {s["name"]: s for s in config.get("stages", [])}

    ingest_ref: str | None = None
    slices_ref: str | None = None
    hypotheses_ref: str | None = None
    accepted_ref: str | None = None
    screen_verdicts_ref: str | None = None
    payloads_ref: str | None = None
    observations_ref: str | None = None
    verdicts_ref: str | None = None

    for stage in config.get("stages", []):
        name = stage["name"]

        if name == "ingest":
            ingest_ref = ingest.run(repo_path)
            print(f"ingest       -> {ingest_ref[:12]}")

        elif name == "index":
            assert ingest_ref, "ingest must run before index"
            slices_ref = index.run(ingest_ref)
            print(f"index        -> {slices_ref[:12]}")

        elif name == "hypothesise":
            assert slices_ref, "index must run before hypothesise"
            hypotheses_ref = hypothesise.run(
                slices_ref,
                model_alias=stage["model"],
                seed=stage.get("seed", 1),
                max_tokens=stage.get("max_tokens", 512),
            )
            print(f"hypothesise  -> {hypotheses_ref[:12]}")

        elif name == "screen":
            assert hypotheses_ref, "hypothesise must run before screen"
            assert slices_ref, "index must run before screen"
            accepted_ref, screen_verdicts_ref = screen.run(hypotheses_ref, slices_ref)
            print(f"screen       -> {accepted_ref[:12]} / {screen_verdicts_ref[:12]}")

        elif name == "synthesise":
            # The screen, when present, narrows the hypothesis set fed to synthesise;
            # without it, synthesise runs on the full hypothesise output.
            synth_input = accepted_ref or hypotheses_ref
            assert synth_input, "hypothesise must run before synthesise"
            payloads_ref = synthesise.run(
                synth_input,
                model_alias=stage["model"],
                seed=stage.get("seed", 2),
                max_tokens=stage.get("max_tokens", 256),
            )
            print(f"synthesise   -> {payloads_ref[:12]}")

        elif name == "execute":
            assert payloads_ref, "synthesise must run before execute"
            assert ingest_ref, "ingest must run before execute"
            observations_ref = execute.run(
                payloads_ref,
                ingest_ref,
                timeout_seconds=stage.get("timeout_seconds", 60),
            )
            print(f"execute      -> {observations_ref[:12]}")

        elif name == "verify":
            assert observations_ref, "execute must run before verify"
            assert hypotheses_ref, "hypothesise must run before verify"
            verdicts_ref = verify.run(observations_ref, hypotheses_ref)
            print(f"verify       -> {verdicts_ref[:12]}")

        elif name == "report":
            assert verdicts_ref, "verify must run before report"
            report_path = report.run(verdicts_ref)
            print(f"report       -> {report_path}")

        else:
            raise NotImplementedError(f"unknown stage: {name!r}")
