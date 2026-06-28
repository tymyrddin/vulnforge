"""vulnforge CLI. Subcommands: bootstrap (the one network step), scan (run
the analysis pipeline), audit-verify (walk the audit log hash chain), plumbing
(end-to-end smoke test), and probe (one-shot hypothesise against a single file,
bypassing the staged pipeline)."""

from __future__ import annotations

import subprocess
from importlib.resources import files
from pathlib import Path

import click

import workspace


def _resolve_workspace(workspace_opt: Path | None) -> workspace.Workspace:
    ws = workspace.Workspace.at(workspace_opt) if workspace_opt is not None else workspace.new_run()
    workspace.use(ws)
    return ws


@click.group()
def main() -> None:
    """vulnforge: AI proposes, execution verifies."""


@main.command()
@click.option("--verify-only", is_flag=True, help="Skip downloads; check existing weights only.")
@click.option("--skip-image", is_flag=True, help="Skip podman build (weights only).")
def bootstrap(verify_only: bool, skip_image: bool) -> None:
    """Fetch weights, build the sandbox image. The only network-using step."""
    from bootstrap import build_sandbox, fetch_cve, fetch_models

    click.echo(f"weights:  {workspace.weights_dir()}")
    fetch_models.fetch_all(verify_only=verify_only)
    click.echo(f"cve:      {workspace.cve_dir()}")
    fetch_cve.fetch_all(verify_only=verify_only)
    if not verify_only and not skip_image:
        image_hash = build_sandbox.build()
        click.echo(f"sandbox image built: {image_hash}")


@main.command()
@click.argument("repo", type=click.Path(exists=True, file_okay=False, path_type=Path))
@click.option(
    "--workspace",
    "workspace_opt",
    type=click.Path(path_type=Path),
    default=None,
    help="Workspace directory (overrides default run dir).",
)
def scan(repo: Path, workspace_opt: Path | None) -> None:
    """Run the analysis pipeline against REPO."""
    from orchestrator import pipeline

    ws = _resolve_workspace(workspace_opt)
    click.echo(f"workspace: {ws.root}")
    pipeline.run(repo)
    click.echo(f"workspace: {ws.root}")


@main.command(name="audit-verify")
@click.option(
    "--workspace",
    "workspace_opt",
    type=click.Path(exists=True, path_type=Path),
    required=True,
    help="Workspace directory to verify.",
)
def audit_verify(workspace_opt: Path) -> None:
    """Walk the audit log and check every hash link."""
    from audit.log import verify_chain

    workspace.use(workspace.Workspace.at(workspace_opt))
    count = verify_chain()
    click.echo(f"{count} entries verified")


@main.command()
@click.option(
    "--alias",
    default="plumbing-check",
    show_default=True,
    help="models.lock alias to use for the smoke run.",
)
@click.option(
    "--prompt",
    default="Reply with the single word: PIPES",
    show_default=True,
    help="Prompt sent to the model.",
)
@click.option("--max-tokens", default=16, show_default=True, type=int)
@click.option(
    "--timeout", default=120, show_default=True, type=int, help="Sandbox timeout in seconds."
)
@click.option(
    "--workspace",
    "workspace_opt",
    type=click.Path(path_type=Path),
    default=None,
    help="Workspace directory (overrides default run dir).",
)
def plumbing(
    alias: str, prompt: str, max_tokens: int, timeout: int, workspace_opt: Path | None
) -> None:
    """End-to-end smoke test. Needs `vulnforge bootstrap` to have completed.

    Confirms: podman runs, the sandbox image is built, the named weights are
    present and hash-matched, and llama-cli produces output inside the sandbox.
    Useful for verifying the full pipework before any real analysis.
    """
    from bootstrap import build_sandbox, fetch_models
    from inference.runner import infer

    ws = _resolve_workspace(workspace_opt)
    click.echo(f"workspace: {ws.root}")

    try:
        version = subprocess.check_output(["podman", "--version"], text=True).strip()
    except FileNotFoundError as e:
        raise click.ClickException(f"podman not found on PATH: {e}") from e
    except subprocess.CalledProcessError as e:
        raise click.ClickException(f"podman --version failed: {e}") from e
    click.echo(f"podman:   {version}")

    try:
        image_hash = build_sandbox.current_hash()
    except FileNotFoundError as e:
        raise click.ClickException(
            "sandbox image not built; run `vulnforge bootstrap` first"
        ) from e
    click.echo(f"image:    {image_hash[:12]}")

    specs = {s.alias: s for s in fetch_models.load_specs()}
    if alias not in specs:
        raise click.ClickException(
            f"alias '{alias}' not found in bootstrap/models.lock; known aliases: {sorted(specs)}"
        )
    spec = specs[alias]
    if not spec.dest.exists():
        raise click.ClickException(f"weights missing: {spec.dest}; run `vulnforge bootstrap`")
    click.echo(f"weights:  {spec.alias} ({spec.dest})")

    click.echo("inference running inside sandbox...")
    click.echo(f"stderr log: {ws.logs_dir}/llama-*.log")
    result = infer(
        prompt=prompt,
        weights_path=spec.dest,
        weights_hash=spec.sha256,
        sandbox_image=image_hash,
        seed=1,
        max_tokens=max_tokens,
        timeout_seconds=timeout,
        log_dir=ws.logs_dir,
    )
    click.echo(f"output:   {result.output_text.strip()!r}")
    click.echo(
        f"hashes:   weights={result.weights_hash[:12]} "
        f"stdout={result.stdout_hash[:12]} stderr={result.stderr_hash[:12]}"
    )
    click.echo("plumbing ok")


PROMPT_PATH = files("inference") / "prompts" / "hypothesise.txt"


def _extract_first_json_object(text: str) -> str:
    """Return the first balanced ``{...}`` block in text, ignoring preamble.

    Aware of strings and escapes; suitable for stripping conversational chrome
    or echoed prompt rules around the model's JSON reply.
    """
    start = text.find("{")
    if start < 0:
        raise ValueError("no '{' in output")
    depth = 0
    in_string = False
    escape = False
    for i in range(start, len(text)):
        c = text[i]
        if escape:
            escape = False
            continue
        if c == "\\":
            escape = True
            continue
        if c == '"':
            in_string = not in_string
            continue
        if in_string:
            continue
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return text[start : i + 1]
    raise ValueError("unbalanced JSON object")


@main.command()
@click.argument("source", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option(
    "--alias", default="qwen3-8b", show_default=True, help="models.lock alias to use for inference."
)
@click.option("--seed", default=1, show_default=True, type=int)
@click.option("--max-tokens", default=1024, show_default=True, type=int)
@click.option(
    "--ctx-size",
    default=4096,
    show_default=True,
    type=int,
    help="llama.cpp context window. Probe budgets header + source + reply.",
)
@click.option(
    "--timeout", default=600, show_default=True, type=int, help="Sandbox timeout in seconds."
)
@click.option(
    "--workspace",
    "workspace_opt",
    type=click.Path(path_type=Path),
    default=None,
    help="Workspace directory (overrides default run dir).",
)
@click.option(
    "--debug-llama",
    is_flag=True,
    help="Stream llama.cpp's own load and timing logs to stderr "
    "instead of suppressing them (--log-disable -> --log-file).",
)
@click.option(
    "--function",
    "function_name",
    default=None,
    metavar="NAME",
    help="Extract a single named function using the pipeline slice format "
    "instead of sending the raw file. Keeps probe representative of "
    "the real pipeline context.",
)
def probe(
    source: Path,
    alias: str,
    seed: int,
    max_tokens: int,
    ctx_size: int,
    timeout: int,
    workspace_opt: Path | None,
    debug_llama: bool,
    function_name: str | None,
) -> None:
    """Run the hypothesise prompt against SOURCE (a single file).

    Bypasses the staged pipeline. By default, extracts every function via AST
    and runs one inference per function using the same slice format the pipeline
    uses. Use --function NAME to focus on a single function.

    Falls back to sending the raw file only when no Python functions are found.

    Run artefacts under the workspace root:
      probe-prompt.txt            single-function runs
      probe-<fn>-prompt.txt       multi-function runs (one set per function)
      probe-output.txt / probe-<fn>-output.txt
      probe-extracted.txt / probe-<fn>-extracted.txt
      probe-parsed.json / probe-<fn>-parsed.json
      probe-rejections.jsonl / probe-<fn>-rejections.jsonl (only if any)
      probe-screen.jsonl / probe-<fn>-screen.jsonl (grounding per hypothesis)
    """
    import ast
    import json

    from bootstrap import build_sandbox, fetch_models
    from inference.runner import infer
    from stages.hypothesise import _format_slice
    from stages.index import _index_file

    ws = _resolve_workspace(workspace_opt)
    click.echo(f"workspace: {ws.root}")

    try:
        image_hash = build_sandbox.current_hash()
    except FileNotFoundError as e:
        raise click.ClickException(
            "sandbox image not built; run `vulnforge bootstrap` first"
        ) from e

    specs = {s.alias: s for s in fetch_models.load_specs()}
    if alias not in specs:
        raise click.ClickException(
            f"alias '{alias}' not found in bootstrap/models.lock; known aliases: {sorted(specs)}"
        )
    spec = specs[alias]
    if not spec.dest.exists():
        raise click.ClickException(f"weights missing: {spec.dest}; run `vulnforge bootstrap`")

    prompt_template = PROMPT_PATH.read_text()
    source_text = source.read_text()

    # Build the list of (code_context, fn_label, artefact_prefix) entries to run.
    raw_fallback = False
    if function_name is not None:
        try:
            tree = ast.parse(source_text, filename=str(source))
        except SyntaxError as e:
            raise click.ClickException(f"failed to parse {source}: {e}") from e
        all_slices = _index_file(str(source), "", source_text, tree)
        matches = {k: v for k, v in all_slices.items() if v["function_name"] == function_name}
        if not matches:
            available = sorted(v["function_name"] for v in all_slices.values())
            raise click.ClickException(
                f"function {function_name!r} not found in {source}; "
                f"available: {', '.join(available) or '(none)'}"
            )
        _slice_id, slice_data = next(iter(matches.items()))
        to_probe = [
            (
                _format_slice(slice_data),
                f"{source}::{function_name}",
                "probe",
                slice_data.get("security_facts", []),
                slice_data.get("imports", []),
            )
        ]
    else:
        try:
            tree = ast.parse(source_text, filename=str(source))
            all_slices = _index_file(str(source), "", source_text, tree)
        except SyntaxError:
            all_slices = {}
        if all_slices:
            pairs = sorted(all_slices.items())
            if len(pairs) == 1:
                _sid, sd = pairs[0]
                to_probe = [
                    (
                        _format_slice(sd),
                        f"{source}::{sd['function_name']}",
                        "probe",
                        sd.get("security_facts", []),
                        sd.get("imports", []),
                    )
                ]
            else:
                to_probe = [
                    (
                        _format_slice(sd),
                        f"{source}::{sd['function_name']}",
                        f"probe-{sd['function_name']}",
                        sd.get("security_facts", []),
                        sd.get("imports", []),
                    )
                    for _sid, sd in pairs
                ]
        else:
            raw_fallback = True
            to_probe = [(source_text, str(source), "probe", [], [])]

    ws.root.mkdir(parents=True, exist_ok=True)
    multi = len(to_probe) > 1

    if multi:
        click.echo(f"source:   {source} ({len(to_probe)} functions)")
    click.echo(f"weights:  {spec.alias}")
    click.echo(f"image:    {image_hash[:12]}")
    click.echo(f"stderr:   {ws.logs_dir}/llama-*.log")

    total_accepted = 0
    total_rejected_count = 0
    total_screen_kept = 0

    for code_context, fn_label, artefact_prefix, facts, imports in to_probe:
        prompt = (
            f"{prompt_template}{code_context}"
            if raw_fallback
            else f"{prompt_template}\n\n{code_context}"
        )
        prompt_path = ws.root / f"{artefact_prefix}-prompt.txt"
        prompt_path.write_text(prompt)

        if multi:
            click.echo(f"\nfunction: {fn_label.split('::')[-1]} ({len(code_context)} chars)")
        else:
            click.echo(f"source:   {fn_label} ({len(code_context)} chars)")
        click.echo(f"prompt:   {prompt_path}")
        click.echo("inference running inside sandbox...")

        result = infer(
            prompt=prompt,
            weights_path=spec.dest,
            weights_hash=spec.sha256,
            sandbox_image=image_hash,
            seed=seed,
            max_tokens=max_tokens,
            ctx_size=ctx_size,
            timeout_seconds=timeout,
            log_dir=ws.logs_dir,
            debug_llama=debug_llama,
            no_think=spec.no_think,
        )

        raw_path = ws.root / f"{artefact_prefix}-output.txt"
        raw_path.write_text(result.output_text)

        click.echo()
        click.echo(f"=== {fn_label} ({len(result.output_text)} chars, saved to {raw_path}) ===")
        click.echo(result.output_text)
        click.echo()

        try:
            json_blob = _extract_first_json_object(result.output_text)
        except ValueError as e:
            if multi:
                click.echo(f"no JSON object in output: {e}")
                continue
            raise click.ClickException(f"no JSON object in output: {e}") from e

        extracted_path = ws.root / f"{artefact_prefix}-extracted.txt"
        extracted_path.write_text(json_blob)
        if not multi:
            click.echo(f"extract:  {extracted_path}")

        try:
            data = json.loads(json_blob)
        except json.JSONDecodeError as e:
            if multi:
                click.echo(f"extracted blob is not valid JSON: {e}")
                continue
            raise click.ClickException(f"extracted blob is not valid JSON: {e}") from e

        parsed_path = ws.root / f"{artefact_prefix}-parsed.json"
        parsed_path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")
        if not multi:
            click.echo(f"parsed:   {parsed_path}")

        if not isinstance(data, dict) or "hypotheses" not in data:
            if multi:
                click.echo("output JSON has no 'hypotheses' key")
                continue
            raise click.ClickException("output JSON has no 'hypotheses' key")
        if not isinstance(data["hypotheses"], list):
            if multi:
                click.echo("'hypotheses' is not a list")
                continue
            raise click.ClickException("'hypotheses' is not a list")

        click.echo("=== parsed hypotheses ===")
        # The same grounding gate the scan pipeline applies, run here so the probe
        # shows whether a schema-valid hypothesis is actually grounded in the slice's
        # facts. Code decides; this is not the model judging itself.
        outcomes, accepted, screen_kept = _screen_probe_hypotheses(
            data["hypotheses"], facts, imports, result.weights_hash
        )
        rejections = [
            {"index": o["index"], "raw": o["raw"], "rejection": o["rejection"]}
            for o in outcomes
            if o["kind"] == "rejected"
        ]
        screen_records = [
            {k: v for k, v in o.items() if k not in ("kind", "raw")}
            for o in outcomes
            if o["kind"] == "screened"
        ]
        for o in outcomes:
            if o["kind"] == "rejected":
                click.echo(f"  [{o['index']}] rejected {o['rejection']}")
            else:
                click.echo(
                    f"  [{o['index']}] ok       {o['attack_type']} @ {o['location']} "
                    f"(conf={o['model_confidence']:.2f}, {o['evidence_type']})"
                )
                click.echo(
                    f"         screen {'keep' if o['kept'] else 'drop'}: {o['grounding']} "
                    f"[{o['screen_reason']}] eff_conf={o['effective_confidence']}"
                )

        if rejections:
            rejections_path = ws.root / f"{artefact_prefix}-rejections.jsonl"
            with rejections_path.open("w") as f:
                for r in rejections:
                    f.write(json.dumps(r, sort_keys=True) + "\n")
            if not multi:
                click.echo(f"rejected: {rejections_path}")

        if screen_records:
            screen_path = ws.root / f"{artefact_prefix}-screen.jsonl"
            with screen_path.open("w") as f:
                for r in screen_records:
                    f.write(json.dumps(r, sort_keys=True) + "\n")
            if not multi:
                click.echo(f"screen:   {screen_path}")

        total_accepted += accepted
        total_rejected_count += len(rejections)
        total_screen_kept += screen_kept
        if multi:
            click.echo(
                f"  {accepted} schema-accepted, {len(rejections)} schema-rejected; "
                f"screen kept {screen_kept}, dropped {accepted - screen_kept}"
            )

    click.echo()
    total_dropped = total_accepted - total_screen_kept
    if multi:
        click.echo(
            f"total:    {total_accepted} schema-accepted, {total_rejected_count} schema-rejected "
            f"across {len(to_probe)} functions; "
            f"screen kept {total_screen_kept}, dropped {total_dropped}"
        )
    else:
        click.echo(
            f"summary:  {total_accepted} schema-accepted, {total_rejected_count} schema-rejected; "
            f"screen kept {total_screen_kept}, dropped {total_dropped}"
        )


def _screen_probe_hypotheses(
    hypotheses: list, facts: list, imports: list, model_hash: str
) -> tuple[list[dict], int, int]:
    """Schema-validate then taint-ground each raw model hypothesis dict.

    Pure: no model, no sandbox, no IO. Returns (outcomes, accepted, screen_kept).
    Each outcome is either {"kind": "rejected", index, raw, rejection} when the
    schema gate refuses the hypothesis, or {"kind": "screened", index, attack_type,
    location, evidence_type, model_confidence, grounding, screen_reason,
    effective_confidence, kept} when it passes the schema gate and the grounding gate
    runs. The two gates layer: schema validity first, grounding second.
    """
    from schema.hypothesis import EvidenceType, Hypothesis, VerificationStatus
    from schema.screen import decide_policy
    from stages.screen import _grounding

    outcomes: list[dict] = []
    accepted = 0
    screen_kept = 0
    for i, item in enumerate(hypotheses):
        try:
            h = Hypothesis.propose(
                attack_type=item["attack_type"],
                location=item["location"],
                assumption_broken=item["assumption_broken"],
                expected_effect=item["expected_effect"],
                suggested_inputs=item.get("suggested_inputs", []),
                confidence=float(item["confidence"]),
                model_hash=model_hash,
                evidence_type=EvidenceType(item.get("evidence_type", "static_pattern")),
                verification_status=VerificationStatus(
                    item.get("verification_status", "unverified")
                ),
            )
        except (KeyError, TypeError, ValueError) as e:
            outcomes.append(
                {
                    "kind": "rejected",
                    "index": i,
                    "raw": item,
                    "rejection": f"{type(e).__name__}: {e}",
                }
            )
            continue

        accepted += 1
        grounding, screen_reason = _grounding(item, facts, imports)
        kept, eff_conf = decide_policy(grounding, h.confidence)
        screen_kept += 1 if kept else 0
        outcomes.append(
            {
                "kind": "screened",
                "index": i,
                "attack_type": h.attack_type,
                "location": h.location,
                "evidence_type": h.evidence_type.value,
                "model_confidence": h.confidence,
                "grounding": grounding.value,
                "screen_reason": screen_reason.value,
                "effective_confidence": eff_conf,
                "kept": kept,
            }
        )
    return outcomes, accepted, screen_kept


if __name__ == "__main__":
    main()
