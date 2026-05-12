"""vulnforge CLI. Subcommands: bootstrap (the one network step), scan (run
the analysis pipeline), audit-verify (walk the audit log hash chain), plumbing
(end-to-end smoke test), and probe (one-shot hypothesise against a single
file, bypassing the staged pipeline)."""
from __future__ import annotations

import subprocess
from pathlib import Path

import click

import workspace


def _resolve_workspace(workspace_opt: Path | None) -> workspace.Workspace:
    if workspace_opt is not None:
        ws = workspace.Workspace.at(workspace_opt)
    else:
        ws = workspace.new_run()
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
    from bootstrap import build_sandbox, fetch_models

    click.echo(f"weights:  {workspace.weights_dir()}")
    fetch_models.fetch_all(verify_only=verify_only)
    if not verify_only and not skip_image:
        image_hash = build_sandbox.build()
        click.echo(f"sandbox image built: {image_hash}")


@main.command()
@click.argument("repo", type=click.Path(exists=True, file_okay=False, path_type=Path))
@click.option("--workspace", "workspace_opt", type=click.Path(path_type=Path),
              default=None, help="Workspace directory (overrides default run dir).")
def scan(repo: Path, workspace_opt: Path | None) -> None:
    """Run the analysis pipeline against REPO."""
    from orchestrator import pipeline

    ws = _resolve_workspace(workspace_opt)
    click.echo(f"workspace: {ws.root}")
    pipeline.run(repo_path=repo)
    click.echo(f"workspace: {ws.root}")


@main.command(name="audit-verify")
@click.option("--workspace", "workspace_opt", type=click.Path(exists=True, path_type=Path),
              required=True, help="Workspace directory to verify.")
def audit_verify(workspace_opt: Path) -> None:
    """Walk the audit log and check every hash link."""
    from audit.log import verify_chain

    workspace.use(workspace.Workspace.at(workspace_opt))
    count = verify_chain()
    click.echo(f"{count} entries verified")


@main.command()
@click.option("--alias", default="plumbing-check", show_default=True,
              help="models.lock alias to use for the smoke run.")
@click.option("--prompt", default="Reply with the single word: PIPES",
              show_default=True, help="Prompt sent to the model.")
@click.option("--max-tokens", default=16, show_default=True, type=int)
@click.option("--timeout", default=120, show_default=True, type=int,
              help="Sandbox timeout in seconds.")
@click.option("--workspace", "workspace_opt", type=click.Path(path_type=Path),
              default=None, help="Workspace directory (overrides default run dir).")
def plumbing(alias: str, prompt: str, max_tokens: int, timeout: int,
             workspace_opt: Path | None) -> None:
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
            f"alias '{alias}' not found in bootstrap/models.lock; "
            f"known aliases: {sorted(specs)}"
        )
    spec = specs[alias]
    if not spec.dest.exists():
        raise click.ClickException(
            f"weights missing: {spec.dest}; run `vulnforge bootstrap`"
        )
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
    click.echo(f"hashes:   weights={result.weights_hash[:12]} "
               f"stdout={result.stdout_hash[:12]} stderr={result.stderr_hash[:12]}")
    click.echo("plumbing ok")


PROMPT_PATH = Path("inference/prompts/hypothesise.txt")


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
                return text[start:i + 1]
    raise ValueError("unbalanced JSON object")


@main.command()
@click.argument("source", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--alias", default="qwen2.5-coder-7b", show_default=True,
              help="models.lock alias to use for inference.")
@click.option("--seed", default=1, show_default=True, type=int)
@click.option("--max-tokens", default=1024, show_default=True, type=int)
@click.option("--ctx-size", default=4096, show_default=True, type=int,
              help="llama.cpp context window. Probe budgets header + source + reply.")
@click.option("--timeout", default=600, show_default=True, type=int,
              help="Sandbox timeout in seconds.")
@click.option("--workspace", "workspace_opt", type=click.Path(path_type=Path),
              default=None, help="Workspace directory (overrides default run dir).")
def probe(source: Path, alias: str, seed: int, max_tokens: int, ctx_size: int,
          timeout: int, workspace_opt: Path | None) -> None:
    """Run the hypothesise prompt against SOURCE (a single file).

    Bypasses the staged pipeline. Prints raw model output, then attempts to
    parse it as JSON and reconstruct each hypothesis through the schema gate.
    Hypotheses that violate the schema (e.g. claiming CONFIRMED at propose
    time) are reported as rejected.
    """
    import json

    from bootstrap import build_sandbox, fetch_models
    from inference.runner import infer
    from schema.hypothesis import EvidenceType, Hypothesis, VerificationStatus

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
            f"alias '{alias}' not found in bootstrap/models.lock; "
            f"known aliases: {sorted(specs)}"
        )
    spec = specs[alias]
    if not spec.dest.exists():
        raise click.ClickException(
            f"weights missing: {spec.dest}; run `vulnforge bootstrap`"
        )

    prompt_template = PROMPT_PATH.read_text()
    source_text = source.read_text()
    prompt = f"{prompt_template}{source_text}"

    click.echo(f"source:   {source} ({len(source_text)} chars)")
    click.echo(f"weights:  {spec.alias}")
    click.echo(f"image:    {image_hash[:12]}")
    click.echo(f"stderr:   {ws.logs_dir}/llama-*.log")
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
    )

    raw_path = ws.root / "probe-output.txt"
    raw_path.parent.mkdir(parents=True, exist_ok=True)
    raw_path.write_text(result.output_text)

    click.echo()
    click.echo(f"=== raw model output ({len(result.output_text)} chars, saved to {raw_path}) ===")
    click.echo(result.output_text)
    click.echo()

    try:
        json_blob = _extract_first_json_object(result.output_text)
    except ValueError as e:
        raise click.ClickException(f"no JSON object in output: {e}")
    try:
        data = json.loads(json_blob)
    except json.JSONDecodeError as e:
        raise click.ClickException(f"extracted blob is not valid JSON: {e}")
    if not isinstance(data, dict) or "hypotheses" not in data:
        raise click.ClickException("output JSON has no 'hypotheses' key")
    if not isinstance(data["hypotheses"], list):
        raise click.ClickException("'hypotheses' is not a list")

    click.echo("=== parsed hypotheses ===")
    accepted = 0
    rejected = 0
    for i, item in enumerate(data["hypotheses"]):
        try:
            h = Hypothesis.propose(
                attack_type=item["attack_type"],
                location=item["location"],
                assumption_broken=item["assumption_broken"],
                expected_effect=item["expected_effect"],
                suggested_inputs=tuple(item.get("suggested_inputs", []) or []),
                confidence=float(item["confidence"]),
                model_hash=result.weights_hash,
                evidence_type=EvidenceType(item.get("evidence_type", "static_pattern")),
                verification_status=VerificationStatus(
                    item.get("verification_status", "unverified")
                ),
            )
            click.echo(
                f"  [{i}] ok       {h.attack_type} @ {h.location} "
                f"(conf={h.confidence:.2f}, {h.evidence_type.value})"
            )
            accepted += 1
        except (KeyError, TypeError, ValueError) as e:
            click.echo(f"  [{i}] rejected {type(e).__name__}: {e}")
            rejected += 1
    click.echo()
    click.echo(f"summary:  {accepted} accepted, {rejected} rejected")


if __name__ == "__main__":
    main()
