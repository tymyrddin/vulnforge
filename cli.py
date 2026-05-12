"""vulnforge CLI. Four subcommands: bootstrap (the one network step), scan
(run the analysis pipeline), audit-verify (walk the audit log hash chain),
and plumbing (end-to-end smoke test)."""
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


if __name__ == "__main__":
    main()
