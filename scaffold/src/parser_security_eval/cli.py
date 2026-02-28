"""CLI entry point for parser-security-eval."""

from pathlib import Path

import typer

app = typer.Typer(name="parser-security-eval", help="Parser security evaluation framework.")


@app.command()
def curate(
    source: str = typer.Argument(help="Data source: 'arvo' or 'ossfuzz'"),
    output: Path = typer.Option(Path("benchmark"), help="Output directory for curated data"),
    limit: int | None = typer.Option(None, help="Max vulnerabilities to ingest"),
) -> None:
    """Ingest and curate vulnerability data from ARVO or oss-fuzz."""
    raise NotImplementedError(f"Curation from {source} not yet implemented")


@app.command()
def evaluate(
    task: str = typer.Argument(help="Task to run: 'patching', 'harness', 'triage'"),
    target: str = typer.Option(..., help="Parser target name (e.g. 'libpng')"),
    model: str = typer.Option("openai/gpt-4o", help="Model to evaluate"),
) -> None:
    """Run an Inspect-AI evaluation task."""
    raise NotImplementedError(f"Task {task} not yet implemented")


@app.command()
def build_target(
    target: str = typer.Argument(help="Parser target to build"),
    sanitizer: str = typer.Option("address", help="Sanitizer: address, undefined, memory"),
    engine: str = typer.Option("libfuzzer", help="Fuzz engine: libfuzzer, afl++, honggfuzz"),
) -> None:
    """Build a parser target in Docker with the specified sanitizer and engine."""
    raise NotImplementedError(f"Building {target} not yet implemented")


@app.command()
def verify(
    target: str = typer.Argument(help="Parser target"),
    vuln_id: str = typer.Argument(help="Vulnerability ID"),
    patch: Path = typer.Argument(help="Path to patch file"),
) -> None:
    """Verify a patch against a specific vulnerability."""
    raise NotImplementedError(f"Verification of {vuln_id} not yet implemented")
