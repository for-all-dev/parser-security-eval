"""CLI entry point for parser-security-eval."""

import asyncio
import json
from pathlib import Path

import typer

app = typer.Typer(
    name="parser-security-eval", help="Parser security evaluation framework."
)

_DEFAULT_CACHE = Path.home() / ".cache" / "parser-security-eval"


@app.command()
def curate(
    source: str = typer.Argument(help="Data source: 'arvo' or 'ossfuzz'"),
    output: Path = typer.Option(
        Path("benchmark"), help="Output directory for curated data"
    ),
    limit: int | None = typer.Option(None, help="Max vulnerabilities to ingest"),
    project: str | None = typer.Option(
        None, help="oss-fuzz project name (required for 'ossfuzz' source)"
    ),
    cache_dir: Path = typer.Option(_DEFAULT_CACHE, help="Local cache directory"),
) -> None:
    """Ingest and curate vulnerability data from ARVO or oss-fuzz."""
    from parser_security_eval.dataset.curator import DatasetCurator

    curator = DatasetCurator(output)

    if source == "arvo":
        from parser_security_eval.dataset.arvo import ingest_arvo

        records = ingest_arvo(cache_dir=cache_dir, output_dir=output, limit=limit)
        curator.add_records(records)

    elif source == "ossfuzz":
        if project is None:
            typer.echo(
                "Error: --project is required for 'ossfuzz' source", err=True
            )
            raise typer.Exit(1)

        from parser_security_eval.dataset.ossfuzz import (
            fetch_ossfuzz_bugs,
            parse_ossfuzz_bug,
        )

        bugs = fetch_ossfuzz_bugs(project=project, cache_dir=cache_dir)
        records = [
            r for b in bugs if (r := parse_ossfuzz_bug(b, project)) is not None
        ]
        if limit is not None:
            records = records[:limit]
        curator.add_records(records)

    else:
        typer.echo(
            f"Error: unknown source '{source}'. Choose 'arvo' or 'ossfuzz'.",
            err=True,
        )
        raise typer.Exit(1)

    errors = curator.validate()
    if errors:
        typer.echo(f"Validation warnings ({len(errors)}):", err=True)
        for e in errors:
            typer.echo(f"  {e}", err=True)

    curator.export_metadata()
    summary = curator.summary()
    typer.echo(f"Curated {summary['total']} records -> {output / 'metadata.json'}")
    typer.echo(f"  by target:   {summary['by_target']}")
    typer.echo(f"  by severity: {summary['by_severity']}")


@app.command()
def evaluate(
    task: str = typer.Argument(help="Task: 'patching', 'triage', or 'harness'"),
    model: str = typer.Option("openai/gpt-4o", help="Model to evaluate"),
    target: str | None = typer.Option(
        None, help="Parser target filter (e.g. 'libpng')"
    ),
    benchmark_dir: Path = typer.Option(
        Path("benchmark"), help="Benchmark directory (patching / triage)"
    ),
    targets_root: Path = typer.Option(
        Path("targets"), help="Targets root directory (patching / harness)"
    ),
    engine: str = typer.Option(
        "libfuzzer", help="Fuzz engine: libfuzzer, afl, honggfuzz"
    ),
    fuzz_duration: int = typer.Option(
        300, help="Fuzzer run duration in seconds (harness only)"
    ),
) -> None:
    """Run an Inspect-AI evaluation task."""
    from inspect_ai import eval as inspect_eval

    if task == "patching":
        from parser_security_eval.tasks.patching import vulnerability_patching

        inspect_task = vulnerability_patching(
            benchmark_dir=str(benchmark_dir),
            target=target,
            targets_root=str(targets_root),
            fuzzing_engine=engine,
        )

    elif task == "triage":
        from parser_security_eval.tasks.triage import crash_triage

        inspect_task = crash_triage(
            benchmark_dir=str(benchmark_dir),
            target=target,
        )

    elif task == "harness":
        if target is None:
            typer.echo("Error: --target is required for 'harness' task", err=True)
            raise typer.Exit(1)

        from parser_security_eval.tasks.harness import harness_generation

        inspect_task = harness_generation(
            targets_dir=str(targets_root),
            target=target,
            fuzz_duration=fuzz_duration,
            engine=engine,
        )

    else:
        typer.echo(
            f"Error: unknown task '{task}'. Choose 'patching', 'triage', or 'harness'.",
            err=True,
        )
        raise typer.Exit(1)

    logs = inspect_eval(inspect_task, model=model)

    for log in logs:
        typer.echo(f"\nTask:   {log.task}")
        typer.echo(f"Status: {log.status}")
        if log.results:
            for score in log.results.scores:
                metrics_str = ", ".join(
                    f"{k}={v.value:.3f}" for k, v in score.metrics.items()
                )
                typer.echo(f"  {score.name}: {metrics_str}")


@app.command()
def build_target(
    target: str = typer.Argument(help="Parser target to build"),
    sanitizer: str = typer.Option(
        "address", help="Sanitizer: address, undefined, memory"
    ),
    engine: str = typer.Option(
        "libfuzzer", help="Fuzz engine: libfuzzer, afl, honggfuzz"
    ),
    targets_root: Path = typer.Option(
        Path("targets"), help="Targets root directory"
    ),
) -> None:
    """Build a parser target in Docker with the specified sanitizer and engine."""
    from parser_security_eval.sandbox.docker import DockerSandbox, SandboxConfig

    target_dir = targets_root / target
    if not target_dir.exists():
        typer.echo(f"Error: target directory not found: {target_dir}", err=True)
        raise typer.Exit(1)

    config = SandboxConfig(
        target_name=target,
        target_dir=target_dir,
        sanitizer=sanitizer,
        engine=engine,
    )

    async def _run() -> bool:
        async with DockerSandbox(config) as sandbox:
            return await sandbox.build_target()

    typer.echo(f"Building {target} (sanitizer={sanitizer}, engine={engine})...")
    ok = asyncio.run(_run())
    if ok:
        typer.echo("Build succeeded.")
    else:
        typer.echo("Build failed.", err=True)
        raise typer.Exit(1)


@app.command()
def verify(
    target: str = typer.Argument(help="Parser target"),
    vuln_id: str = typer.Argument(help="Vulnerability ID"),
    patch: Path = typer.Argument(help="Path to patch file (.diff)"),
    benchmark_dir: Path = typer.Option(
        Path("benchmark"), help="Benchmark directory"
    ),
    targets_root: Path = typer.Option(
        Path("targets"), help="Targets root directory"
    ),
    sanitizer: str = typer.Option(
        "address", help="Sanitizer: address, undefined, memory"
    ),
    engine: str = typer.Option(
        "libfuzzer", help="Fuzz engine: libfuzzer, afl, honggfuzz"
    ),
) -> None:
    """Verify a patch against a specific vulnerability."""
    from parser_security_eval.sandbox.docker import DockerSandbox, SandboxConfig
    from parser_security_eval.scorers.patch import score_patch
    from parser_security_eval.tasks.patching import _resolve_fuzz_binary

    # Resolve the vulnerability record to get crash input path.
    metadata_path = benchmark_dir / "metadata.json"
    if not metadata_path.exists():
        typer.echo(f"Error: benchmark metadata not found at {metadata_path}", err=True)
        raise typer.Exit(1)

    raw = json.loads(metadata_path.read_text())
    record = next(
        (r for r in raw.get("records", []) if r["id"] == vuln_id), None
    )
    if record is None:
        typer.echo(
            f"Error: vulnerability '{vuln_id}' not found in {metadata_path}", err=True
        )
        raise typer.Exit(1)

    crash_input_rel = record.get("crash_input_path")
    if not crash_input_rel:
        typer.echo(
            f"Error: no crash_input_path in record for '{vuln_id}'", err=True
        )
        raise typer.Exit(1)

    triggering_input = str(benchmark_dir / crash_input_rel)
    patch_diff = patch.read_text()

    target_dir = targets_root / target
    fuzz_binary = _resolve_fuzz_binary(target_dir, target)

    config = SandboxConfig(
        target_name=target,
        target_dir=target_dir,
        sanitizer=sanitizer,
        engine=engine,
    )

    async def _run():
        async with DockerSandbox(config) as sandbox:
            return await score_patch(
                sandbox=sandbox,
                patch_diff=patch_diff,
                triggering_input_path=triggering_input,
                fuzz_target_binary=fuzz_binary,
                sanitizer=sanitizer,
                fuzzing_engine=engine,
            )

    typer.echo(f"Verifying patch for {vuln_id} ({target})...")
    result = asyncio.run(_run())

    typer.echo(f"  patch_applies:    {result.patch_applies}")
    typer.echo(f"  compiles:         {result.compiles}")
    typer.echo(f"  crash_eliminated: {result.crash_eliminated}")
    typer.echo(f"  tests_pass:       {result.tests_pass}")
    typer.echo(f"  diff_lines:       {result.diff_lines}")
    typer.echo(f"  success:          {result.success}")

    if not result.success:
        raise typer.Exit(1)
