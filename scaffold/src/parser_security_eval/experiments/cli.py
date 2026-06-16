"""CLI commands for experiment orchestration.

Registered as a sub-application on the main ``parser-security-eval`` CLI.

Commands:
    experiment run <config.toml> [--dry-run]
    experiment status <output_dir>
    experiment analyze <output_dir> [--json results.json]
"""

from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

app = typer.Typer(
    name="experiment",
    help="TOML-driven experiment orchestration: sweep models, targets, and parameters.",
)

console = Console()


@app.command("run")
def experiment_run(
    config_path: Path = typer.Argument(help="Path to experiment TOML config"),
    dry_run: bool = typer.Option(
        False, "--dry-run", help="Expand grid and show runs without executing"
    ),
    retry_failed: bool = typer.Option(
        False, "--retry-failed", help="Reset failed runs to pending and re-execute"
    ),
) -> None:
    """Run or resume an experiment from a TOML config file."""
    from parser_security_eval.experiments.runner import load_config, run_experiment

    if not config_path.exists():
        typer.echo(f"Error: config file not found: {config_path}", err=True)
        raise typer.Exit(1)

    config = load_config(config_path)
    console.print(f"[bold]Experiment:[/bold] {config.name}")
    console.print(f"[bold]Task:[/bold] {config.task}")
    console.print(
        f"[bold]Grid:[/bold] {len(config.grid.model)} models x "
        f"{len(config.grid.target)} targets x {config.repetitions} reps"
    )

    if dry_run:
        console.print("[yellow]Dry run mode — no tasks will be executed.[/yellow]")

    manifest = run_experiment(config, dry_run=dry_run, retry_failed=retry_failed)

    # Summary table
    table = Table(title="Experiment Summary")
    table.add_column("Metric", style="bold")
    table.add_column("Value")
    table.add_row("Total runs", str(manifest.total_runs))
    table.add_row("Completed", str(manifest.completed_runs))
    table.add_row("Failed", str(manifest.failed_runs))
    table.add_row("Pending", str(manifest.pending_runs))
    console.print(table)


@app.command("status")
def experiment_status(
    output_dir: Path = typer.Argument(help="Experiment output directory"),
) -> None:
    """Show status of all runs in an experiment."""
    from parser_security_eval.experiments.state import load_manifest

    manifest = load_manifest(output_dir)
    if manifest is None:
        typer.echo(f"Error: no manifest found in {output_dir}", err=True)
        raise typer.Exit(1)

    console.print(f"[bold]Experiment:[/bold] {manifest.experiment_name}")
    console.print(
        f"Total: {manifest.total_runs} | "
        f"Completed: {manifest.completed_runs} | "
        f"Failed: {manifest.failed_runs} | "
        f"Pending: {manifest.pending_runs}"
    )

    table = Table(title="Runs")
    table.add_column("Run ID", style="dim")
    table.add_column("Model")
    table.add_column("Target")
    table.add_column("Rep")
    table.add_column("Status")
    table.add_column("Error")

    status_style = {
        "pending": "yellow",
        "running": "blue",
        "completed": "green",
        "failed": "red",
    }

    for run in sorted(
        manifest.runs.values(), key=lambda r: (r.model, r.target or "", r.repetition)
    ):
        table.add_row(
            run.run_id,
            run.model,
            run.target or "(all)",
            str(run.repetition),
            f"[{status_style.get(run.status, '')}]{run.status}[/]",
            (run.error or "")[:60],
        )

    console.print(table)


@app.command("analyze")
def experiment_analyze(
    output_dir: Path = typer.Argument(help="Experiment output directory"),
    json_out: Path | None = typer.Option(
        None, "--json", help="Export analysis as JSON"
    ),
) -> None:
    """Analyze experiment results: leaderboard, CWE/difficulty/target breakdowns."""
    from parser_security_eval.experiments.analysis import analyze_experiment

    try:
        analysis = analyze_experiment(output_dir)
    except FileNotFoundError as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(1) from exc

    # Leaderboard
    if analysis.leaderboard:
        table = Table(title="Model Leaderboard")
        table.add_column("Model")
        table.add_column("Score", justify="right")
        table.add_column("N", justify="right")
        table.add_column("Avg Time", justify="right")
        table.add_column("Avg Tokens", justify="right")

        if analysis.task_type == "patching":
            table.add_column("Applies", justify="right")
            table.add_column("Compiles", justify="right")
            table.add_column("No Crash", justify="right")
            table.add_column("Tests", justify="right")

        for m in analysis.leaderboard:
            row = [
                m.model,
                f"{m.mean_score:.3f}",
                str(m.n_samples),
                f"{m.mean_total_time:.1f}s",
                f"{m.mean_input_tokens + m.mean_output_tokens:.0f}",
            ]
            if analysis.task_type == "patching":
                row.extend(
                    [
                        f"{m.patch_applies_rate:.1%}",
                        f"{m.compiles_rate:.1%}",
                        f"{m.crash_eliminated_rate:.1%}",
                        f"{m.tests_pass_rate:.1%}",
                    ]
                )
            table.add_row(*row)
        console.print(table)

    # CWE breakdown
    if analysis.cwe_breakdown:
        table = Table(title="CWE Breakdown")
        table.add_column("Model")
        table.add_column("CWE")
        table.add_column("Score", justify="right")
        table.add_column("N", justify="right")
        for b in sorted(analysis.cwe_breakdown, key=lambda x: (x.model, x.cwe)):
            table.add_row(b.model, b.cwe, f"{b.mean_score:.3f}", str(b.n_samples))
        console.print(table)

    # Difficulty curve
    if analysis.difficulty_breakdown:
        table = Table(title="Difficulty Breakdown")
        table.add_column("Model")
        table.add_column("Difficulty")
        table.add_column("Score", justify="right")
        table.add_column("N", justify="right")
        for b in sorted(
            analysis.difficulty_breakdown, key=lambda x: (x.model, x.difficulty)
        ):
            table.add_row(
                b.model, b.difficulty, f"{b.mean_score:.3f}", str(b.n_samples)
            )
        console.print(table)

    # Target breakdown
    if analysis.target_breakdown:
        table = Table(title="Target Breakdown")
        table.add_column("Model")
        table.add_column("Target")
        table.add_column("Score", justify="right")
        table.add_column("N", justify="right")
        for b in sorted(analysis.target_breakdown, key=lambda x: (x.model, x.target)):
            table.add_row(b.model, b.target, f"{b.mean_score:.3f}", str(b.n_samples))
        console.print(table)

    if not any(
        [
            analysis.leaderboard,
            analysis.cwe_breakdown,
            analysis.difficulty_breakdown,
            analysis.target_breakdown,
        ]
    ):
        console.print("[yellow]No completed runs with data to analyze.[/yellow]")

    if json_out is not None:
        json_out.write_text(analysis.model_dump_json(indent=2))
        console.print(f"Analysis exported to {json_out}")
