"""CLI commands for the swarm orchestrator.

Registered as a sub-application on the main ``parser-security-eval`` CLI.

Commands:
    swarm run <target> --agents N --duration T [--max-parallel P]
    swarm show-config --agents N
"""

from __future__ import annotations

import asyncio
import json
import logging
from pathlib import Path

import typer

from parser_security_eval.swarm.diversity import DiversityConfig

app = typer.Typer(
    name="swarm", help="Swarm orchestrator: spawn N parallel fuzz agents."
)

_DEFAULT_TARGETS = Path("../targets")


@app.command("run")
def swarm_run(
    target: str = typer.Argument(help="Parser target name (e.g. 'libxml2')"),
    agents: int = typer.Option(4, "--agents", "-n", help="Number of parallel agents"),
    duration: int = typer.Option(
        60, "--duration", "-t", help="Per-agent fuzzing duration in seconds"
    ),
    max_parallel: int | None = typer.Option(
        None,
        "--max-parallel",
        "-p",
        help="Max concurrent agents (default: all agents run in parallel)",
    ),
    targets_root: Path = typer.Option(_DEFAULT_TARGETS, help="Targets root directory"),
) -> None:
    """Run a swarm of N parallel fuzzing agents against TARGET.

    Each agent runs an independent live_fuzzing() inspect_ai task with its
    own DockerSandbox.  Diversity is assigned automatically using the default
    portfolio (grammar, coverage, semantic, directed strategies).

    Example:
        parser-security-eval swarm run libxml2 --agents 4 --duration 120
    """
    from parser_security_eval.swarm.orchestrator import SwarmOrchestrator  # noqa: PLC0415

    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    typer.echo(
        f"Launching swarm: target={target} agents={agents} "
        f"duration={duration}s max_parallel={max_parallel or agents}"
    )

    orchestrator = SwarmOrchestrator(targets_dir=targets_root)

    result = asyncio.run(
        orchestrator.run_swarm(
            target=target,
            n_agents=agents,
            duration_seconds=duration,
            max_parallel=max_parallel,
        )
    )

    typer.echo(f"\nSwarm complete for target '{result.target}'")
    typer.echo(f"  Agents run:           {result.n_agents}")
    typer.echo(f"  Total unique crashes: {result.total_unique_crashes}")
    typer.echo(f"  Coverage union:       {result.total_coverage_union:.3f}")
    typer.echo(f"  Wall time:            {result.total_wall_time_seconds:.1f}s")
    typer.echo(f"  CPU hours:            {result.total_cpu_hours:.4f}h")

    typer.echo("\nAgent breakdown:")
    for ar in result.agent_results:
        if ar.session_result is not None:
            sr = ar.session_result
            typer.echo(
                f"  {ar.agent_id}  engine={ar.config.engine.value}"
                f"  strategy={ar.config.mutation_strategy.value}"
                f"  role={ar.config.role.value}"
                f"  crashes={sr.unique_crashes}"
                f"  score={sr.score:.3f}"
                f"  wall={ar.wall_time_seconds:.1f}s"
            )
        else:
            typer.echo(f"  {ar.agent_id}  FAILED: {ar.error or 'unknown error'}")

    curve = result.marginal_crash_curve()
    if curve:
        typer.echo(f"\nMarginal crash curve: {curve}")


@app.command("show-config")
def show_config(
    agents: int = typer.Option(4, "--agents", "-n", help="Number of agents"),
) -> None:
    """Print the default DiversityConfig for N agents as JSON.

    Useful for inspecting which engine/strategy/role each agent slot would be
    assigned before running an actual swarm.

    Example:
        parser-security-eval swarm show-config --agents 8
    """
    config = DiversityConfig.default_portfolio(agents)
    typer.echo(config.model_dump_json(indent=2))


def _show_config_as_dict(agents: int) -> dict:
    """Return the default portfolio config as a plain dict (for testing)."""
    config = DiversityConfig.default_portfolio(agents)
    return json.loads(config.model_dump_json())
