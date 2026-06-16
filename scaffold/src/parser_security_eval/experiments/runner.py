"""Core experiment orchestration — grid expansion, task building, run loop."""

from __future__ import annotations

import itertools
import tomllib
from pathlib import Path
from typing import Any

from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    TextColumn,
    TimeElapsedColumn,
)

from parser_security_eval.experiments.models import (
    ExperimentConfig,
    ExperimentManifest,
    RunSpec,
    RunStatus,
    TaskType,
)
from parser_security_eval.experiments.state import (
    extract_run_result,
    init_or_resume_manifest,
    mark_run_completed,
    mark_run_failed,
    mark_run_started,
)
from parser_security_eval.log import get_log

log = get_log(__name__)


def load_config(config_path: Path) -> ExperimentConfig:
    """Parse a TOML experiment config file."""
    with open(config_path, "rb") as f:
        raw = tomllib.load(f)
    return ExperimentConfig.model_validate(raw)


def expand_grid(config: ExperimentConfig) -> list[RunSpec]:
    """Cartesian product of grid dimensions x repetitions -> list of RunSpec."""
    grid = config.grid
    models = grid.model
    targets = grid.target

    # Build extra dimension lists for cartesian product
    extra_keys = sorted(grid.extra.keys())
    extra_values = [grid.extra[k] for k in extra_keys]

    runs: list[RunSpec] = []
    extra_combos: list[tuple[Any, ...]] = (
        list(itertools.product(*extra_values)) if extra_values else [()]
    )

    for model in models:
        for target in targets:
            for extra_combo in extra_combos:
                extra_kwargs = dict(zip(extra_keys, extra_combo))
                for rep in range(config.repetitions):
                    run_id = RunSpec.make_id(
                        config.name, model, target, rep, extra_kwargs
                    )
                    task_kwargs = {**extra_kwargs}
                    runs.append(
                        RunSpec(
                            run_id=run_id,
                            model=model,
                            target=target,
                            repetition=rep,
                            task_kwargs=task_kwargs,
                        )
                    )
    return runs


def _build_task(config: ExperimentConfig, run: RunSpec) -> Any:
    """Construct an Inspect-AI Task for the given run (lazy imports)."""
    defaults = config.defaults

    if config.task == TaskType.patching:
        from parser_security_eval.tasks.patching import vulnerability_patching

        return vulnerability_patching(
            benchmark_dir=defaults.benchmark_dir,
            target=run.target,
            targets_root=defaults.targets_root,
            fuzzing_engine=defaults.engine,
            ready_only=defaults.ready_only,
            seed=defaults.seed,
        )

    elif config.task == TaskType.triage:
        from parser_security_eval.tasks.triage import crash_triage

        return crash_triage(
            benchmark_dir=defaults.benchmark_dir,
            target=run.target,
            ready_only=defaults.ready_only,
        )

    elif config.task == TaskType.harness:
        from parser_security_eval.tasks.harness import harness_generation

        if run.target is None:
            msg = "harness task requires a target"
            raise ValueError(msg)
        return harness_generation(
            targets_dir=defaults.targets_root,
            target=run.target,
            fuzz_duration=run.task_kwargs.get("fuzz_duration", defaults.fuzz_duration),
            engine=defaults.engine,
        )

    elif config.task == TaskType.fuzzing:
        from parser_security_eval.tasks.fuzzing import live_fuzzing

        if run.target is None:
            msg = "fuzzing task requires a target"
            raise ValueError(msg)
        return live_fuzzing(
            targets_dir=defaults.targets_root,
            target=run.target,
            fuzzing_engine=defaults.engine,
            fuzz_duration=run.task_kwargs.get("fuzz_duration", defaults.fuzz_duration),
            message_limit=defaults.message_limit,
        )

    msg = f"Unknown task type: {config.task}"
    raise ValueError(msg)


def run_experiment(
    config: ExperimentConfig,
    *,
    dry_run: bool = False,
    retry_failed: bool = False,
) -> ExperimentManifest:
    """Main experiment loop: expand grid, init/resume manifest, execute runs."""
    runs = expand_grid(config)
    manifest = init_or_resume_manifest(config, runs, retry_failed=retry_failed)

    pending = [r for r in manifest.runs.values() if r.status == RunStatus.pending]

    if dry_run:
        log.info(
            "Dry run: %d total runs, %d pending, %d completed, %d failed",
            manifest.total_runs,
            manifest.pending_runs,
            manifest.completed_runs,
            manifest.failed_runs,
        )
        for run in pending:
            log.info(
                "  [%s] model=%s target=%s rep=%d kwargs=%s",
                run.run_id,
                run.model,
                run.target,
                run.repetition,
                run.task_kwargs,
            )
        return manifest

    if not pending:
        log.info("All %d runs already completed or failed.", manifest.total_runs)
        return manifest

    from inspect_ai import eval as inspect_eval

    from parser_security_eval.telemetry import configure_telemetry

    configure_telemetry()

    log_dir = str(Path(config.output_dir) / "logs")

    with Progress(
        TextColumn("[bold blue]{task.description}"),
        BarColumn(),
        MofNCompleteColumn(),
        TimeElapsedColumn(),
    ) as progress:
        task_id = progress.add_task(f"Experiment: {config.name}", total=len(pending))

        for run in pending:
            progress.update(
                task_id,
                description=f"{config.name} | {run.model} / {run.target or 'all'} rep={run.repetition}",
            )
            mark_run_started(manifest, run.run_id)

            try:
                inspect_task = _build_task(config, run)
                logs = inspect_eval(
                    inspect_task,
                    model=run.model,
                    log_dir=log_dir,
                    limit=config.defaults.limit,
                )

                # Check that inspect_eval actually succeeded
                if not logs or logs[0].status != "success":
                    status = logs[0].status if logs else "no-log"
                    error_msg = f"inspect_eval returned status={status}"
                    if logs and logs[0].error:
                        error_msg += f": {logs[0].error.message}"
                    run_result = extract_run_result(logs[0]) if logs else None
                    mark_run_failed(manifest, run.run_id, error_msg, result=run_result)
                    log.error("Run %s failed: %s", run.run_id, error_msg)
                else:
                    eval_log_path = (
                        str(logs[0].location)
                        if hasattr(logs[0], "location")
                        else log_dir
                    )
                    run_result = extract_run_result(logs[0])
                    mark_run_completed(
                        manifest, run.run_id, eval_log_path, result=run_result
                    )
                    log.info("Run %s completed.", run.run_id)

            except Exception as exc:
                mark_run_failed(manifest, run.run_id, str(exc))
                log.error("Run %s failed: %s", run.run_id, exc)

            progress.advance(task_id)

    return manifest
