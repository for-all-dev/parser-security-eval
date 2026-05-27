"""Manifest persistence — atomic save/load, resume logic."""

from __future__ import annotations

import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from parser_security_eval.experiments.models import (
    ExperimentConfig,
    ExperimentManifest,
    RunResult,
    RunSpec,
    RunStatus,
)

MANIFEST_FILENAME = "manifest.json"
RESULTS_FILENAME = "results.json"


def _manifest_path(output_dir: Path) -> Path:
    return output_dir / MANIFEST_FILENAME


def _results_path(output_dir: Path) -> Path:
    return output_dir / RESULTS_FILENAME


def _atomic_write(path: Path, data: str) -> None:
    """Write data to path atomically via tmp+rename."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, suffix=".tmp")
    try:
        with open(fd, "w") as f:
            f.write(data)
        Path(tmp).replace(path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


def load_manifest(output_dir: Path) -> ExperimentManifest | None:
    """Load an existing manifest from disk, or return None."""
    p = _manifest_path(output_dir)
    if not p.exists():
        return None
    return ExperimentManifest.model_validate_json(p.read_text())


def save_manifest(manifest: ExperimentManifest) -> None:
    """Atomic write of manifest + results.json."""
    manifest.updated_at = datetime.now(timezone.utc)
    out_dir = Path(manifest.config.output_dir)
    _atomic_write(_manifest_path(out_dir), manifest.model_dump_json(indent=2))
    _save_results(manifest)


def _save_results(manifest: ExperimentManifest) -> None:
    """Write a clean results.json summarizing all non-pending runs."""
    out_dir = Path(manifest.config.output_dir)
    results: list[dict[str, Any]] = []

    for run in sorted(
        manifest.runs.values(),
        key=lambda r: (r.model, r.target or "", r.repetition),
    ):
        if run.status == RunStatus.pending:
            continue
        entry: dict[str, Any] = {
            "run_id": run.run_id,
            "model": run.model,
            "target": run.target,
            "repetition": run.repetition,
            "status": str(run.status),
        }
        if run.task_kwargs:
            entry["task_kwargs"] = run.task_kwargs
        if run.result:
            entry["scores"] = run.result.scores
            entry["n_samples"] = run.result.n_samples
            entry["total_time"] = run.result.total_time
        if run.error:
            entry["error"] = run.error
        if run.eval_log_path:
            entry["eval_log"] = run.eval_log_path
        results.append(entry)

    import json

    payload = {
        "experiment": manifest.experiment_name,
        "task": str(manifest.config.task),
        "total_runs": manifest.total_runs,
        "completed": manifest.completed_runs,
        "failed": manifest.failed_runs,
        "pending": manifest.pending_runs,
        "runs": results,
    }
    _atomic_write(_results_path(out_dir), json.dumps(payload, indent=2, default=str))


def extract_run_result(log: Any) -> RunResult:
    """Extract a RunResult from an inspect_ai EvalLog."""
    scores: dict[str, dict[str, float]] = {}
    if log.results:
        for score in log.results.scores:
            scores[score.name] = {k: v.value for k, v in score.metrics.items()}

    n_samples = len(log.samples) if log.samples else 0

    total_time = 0.0
    if log.stats:
        if hasattr(log.stats, "eval_time") and log.stats.eval_time:
            total_time = log.stats.eval_time
        elif log.stats.started_at and log.stats.completed_at:
            from datetime import datetime

            try:
                started = datetime.fromisoformat(
                    str(log.stats.started_at).replace("Z", "+00:00")
                )
                completed = datetime.fromisoformat(
                    str(log.stats.completed_at).replace("Z", "+00:00")
                )
                total_time = (completed - started).total_seconds()
            except ValueError, TypeError:
                pass

    error_msg = None
    if log.error:
        error_msg = (
            log.error.message if hasattr(log.error, "message") else str(log.error)
        )

    return RunResult(
        eval_status=str(log.status),
        scores=scores,
        n_samples=n_samples,
        total_time=total_time,
        error=error_msg,
    )


def init_or_resume_manifest(
    config: ExperimentConfig,
    runs: list[RunSpec],
    *,
    retry_failed: bool = False,
) -> ExperimentManifest:
    """Create a new manifest or resume an existing one.

    On resume:
    - Keep completed runs as-is
    - Reset stuck "running" runs to "pending"
    - If *retry_failed*, also reset "failed" runs to "pending"
    - Add any new grid cells not present in the old manifest
    """
    existing = load_manifest(Path(config.output_dir))

    if existing is None:
        manifest = ExperimentManifest(
            experiment_name=config.name,
            config=config,
            runs={r.run_id: r for r in runs},
        )
        save_manifest(manifest)
        return manifest

    # Reset stuck running -> pending
    for run in existing.runs.values():
        if run.status == RunStatus.running:
            run.status = RunStatus.pending
            run.started_at = None
        elif run.status == RunStatus.failed and retry_failed:
            run.status = RunStatus.pending
            run.started_at = None
            run.completed_at = None
            run.error = None
            run.result = None

    # Add new grid cells
    for run in runs:
        if run.run_id not in existing.runs:
            existing.runs[run.run_id] = run

    existing.config = config
    save_manifest(existing)
    return existing


def mark_run_started(manifest: ExperimentManifest, run_id: str) -> None:
    run = manifest.runs[run_id]
    run.status = RunStatus.running
    run.started_at = datetime.now(timezone.utc)
    save_manifest(manifest)


def mark_run_completed(
    manifest: ExperimentManifest,
    run_id: str,
    eval_log_path: str,
    result: RunResult,
) -> None:
    run = manifest.runs[run_id]
    run.status = RunStatus.completed
    run.completed_at = datetime.now(timezone.utc)
    run.eval_log_path = eval_log_path
    run.result = result
    save_manifest(manifest)


def mark_run_failed(
    manifest: ExperimentManifest,
    run_id: str,
    error: str,
    result: RunResult | None = None,
) -> None:
    run = manifest.runs[run_id]
    run.status = RunStatus.failed
    run.completed_at = datetime.now(timezone.utc)
    run.error = error
    run.result = result
    save_manifest(manifest)
