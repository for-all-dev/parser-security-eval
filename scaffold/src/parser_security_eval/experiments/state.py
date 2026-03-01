"""Manifest persistence — atomic save/load, resume logic."""

from __future__ import annotations

import tempfile
from datetime import datetime, timezone
from pathlib import Path

from parser_security_eval.experiments.models import (
    ExperimentConfig,
    ExperimentManifest,
    RunSpec,
    RunStatus,
)

MANIFEST_FILENAME = "manifest.json"


def _manifest_path(output_dir: Path) -> Path:
    return output_dir / MANIFEST_FILENAME


def load_manifest(output_dir: Path) -> ExperimentManifest | None:
    """Load an existing manifest from disk, or return None."""
    p = _manifest_path(output_dir)
    if not p.exists():
        return None
    return ExperimentManifest.model_validate_json(p.read_text())


def save_manifest(manifest: ExperimentManifest) -> None:
    """Atomic write: write to tmp file then rename."""
    manifest.updated_at = datetime.now(timezone.utc)
    out_dir = Path(manifest.config.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    target = _manifest_path(out_dir)

    data = manifest.model_dump_json(indent=2)
    fd, tmp = tempfile.mkstemp(dir=out_dir, suffix=".tmp")
    try:
        with open(fd, "w") as f:
            f.write(data)
        Path(tmp).replace(target)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


def init_or_resume_manifest(
    config: ExperimentConfig, runs: list[RunSpec]
) -> ExperimentManifest:
    """Create a new manifest or resume an existing one.

    On resume:
    - Keep completed and failed runs as-is
    - Reset stuck "running" runs to "pending"
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
    manifest: ExperimentManifest, run_id: str, eval_log_path: str
) -> None:
    run = manifest.runs[run_id]
    run.status = RunStatus.completed
    run.completed_at = datetime.now(timezone.utc)
    run.eval_log_path = eval_log_path
    save_manifest(manifest)


def mark_run_failed(manifest: ExperimentManifest, run_id: str, error: str) -> None:
    run = manifest.runs[run_id]
    run.status = RunStatus.failed
    run.completed_at = datetime.now(timezone.utc)
    run.error = error
    save_manifest(manifest)
