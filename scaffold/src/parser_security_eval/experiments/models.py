"""Pydantic models for TOML-driven experiment orchestration."""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Config models (parsed from TOML)
# ---------------------------------------------------------------------------


class TaskType(StrEnum):
    patching = "patching"
    triage = "triage"
    harness = "harness"
    fuzzing = "fuzzing"


class ExperimentDefaults(BaseModel):
    benchmark_dir: str = "../benchmark"
    targets_root: str = "../targets"
    ready_only: bool = False
    seed: int | None = None
    limit: int | None = None
    engine: str = "libfuzzer"
    fuzz_duration: int = 300
    message_limit: int = 120
    max_rounds: int = 3
    round_duration: int = 60


class ExperimentGrid(BaseModel):
    model: list[str]
    target: list[str | None] = Field(default_factory=lambda: [None])
    extra: dict[str, list[Any]] = Field(default_factory=dict)


class ExperimentConfig(BaseModel):
    name: str
    description: str = ""
    task: TaskType
    output_dir: str = "results"
    defaults: ExperimentDefaults = Field(default_factory=ExperimentDefaults)
    grid: ExperimentGrid
    repetitions: int = 1


# ---------------------------------------------------------------------------
# State models
# ---------------------------------------------------------------------------


class RunStatus(StrEnum):
    pending = "pending"
    running = "running"
    completed = "completed"
    failed = "failed"


def _run_id(
    experiment_name: str,
    model: str,
    target: str | None,
    repetition: int,
    extra_kwargs: dict[str, Any],
) -> str:
    """Deterministic run ID: sha256 hash truncated to 12 hex chars."""
    blob = f"{experiment_name}|{model}|{target}|{repetition}|{sorted(extra_kwargs.items())}"
    return hashlib.sha256(blob.encode()).hexdigest()[:12]


class RunResult(BaseModel):
    """Extracted outcome from a completed eval log."""

    eval_status: str
    scores: dict[str, dict[str, float]] = Field(default_factory=dict)
    n_samples: int = 0
    total_time: float = 0.0
    error: str | None = None


class RunSpec(BaseModel):
    run_id: str
    model: str
    target: str | None = None
    repetition: int = 0
    task_kwargs: dict[str, Any] = Field(default_factory=dict)
    status: RunStatus = RunStatus.pending
    eval_log_path: str | None = None
    started_at: datetime | None = None
    completed_at: datetime | None = None
    error: str | None = None
    result: RunResult | None = None

    @staticmethod
    def make_id(
        experiment_name: str,
        model: str,
        target: str | None,
        repetition: int,
        extra_kwargs: dict[str, Any] | None = None,
    ) -> str:
        return _run_id(experiment_name, model, target, repetition, extra_kwargs or {})


class ExperimentManifest(BaseModel):
    experiment_name: str
    config: ExperimentConfig
    runs: dict[str, RunSpec] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def total_runs(self) -> int:
        return len(self.runs)

    @property
    def completed_runs(self) -> int:
        return sum(1 for r in self.runs.values() if r.status == RunStatus.completed)

    @property
    def failed_runs(self) -> int:
        return sum(1 for r in self.runs.values() if r.status == RunStatus.failed)

    @property
    def pending_runs(self) -> int:
        return sum(1 for r in self.runs.values() if r.status == RunStatus.pending)


# ---------------------------------------------------------------------------
# Analysis models
# ---------------------------------------------------------------------------


class ModelScore(BaseModel):
    model: str
    mean_score: float = 0.0
    patch_applies_rate: float = 0.0
    compiles_rate: float = 0.0
    crash_eliminated_rate: float = 0.0
    tests_pass_rate: float = 0.0
    mean_input_tokens: float = 0.0
    mean_output_tokens: float = 0.0
    mean_total_time: float = 0.0
    n_samples: int = 0
    # Fuzzing resource-efficiency aggregates (issue #135); pooled, not averaged.
    total_unique_crashes: float = 0.0
    vulns_per_mtok: float = 0.0
    vulns_per_fuzz_hour: float = 0.0
    vulns_per_mtok_equiv: float = 0.0
    token_rate: float = 0.0


class CWEBreakdown(BaseModel):
    model: str
    cwe: str
    mean_score: float = 0.0
    n_samples: int = 0


class DifficultyBreakdown(BaseModel):
    model: str
    difficulty: str
    mean_score: float = 0.0
    n_samples: int = 0


class TargetBreakdown(BaseModel):
    model: str
    target: str
    mean_score: float = 0.0
    n_samples: int = 0


class ExperimentAnalysis(BaseModel):
    experiment_name: str
    task_type: str
    leaderboard: list[ModelScore] = Field(default_factory=list)
    cwe_breakdown: list[CWEBreakdown] = Field(default_factory=list)
    difficulty_breakdown: list[DifficultyBreakdown] = Field(default_factory=list)
    target_breakdown: list[TargetBreakdown] = Field(default_factory=list)
