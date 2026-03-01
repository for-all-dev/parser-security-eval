"""Pydantic models for per-target agent memory."""

from datetime import datetime, timezone

from pydantic import BaseModel, Field


def _utcnow() -> datetime:
    return datetime.now(tz=timezone.utc)


class Hypothesis(BaseModel):
    """A specific approach the agent tried during a session."""

    id: str  # uuid4
    description: str  # what the agent was trying
    entry_point: str  # which function was targeted
    harness_id: str | None  # links to HarnessRecord if applicable
    led_to_crash: bool
    coverage_delta: float  # fractional branch coverage change (0.0 if no data)
    notes: str  # agent's own reflection on why it worked/didn't
    created_at: datetime


class HarnessRecord(BaseModel):
    """A harness variant that was generated and compiled."""

    id: str  # sha256 of the source
    source_hash: str
    entry_point: str
    compile_success: bool
    compile_iterations: int  # how many repair iterations were needed
    crashes_found: int
    coverage_achieved: float  # branch%
    created_at: datetime


class CrashSummary(BaseModel):
    """A unique crash that was found."""

    id: str  # stack hash (top 5 frames)
    stack_hash: str
    cwe: str | None  # e.g. "CWE-122"
    severity: str | None  # critical/high/medium/low
    entry_point: str
    crash_file: str | None  # path to crash artifact relative to target dir
    found_at: datetime
    patched: bool = False


class CoverageSnapshot(BaseModel):
    """Coverage measurement at a point in time."""

    timestamp: datetime
    line_pct: float
    branch_pct: float
    harness_id: str | None


class TargetMemory(BaseModel):
    """Full per-target memory, persisted as targets/<target>/memory.json."""

    target_name: str
    hypotheses_tried: list[Hypothesis] = Field(default_factory=list)
    crashes_found: list[CrashSummary] = Field(default_factory=list)
    harness_variants: list[HarnessRecord] = Field(default_factory=list)
    coverage_history: list[CoverageSnapshot] = Field(default_factory=list)
    last_updated: datetime = Field(default_factory=_utcnow)
