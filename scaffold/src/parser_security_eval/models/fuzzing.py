"""Data models for live fuzzing task: harness records, cycles, and results."""

from __future__ import annotations

from pydantic import BaseModel, Field


class HarnessRecord(BaseModel):
    """Record of a single harness write attempt for one entry-point."""

    entry_point: str  # the function being targeted, e.g. "xmlReadMemory"
    code: str  # the full C/C++ source of the harness
    compile_success: bool = False
    compile_errors: str = ""  # compiler stderr if compile_success is False
    repair_iterations: int = 0  # how many compile-fix loops were needed
    first_try_success: bool = (
        False  # True iff compile_success and repair_iterations == 0
    )


class FuzzingResult(BaseModel):
    """Parsed result of one fuzzing run (one call to start_fuzzing)."""

    duration_seconds: int
    execs_per_sec: float | None = None
    corpus_size: int | None = None
    crashes_found: int = 0
    # Stack-hash-deduplicated crashes: mapping hash → ASAN output snippet
    unique_crash_hashes: dict[str, str] = Field(default_factory=dict)
    timed_out: bool = False
    oom_killed: bool = False
    raw_log: str = ""


class CoverageDelta(BaseModel):
    """Coverage change from one fuzzing cycle to the next."""

    line_pct_before: float = 0.0
    line_pct_after: float = 0.0
    branch_pct_before: float = 0.0
    branch_pct_after: float = 0.0

    @property
    def line_delta(self) -> float:
        return self.line_pct_after - self.line_pct_before

    @property
    def branch_delta(self) -> float:
        return self.branch_pct_after - self.branch_pct_before


class FuzzingCycle(BaseModel):
    """One complete Analyze→Synthesize→Fuzz→Triage iteration."""

    cycle_index: int  # 0-based cycle number
    entry_point: str  # which entry-point this cycle targeted
    harness: HarnessRecord
    fuzz_result: FuzzingResult | None = None
    coverage: CoverageDelta | None = None
    triage_notes: str = ""  # agent's triage observations for this cycle


class LiveFuzzingSessionResult(BaseModel):
    """Aggregate result of an entire live fuzzing session (all cycles)."""

    target_name: str
    engine: str
    total_cycles: int = 0
    cycles: list[FuzzingCycle] = Field(default_factory=list)

    # Aggregate crash stats across all cycles
    total_unique_crashes: int = 0
    all_crash_hashes: dict[str, str] = Field(default_factory=dict)

    # Coverage at end of session
    final_line_coverage_pct: float = 0.0
    final_branch_coverage_pct: float = 0.0

    # Harness quality metrics
    total_harnesses_attempted: int = 0
    harnesses_compiled_first_try: int = 0
    total_repair_iterations: int = 0

    @property
    def first_try_compile_rate(self) -> float:
        if self.total_harnesses_attempted == 0:
            return 0.0
        return self.harnesses_compiled_first_try / self.total_harnesses_attempted

    @property
    def mean_repair_iterations(self) -> float:
        if self.total_harnesses_attempted == 0:
            return 0.0
        return self.total_repair_iterations / self.total_harnesses_attempted
