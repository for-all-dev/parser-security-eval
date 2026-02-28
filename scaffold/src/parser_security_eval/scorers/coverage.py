"""Scorers for evaluating fuzz harness coverage.

After a fuzz harness is compiled and run for a fixed duration,
measure the code coverage achieved.
"""

from dataclasses import dataclass


@dataclass
class CoverageResult:
    """Coverage metrics from a fuzzing run."""

    line_coverage_pct: float
    branch_coverage_pct: float
    function_coverage_pct: float
    unique_crashes: int
    total_executions: int
    execs_per_sec: float


async def run_fuzzer_and_measure(
    sandbox_dir: str,
    fuzz_target_binary: str,
    corpus_dir: str,
    duration_seconds: int = 300,
    engine: str = "libfuzzer",
) -> CoverageResult:
    """Run a fuzzer for a fixed duration and collect coverage metrics."""
    raise NotImplementedError


async def generate_coverage_report(
    sandbox_dir: str,
    fuzz_target_binary: str,
    corpus_dir: str,
) -> dict:
    """Generate an llvm-cov coverage report from a corpus."""
    raise NotImplementedError
