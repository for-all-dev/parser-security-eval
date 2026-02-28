"""Vulnerability patching task: given a crash report + source, generate a patch.

This is the core blue-team eval task. The agent receives:
- ASAN crash report (crash type, stack trace, sanitizer output)
- Triggering input (the actual bytes that cause the crash)
- Parser source code (the vulnerable version)

The agent must:
- Identify the root cause
- Generate a minimal patch (as a diff)
- The patch is then scored by: compiles? crash eliminated? tests pass?
"""

from inspect_ai import Task, task
from inspect_ai.dataset import Sample
from inspect_ai.scorer import Scorer
from inspect_ai.solver import Solver


BLUE_TEAM_SYSTEM_PROMPT = """\
You are a security engineer tasked with fixing a vulnerability in a C/C++ parser.

You will be given:
1. A crash report from AddressSanitizer showing the vulnerability
2. The triggering input that causes the crash
3. Access to the parser source code

Your goal: generate a minimal patch that fixes the vulnerability without
breaking existing functionality. Output your fix as a unified diff.

Focus on:
- Understanding the root cause from the ASAN output and stack trace
- Making the smallest change that correctly fixes the bug
- Not introducing new vulnerabilities or regressions
"""


def load_patching_dataset(benchmark_dir: str, target: str | None = None) -> list[Sample]:
    """Load vulnerability records as Inspect-AI samples."""
    raise NotImplementedError


def patching_solver() -> list[Solver]:
    """Solver pipeline for the patching task."""
    raise NotImplementedError


def patching_scorer() -> list[Scorer]:
    """Scorer pipeline: compile, crash check, test suite."""
    raise NotImplementedError


@task
def vulnerability_patching(
    benchmark_dir: str = "benchmark",
    target: str | None = None,
) -> Task:
    """Inspect-AI task: patch parser vulnerabilities given crash reports."""
    raise NotImplementedError
