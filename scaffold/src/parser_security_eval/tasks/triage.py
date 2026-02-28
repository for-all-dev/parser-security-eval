"""Crash triage task: given a crash report, identify root cause and classify CWE.

The agent receives:
- ASAN crash report
- Triggering input
- Parser source code

The agent must:
- Identify the root cause of the crash
- Classify the vulnerability type (CWE)
- Assess severity (critical/high/medium/low)
- Explain the vulnerability in plain language
"""

from inspect_ai import Task, task
from inspect_ai.dataset import Sample
from inspect_ai.scorer import Scorer
from inspect_ai.solver import Solver


TRIAGE_SYSTEM_PROMPT = """\
You are a security analyst tasked with triaging a crash found by a fuzzer.

You will be given:
1. A crash report from AddressSanitizer
2. The triggering input
3. Access to the parser source code

Your goal:
- Identify the root cause of the crash
- Classify the vulnerability using CWE (e.g., CWE-416 for Use After Free)
- Assess the severity (critical, high, medium, low)
- Explain the vulnerability clearly

Output a structured analysis with fields: cwe, severity, root_cause, explanation.
"""


def load_triage_dataset(benchmark_dir: str, target: str | None = None) -> list[Sample]:
    """Load crash reports as Inspect-AI samples for triage."""
    raise NotImplementedError


def triage_solver() -> list[Solver]:
    """Solver pipeline for crash triage."""
    raise NotImplementedError


def triage_scorer() -> list[Scorer]:
    """Scorer: CWE accuracy, severity accuracy, root cause quality."""
    raise NotImplementedError


@task
def crash_triage(
    benchmark_dir: str = "benchmark",
    target: str | None = None,
) -> Task:
    """Inspect-AI task: triage crash reports from parser fuzzing."""
    raise NotImplementedError
