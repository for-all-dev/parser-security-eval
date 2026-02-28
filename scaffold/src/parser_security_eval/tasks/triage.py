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

from __future__ import annotations

import json
import re
from pathlib import Path

from inspect_ai import Task, task
from inspect_ai.dataset import Sample
from inspect_ai.scorer import (
    CORRECT,
    INCORRECT,
    Score,
    Scorer,
    Target,
    accuracy,
    model_graded_fact,
    scorer,
)
from inspect_ai.solver import Solver, TaskState, generate, solver, system_message

from parser_security_eval.models.vulnerability import (
    Severity,
    VulnerabilityRecord,
)


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

You MUST output your analysis in the following JSON format (and nothing else after it):

```json
{
  "cwe": "CWE-XXX",
  "severity": "critical|high|medium|low",
  "root_cause": "Brief description of the root cause",
  "explanation": "Detailed explanation of the vulnerability"
}
```
"""

# CWE parent-child relationships for partial credit scoring.
# Maps child CWE to its parent CWE(s). This is a subset covering
# common memory-corruption CWEs encountered in parser fuzzing.
CWE_PARENTS: dict[str, list[str]] = {
    "CWE-122": ["CWE-787", "CWE-119"],  # Heap-based Buffer Overflow
    "CWE-125": ["CWE-119"],  # Out-of-bounds Read
    "CWE-126": ["CWE-125", "CWE-119"],  # Buffer Over-read
    "CWE-127": ["CWE-125", "CWE-119"],  # Buffer Under-read
    "CWE-170": ["CWE-119"],  # Improper Null Termination
    "CWE-190": ["CWE-682"],  # Integer Overflow
    "CWE-191": ["CWE-682"],  # Integer Underflow
    "CWE-369": ["CWE-682"],  # Divide By Zero
    "CWE-415": ["CWE-825", "CWE-672"],  # Double Free
    "CWE-416": ["CWE-825", "CWE-672"],  # Use After Free
    "CWE-476": ["CWE-754"],  # NULL Pointer Dereference
    "CWE-787": ["CWE-119"],  # Out-of-bounds Write
    "CWE-788": ["CWE-787", "CWE-119"],  # Access of Memory Beyond Buffer End
    "CWE-805": ["CWE-787", "CWE-119"],  # Buffer Access with Incorrect Length
    "CWE-823": ["CWE-119"],  # Use of Out-of-range Pointer Offset
    "CWE-824": ["CWE-119"],  # Access of Uninitialized Pointer
    "CWE-825": ["CWE-119"],  # Expired Pointer Dereference
}


def _normalize_cwe(cwe: str) -> str:
    """Normalize a CWE identifier to 'CWE-NNN' format."""
    match = re.search(r"(\d+)", cwe)
    if match:
        return f"CWE-{match.group(1)}"
    return cwe.strip().upper()


def _cwe_matches(predicted: str, ground_truth: str) -> bool:
    """Check if predicted CWE matches ground truth, allowing parent-CWE matches.

    Exact match, or predicted is a parent of ground truth, or ground truth
    is a parent of predicted.
    """
    pred = _normalize_cwe(predicted)
    gt = _normalize_cwe(ground_truth)

    if pred == gt:
        return True

    # Check if pred is a parent of gt
    gt_parents = _get_all_parents(gt)
    if pred in gt_parents:
        return True

    # Check if gt is a parent of pred
    pred_parents = _get_all_parents(pred)
    if gt in pred_parents:
        return True

    return False


def _get_all_parents(cwe: str) -> set[str]:
    """Get all ancestor CWEs for a given CWE."""
    parents: set[str] = set()
    queue = [cwe]
    while queue:
        current = queue.pop()
        for parent in CWE_PARENTS.get(current, []):
            if parent not in parents:
                parents.add(parent)
                queue.append(parent)
    return parents


def _parse_triage_output(text: str) -> dict[str, str]:
    """Parse the structured JSON output from the model's triage response.

    Looks for a JSON block with cwe, severity, root_cause, and explanation fields.
    """
    # Try to find JSON in a code block first
    json_match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
    if json_match:
        try:
            return json.loads(json_match.group(1))
        except json.JSONDecodeError:
            pass

    # Try to find a raw JSON object
    json_match = re.search(r"\{[^{}]*\"cwe\"[^{}]*\}", text, re.DOTALL)
    if json_match:
        try:
            return json.loads(json_match.group(0))
        except json.JSONDecodeError:
            pass

    return {}


def _load_records(
    benchmark_dir: Path, target: str | None = None
) -> list[VulnerabilityRecord]:
    """Load VulnerabilityRecords from benchmark metadata.json."""
    metadata_path = benchmark_dir / "metadata.json"
    if not metadata_path.exists():
        return []

    data = json.loads(metadata_path.read_text())
    records = [VulnerabilityRecord(**r) for r in data.get("records", [])]

    if target is not None:
        records = [r for r in records if r.target == target]

    return records


def _build_sample_input(record: VulnerabilityRecord, benchmark_dir: Path) -> str:
    """Build the input text for a triage sample from a vulnerability record."""
    parts: list[str] = []
    parts.append("## Crash Information")
    parts.append(f"**Vulnerability ID:** {record.id}")
    parts.append(f"**Target:** {record.target}")
    parts.append(f"**Crash Type:** {record.crash_type}")
    parts.append(f"**Sanitizer:** {record.sanitizer}")
    parts.append(f"**Affected File:** {record.affected_file}")

    if record.affected_function:
        parts.append(f"**Affected Function:** {record.affected_function}")

    # Include crash report content if available
    if record.crash_report_path:
        report_path = benchmark_dir / record.crash_report_path
        if report_path.exists():
            parts.append(f"\n## ASAN Crash Report\n```\n{report_path.read_text()}\n```")

    # Reference the triggering input
    if record.crash_input_path:
        input_path = benchmark_dir / record.crash_input_path
        if input_path.exists():
            try:
                content = input_path.read_text(errors="replace")
                parts.append(f"\n## Triggering Input\n```\n{content}\n```")
            except Exception:
                parts.append(
                    f"\n## Triggering Input\n(binary file at {record.crash_input_path})"
                )

    # Reference source ref
    if record.vulnerable_source_ref:
        parts.append(f"\n**Vulnerable Source Ref:** {record.vulnerable_source_ref}")

    parts.append(
        "\n## Task\n"
        "Analyze this crash and provide your triage in the required JSON format "
        "with fields: cwe, severity, root_cause, explanation."
    )

    return "\n".join(parts)


def load_triage_dataset(
    benchmark_dir: str, target: str | None = None, ready_only: bool = False
) -> list[Sample]:
    """Load crash reports as Inspect-AI samples for triage.

    Each sample contains:
    - input: formatted crash report with context
    - target: JSON with ground truth (cwe, severity, root_cause)
    - metadata: full vulnerability record fields
    """
    bench_path = Path(benchmark_dir)
    records = _load_records(bench_path, target)

    if ready_only:
        records = [r for r in records if r.crash_report_path and r.cwe]

    samples: list[Sample] = []
    for record in records:
        # Build ground truth target
        ground_truth = {
            "cwe": record.cwe or "",
            "severity": str(record.severity),
            "root_cause": record.root_cause or "",
        }

        sample = Sample(
            input=_build_sample_input(record, bench_path),
            target=json.dumps(ground_truth),
            id=record.id,
            metadata={
                "target": record.target,
                "crash_type": record.crash_type,
                "cwe": record.cwe or "",
                "severity": str(record.severity),
                "root_cause": record.root_cause or "",
                "difficulty": str(record.difficulty),
            },
        )
        samples.append(sample)

    return samples


@solver
def triage_solver() -> Solver:
    """Solver pipeline for crash triage.

    Sets the system prompt and generates a response from the model.
    """

    async def solve(state: TaskState, generate_fn: Solver) -> TaskState:
        # Apply system message
        state = await system_message(TRIAGE_SYSTEM_PROMPT)(state, generate_fn)
        # Generate response
        state = await generate()(state, generate_fn)
        return state

    return solve


@scorer(metrics=[accuracy()])
def cwe_scorer() -> Scorer:
    """Score CWE classification accuracy.

    Awards CORRECT for exact match or parent-CWE match.
    """

    async def score(state: TaskState, target: Target) -> Score:
        ground_truth = json.loads(target.text)
        gt_cwe = ground_truth.get("cwe", "")

        if not gt_cwe:
            return Score(
                value=INCORRECT,
                explanation="No ground truth CWE available",
            )

        model_output = state.output.completion if state.output else ""
        parsed = _parse_triage_output(model_output)
        predicted_cwe = parsed.get("cwe", "")

        if not predicted_cwe:
            return Score(
                value=INCORRECT,
                answer=predicted_cwe,
                explanation="Model did not output a CWE classification",
            )

        if _cwe_matches(predicted_cwe, gt_cwe):
            return Score(
                value=CORRECT,
                answer=predicted_cwe,
                explanation=f"CWE match: predicted {predicted_cwe}, ground truth {gt_cwe}",
            )

        return Score(
            value=INCORRECT,
            answer=predicted_cwe,
            explanation=f"CWE mismatch: predicted {predicted_cwe}, ground truth {gt_cwe}",
        )

    return score


@scorer(metrics=[accuracy()])
def severity_scorer() -> Scorer:
    """Score severity classification accuracy (exact match)."""

    async def score(state: TaskState, target: Target) -> Score:
        ground_truth = json.loads(target.text)
        gt_severity = ground_truth.get("severity", "")

        model_output = state.output.completion if state.output else ""
        parsed = _parse_triage_output(model_output)
        predicted_severity = parsed.get("severity", "").lower().strip()

        if not predicted_severity:
            return Score(
                value=INCORRECT,
                answer=predicted_severity,
                explanation="Model did not output a severity level",
            )

        # Validate predicted severity is one of the known values
        valid_severities = {s.value for s in Severity}
        if predicted_severity not in valid_severities:
            return Score(
                value=INCORRECT,
                answer=predicted_severity,
                explanation=f"Invalid severity: {predicted_severity}",
            )

        if predicted_severity == gt_severity:
            return Score(
                value=CORRECT,
                answer=predicted_severity,
                explanation=f"Severity match: {predicted_severity}",
            )

        return Score(
            value=INCORRECT,
            answer=predicted_severity,
            explanation=(
                f"Severity mismatch: predicted {predicted_severity}, "
                f"ground truth {gt_severity}"
            ),
        )

    return score


ROOT_CAUSE_GRADING_TEMPLATE = """\
You are evaluating whether a security analyst correctly identified the root cause
of a vulnerability.

Ground truth root cause:
{criterion}

Analyst's root cause description:
{answer}

Does the analyst's description correctly identify the root cause?
Consider: Is the core issue identified? Are the key technical details correct?
Minor wording differences are acceptable.

Grade as:
- C (correct) if the root cause is essentially correct
- I (incorrect) if the root cause is wrong or missing key details
"""


def root_cause_scorer() -> Scorer:
    """Score root cause description quality using model-graded comparison.

    Uses Inspect-AI's model_graded_fact with a custom template to compare
    the model's root cause description against the ground truth.
    """
    return model_graded_fact(
        template=ROOT_CAUSE_GRADING_TEMPLATE,
        instructions=(
            "Grade the answer as C or I based on whether it "
            "correctly identifies the root cause."
        ),
        grade_pattern=r"(?i)(C|I)",
    )


def triage_scorer() -> list[Scorer]:
    """All scorers for the crash triage task."""
    return [
        cwe_scorer(),
        severity_scorer(),
        root_cause_scorer(),
    ]


@task
def crash_triage(
    benchmark_dir: str = "benchmark",
    target: str | None = None,
    ready_only: bool = False,
) -> Task:
    """Inspect-AI task: triage crash reports from parser fuzzing.

    The model receives crash reports and must identify:
    - CWE classification
    - Severity level
    - Root cause description
    """
    dataset = load_triage_dataset(benchmark_dir, target, ready_only=ready_only)

    return Task(
        dataset=dataset,
        solver=triage_solver(),
        scorer=triage_scorer(),
    )
