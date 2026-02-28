"""EvalLog → pandas DataFrame loader for the Streamlit visualizer."""

from __future__ import annotations

import re
from enum import Enum
from typing import Any

import pandas as pd
import streamlit as st
from inspect_ai.log import (
    EvalLog,
    EvalSampleSummary,
    read_eval_log,
    read_eval_log_sample_summaries,
    read_eval_log_samples,
)
from pydantic import BaseModel


class TaskType(str, Enum):
    CRASH_TRIAGE = "crash_triage"
    VULNERABILITY_PATCHING = "vulnerability_patching"
    UNKNOWN = "unknown"


def _detect_task_type(task_name: str) -> TaskType:
    if "crash_triage" in task_name:
        return TaskType.CRASH_TRIAGE
    if "vulnerability_patching" in task_name or "vulnerability-patching" in task_name:
        return TaskType.VULNERABILITY_PATCHING
    return TaskType.UNKNOWN


def _ci_to_int(value: Any) -> int:
    """Map score value C/I/None → 1/0/-1 (sentinel for no ground truth)."""
    if value is None:
        return -1
    s = str(value).strip().upper()
    if s == "C":
        return 1
    if s == "I":
        return 0
    return -1


_PATCH_RE = re.compile(
    r"patch_applies=(\w+).*?compiles=(\w+).*?crash_eliminated=(\w+).*?tests_pass=(\w+).*?diff_lines=(\d+)",
    re.DOTALL,
)


def _parse_patch_explanation(explanation: str | None) -> dict[str, Any]:
    """Parse patch scorer explanation string into structured fields."""
    defaults: dict[str, Any] = {
        "patch_applies": False,
        "compiles": False,
        "crash_eliminated": False,
        "tests_pass": False,
        "diff_lines": 0,
    }
    if not explanation:
        return defaults
    m = _PATCH_RE.search(explanation)
    if not m:
        return defaults
    return {
        "patch_applies": m.group(1).lower() == "true",
        "compiles": m.group(2).lower() == "true",
        "crash_eliminated": m.group(3).lower() == "true",
        "tests_pass": m.group(4).lower() == "true",
        "diff_lines": int(m.group(5)),
    }


def _usage_from_summary(summary: EvalSampleSummary) -> tuple[int, int, int]:
    """Return (input_tokens, output_tokens, total_tokens) from a sample summary."""
    if not summary.model_usage:
        return 0, 0, 0
    # Sum across all models (usually just one)
    inp = sum(u.input_tokens for u in summary.model_usage.values())
    out = sum(u.output_tokens for u in summary.model_usage.values())
    tot = sum(u.total_tokens for u in summary.model_usage.values())
    return inp, out, tot


def _summary_to_row_triage(summary: EvalSampleSummary) -> dict[str, Any]:
    meta = summary.metadata or {}
    scores = summary.scores or {}

    cwe_score_obj = scores.get("cwe_scorer")
    sev_score_obj = scores.get("severity_scorer")
    fact_score_obj = scores.get("model_graded_fact")

    cwe_score = _ci_to_int(cwe_score_obj.value if cwe_score_obj else None)
    severity_score = _ci_to_int(sev_score_obj.value if sev_score_obj else None)
    fact_score = _ci_to_int(fact_score_obj.value if fact_score_obj else None)

    cwe_predicted = cwe_score_obj.answer if cwe_score_obj else None
    sev_predicted = sev_score_obj.answer if sev_score_obj else None

    inp, out, tot = _usage_from_summary(summary)
    return {
        "sample_id": str(summary.id),
        "target": meta.get("target", ""),
        "difficulty": meta.get("difficulty", ""),
        "crash_type": meta.get("crash_type", ""),
        "cwe": meta.get("cwe", ""),
        "severity": meta.get("severity", ""),
        "total_time": summary.total_time or 0.0,
        "input_tokens": inp,
        "output_tokens": out,
        "total_tokens": tot,
        "completed": summary.completed,
        "cwe_score": cwe_score,
        "severity_score": severity_score,
        "fact_score": fact_score,
        "cwe_predicted": cwe_predicted,
        "severity_predicted": sev_predicted,
    }


def _summary_to_row_patching(summary: EvalSampleSummary) -> dict[str, Any]:
    meta = summary.metadata or {}
    scores = summary.scores or {}

    patch_obj = scores.get("_patch_scorer")
    patch_score = patch_obj.as_float() if patch_obj else 0.0
    explanation = patch_obj.explanation if patch_obj else None
    parsed = _parse_patch_explanation(explanation)

    inp, out, tot = _usage_from_summary(summary)

    pipeline_stages = []
    if parsed["patch_applies"]:
        pipeline_stages.append("patch_applies")
    if parsed["compiles"]:
        pipeline_stages.append("compiles")
    if parsed["crash_eliminated"]:
        pipeline_stages.append("crash_eliminated")
    if parsed["tests_pass"]:
        pipeline_stages.append("tests_pass")

    return {
        "sample_id": str(summary.id),
        "target": meta.get("target", ""),
        "difficulty": meta.get("difficulty", ""),
        "sanitizer": meta.get("sanitizer", ""),
        "total_time": summary.total_time or 0.0,
        "input_tokens": inp,
        "output_tokens": out,
        "total_tokens": tot,
        "completed": summary.completed,
        "patch_score": patch_score,
        "patch_applies": parsed["patch_applies"],
        "compiles": parsed["compiles"],
        "crash_eliminated": parsed["crash_eliminated"],
        "tests_pass": parsed["tests_pass"],
        "diff_lines": parsed["diff_lines"],
        "pipeline_stage": ", ".join(pipeline_stages) if pipeline_stages else "none",
        "message_count": summary.message_count or 0,
    }


class LogData(BaseModel):
    """Parsed representation of a single .eval log file."""

    model_config = {"arbitrary_types_allowed": True}

    path: str
    task_type: TaskType
    model: str
    created: str
    n_samples: int
    df: pd.DataFrame
    header: EvalLog


@st.cache_data(show_spinner="Loading eval log…")
def load_log_data(path: str) -> LogData:
    """Read an .eval file and return a LogData with a populated DataFrame."""
    header = read_eval_log(path, header_only=True)
    task_type = _detect_task_type(header.eval.task)

    summaries = read_eval_log_sample_summaries(path)

    if task_type == TaskType.CRASH_TRIAGE:
        rows = [_summary_to_row_triage(s) for s in summaries]
    elif task_type == TaskType.VULNERABILITY_PATCHING:
        rows = [_summary_to_row_patching(s) for s in summaries]
    else:
        rows = []

    df = pd.DataFrame(rows)

    return LogData(
        path=path,
        task_type=task_type,
        model=header.eval.model,
        created=str(header.eval.created),
        n_samples=len(summaries),
        df=df,
        header=header,
    )


_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[mK]")


class PatchSampleDetail(BaseModel):
    """Prompt + ground-truth diff for one patching sample (from summaries, no full load)."""

    sample_id: str
    prompt_header: str  # structured header lines before "--- Crash Report ---"
    crash_report: str  # everything from "--- Crash Report ---" onward, ANSI stripped
    ground_truth_diff: str  # sample.target verbatim


@st.cache_data(show_spinner="Loading patch inputs…")
def load_patch_details(log_path: str) -> dict[str, PatchSampleDetail]:
    """Return PatchSampleDetail for every sample in a patching log (fast, uses summaries)."""
    summaries = read_eval_log_sample_summaries(log_path)
    result: dict[str, PatchSampleDetail] = {}
    for s in summaries:
        raw_input = str(s.input or "")
        raw_target = str(s.target or "")

        # Split prompt into header block + crash report
        split_marker = "--- Crash Report ---"
        if split_marker in raw_input:
            header_part, crash_part = raw_input.split(split_marker, 1)
            crash_report = _ANSI_RE.sub("", split_marker + crash_part)
        else:
            header_part = raw_input
            crash_report = ""

        result[str(s.id)] = PatchSampleDetail(
            sample_id=str(s.id),
            prompt_header=header_part.strip(),
            crash_report=crash_report.strip(),
            ground_truth_diff=raw_target.strip(),
        )
    return result


class TrajTurn(BaseModel):
    """One agent turn: an assistant reasoning step followed by a tool call/result."""

    turn_index: int
    reasoning: str  # assistant text before / around the diff
    proposed_diff: str  # extracted unified diff (may be empty)
    tool_name: str  # e.g. "try_patch"
    tool_result: str  # full tool output text
    tool_ok: bool  # True if result indicates success
    model_time: float  # seconds for the LLM call
    tool_time: float  # seconds for the tool execution


_TOOL_SUCCESS_RE = re.compile(r"applied|success", re.IGNORECASE)
# Reuse diff-extraction pattern from views — inline here to avoid circular import
_TRAJ_CODE_RE = re.compile(r"```(?:diff)?\s*\n(.*?)```", re.DOTALL)
_TRAJ_DIFF_HDR_RE = re.compile(r"((?:diff --git|---|\+\+\+).*)", re.MULTILINE)


def _extract_diff_from_text(text: str) -> tuple[str, str]:
    """Return (prose, diff) extracted from assistant text."""
    for m in _TRAJ_CODE_RE.finditer(text):
        block = m.group(1)
        if any(
            line.startswith(("diff --git", "--- ", "+++ ", "@@"))
            for line in block.splitlines()
        ):
            return text[: m.start()].strip(), block.strip()
    m2 = _TRAJ_DIFF_HDR_RE.search(text)
    if m2:
        return text[: m2.start()].strip(), text[m2.start() :].strip()
    return text.strip(), ""


def _resolve_attachment(value: Any, attachments: dict[str, Any]) -> str:
    """If value is an attachment:// reference, resolve it; otherwise return as-is."""
    s = str(value) if value else ""
    if s.startswith("attachment://"):
        key = s[len("attachment://") :]
        return str(attachments.get(key, "")) or ""
    return s


def _parse_trajectory(sample: Any) -> list[TrajTurn]:
    """Build ordered TrajTurn list from sample events (primary) + messages (reasoning text)."""
    attachments: dict[str, Any] = sample.attachments or {}

    # Pull ModelEvent + ToolEvent in chronological order
    paired: list[tuple[Any, Any]] = []  # (ModelEvent, ToolEvent | None)
    action_events = [
        e
        for e in (sample.events or [])
        if type(e).__name__ in ("ModelEvent", "ToolEvent")
    ]
    i = 0
    while i < len(action_events):
        e = action_events[i]
        if type(e).__name__ == "ModelEvent":
            nxt = action_events[i + 1] if i + 1 < len(action_events) else None
            tool_ev = nxt if nxt and type(nxt).__name__ == "ToolEvent" else None
            paired.append((e, tool_ev))
            i += 2 if tool_ev else 1
        else:
            i += 1

    # Also collect reasoning text from assistant messages (richer than event output)
    assistant_texts: list[str] = []
    for msg in sample.messages or []:
        if msg.role == "assistant":
            text = ""
            content = msg.content
            if isinstance(content, list):
                for part in content:
                    if hasattr(part, "text") and part.text:
                        text += part.text
            elif isinstance(content, str):
                text = content
            assistant_texts.append(text)

    turns: list[TrajTurn] = []
    for turn_idx, (model_ev, tool_ev) in enumerate(paired):
        md = model_ev.model_dump()
        m_time = float(md.get("working_time", 0) or 0)

        # Reasoning: prefer the matching assistant message (same order), fall back to event output
        reasoning = assistant_texts[turn_idx] if turn_idx < len(assistant_texts) else ""
        if not reasoning:
            for choice in md.get("output", {}).get("choices", []):
                for part in choice.get("message", {}).get("content", []):
                    if isinstance(part, dict) and part.get("type") == "text":
                        reasoning += part.get("text", "")

        # Proposed diff: from ToolEvent arguments, resolved via attachments
        proposed_diff = ""
        tool_name = "try_patch"
        tool_result = ""
        tool_ok = False
        t_time = 0.0

        if tool_ev is not None:
            td = tool_ev.model_dump()
            tool_name = td.get("function", "try_patch") or "try_patch"
            t_time = float(td.get("working_time", 0) or 0)
            tool_result = str(td.get("result", "") or "")
            tool_ok = bool(_TOOL_SUCCESS_RE.search(tool_result))
            args = td.get("arguments", {}) or {}
            if isinstance(args, dict):
                proposed_diff = _resolve_attachment(args.get("diff", ""), attachments)

        turns.append(
            TrajTurn(
                turn_index=turn_idx,
                reasoning=reasoning,
                proposed_diff=proposed_diff,
                tool_name=tool_name,
                tool_result=tool_result,
                tool_ok=tool_ok,
                model_time=m_time,
                tool_time=t_time,
            )
        )

    return turns


@st.cache_data(show_spinner="Loading trajectory…")
def load_trajectory(log_path: str, sample_id: str) -> list[TrajTurn]:
    """Load agent turns for a single sample (requires full sample read)."""
    for sample in read_eval_log_samples(log_path):
        if str(sample.id) == sample_id:
            return _parse_trajectory(sample)
    return []


@st.cache_data(show_spinner="Loading sample output…")
def load_completion(log_path: str, sample_id: str) -> str:
    """Lazily load the full model completion for a single sample."""
    for sample in read_eval_log_samples(log_path):
        if str(sample.id) == sample_id:
            msgs = sample.output.completion if sample.output else ""
            return str(msgs) if msgs else "(no output)"
    return "(sample not found)"
