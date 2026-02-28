"""Patch diff viewer: per-sample vulnerability description, ground-truth diff, model output."""

from __future__ import annotations

import re

import streamlit as st

from viz.loader import LogData, TaskType, load_completion, load_patch_details

# Regex to find ```diff ... ``` or bare diff headers in model output
_CODE_BLOCK_RE = re.compile(r"```(?:diff)?\s*\n(.*?)```", re.DOTALL)
_DIFF_HEADER_RE = re.compile(r"((?:diff --git|---|\+\+\+).*)", re.MULTILINE)


def _extract_model_diff(completion: str) -> tuple[str, str]:
    """Split model output into (prose, diff).

    Returns (prose_text, diff_text). If no diff block is found, diff_text is empty.
    """
    # Prefer an explicit ```diff or ``` code block that looks like a diff
    for m in _CODE_BLOCK_RE.finditer(completion):
        block = m.group(1)
        if any(
            line.startswith(("diff --git", "--- ", "+++ ", "@@"))
            for line in block.splitlines()
        ):
            prose = completion[: m.start()].strip()
            return prose, block.strip()

    # Fall back: find bare diff lines
    m_header = _DIFF_HEADER_RE.search(completion)
    if m_header:
        prose = completion[: m_header.start()].strip()
        diff_block = completion[m_header.start() :].strip()
        return prose, diff_block

    return completion.strip(), ""


def _score_badge(row: dict[str, object]) -> str:
    score = row.get("patch_score", 0.0)
    applies = row.get("patch_applies", False)
    compiles = row.get("compiles", False)
    eliminated = row.get("crash_eliminated", False)
    tests = row.get("tests_pass", False)
    stages = [
        s
        for s, v in [
            ("applies", applies),
            ("compiles", compiles),
            ("crash eliminated", eliminated),
            ("tests pass", tests),
        ]
        if v
    ]
    stage_str = " → ".join(stages) if stages else "none"
    return f"score={score:.2f} | {stage_str}"


def render(logs: dict[str, LogData]) -> None:
    st.header("Patch Diff Viewer")

    patch_logs = {
        p: lg
        for p, lg in logs.items()
        if lg.task_type == TaskType.VULNERABILITY_PATCHING
    }

    if not patch_logs:
        st.info(
            "No vulnerability-patching logs selected. Load a patching .eval file in the sidebar."
        )
        return

    # If multiple patching logs, let user pick one
    log_names = list(patch_logs.keys())
    if len(log_names) > 1:
        selected_path = st.selectbox(
            "Log file", log_names, format_func=lambda p: p.split("/")[-1]
        )
    else:
        selected_path = log_names[0]

    log = patch_logs[selected_path]
    df = log.df

    # Build selector options: "ARVO-XXXXX — libxml2 | score=0.00 | none"
    options = [
        f"{row['sample_id']} — {row.get('target', '?')} | {_score_badge(dict(row))}"
        for _, row in df.iterrows()
    ]
    id_for_option = {
        opt: str(row["sample_id"]) for opt, (_, row) in zip(options, df.iterrows())
    }

    selected_option = st.selectbox("Sample", options)
    if not selected_option:
        return
    sample_id = id_for_option[selected_option]

    # Load lightweight details (from summaries cache — fast)
    details = load_patch_details(selected_path)
    detail = details.get(sample_id)
    if not detail:
        st.error(f"Details not found for {sample_id}")
        return

    st.divider()

    # ── Section 1: Vulnerability description ────────────────────────────────
    with st.expander("Vulnerability Description", expanded=True):
        # Parse the header lines into a neat table
        header_lines = detail.prompt_header.splitlines()
        pairs: list[tuple[str, str]] = []
        for line in header_lines:
            if ": " in line:
                key, _, val = line.partition(": ")
                pairs.append((key.strip(), val.strip()))

        if pairs:
            col1, col2 = st.columns([1, 3])
            with col1:
                for k, _ in pairs:
                    st.markdown(f"**{k}**")
            with col2:
                for _, v in pairs:
                    st.write(v)

        if detail.crash_report:
            st.markdown("**Crash Report**")
            with st.container(height=300):
                st.code(detail.crash_report, language=None, wrap_lines=False)

    # ── Section 2: Ground truth patch ───────────────────────────────────────
    with st.expander("Ground Truth Patch", expanded=True):
        if detail.ground_truth_diff:
            with st.container(height=300):
                st.code(detail.ground_truth_diff, language="diff", wrap_lines=False)
        else:
            st.info("No ground truth diff available.")

    # ── Section 3: Model's proposed patch ───────────────────────────────────
    with st.expander("Model's Proposed Patch", expanded=True):
        with st.spinner("Loading model output…"):
            completion = load_completion(selected_path, sample_id)

        prose, diff_block = _extract_model_diff(completion)

        if prose:
            st.markdown("**Analysis**")
            with st.container(height=350):
                st.markdown(prose)

        if diff_block:
            st.markdown("**Proposed Diff**")
            with st.container(height=350):
                st.code(diff_block, language="diff", wrap_lines=False)
        elif completion and not prose:
            with st.container(height=400):
                st.code(completion, language=None, wrap_lines=True)
