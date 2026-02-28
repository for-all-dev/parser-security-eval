"""Sample browser page: filterable table with lazy-loaded model output."""

from __future__ import annotations

import pandas as pd
import streamlit as st

from viz.loader import LogData, TaskType, load_completion


def _filter_df(
    df: pd.DataFrame, target: str, difficulty: str, search: str
) -> pd.DataFrame:
    if target != "All":
        df = df[df["target"] == target]
    if difficulty != "All":
        df = df[df["difficulty"] == difficulty]
    if search:
        df = df[df["sample_id"].str.contains(search, case=False, na=False)]
    return df


def _display_cols(task_type: TaskType) -> list[str]:
    common = [
        "sample_id",
        "target",
        "difficulty",
        "completed",
        "total_time",
        "total_tokens",
    ]
    if task_type == TaskType.CRASH_TRIAGE:
        return common + [
            "crash_type",
            "cwe",
            "cwe_score",
            "severity",
            "severity_score",
            "fact_score",
        ]
    if task_type == TaskType.VULNERABILITY_PATCHING:
        return common + [
            "sanitizer",
            "patch_score",
            "patch_applies",
            "compiles",
            "crash_eliminated",
            "tests_pass",
        ]
    return common


def render(logs: dict[str, LogData]) -> None:
    st.header("Sample Browser")

    if not logs:
        st.info("Select one or more .eval files in the sidebar.")
        return

    # Pick which log to browse if multiple are loaded
    log_names = list(logs.keys())
    if len(log_names) > 1:
        selected_path = st.selectbox(
            "Log file", log_names, format_func=lambda p: p.split("/")[-1]
        )
    else:
        selected_path = log_names[0]

    log = logs[selected_path]
    df = log.df

    # Filters
    col1, col2, col3 = st.columns(3)
    targets = (
        ["All"] + sorted(df["target"].dropna().unique().tolist())
        if "target" in df.columns
        else ["All"]
    )
    difficulties = (
        ["All"]
        + [d for d in ["easy", "medium", "hard"] if d in df["difficulty"].unique()]
        if "difficulty" in df.columns
        else ["All"]
    )

    with col1:
        target_filter = st.selectbox("Target", targets, key="sb_target")
    with col2:
        diff_filter = st.selectbox("Difficulty", difficulties, key="sb_diff")
    with col3:
        search = st.text_input("Search sample_id", key="sb_search")

    filtered = _filter_df(df, target_filter, diff_filter, search)
    display_cols = [c for c in _display_cols(log.task_type) if c in filtered.columns]
    st.caption(f"{len(filtered)} samples shown")

    event = st.dataframe(
        filtered[display_cols].reset_index(drop=True),
        use_container_width=True,
        on_select="rerun",
        selection_mode="single-row",
    )

    # Detail panel for selected row
    _sel = getattr(event, "selection", None)
    selected_rows: list[int] = _sel.get("rows", []) if _sel else []
    if selected_rows:
        row_idx = selected_rows[0]
        row = filtered.iloc[row_idx]
        sample_id = str(row["sample_id"])

        st.subheader(f"Sample: {sample_id}")
        meta_cols = st.columns(3)
        meta_cols[0].write(f"**Target:** {row.get('target', 'N/A')}")
        meta_cols[1].write(f"**Difficulty:** {row.get('difficulty', 'N/A')}")
        meta_cols[2].write(f"**Time:** {row.get('total_time', 0):.1f}s")

        with st.expander("Model Output (click to expand)", expanded=True):
            with st.spinner("Loading model output…"):
                completion = load_completion(selected_path, sample_id)
            st.code(completion, language=None, wrap_lines=True)
