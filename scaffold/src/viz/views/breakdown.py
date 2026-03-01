"""Score breakdown page: bar charts and confusion heatmap per log."""

from __future__ import annotations

from pathlib import Path

import pandas as pd
import plotly.express as px
import streamlit as st

from viz.loader import LogData, TaskType


def _accuracy_by(df: pd.DataFrame, score_col: str, group_col: str) -> pd.DataFrame:
    """Mean score_col (excluding -1) grouped by group_col."""
    valid = df[df[score_col] >= 0].copy()
    if valid.empty:
        return pd.DataFrame(columns=pd.Index([group_col, "accuracy"]))
    grouped = valid.groupby(group_col)[score_col].mean().reset_index()
    grouped.columns = pd.Index([group_col, "accuracy"])
    return grouped


def _render_triage(log: LogData, fname: str) -> None:
    df = log.df
    scorer = st.selectbox(
        "Scorer",
        ["CWE (cwe_score)", "Severity (severity_score)", "Root Cause (fact_score)"],
        key=f"scorer_{log.path}",
    )
    score_col = {
        "CWE (cwe_score)": "cwe_score",
        "Severity (severity_score)": "severity_score",
        "Root Cause (fact_score)": "fact_score",
    }[scorer]

    tab_target, tab_diff, tab_crash = st.tabs(
        ["By Target", "By Difficulty", "By Crash Type"]
    )

    with tab_target:
        data = _accuracy_by(df, score_col, "target")
        if not data.empty:
            fig = px.bar(
                data,
                x="target",
                y="accuracy",
                title="Accuracy by Target",
                range_y=[0, 1],
            )
            st.plotly_chart(
                fig, use_container_width=True, key=f"breakdown_target_{fname}"
            )
        else:
            st.info("No data.")

    with tab_diff:
        data = _accuracy_by(df, score_col, "difficulty")
        if not data.empty:
            order = [
                d for d in ["easy", "medium", "hard"] if d in data["difficulty"].values
            ]
            data["difficulty"] = pd.Categorical(
                data["difficulty"], categories=order, ordered=True
            )
            data = data.sort_values("difficulty")
            fig = px.bar(
                data,
                x="difficulty",
                y="accuracy",
                title="Accuracy by Difficulty",
                range_y=[0, 1],
            )
            st.plotly_chart(
                fig, use_container_width=True, key=f"breakdown_difficulty_{fname}"
            )
        else:
            st.info("No data.")

    with tab_crash:
        data = _accuracy_by(df, score_col, "crash_type")
        if not data.empty:
            fig = px.bar(
                data,
                x="crash_type",
                y="accuracy",
                title="Accuracy by Crash Type",
                range_y=[0, 1],
            )
            fig.update_layout(xaxis_tickangle=-30)
            st.plotly_chart(
                fig, use_container_width=True, key=f"breakdown_crash_{fname}"
            )
        else:
            st.info("No data.")

    # CWE confusion heatmap (only for cwe scorer)
    if (
        score_col == "cwe_score"
        and "cwe" in df.columns
        and "cwe_predicted" in df.columns
    ):
        st.subheader("CWE Confusion Heatmap")
        valid = df[df["cwe"].notna() & df["cwe_predicted"].notna()]
        if not valid.empty:
            ct = pd.crosstab(valid["cwe"], valid["cwe_predicted"])
            fig = px.imshow(
                ct, title="Ground Truth CWE vs Predicted CWE", aspect="auto"
            )
            st.plotly_chart(
                fig, use_container_width=True, key=f"breakdown_cwe_heatmap_{fname}"
            )


def _render_patching(log: LogData, fname: str) -> None:
    df = log.df
    tab_target, tab_diff = st.tabs(["By Target", "By Difficulty"])

    with tab_target:
        if "target" in df.columns:
            data = df.groupby("target")["patch_score"].mean().reset_index()
            fig = px.bar(
                data,
                x="target",
                y="patch_score",
                title="Mean Patch Score by Target",
                range_y=[0, 1],
            )
            st.plotly_chart(
                fig, use_container_width=True, key=f"breakdown_patch_target_{fname}"
            )

    with tab_diff:
        if "difficulty" in df.columns:
            data = df.groupby("difficulty")["patch_score"].mean().reset_index()
            fig = px.bar(
                data,
                x="difficulty",
                y="patch_score",
                title="Mean Patch Score by Difficulty",
                range_y=[0, 1],
            )
            st.plotly_chart(
                fig, use_container_width=True, key=f"breakdown_patch_difficulty_{fname}"
            )
        else:
            st.info("No difficulty data for patching logs.")


def render(logs: dict[str, LogData]) -> None:
    st.header("Score Breakdown")

    if not logs:
        st.info("Select one or more .eval files in the sidebar.")
        return

    for path, log in logs.items():
        fname = Path(path).stem
        st.subheader(fname)

        if log.task_type == TaskType.CRASH_TRIAGE:
            _render_triage(log, fname)
        elif log.task_type == TaskType.VULNERABILITY_PATCHING:
            _render_patching(log, fname)
        else:
            st.warning("Unknown task type — no breakdown available.")

        st.divider()
