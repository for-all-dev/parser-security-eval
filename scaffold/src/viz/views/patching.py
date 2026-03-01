"""Patching funnel page: pipeline funnel, score distribution, diff-size scatter."""

from __future__ import annotations

from pathlib import Path

import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from viz.loader import LogData, TaskType


def render(logs: dict[str, LogData]) -> None:
    st.header("Patching Funnel")

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

    for path, log in patch_logs.items():
        fname = Path(path).stem
        st.subheader(fname)
        df = log.df

        # 5-stage funnel
        n_total = len(df)
        n_applies = int(df["patch_applies"].sum())
        n_compiles = int(df["compiles"].sum())
        n_elim = int(df["crash_eliminated"].sum())
        n_pass = int(df["tests_pass"].sum())

        stages = [
            "Attempted",
            "Patch Applies",
            "Compiles",
            "Crash Eliminated",
            "Tests Pass",
        ]
        values = [n_total, n_applies, n_compiles, n_elim, n_pass]

        fig_funnel = go.Figure(
            go.Funnel(
                y=stages,
                x=values,
                textinfo="value+percent initial",
            )
        )
        fig_funnel.update_layout(title="Patch Pipeline Funnel")
        st.plotly_chart(
            fig_funnel, use_container_width=True, key=f"patching_funnel_{fname}"
        )

        col1, col2 = st.columns(2)

        with col1:
            fig_hist = px.histogram(
                df,
                x="patch_score",
                nbins=20,
                title="Patch Score Distribution",
                range_x=[0, 1],
            )
            st.plotly_chart(
                fig_hist, use_container_width=True, key=f"patching_hist_{fname}"
            )

        with col2:
            fig_scatter = px.scatter(
                df,
                x="diff_lines",
                y="patch_score",
                color="target",
                title="Diff Size vs Patch Score",
                labels={"diff_lines": "Diff Lines", "patch_score": "Patch Score"},
            )
            st.plotly_chart(
                fig_scatter, use_container_width=True, key=f"patching_scatter_{fname}"
            )

        st.divider()
