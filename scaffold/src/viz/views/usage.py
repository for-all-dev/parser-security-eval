"""Model usage / token cost page."""

from __future__ import annotations

from pathlib import Path

import plotly.express as px
import streamlit as st

from viz.loader import LogData

# claude-sonnet-4-6 pricing (per million tokens)
_COST_PER_M_IN = 3.0
_COST_PER_M_OUT = 15.0


def _estimate_cost(inp: int, out: int) -> float:
    return inp / 1_000_000 * _COST_PER_M_IN + out / 1_000_000 * _COST_PER_M_OUT


def render(logs: dict[str, LogData]) -> None:
    st.header("Model Usage")

    if not logs:
        st.info("Select one or more .eval files in the sidebar.")
        return

    for path, log in logs.items():
        fname = Path(path).stem
        st.subheader(fname)
        df = log.df

        total_in = int(df["input_tokens"].sum()) if "input_tokens" in df.columns else 0
        total_out = (
            int(df["output_tokens"].sum()) if "output_tokens" in df.columns else 0
        )
        total_tokens = (
            int(df["total_tokens"].sum()) if "total_tokens" in df.columns else 0
        )
        cost = _estimate_cost(total_in, total_out)

        cols = st.columns(4)
        cols[0].metric("Total Input Tokens", f"{total_in:,}")
        cols[1].metric("Total Output Tokens", f"{total_out:,}")
        cols[2].metric("Total Tokens", f"{total_tokens:,}")
        cols[3].metric("Est. Cost (claude-sonnet-4-6)", f"${cost:.4f}")

        st.caption("Pricing: $3/M input, $15/M output (claude-sonnet-4-6)")

        col1, col2 = st.columns(2)

        with col1:
            fig_hist = px.histogram(
                df,
                x="total_tokens",
                nbins=30,
                title="Total Tokens per Sample",
                labels={"total_tokens": "Total Tokens"},
            )
            st.plotly_chart(
                fig_hist, use_container_width=True, key=f"usage_hist_{fname}"
            )

        with col2:
            if "total_time" in df.columns:
                fig_scatter = px.scatter(
                    df,
                    x="total_tokens",
                    y="total_time",
                    color="target" if "target" in df.columns else None,
                    title="Tokens vs Time",
                    labels={"total_tokens": "Total Tokens", "total_time": "Time (s)"},
                )
                st.plotly_chart(
                    fig_scatter, use_container_width=True, key=f"usage_scatter_{fname}"
                )

        st.divider()
