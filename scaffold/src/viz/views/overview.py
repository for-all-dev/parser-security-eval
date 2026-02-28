"""Overview page: summary metrics per loaded log."""

from __future__ import annotations

import streamlit as st

from viz.loader import LogData, TaskType


def _accuracy(df, col: str) -> float:
    """Mean of col, excluding sentinel -1 (no ground truth)."""
    valid = df[df[col] >= 0][col]
    return float(valid.mean()) if len(valid) > 0 else 0.0


def render(logs: dict[str, LogData]) -> None:
    st.header("Overview")

    if not logs:
        st.info("Select one or more .eval files in the sidebar.")
        return

    for path, log in logs.items():
        fname = path.split("/")[-1]
        st.subheader(fname)
        df = log.df

        completed = (
            int(df["completed"].sum()) if "completed" in df.columns else log.n_samples
        )
        mean_time = (
            float(df["total_time"].mean()) if "total_time" in df.columns else 0.0
        )

        if log.task_type == TaskType.CRASH_TRIAGE:
            cwe_acc = _accuracy(df, "cwe_score")
            sev_acc = _accuracy(df, "severity_score")
            fact_acc = _accuracy(df, "fact_score")

            cols = st.columns(6)
            cols[0].metric("Samples", log.n_samples)
            cols[1].metric("Completed", completed)
            cols[2].metric("CWE Accuracy", f"{cwe_acc:.1%}")
            cols[3].metric("Severity Accuracy", f"{sev_acc:.1%}")
            cols[4].metric("Root-Cause Accuracy", f"{fact_acc:.1%}")
            cols[5].metric("Avg Time (s)", f"{mean_time:.1f}")

        elif log.task_type == TaskType.VULNERABILITY_PATCHING:
            mean_score = (
                float(df["patch_score"].mean()) if "patch_score" in df.columns else 0.0
            )
            full_success = (
                int(df["tests_pass"].sum()) if "tests_pass" in df.columns else 0
            )
            patch_applies = (
                int(df["patch_applies"].sum()) if "patch_applies" in df.columns else 0
            )

            cols = st.columns(6)
            cols[0].metric("Samples", log.n_samples)
            cols[1].metric("Completed", completed)
            cols[2].metric("Mean Patch Score", f"{mean_score:.3f}")
            cols[3].metric("Full Successes", full_success)
            cols[4].metric("Patches Apply", patch_applies)
            cols[5].metric("Avg Time (s)", f"{mean_time:.1f}")

        else:
            cols = st.columns(2)
            cols[0].metric("Samples", log.n_samples)
            cols[1].metric("Completed", completed)

        st.caption(f"Model: `{log.model}` | Created: {log.created}")
        st.divider()
