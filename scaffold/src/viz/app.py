"""Streamlit dashboard entry point for parser security eval results."""

from __future__ import annotations

import sys
from pathlib import Path

# Ensure src/ is on sys.path so `viz.*` imports resolve when streamlit
# runs this file directly (streamlit adds src/viz/ but not its parent).
_src_dir = Path(__file__).parent.parent
if str(_src_dir) not in sys.path:
    sys.path.insert(0, str(_src_dir))

import streamlit as st  # noqa: E402

from viz.loader import LogData, load_log_data  # noqa: E402
from viz.views import (  # noqa: E402
    breakdown,
    diff_viewer,
    overview,
    patching,
    samples,
    trajectory,
    usage,
)

LOG_DIR = Path(__file__).parent.parent.parent / "logs"

st.set_page_config(
    page_title="Parser Security Eval",
    page_icon=":shield:",
    layout="wide",
)


def _find_eval_files() -> list[Path]:
    if not LOG_DIR.exists():
        return []
    files = sorted(
        LOG_DIR.glob("*.eval"), key=lambda p: p.stat().st_mtime, reverse=True
    )
    return files


def main() -> None:
    st.title("Parser Security Eval Dashboard")

    eval_files = _find_eval_files()

    with st.sidebar:
        st.header("Log Files")
        if not eval_files:
            st.warning(f"No .eval files found in `{LOG_DIR}`.")
            selected_paths: list[str] = []
        else:
            # Truncate long filenames with ellipsis; full name shown in help tooltip.
            st.markdown(
                """
                <style>
                [data-testid="stCheckbox"] label div p {
                    white-space: nowrap !important;
                    overflow: hidden !important;
                    text-overflow: ellipsis !important;
                }
                </style>
                """,
                unsafe_allow_html=True,
            )
            selected_paths = []
            with st.container(height=200):
                for p in eval_files:
                    if st.checkbox(
                        p.name, value=True, key=f"log_{p.name}", help=p.name
                    ):
                        selected_paths.append(str(p))

        st.divider()
        page = st.radio(
            "Page",
            [
                "Overview",
                "Score Breakdown",
                "Sample Browser",
                "Patching Funnel",
                "Patch Diff Viewer",
                "Agent Trajectory",
                "Model Usage",
            ],
        )

    # Load selected logs
    logs: dict[str, LogData] = {}
    for path in selected_paths:
        logs[path] = load_log_data(path)

    # Route to page
    if page == "Overview":
        overview.render(logs)
    elif page == "Score Breakdown":
        breakdown.render(logs)
    elif page == "Sample Browser":
        samples.render(logs)
    elif page == "Patching Funnel":
        patching.render(logs)
    elif page == "Patch Diff Viewer":
        diff_viewer.render(logs)
    elif page == "Agent Trajectory":
        trajectory.render(logs)
    elif page == "Model Usage":
        usage.render(logs)


if __name__ == "__main__":
    main()
