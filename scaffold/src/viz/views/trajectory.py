"""Agent trajectory viewer: per-turn reasoning, proposed diffs, and tool results."""

from __future__ import annotations

import streamlit as st

from viz.loader import LogData, TaskType, TrajTurn, load_trajectory

# Minimum message count to consider a log as having agent trajectories
_AGENT_THRESHOLD = 5


def _result_label(turn: TrajTurn) -> str:
    return "✅ Accepted" if turn.tool_ok else "❌ Rejected"


def _render_turn(turn: TrajTurn, expanded: bool) -> None:
    result_icon = "✅" if turn.tool_ok else "❌"
    label = (
        f"{result_icon} Turn {turn.turn_index + 1} — `{turn.tool_name}` "
        f"({_result_label(turn)}) · LLM {turn.model_time:.1f}s · tool {turn.tool_time:.2f}s"
    )
    with st.expander(label, expanded=expanded):
        if turn.reasoning:
            st.markdown("**Reasoning**")
            with st.container(height=200):
                st.markdown(turn.reasoning)

        if turn.proposed_diff:
            st.markdown("**Proposed Diff**")
            with st.container(height=250):
                st.code(turn.proposed_diff, language="diff", wrap_lines=False)

        icon = "✅" if turn.tool_ok else "❌"
        st.markdown(f"**Tool Result** {icon}")
        truncated = turn.tool_result[:1500] + (
            "…" if len(turn.tool_result) > 1500 else ""
        )
        st.code(truncated, language=None, wrap_lines=True)


def render(logs: dict[str, LogData]) -> None:
    st.header("Agent Trajectory")

    # Only patching logs with agent turns
    agent_logs = {
        p: lg
        for p, lg in logs.items()
        if lg.task_type == TaskType.VULNERABILITY_PATCHING
        and "message_count" in lg.df.columns
        and int(lg.df["message_count"].max()) >= _AGENT_THRESHOLD
    }

    if not agent_logs:
        st.info(
            "No agent trajectory data found in selected logs. "
            "Load a vulnerability-patching log produced by an agent (multi-turn) run."
        )
        return

    log_names = list(agent_logs.keys())
    if len(log_names) > 1:
        selected_path = st.selectbox(
            "Log file", log_names, format_func=lambda p: p.split("/")[-1]
        )
    else:
        selected_path = log_names[0]

    log = agent_logs[selected_path]
    df = log.df

    # Sample selector — show ID, target, patch score, turn count
    rows = df[df["message_count"] >= _AGENT_THRESHOLD]
    options = [
        f"{row['sample_id']} — {row.get('target', '?')} | "
        f"score={row.get('patch_score', 0.0):.2f} | {int(row.get('message_count', 0))} msgs"
        for _, row in rows.iterrows()
    ]
    id_for_opt = {
        opt: str(row["sample_id"]) for opt, (_, row) in zip(options, rows.iterrows())
    }

    selected_opt = st.selectbox("Sample", options)
    if not selected_opt:
        return
    sample_id = id_for_opt[selected_opt]

    # Load trajectory
    with st.spinner("Loading agent trajectory…"):
        turns = load_trajectory(selected_path, sample_id)

    if not turns:
        st.warning("No agent turns found for this sample.")
        return

    # Summary strip
    n_ok = sum(1 for t in turns if t.tool_ok)
    total_model_t = sum(t.model_time for t in turns)
    total_tool_t = sum(t.tool_time for t in turns)
    cols = st.columns(4)
    cols[0].metric("Agent Turns", len(turns))
    cols[1].metric("Successful Patches", n_ok)
    cols[2].metric("Total LLM Time (s)", f"{total_model_t:.1f}")
    cols[3].metric("Total Tool Time (s)", f"{total_tool_t:.1f}")

    st.divider()

    # Render each turn; collapse all but the first by default
    for turn in turns:
        _render_turn(turn, expanded=(turn.turn_index == 0))
