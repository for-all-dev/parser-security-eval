"""Result models for the swarm orchestrator.

``AgentResult`` wraps a single agent's fuzzing session outcome.
``SwarmResult`` aggregates all agent results and computes ensemble metrics.
``LiveFuzzingSessionResult`` is a lightweight summary of one inspect_eval run.
"""

from __future__ import annotations

from pydantic import BaseModel

from parser_security_eval.swarm.diversity import AgentConfig, DiversityConfig


class LiveFuzzingSessionResult(BaseModel):
    """Lightweight summary of one inspect_ai live_fuzzing eval run.

    Captured from the eval log returned by ``inspect_eval()``.  Fields mirror
    the metadata stored by ``live_fuzzing_scorer``.
    """

    unique_crashes: int = 0
    coverage_pct: float = 0.0
    rounds_completed: int = 0
    total_executions: int = 0
    score: float = 0.0
    status: str = "success"  # "success" | "error" | "timeout"


class AgentResult(BaseModel):
    """Result for a single agent in the swarm."""

    agent_id: str
    config: AgentConfig
    target: str
    session_result: LiveFuzzingSessionResult | None  # None if agent failed/timed out
    wall_time_seconds: float
    error: str | None = None  # populated if agent crashed or timed out


class SwarmResult(BaseModel):
    """Aggregated result from a complete swarm run."""

    target: str
    n_agents: int
    diversity_config: DiversityConfig
    agent_results: list[AgentResult]
    total_wall_time_seconds: float
    total_cpu_hours: float  # sum of (agent wall_time * cores_per_agent)

    # Aggregate (computed from agent_results)
    total_unique_crashes: int
    total_coverage_union: float  # branch% union across all agents

    def marginal_crash_curve(self) -> list[int]:
        """Return [crashes_at_1_agent, crashes_at_2_agents, ...] for N agents.

        Each entry is the cumulative unique crash count when that many agents
        have been included (in the order they appear in ``agent_results``).
        Agents that failed (``session_result`` is None) contribute 0 crashes.

        Returns:
            A list of length ``n_agents`` with cumulative crash counts.
        """
        curve: list[int] = []
        running_total = 0
        for result in self.agent_results:
            if result.session_result is not None:
                running_total += result.session_result.unique_crashes
            curve.append(running_total)
        return curve
