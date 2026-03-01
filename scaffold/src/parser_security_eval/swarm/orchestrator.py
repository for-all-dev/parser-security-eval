"""Swarm orchestrator: spawn and manage N parallel fuzzing agents.

Each agent is an independent ``live_fuzzing()`` inspect_ai task run in its
own DockerSandbox.  No shared state during fuzzing -- results are merged at
the end.

Parallelism is controlled with ``asyncio.gather`` and a semaphore so that
``max_parallel`` concurrent agents run at most at any time.
"""

from __future__ import annotations

import asyncio
import logging
import time
from pathlib import Path

from parser_security_eval.swarm.diversity import AgentConfig, DiversityConfig
from parser_security_eval.swarm.result import (
    AgentResult,
    LiveFuzzingSessionResult,
    SwarmResult,
)

logger = logging.getLogger(__name__)

# Assumed cores per agent for cpu-hours accounting.
_CORES_PER_AGENT = 1


class SwarmOrchestrator:
    """Orchestrates N parallel fuzzing agents against a single parser target.

    Each agent is an independent ``live_fuzzing()`` eval run with its own
    DockerSandbox.  Results are merged after all agents complete.

    Args:
        targets_dir: Root directory containing parser target definitions.
            If ``None``, defaults to ``Path("../targets")`` relative to cwd.
    """

    def __init__(self, targets_dir: Path | None = None) -> None:
        self.targets_dir: Path = (
            targets_dir if targets_dir is not None else Path("../targets")
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def run_swarm(
        self,
        target: str,
        n_agents: int,
        duration_seconds: int,
        diversity_config: DiversityConfig | None = None,
        *,
        max_parallel: int | None = None,
    ) -> SwarmResult:
        """Spawn *n_agents* independent fuzzing sessions for *target*.

        Each agent is an independent instance of the ``live_fuzzing()`` task
        with its own DockerSandbox.  No shared state during fuzzing; results
        are merged at the end.

        If *max_parallel* is set, agents are batched (e.g. ``max_parallel=4``
        with ``n_agents=8`` runs two batches of 4).

        Args:
            target: Parser target name (subdirectory of ``targets_dir``).
            n_agents: How many agent sessions to spawn.
            duration_seconds: Per-agent fuzzing budget in seconds.
            diversity_config: How to assign engine/strategy/role to each agent.
                If ``None``, ``DiversityConfig.default_portfolio(n_agents)`` is
                used.
            max_parallel: Maximum number of concurrently running agents.
                Defaults to *n_agents* (all run in parallel).

        Returns:
            A :class:`SwarmResult` aggregating all agent outcomes.
        """
        if diversity_config is None:
            diversity_config = DiversityConfig.default_portfolio(n_agents)

        # If we have fewer configs than agents (shouldn't happen with
        # default_portfolio, but guard anyway) pad with default configs.
        configs = diversity_config.agents[:n_agents]
        while len(configs) < n_agents:
            configs.append(
                DiversityConfig.default_portfolio(n_agents).agents[len(configs) % 4]
            )

        effective_max = max_parallel if max_parallel is not None else n_agents
        semaphore = asyncio.Semaphore(effective_max)

        swarm_start = time.monotonic()

        async def _bounded_run(cfg: AgentConfig) -> AgentResult:
            async with semaphore:
                try:
                    return await self._run_agent(cfg, target, duration_seconds)
                except Exception as exc:
                    # Catch any exception that escapes _run_agent (e.g. from mocks
                    # in tests or unexpected failures) so one agent cannot abort
                    # the whole swarm.
                    msg = f"Agent {cfg.agent_id} failed unexpectedly: {exc}"
                    logger.exception("Unexpected failure in agent %s", cfg.agent_id)
                    return AgentResult(
                        agent_id=cfg.agent_id,
                        config=cfg,
                        target=target,
                        session_result=None,
                        wall_time_seconds=0.0,
                        error=msg,
                    )

        tasks = [_bounded_run(cfg) for cfg in configs]
        agent_results: list[AgentResult] = await asyncio.gather(*tasks)

        total_wall_time = time.monotonic() - swarm_start

        # Aggregate metrics
        total_unique_crashes = sum(
            r.session_result.unique_crashes
            for r in agent_results
            if r.session_result is not None
        )

        # Coverage union: simple max across agents (without actual branch
        # bitmaps we cannot compute a true union; max is a conservative
        # lower bound and a useful approximation).
        coverage_values = [
            r.session_result.coverage_pct
            for r in agent_results
            if r.session_result is not None
        ]
        total_coverage_union = max(coverage_values) if coverage_values else 0.0

        total_cpu_hours = (
            sum(r.wall_time_seconds for r in agent_results) * _CORES_PER_AGENT / 3600.0
        )

        return SwarmResult(
            target=target,
            n_agents=n_agents,
            diversity_config=diversity_config,
            agent_results=list(agent_results),
            total_wall_time_seconds=total_wall_time,
            total_cpu_hours=total_cpu_hours,
            total_unique_crashes=total_unique_crashes,
            total_coverage_union=total_coverage_union,
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _run_agent(
        self,
        agent_config: AgentConfig,
        target: str,
        duration_seconds: int,
    ) -> AgentResult:
        """Run a single agent session, returning an :class:`AgentResult`.

        Launches an ``inspect_eval`` run for the ``live_fuzzing()`` task with
        the agent's config injected via task parameters.  Handles timeouts and
        exceptions gracefully -- on failure the ``AgentResult.error`` field is
        populated and ``session_result`` is ``None``.

        Args:
            agent_config: The agent's engine/strategy/role configuration.
            target: Parser target name.
            duration_seconds: Per-round fuzzing duration hint passed to the task.

        Returns:
            An :class:`AgentResult` (with ``error`` set on failure).
        """
        agent_start = time.monotonic()
        logger.info(
            "Starting agent %s: engine=%s strategy=%s role=%s target=%s",
            agent_config.agent_id,
            agent_config.engine,
            agent_config.mutation_strategy,
            agent_config.role,
            target,
        )

        try:
            session_result = await self._run_inspect_eval(
                agent_config=agent_config,
                target=target,
                duration_seconds=duration_seconds,
            )
            wall_time = time.monotonic() - agent_start
            logger.info(
                "Agent %s finished in %.1fs: crashes=%d",
                agent_config.agent_id,
                wall_time,
                session_result.unique_crashes if session_result else 0,
            )
            return AgentResult(
                agent_id=agent_config.agent_id,
                config=agent_config,
                target=target,
                session_result=session_result,
                wall_time_seconds=wall_time,
            )
        except asyncio.TimeoutError:
            wall_time = time.monotonic() - agent_start
            msg = f"Agent {agent_config.agent_id} timed out after {wall_time:.1f}s"
            logger.warning(msg)
            return AgentResult(
                agent_id=agent_config.agent_id,
                config=agent_config,
                target=target,
                session_result=None,
                wall_time_seconds=wall_time,
                error=msg,
            )
        except Exception as exc:
            wall_time = time.monotonic() - agent_start
            msg = f"Agent {agent_config.agent_id} failed: {exc}"
            logger.exception("Agent %s raised an exception", agent_config.agent_id)
            return AgentResult(
                agent_id=agent_config.agent_id,
                config=agent_config,
                target=target,
                session_result=None,
                wall_time_seconds=wall_time,
                error=msg,
            )

    async def _run_inspect_eval(
        self,
        agent_config: AgentConfig,
        target: str,
        duration_seconds: int,
    ) -> LiveFuzzingSessionResult:
        """Run one inspect_eval session and extract a LiveFuzzingSessionResult.

        Calls ``inspect_ai.eval`` in a thread pool executor so it does not
        block the event loop.  The agent's ``engine`` and ``model`` are
        passed as task parameters.

        Args:
            agent_config: Configuration for this agent.
            target: Parser target name.
            duration_seconds: Per-round duration hint.

        Returns:
            A :class:`LiveFuzzingSessionResult` extracted from the eval log.
        """
        loop = asyncio.get_running_loop()

        def _blocking_eval() -> LiveFuzzingSessionResult:
            from inspect_ai import eval as inspect_eval  # noqa: PLC0415

            from parser_security_eval.tasks.fuzzing import live_fuzzing  # noqa: PLC0415

            inspect_task = live_fuzzing(
                targets_dir=str(self.targets_dir),
                target=target,
                engine=agent_config.engine.value,
                max_rounds=3,
                round_duration=duration_seconds,
            )

            logs = inspect_eval(
                inspect_task,
                model=f"anthropic/{agent_config.model}",
            )

            if not logs:
                return LiveFuzzingSessionResult(status="error")

            log = logs[0]

            if log.status not in ("success", "error"):
                return LiveFuzzingSessionResult(status=log.status)

            # Extract scorer metadata from the first (and only) sample result
            unique_crashes = 0
            coverage_pct = 0.0
            rounds_completed = 0
            total_executions = 0
            score_value = 0.0

            if log.results and log.results.scores:
                for scorer_result in log.results.scores:
                    if scorer_result.name == "live_fuzzing_scorer":
                        # Pull aggregate metric from the scorer
                        for metric_name, metric in scorer_result.metrics.items():
                            if metric_name == "mean":
                                try:
                                    score_value = float(metric.value)
                                except TypeError, ValueError:
                                    pass

            # Try to get per-sample metadata for richer fields
            if log.samples:
                for sample in log.samples:
                    if sample.scores:
                        for score_obj in sample.scores.values():
                            meta = score_obj.metadata or {}
                            unique_crashes += int(meta.get("unique_crashes", 0))
                            coverage_pct = max(
                                coverage_pct,
                                float(meta.get("coverage_pct", 0.0)),
                            )
                            rounds_completed += int(meta.get("rounds_completed", 0))
                            total_executions += int(meta.get("total_executions", 0))
                            try:
                                score_value = float(score_obj.as_float() or 0.0)
                            except TypeError, ValueError:
                                pass

            return LiveFuzzingSessionResult(
                unique_crashes=unique_crashes,
                coverage_pct=coverage_pct,
                rounds_completed=rounds_completed,
                total_executions=total_executions,
                score=score_value,
                status="success" if log.status == "success" else "error",
            )

        return await loop.run_in_executor(None, _blocking_eval)
