"""Tests for the swarm orchestrator — no real Docker or API calls.

Tests cover:
- DiversityConfig.default_portfolio strategy assignment
- SwarmResult.marginal_crash_curve
- AgentResult serialization/deserialization
- Orchestrator gracefully handles agent failures
"""

from __future__ import annotations

import asyncio
from unittest.mock import patch

import pytest

from parser_security_eval.swarm.diversity import (
    AgentConfig,
    AgentRole,
    DiversityConfig,
    FuzzEngine,
    MutationStrategy,
)
from parser_security_eval.swarm.orchestrator import SwarmOrchestrator
from parser_security_eval.swarm.result import (
    AgentResult,
    LiveFuzzingSessionResult,
    SwarmResult,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_session_result(
    crashes: int = 0, coverage: float = 0.0
) -> LiveFuzzingSessionResult:
    return LiveFuzzingSessionResult(
        unique_crashes=crashes,
        coverage_pct=coverage,
        rounds_completed=1,
        total_executions=10000,
        score=min(1.0, crashes / 5.0) * 0.7 + coverage * 0.3,
    )


def _make_agent_config(agent_id: str = "agent-00") -> AgentConfig:
    return AgentConfig(
        agent_id=agent_id,
        engine=FuzzEngine.LIBFUZZER,
        mutation_strategy=MutationStrategy.GRAMMAR_BASED,
        role=AgentRole.EXPLOITER,
    )


def _make_agent_result(
    agent_id: str = "agent-00",
    crashes: int = 2,
    wall_time: float = 10.0,
    error: str | None = None,
) -> AgentResult:
    return AgentResult(
        agent_id=agent_id,
        config=_make_agent_config(agent_id),
        target="libxml2",
        session_result=_make_session_result(crashes) if error is None else None,
        wall_time_seconds=wall_time,
        error=error,
    )


def _make_swarm_result(agent_results: list[AgentResult]) -> SwarmResult:
    n = len(agent_results)
    diversity_config = DiversityConfig.default_portfolio(n)
    total_crashes = sum(
        r.session_result.unique_crashes
        for r in agent_results
        if r.session_result is not None
    )
    return SwarmResult(
        target="libxml2",
        n_agents=n,
        diversity_config=diversity_config,
        agent_results=agent_results,
        total_wall_time_seconds=30.0,
        total_cpu_hours=30.0 / 3600.0,
        total_unique_crashes=total_crashes,
        total_coverage_union=0.0,
    )


# ---------------------------------------------------------------------------
# DiversityConfig.default_portfolio
# ---------------------------------------------------------------------------


class TestDefaultPortfolio:
    def test_n_equals_1(self) -> None:
        config = DiversityConfig.default_portfolio(1)
        assert len(config.agents) == 1
        agent = config.agents[0]
        assert agent.mutation_strategy == MutationStrategy.GRAMMAR_BASED
        assert agent.engine == FuzzEngine.LIBFUZZER
        assert agent.role == AgentRole.EXPLOITER

    def test_n_equals_2(self) -> None:
        config = DiversityConfig.default_portfolio(2)
        assert len(config.agents) == 2
        strategies = [a.mutation_strategy for a in config.agents]
        assert strategies[0] == MutationStrategy.GRAMMAR_BASED
        assert strategies[1] == MutationStrategy.COVERAGE_DIRECTED

    def test_n_equals_4_all_strategies_covered(self) -> None:
        config = DiversityConfig.default_portfolio(4)
        assert len(config.agents) == 4
        strategies = {a.mutation_strategy for a in config.agents}
        assert strategies == {
            MutationStrategy.GRAMMAR_BASED,
            MutationStrategy.COVERAGE_DIRECTED,
            MutationStrategy.SEMANTIC,
            MutationStrategy.DIRECTED,
        }

    def test_n_equals_4_roles_alternate(self) -> None:
        config = DiversityConfig.default_portfolio(4)
        roles = [a.role for a in config.agents]
        assert roles[0] == AgentRole.EXPLOITER
        assert roles[1] == AgentRole.EXPLORER
        assert roles[2] == AgentRole.EXPLOITER
        assert roles[3] == AgentRole.EXPLORER

    def test_n_equals_8_cycles_strategies(self) -> None:
        config = DiversityConfig.default_portfolio(8)
        assert len(config.agents) == 8
        # strategies should cycle: 0,1,2,3,0,1,2,3
        expected = [
            MutationStrategy.GRAMMAR_BASED,
            MutationStrategy.COVERAGE_DIRECTED,
            MutationStrategy.SEMANTIC,
            MutationStrategy.DIRECTED,
            MutationStrategy.GRAMMAR_BASED,
            MutationStrategy.COVERAGE_DIRECTED,
            MutationStrategy.SEMANTIC,
            MutationStrategy.DIRECTED,
        ]
        actual = [a.mutation_strategy for a in config.agents]
        assert actual == expected

    def test_n_equals_8_agent_ids_are_unique(self) -> None:
        config = DiversityConfig.default_portfolio(8)
        ids = [a.agent_id for a in config.agents]
        assert len(ids) == len(set(ids))

    def test_n_equals_0_returns_empty(self) -> None:
        config = DiversityConfig.default_portfolio(0)
        assert config.agents == []

    def test_first_n_strategies_for_small_n(self) -> None:
        """For n < 4, only the first n strategies are used (no cycling needed)."""
        for n in range(1, 4):
            config = DiversityConfig.default_portfolio(n)
            assert len(config.agents) == n
            expected_strategies = [
                MutationStrategy.GRAMMAR_BASED,
                MutationStrategy.COVERAGE_DIRECTED,
                MutationStrategy.SEMANTIC,
            ][:n]
            actual = [a.mutation_strategy for a in config.agents]
            assert actual == expected_strategies

    def test_all_agents_have_valid_engine(self) -> None:
        config = DiversityConfig.default_portfolio(8)
        valid_engines = set(FuzzEngine)
        for agent in config.agents:
            assert agent.engine in valid_engines


# ---------------------------------------------------------------------------
# SwarmResult.marginal_crash_curve
# ---------------------------------------------------------------------------


class TestMarginalCrashCurve:
    def test_all_successful_agents(self) -> None:
        results = [
            _make_agent_result("agent-00", crashes=3),
            _make_agent_result("agent-01", crashes=2),
            _make_agent_result("agent-02", crashes=5),
        ]
        swarm = _make_swarm_result(results)
        curve = swarm.marginal_crash_curve()
        assert curve == [3, 5, 10]

    def test_failed_agent_contributes_zero(self) -> None:
        results = [
            _make_agent_result("agent-00", crashes=3),
            _make_agent_result("agent-01", error="timeout"),
            _make_agent_result("agent-02", crashes=2),
        ]
        swarm = _make_swarm_result(results)
        curve = swarm.marginal_crash_curve()
        assert curve == [3, 3, 5]

    def test_all_failed_agents(self) -> None:
        results = [
            _make_agent_result("agent-00", error="timeout"),
            _make_agent_result("agent-01", error="docker error"),
        ]
        swarm = _make_swarm_result(results)
        curve = swarm.marginal_crash_curve()
        assert curve == [0, 0]

    def test_empty_agents_returns_empty(self) -> None:
        swarm = SwarmResult(
            target="libxml2",
            n_agents=0,
            diversity_config=DiversityConfig(agents=[]),
            agent_results=[],
            total_wall_time_seconds=0.0,
            total_cpu_hours=0.0,
            total_unique_crashes=0,
            total_coverage_union=0.0,
        )
        assert swarm.marginal_crash_curve() == []

    def test_curve_length_equals_n_agents(self) -> None:
        results = [_make_agent_result(f"agent-{i:02d}", crashes=i) for i in range(6)]
        swarm = _make_swarm_result(results)
        curve = swarm.marginal_crash_curve()
        assert len(curve) == 6

    def test_curve_is_monotonically_non_decreasing(self) -> None:
        results = [_make_agent_result(f"agent-{i:02d}", crashes=i) for i in range(5)]
        swarm = _make_swarm_result(results)
        curve = swarm.marginal_crash_curve()
        for i in range(1, len(curve)):
            assert curve[i] >= curve[i - 1]


# ---------------------------------------------------------------------------
# AgentResult serialization / deserialization
# ---------------------------------------------------------------------------


class TestAgentResultSerialization:
    def test_round_trips_successful_result(self) -> None:
        result = _make_agent_result("agent-00", crashes=3, wall_time=42.7)
        data = result.model_dump()
        restored = AgentResult.model_validate(data)
        assert restored.agent_id == result.agent_id
        assert restored.wall_time_seconds == result.wall_time_seconds
        assert restored.error is None
        assert restored.session_result is not None
        assert restored.session_result.unique_crashes == 3

    def test_round_trips_failed_result(self) -> None:
        result = _make_agent_result("agent-01", error="Connection refused")
        data = result.model_dump()
        restored = AgentResult.model_validate(data)
        assert restored.session_result is None
        assert restored.error == "Connection refused"

    def test_json_round_trip(self) -> None:
        result = _make_agent_result("agent-02", crashes=5)
        json_str = result.model_dump_json()
        restored = AgentResult.model_validate_json(json_str)
        assert restored.agent_id == "agent-02"
        assert restored.session_result is not None
        assert restored.session_result.unique_crashes == 5

    def test_config_is_preserved(self) -> None:
        config = AgentConfig(
            agent_id="agent-03",
            engine=FuzzEngine.AFL_PLUS_PLUS,
            mutation_strategy=MutationStrategy.SEMANTIC,
            role=AgentRole.EXPLORER,
            model="claude-opus-4-6",
            temperature=0.8,
        )
        result = AgentResult(
            agent_id="agent-03",
            config=config,
            target="libpng",
            session_result=_make_session_result(crashes=1),
            wall_time_seconds=99.0,
        )
        restored = AgentResult.model_validate(result.model_dump())
        assert restored.config.engine == FuzzEngine.AFL_PLUS_PLUS
        assert restored.config.mutation_strategy == MutationStrategy.SEMANTIC
        assert restored.config.role == AgentRole.EXPLORER
        assert restored.config.model == "claude-opus-4-6"
        assert restored.config.temperature == pytest.approx(0.8)


# ---------------------------------------------------------------------------
# SwarmOrchestrator — graceful failure handling
# ---------------------------------------------------------------------------


class TestSwarmOrchestratorFailureHandling:
    """Test orchestrator robustness without real Docker or API calls."""

    @pytest.mark.asyncio
    async def test_agent_exception_does_not_crash_swarm(self, tmp_path) -> None:
        """If one agent raises, the swarm still returns results for other agents."""
        orchestrator = SwarmOrchestrator(targets_dir=tmp_path)

        # First agent raises, second succeeds
        call_count = 0

        async def mock_run_agent(
            agent_config: AgentConfig, target: str, duration_seconds: int
        ) -> AgentResult:
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise RuntimeError("Docker daemon not running")
            return AgentResult(
                agent_id=agent_config.agent_id,
                config=agent_config,
                target=target,
                session_result=_make_session_result(crashes=2),
                wall_time_seconds=5.0,
            )

        with patch.object(orchestrator, "_run_agent", side_effect=mock_run_agent):
            result = await orchestrator.run_swarm(
                target="libxml2",
                n_agents=2,
                duration_seconds=10,
            )

        assert len(result.agent_results) == 2
        # First agent failed
        assert result.agent_results[0].error is not None
        assert result.agent_results[0].session_result is None
        # Second agent succeeded
        assert result.agent_results[1].session_result is not None
        assert result.agent_results[1].session_result.unique_crashes == 2

    @pytest.mark.asyncio
    async def test_all_agents_fail_returns_zero_crashes(self, tmp_path) -> None:
        orchestrator = SwarmOrchestrator(targets_dir=tmp_path)

        async def mock_run_agent(
            agent_config: AgentConfig, target: str, duration_seconds: int
        ) -> AgentResult:
            raise RuntimeError("Everything is on fire")

        with patch.object(orchestrator, "_run_agent", side_effect=mock_run_agent):
            result = await orchestrator.run_swarm(
                target="libpng",
                n_agents=3,
                duration_seconds=10,
            )

        assert result.total_unique_crashes == 0
        assert all(r.error is not None for r in result.agent_results)

    @pytest.mark.asyncio
    async def test_max_parallel_respected(self, tmp_path) -> None:
        """With max_parallel=2 and n_agents=4, at most 2 agents run concurrently."""
        orchestrator = SwarmOrchestrator(targets_dir=tmp_path)

        concurrent_count = 0
        max_concurrent_seen = 0

        async def mock_run_agent(
            agent_config: AgentConfig, target: str, duration_seconds: int
        ) -> AgentResult:
            nonlocal concurrent_count, max_concurrent_seen
            concurrent_count += 1
            max_concurrent_seen = max(max_concurrent_seen, concurrent_count)
            await asyncio.sleep(0.05)  # simulate work
            concurrent_count -= 1
            return AgentResult(
                agent_id=agent_config.agent_id,
                config=agent_config,
                target=target,
                session_result=_make_session_result(crashes=1),
                wall_time_seconds=0.05,
            )

        with patch.object(orchestrator, "_run_agent", side_effect=mock_run_agent):
            result = await orchestrator.run_swarm(
                target="libxml2",
                n_agents=4,
                duration_seconds=10,
                max_parallel=2,
            )

        assert len(result.agent_results) == 4
        assert max_concurrent_seen <= 2

    @pytest.mark.asyncio
    async def test_diversity_config_passed_to_agents(self, tmp_path) -> None:
        """Custom DiversityConfig is used instead of default portfolio."""
        orchestrator = SwarmOrchestrator(targets_dir=tmp_path)
        captured_configs: list[AgentConfig] = []

        async def mock_run_agent(
            agent_config: AgentConfig, target: str, duration_seconds: int
        ) -> AgentResult:
            captured_configs.append(agent_config)
            return AgentResult(
                agent_id=agent_config.agent_id,
                config=agent_config,
                target=target,
                session_result=_make_session_result(),
                wall_time_seconds=1.0,
            )

        custom_config = DiversityConfig(
            agents=[
                AgentConfig(
                    agent_id="custom-agent-0",
                    engine=FuzzEngine.HONGGFUZZ,
                    mutation_strategy=MutationStrategy.DIRECTED,
                    role=AgentRole.EXPLOITER,
                ),
                AgentConfig(
                    agent_id="custom-agent-1",
                    engine=FuzzEngine.AFL_PLUS_PLUS,
                    mutation_strategy=MutationStrategy.SEMANTIC,
                    role=AgentRole.EXPLORER,
                ),
            ]
        )

        with patch.object(orchestrator, "_run_agent", side_effect=mock_run_agent):
            await orchestrator.run_swarm(
                target="libxml2",
                n_agents=2,
                duration_seconds=10,
                diversity_config=custom_config,
            )

        assert len(captured_configs) == 2
        assert captured_configs[0].engine == FuzzEngine.HONGGFUZZ
        assert captured_configs[1].engine == FuzzEngine.AFL_PLUS_PLUS

    @pytest.mark.asyncio
    async def test_cpu_hours_computed_correctly(self, tmp_path) -> None:
        orchestrator = SwarmOrchestrator(targets_dir=tmp_path)

        async def mock_run_agent(
            agent_config: AgentConfig, target: str, duration_seconds: int
        ) -> AgentResult:
            return AgentResult(
                agent_id=agent_config.agent_id,
                config=agent_config,
                target=target,
                session_result=_make_session_result(),
                wall_time_seconds=3600.0,  # 1 hour per agent
            )

        with patch.object(orchestrator, "_run_agent", side_effect=mock_run_agent):
            result = await orchestrator.run_swarm(
                target="libxml2",
                n_agents=3,
                duration_seconds=3600,
            )

        # 3 agents * 1 core * 3600s / 3600 = 3 cpu-hours
        assert result.total_cpu_hours == pytest.approx(3.0, abs=0.01)

    @pytest.mark.asyncio
    async def test_swarm_result_has_correct_n_agents(self, tmp_path) -> None:
        orchestrator = SwarmOrchestrator(targets_dir=tmp_path)

        async def mock_run_agent(
            agent_config: AgentConfig, target: str, duration_seconds: int
        ) -> AgentResult:
            return AgentResult(
                agent_id=agent_config.agent_id,
                config=agent_config,
                target=target,
                session_result=_make_session_result(crashes=1),
                wall_time_seconds=5.0,
            )

        with patch.object(orchestrator, "_run_agent", side_effect=mock_run_agent):
            result = await orchestrator.run_swarm(
                target="libxml2",
                n_agents=5,
                duration_seconds=60,
            )

        assert result.n_agents == 5
        assert len(result.agent_results) == 5


# ---------------------------------------------------------------------------
# LiveFuzzingSessionResult
# ---------------------------------------------------------------------------


class TestLiveFuzzingSessionResult:
    def test_defaults(self) -> None:
        r = LiveFuzzingSessionResult()
        assert r.unique_crashes == 0
        assert r.coverage_pct == 0.0
        assert r.rounds_completed == 0
        assert r.total_executions == 0
        assert r.score == 0.0
        assert r.status == "success"

    def test_round_trips(self) -> None:
        r = LiveFuzzingSessionResult(
            unique_crashes=7,
            coverage_pct=0.42,
            rounds_completed=3,
            total_executions=50000,
            score=0.84,
            status="success",
        )
        restored = LiveFuzzingSessionResult.model_validate(r.model_dump())
        assert restored.unique_crashes == 7
        assert restored.coverage_pct == pytest.approx(0.42)
        assert restored.score == pytest.approx(0.84)
