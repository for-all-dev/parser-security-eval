"""Diversity strategy configuration for the swarm orchestrator.

Each agent in the swarm is assigned a distinct combination of fuzzing engine,
mutation strategy, and role — drawn from the 4-strategy portfolio described in
the literature review (R12). This module defines those configuration models.
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel


class FuzzEngine(StrEnum):
    LIBFUZZER = "libfuzzer"
    AFL_PLUS_PLUS = "afl++"
    HONGGFUZZ = "honggfuzz"


class MutationStrategy(StrEnum):
    GRAMMAR_BASED = "grammar"  # LLM-extracted format grammar -> structured generator
    COVERAGE_DIRECTED = "coverage"  # AFL++ standard mutators, coverage-directed
    SEMANTIC = "semantic"  # LLM semantic mutation (async, low-frequency)
    DIRECTED = "directed"  # Targeted at specific CVE-adjacent locations


class AgentRole(StrEnum):
    EXPLOITER = "exploiter"  # minimise distance to known-vulnerable locations
    EXPLORER = "explorer"  # maximise path diversity, avoid already-covered paths


class AgentConfig(BaseModel):
    agent_id: str
    engine: FuzzEngine
    mutation_strategy: MutationStrategy
    role: AgentRole
    model: str = "claude-sonnet-4-6"
    temperature: float = 0.5
    prompt_variant: str = "default"  # which system prompt variant to use


class DiversityConfig(BaseModel):
    """Describes how to distribute diversity across N agents."""

    agents: list[AgentConfig]

    @classmethod
    def default_portfolio(cls, n_agents: int) -> "DiversityConfig":
        """Assign agents the 4-strategy portfolio from the lit review (R12).

        Cycles through: grammar, coverage, semantic, directed.
        Alternates roles: exploiter/explorer.
        For n_agents < 4, uses the first n strategies.

        Args:
            n_agents: Total number of agents to configure.

        Returns:
            A ``DiversityConfig`` with one ``AgentConfig`` per agent.
        """
        if n_agents < 1:
            return cls(agents=[])

        # The four canonical strategies from R12, in priority order
        strategies: list[MutationStrategy] = [
            MutationStrategy.GRAMMAR_BASED,
            MutationStrategy.COVERAGE_DIRECTED,
            MutationStrategy.SEMANTIC,
            MutationStrategy.DIRECTED,
        ]

        # Engine assignments that pair naturally with each strategy
        engines: list[FuzzEngine] = [
            FuzzEngine.LIBFUZZER,  # grammar: libfuzzer + LLM-generated structured inputs
            FuzzEngine.AFL_PLUS_PLUS,  # coverage: AFL++ native coverage-directed mutators
            FuzzEngine.LIBFUZZER,  # semantic: libfuzzer + LLM semantic mutations
            FuzzEngine.AFL_PLUS_PLUS,  # directed: AFL++ with directed mode
        ]

        roles: list[AgentRole] = [AgentRole.EXPLOITER, AgentRole.EXPLORER]

        agents: list[AgentConfig] = []
        for i in range(n_agents):
            strategy_idx = i % len(strategies)
            agents.append(
                AgentConfig(
                    agent_id=f"agent-{i:02d}",
                    engine=engines[strategy_idx],
                    mutation_strategy=strategies[strategy_idx],
                    role=roles[i % len(roles)],
                )
            )

        return cls(agents=agents)
