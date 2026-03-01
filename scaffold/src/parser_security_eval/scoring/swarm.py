"""Swarm scoring model: individual agent + aggregate swarm metrics.

Evaluates both individual agents and the swarm as a whole, enabling
comparison of agent strategies and measuring whether diversity helps.

Individual agent score
----------------------
``score_individual = (
    unique_crashes_found * severity_weight
    + marginal_coverage_contribution
    + first_to_find_bonus
)``

Swarm aggregate score
---------------------
``score_swarm = (
    total_unique_crashes
    + total_coverage
    + coverage_diversity_bonus
)``

Efficiency metrics
------------------
- Crashes per CPU-hour
- Coverage per CPU-hour
- Marginal value curve: additional bugs per additional agent

Integration
-----------
The ``swarm_scorer`` function returns an Inspect-AI ``Scorer`` that can be
attached to any swarm fuzzing task.  It reads per-agent metadata from the
task state and computes all three metric families.
"""

from __future__ import annotations

import logging
from collections.abc import Sequence

from pydantic import BaseModel, Field

from parser_security_eval.scoring.coverage_agg import (
    AgentCoverage,
    AggregateCoverage,
    merge_agent_coverage_from_sets,
)
from parser_security_eval.scoring.dedup import CrashCluster
from parser_security_eval.triage.casr import Exploitability

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Severity weight mapping (from CASR exploitability)
# ---------------------------------------------------------------------------

SEVERITY_WEIGHTS: dict[Exploitability, float] = {
    Exploitability.EXPLOITABLE: 3.0,
    Exploitability.PROBABLY_EXPLOITABLE: 2.0,
    Exploitability.NOT_EXPLOITABLE: 1.0,
    Exploitability.UNKNOWN: 1.0,
}


def _severity_weight_for_cluster(cluster: CrashCluster) -> float:
    """Return the severity weight for a crash cluster.

    Uses the representative crash's CASR exploitability rating.
    Falls back to 1.0 (NOT_EXPLOITABLE equivalent) when severity is absent.
    """
    rep = cluster.representative
    if hasattr(rep, "severity") and rep.severity is not None:
        return SEVERITY_WEIGHTS.get(rep.severity.exploitability, 1.0)
    return 1.0


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------


class IndividualScore(BaseModel):
    """Score for a single agent in the swarm.

    Attributes:
        agent_id: Identifier of the scored agent.
        unique_crashes_found: Number of unique crash clusters attributed to
            this agent after deduplication.
        severity_weighted_crashes: Sum of ``severity_weight`` over the agent's
            unique crashes.
        marginal_coverage_contribution: Number of lines/branches that only
            this agent reached (from ``AgentMarginalCoverage``).
        first_to_find_bonus: Bonus for finding a bug before any other agent.
            Each first-find adds 1.0 to this total.
        score: Composite individual score.
    """

    agent_id: str
    unique_crashes_found: int = 0
    severity_weighted_crashes: float = 0.0
    marginal_coverage_contribution: int = 0
    first_to_find_bonus: float = 0.0
    score: float = 0.0


class SwarmScore(BaseModel):
    """Aggregate score for the entire swarm.

    Attributes:
        total_unique_crashes: Total unique crash clusters across all agents.
        total_coverage: Total union coverage count (lines + branches).
        coverage_diversity_bonus: Reward for non-overlapping coverage,
            computed as ``1 - mean_pairwise_jaccard``.  Higher means agents
            explored more distinct regions.
        score: Composite swarm score.
        individual_scores: Per-agent breakdown.
    """

    total_unique_crashes: int = 0
    total_coverage: int = 0
    coverage_diversity_bonus: float = 0.0
    score: float = 0.0
    individual_scores: list[IndividualScore] = Field(default_factory=list)


class EfficiencyMetrics(BaseModel):
    """Compute-normalised efficiency metrics.

    Attributes:
        crashes_per_cpu_hour: Unique crashes found / total CPU-hours.
        coverage_per_cpu_hour: Union coverage count / total CPU-hours.
        marginal_value_curve: ``marginal_value_curve[i]`` is the number of
            *additional* unique bugs discovered by adding the ``(i+1)``-th
            agent (in the order given).  The first entry is the bug count of
            the first agent alone.
        total_cpu_hours: Total CPU-hours consumed by the swarm.
    """

    crashes_per_cpu_hour: float = 0.0
    coverage_per_cpu_hour: float = 0.0
    marginal_value_curve: list[int] = Field(default_factory=list)
    total_cpu_hours: float = 0.0


# ---------------------------------------------------------------------------
# Scoring functions
# ---------------------------------------------------------------------------


def compute_individual_scores(
    crash_clusters: list[CrashCluster],
    agent_coverages: list[AgentCoverage],
    agent_ids: Sequence[str],
) -> list[IndividualScore]:
    """Compute per-agent individual scores.

    Args:
        crash_clusters: Deduplicated crash clusters (each cluster knows which
            agents found it via ``agent_ids``).
        agent_coverages: Per-agent coverage data from the coverage aggregation
            pipeline.  May be empty if coverage was not collected.
        agent_ids: Ordered list of all agent identifiers to score.

    Returns:
        A list of :class:`IndividualScore`, one per agent in ``agent_ids`` order.
    """
    # Build a lookup: agent_id -> set of cluster indices attributed to it
    agent_clusters: dict[str, list[CrashCluster]] = {aid: [] for aid in agent_ids}
    for cluster in crash_clusters:
        for aid in cluster.agent_ids:
            if aid in agent_clusters:
                agent_clusters[aid].append(cluster)

    # First-to-find: cluster.representative.agent_id was the first finder.
    first_find_agents: dict[int, str] = {}
    for cluster in crash_clusters:
        first_find_agents[cluster.cluster_id] = cluster.representative.agent_id

    # Marginal coverage: compute from AgentCoverage if available
    marginal_map: dict[str, int] = {}
    if agent_coverages:
        try:
            agg = merge_agent_coverage_from_sets(agent_coverages)
            for m in agg.per_agent:
                marginal_map[m.agent_id] = (
                    m.marginal_line_count + m.marginal_branch_count
                )
        except ValueError:
            logger.warning("Could not compute marginal coverage", exc_info=True)

    scores: list[IndividualScore] = []
    for aid in agent_ids:
        clusters_for_agent = agent_clusters.get(aid, [])
        unique_count = len(clusters_for_agent)

        severity_weighted = sum(
            _severity_weight_for_cluster(c) for c in clusters_for_agent
        )

        marginal_cov = marginal_map.get(aid, 0)

        first_bonus = sum(
            1.0
            for cluster in crash_clusters
            if first_find_agents.get(cluster.cluster_id) == aid
        )

        composite = severity_weighted + marginal_cov + first_bonus

        scores.append(
            IndividualScore(
                agent_id=aid,
                unique_crashes_found=unique_count,
                severity_weighted_crashes=severity_weighted,
                marginal_coverage_contribution=marginal_cov,
                first_to_find_bonus=first_bonus,
                score=composite,
            )
        )

    return scores


def compute_swarm_score(
    crash_clusters: list[CrashCluster],
    agent_coverages: list[AgentCoverage],
    agent_ids: Sequence[str],
) -> SwarmScore:
    """Compute the aggregate swarm score.

    Args:
        crash_clusters: Deduplicated crash clusters.
        agent_coverages: Per-agent coverage data.
        agent_ids: Ordered list of agent identifiers.

    Returns:
        A :class:`SwarmScore` with individual breakdowns.
    """
    individual = compute_individual_scores(crash_clusters, agent_coverages, agent_ids)

    total_unique = len(crash_clusters)

    # Total coverage = union line count + union branch count
    total_coverage = 0
    coverage_diversity_bonus = 0.0

    if agent_coverages:
        try:
            agg = merge_agent_coverage_from_sets(agent_coverages)
            total_coverage = agg.union_line_count + agg.union_branch_count

            # Coverage diversity bonus: 1 - mean pairwise Jaccard
            coverage_diversity_bonus = _compute_diversity_bonus(agg)
        except ValueError:
            logger.warning("Could not compute aggregate coverage", exc_info=True)

    composite = total_unique + total_coverage + coverage_diversity_bonus

    return SwarmScore(
        total_unique_crashes=total_unique,
        total_coverage=total_coverage,
        coverage_diversity_bonus=coverage_diversity_bonus,
        score=composite,
        individual_scores=individual,
    )


def _compute_diversity_bonus(agg: AggregateCoverage) -> float:
    """Compute ``1 - mean_pairwise_jaccard`` from an aggregate coverage result.

    If there are fewer than 2 agents, returns 0.0 (no diversity to measure).
    Uses the line-based Jaccard similarity values stored in the aggregate.
    """
    if len(agg.agent_ids) < 2:
        return 0.0

    jaccard_values = list(agg.jaccard_lines.values())
    if not jaccard_values:
        return 0.0

    mean_jaccard = sum(jaccard_values) / len(jaccard_values)
    return 1.0 - mean_jaccard


def compute_efficiency_metrics(
    crash_clusters: list[CrashCluster],
    agent_coverages: list[AgentCoverage],
    total_cpu_hours: float,
    agent_ids: Sequence[str],
    agent_crash_clusters: dict[str, list[CrashCluster]] | None = None,
) -> EfficiencyMetrics:
    """Compute efficiency metrics normalised by CPU-hours.

    Args:
        crash_clusters: Deduplicated crash clusters.
        agent_coverages: Per-agent coverage data.
        total_cpu_hours: Total CPU-hours consumed by the swarm.
        agent_ids: Ordered list of agent identifiers (used for the marginal
            value curve -- agents are added in this order).
        agent_crash_clusters: Optional pre-computed mapping from agent_id to
            the clusters it found.  If None, derived from ``crash_clusters``.

    Returns:
        An :class:`EfficiencyMetrics` instance.
    """
    total_unique = len(crash_clusters)

    total_coverage = 0
    if agent_coverages:
        try:
            agg = merge_agent_coverage_from_sets(agent_coverages)
            total_coverage = agg.union_line_count + agg.union_branch_count
        except ValueError:
            pass

    crashes_per_hour = total_unique / total_cpu_hours if total_cpu_hours > 0 else 0.0
    coverage_per_hour = total_coverage / total_cpu_hours if total_cpu_hours > 0 else 0.0

    # Marginal value curve: add agents one-by-one, track new unique bugs
    marginal_curve = _compute_marginal_value_curve(
        crash_clusters, agent_ids, agent_crash_clusters
    )

    return EfficiencyMetrics(
        crashes_per_cpu_hour=crashes_per_hour,
        coverage_per_cpu_hour=coverage_per_hour,
        marginal_value_curve=marginal_curve,
        total_cpu_hours=total_cpu_hours,
    )


def _compute_marginal_value_curve(
    crash_clusters: list[CrashCluster],
    agent_ids: Sequence[str],
    agent_crash_clusters: dict[str, list[CrashCluster]] | None = None,
) -> list[int]:
    """Compute the marginal value curve: bugs per additional agent.

    Returns a list of length ``len(agent_ids)`` where entry ``i`` is the
    number of *new* unique bugs added by agent ``i`` beyond the bugs already
    found by agents ``0..i-1``.
    """
    # Build agent -> cluster_ids mapping if not provided
    if agent_crash_clusters is None:
        agent_crash_clusters = {}
        for cluster in crash_clusters:
            for aid in cluster.agent_ids:
                agent_crash_clusters.setdefault(aid, []).append(cluster)

    seen_cluster_ids: set[int] = set()
    curve: list[int] = []

    for aid in agent_ids:
        clusters = agent_crash_clusters.get(aid, [])
        new_bugs = 0
        for cluster in clusters:
            if cluster.cluster_id not in seen_cluster_ids:
                seen_cluster_ids.add(cluster.cluster_id)
                new_bugs += 1
        curve.append(new_bugs)

    return curve


# ---------------------------------------------------------------------------
# Inspect-AI scorer integration
# ---------------------------------------------------------------------------


def swarm_scorer() -> list:
    """Return an Inspect-AI scorer for swarm fuzzing tasks.

    The scorer reads per-agent metadata from the task state and computes
    individual scores, the swarm aggregate score, and efficiency metrics.

    Expected metadata keys on ``state.metadata``:
        - ``crash_clusters``: list of serialised CrashCluster dicts
        - ``agent_coverages``: list of serialised AgentCoverage dicts
        - ``agent_ids``: list of agent identifier strings
        - ``total_cpu_hours``: float
    """
    from inspect_ai.scorer import Score, Scorer, mean, scorer
    from inspect_ai.solver import TaskState

    @scorer(metrics=[mean()])
    def _swarm_scorer() -> Scorer:
        async def score(state: TaskState, target: object) -> Score:
            meta: dict = state.metadata or {}

            agent_ids: list[str] = meta.get("agent_ids", [])
            total_cpu_hours: float = meta.get("total_cpu_hours", 0.0)

            # Deserialise crash clusters
            raw_clusters = meta.get("crash_clusters", [])
            clusters: list[CrashCluster] = []
            for raw in raw_clusters:
                if isinstance(raw, CrashCluster):
                    clusters.append(raw)
                elif isinstance(raw, dict):
                    clusters.append(CrashCluster.model_validate(raw))

            # Deserialise agent coverages
            raw_coverages = meta.get("agent_coverages", [])
            coverages: list[AgentCoverage] = []
            for raw in raw_coverages:
                if isinstance(raw, AgentCoverage):
                    coverages.append(raw)
                elif isinstance(raw, dict):
                    coverages.append(AgentCoverage.model_validate(raw))

            if not agent_ids:
                return Score(
                    value=0.0,
                    explanation="No agent data found in task state metadata.",
                )

            swarm = compute_swarm_score(clusters, coverages, agent_ids)
            efficiency = compute_efficiency_metrics(
                clusters, coverages, total_cpu_hours, agent_ids
            )

            explanation = (
                f"total_unique_crashes={swarm.total_unique_crashes}, "
                f"total_coverage={swarm.total_coverage}, "
                f"diversity_bonus={swarm.coverage_diversity_bonus:.3f}, "
                f"crashes_per_cpu_hour={efficiency.crashes_per_cpu_hour:.3f}, "
                f"coverage_per_cpu_hour={efficiency.coverage_per_cpu_hour:.3f}"
            )

            return Score(
                value=swarm.score,
                explanation=explanation,
                metadata={
                    "swarm_score": swarm.model_dump(),
                    "efficiency_metrics": efficiency.model_dump(),
                },
            )

        return score

    return [_swarm_scorer()]
