"""Tests for the swarm scoring model (scoring/swarm.py).

Covers:
- IndividualScore / SwarmScore / EfficiencyMetrics Pydantic models.
- compute_individual_scores: severity weighting, marginal coverage, first-find.
- compute_swarm_score: aggregate score, diversity bonus.
- compute_efficiency_metrics: crashes/coverage per CPU-hour, marginal value curve.
- _compute_diversity_bonus: edge cases (single agent, identical coverage, etc.).
- _compute_marginal_value_curve: ordering, empty inputs.
"""

from __future__ import annotations


import pytest

from parser_security_eval.scoring.coverage_agg import AgentCoverage
from parser_security_eval.scoring.dedup import CrashCluster, CrashReport, FuzzerEngine
from parser_security_eval.scoring.swarm import (
    EfficiencyMetrics,
    IndividualScore,
    SwarmScore,
    _compute_diversity_bonus,
    _compute_marginal_value_curve,
    _severity_weight_for_cluster,
    compute_efficiency_metrics,
    compute_individual_scores,
    compute_swarm_score,
)
from parser_security_eval.triage.casr import (
    CrashSeverity,
    Exploitability,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_crash_report(
    agent_id: str = "agent-00",
    frames: list[str] | None = None,
) -> CrashReport:
    """Create a dedup-module CrashReport."""
    return CrashReport(
        agent_id=agent_id,
        crash_input=b"\x00",
        stack_frames=frames if frames is not None else ["#0 foo x.c:1"],
        engine=FuzzerEngine.LIBFUZZER,
        target="libpng",
        crash_type="heap-buffer-overflow",
    )


def _make_cluster(
    cluster_id: int,
    agent_ids: tuple[str, ...],
    representative_agent: str | None = None,
    severity: CrashSeverity | None = None,
) -> CrashCluster:
    """Create a CrashCluster with the given agents."""
    rep_agent = representative_agent or agent_ids[0]
    rep = _make_crash_report(
        rep_agent, frames=[f"#0 func_{cluster_id} x.c:{cluster_id}"]
    )
    # Attach severity to the representative via a CASR-style CrashReport
    # stored on the dedup cluster.  The dedup CrashReport doesn't have
    # severity, so we monkeypatch it for scoring tests.
    if severity is not None:
        object.__setattr__(rep, "severity", severity)
    return CrashCluster(
        cluster_id=cluster_id,
        stack_hash=f"hash_{cluster_id}",
        representative=rep,
        members=[],
        agent_ids=agent_ids,
    )


def _make_agent_coverage(
    agent_id: str = "agent-00",
    binary_name: str = "fuzz_png",
    lines: set[str] | None = None,
    branches: set[str] | None = None,
) -> AgentCoverage:
    return AgentCoverage(
        agent_id=agent_id,
        binary_name=binary_name,
        covered_lines=lines or set(),
        covered_branches=branches or set(),
        covered_functions=set(),
        line_coverage_pct=50.0,
        branch_coverage_pct=40.0,
        function_coverage_pct=60.0,
    )


# ---------------------------------------------------------------------------
# IndividualScore model
# ---------------------------------------------------------------------------


class TestIndividualScoreModel:
    def test_construction(self) -> None:
        s = IndividualScore(agent_id="a", unique_crashes_found=3, score=10.0)
        assert s.agent_id == "a"
        assert s.unique_crashes_found == 3
        assert s.score == 10.0

    def test_defaults(self) -> None:
        s = IndividualScore(agent_id="a")
        assert s.unique_crashes_found == 0
        assert s.severity_weighted_crashes == 0.0
        assert s.marginal_coverage_contribution == 0
        assert s.first_to_find_bonus == 0.0
        assert s.score == 0.0

    def test_round_trip(self) -> None:
        s = IndividualScore(
            agent_id="a",
            unique_crashes_found=2,
            severity_weighted_crashes=5.0,
            marginal_coverage_contribution=10,
            first_to_find_bonus=2.0,
            score=17.0,
        )
        restored = IndividualScore.model_validate(s.model_dump())
        assert restored == s


# ---------------------------------------------------------------------------
# SwarmScore model
# ---------------------------------------------------------------------------


class TestSwarmScoreModel:
    def test_construction(self) -> None:
        s = SwarmScore(total_unique_crashes=5, total_coverage=100, score=105.5)
        assert s.total_unique_crashes == 5
        assert s.score == 105.5

    def test_defaults(self) -> None:
        s = SwarmScore()
        assert s.total_unique_crashes == 0
        assert s.total_coverage == 0
        assert s.coverage_diversity_bonus == 0.0
        assert s.individual_scores == []

    def test_round_trip(self) -> None:
        ind = IndividualScore(agent_id="a", score=5.0)
        s = SwarmScore(
            total_unique_crashes=3,
            total_coverage=50,
            coverage_diversity_bonus=0.8,
            score=53.8,
            individual_scores=[ind],
        )
        restored = SwarmScore.model_validate(s.model_dump())
        assert restored.total_unique_crashes == 3
        assert len(restored.individual_scores) == 1


# ---------------------------------------------------------------------------
# EfficiencyMetrics model
# ---------------------------------------------------------------------------


class TestEfficiencyMetricsModel:
    def test_construction(self) -> None:
        m = EfficiencyMetrics(
            crashes_per_cpu_hour=2.5,
            coverage_per_cpu_hour=100.0,
            marginal_value_curve=[3, 1, 0],
            total_cpu_hours=4.0,
        )
        assert m.crashes_per_cpu_hour == 2.5
        assert m.marginal_value_curve == [3, 1, 0]

    def test_defaults(self) -> None:
        m = EfficiencyMetrics()
        assert m.crashes_per_cpu_hour == 0.0
        assert m.marginal_value_curve == []
        assert m.total_cpu_hours == 0.0

    def test_round_trip(self) -> None:
        m = EfficiencyMetrics(
            crashes_per_cpu_hour=1.0,
            coverage_per_cpu_hour=50.0,
            marginal_value_curve=[2, 1],
            total_cpu_hours=3.0,
        )
        restored = EfficiencyMetrics.model_validate(m.model_dump())
        assert restored.marginal_value_curve == [2, 1]


# ---------------------------------------------------------------------------
# _severity_weight_for_cluster
# ---------------------------------------------------------------------------


class TestSeverityWeight:
    def test_no_severity_returns_default(self) -> None:
        cluster = _make_cluster(1, ("agent-00",))
        assert _severity_weight_for_cluster(cluster) == 1.0

    def test_exploitable_returns_3(self) -> None:
        sev = CrashSeverity(
            short_description="heap-overflow",
            exploitability=Exploitability.EXPLOITABLE,
        )
        cluster = _make_cluster(1, ("agent-00",), severity=sev)
        assert _severity_weight_for_cluster(cluster) == 3.0

    def test_not_exploitable_returns_1(self) -> None:
        sev = CrashSeverity(
            short_description="stack-overflow",
            exploitability=Exploitability.NOT_EXPLOITABLE,
        )
        cluster = _make_cluster(1, ("agent-00",), severity=sev)
        assert _severity_weight_for_cluster(cluster) == 1.0


# ---------------------------------------------------------------------------
# compute_individual_scores
# ---------------------------------------------------------------------------


class TestComputeIndividualScores:
    def test_single_agent_single_crash(self) -> None:
        clusters = [_make_cluster(1, ("agent-00",))]
        scores = compute_individual_scores(clusters, [], ["agent-00"])
        assert len(scores) == 1
        s = scores[0]
        assert s.agent_id == "agent-00"
        assert s.unique_crashes_found == 1
        # Default severity weight = 1.0, first-find bonus = 1.0
        assert s.severity_weighted_crashes == 1.0
        assert s.first_to_find_bonus == 1.0

    def test_two_agents_shared_crash(self) -> None:
        clusters = [
            _make_cluster(1, ("agent-00", "agent-01"), representative_agent="agent-00")
        ]
        scores = compute_individual_scores(clusters, [], ["agent-00", "agent-01"])
        s0 = next(s for s in scores if s.agent_id == "agent-00")
        s1 = next(s for s in scores if s.agent_id == "agent-01")
        # Both agents found the crash
        assert s0.unique_crashes_found == 1
        assert s1.unique_crashes_found == 1
        # Only agent-00 gets the first-find bonus (representative)
        assert s0.first_to_find_bonus == 1.0
        assert s1.first_to_find_bonus == 0.0

    def test_marginal_coverage_counted(self) -> None:
        cov_a = _make_agent_coverage(
            "agent-00", lines={"f:1", "f:2"}, branches={"f:1:0"}
        )
        cov_b = _make_agent_coverage(
            "agent-01", lines={"f:2", "f:3"}, branches={"f:2:0"}
        )
        scores = compute_individual_scores([], [cov_a, cov_b], ["agent-00", "agent-01"])
        s0 = next(s for s in scores if s.agent_id == "agent-00")
        s1 = next(s for s in scores if s.agent_id == "agent-01")
        # agent-00 marginal: line f:1 + branch f:1:0 = 2
        assert s0.marginal_coverage_contribution == 2
        # agent-01 marginal: line f:3 + branch f:2:0 = 2
        assert s1.marginal_coverage_contribution == 2

    def test_no_crashes_no_coverage(self) -> None:
        scores = compute_individual_scores([], [], ["agent-00"])
        assert len(scores) == 1
        assert scores[0].score == 0.0
        assert scores[0].unique_crashes_found == 0

    def test_multiple_crashes_different_agents(self) -> None:
        c1 = _make_cluster(1, ("agent-00",))
        c2 = _make_cluster(2, ("agent-01",))
        c3 = _make_cluster(3, ("agent-00", "agent-01"), representative_agent="agent-01")
        scores = compute_individual_scores([c1, c2, c3], [], ["agent-00", "agent-01"])
        s0 = next(s for s in scores if s.agent_id == "agent-00")
        s1 = next(s for s in scores if s.agent_id == "agent-01")
        # agent-00 found clusters 1 and 3
        assert s0.unique_crashes_found == 2
        # agent-01 found clusters 2 and 3
        assert s1.unique_crashes_found == 2
        # First-finds: agent-00 first on c1, agent-01 first on c2 and c3
        assert s0.first_to_find_bonus == 1.0
        assert s1.first_to_find_bonus == 2.0


# ---------------------------------------------------------------------------
# compute_swarm_score
# ---------------------------------------------------------------------------


class TestComputeSwarmScore:
    def test_basic_swarm_score(self) -> None:
        c1 = _make_cluster(1, ("agent-00",))
        c2 = _make_cluster(2, ("agent-01",))
        swarm = compute_swarm_score([c1, c2], [], ["agent-00", "agent-01"])
        assert swarm.total_unique_crashes == 2
        assert len(swarm.individual_scores) == 2
        # No coverage → total_coverage=0, diversity_bonus=0
        assert swarm.total_coverage == 0
        assert swarm.coverage_diversity_bonus == 0.0
        # score = 2 + 0 + 0 = 2
        assert swarm.score == 2.0

    def test_with_coverage(self) -> None:
        cov_a = _make_agent_coverage(
            "agent-00", lines={"f:1", "f:2"}, branches={"f:1:0"}
        )
        cov_b = _make_agent_coverage("agent-01", lines={"f:3"}, branches={"f:2:0"})
        swarm = compute_swarm_score([], [cov_a, cov_b], ["agent-00", "agent-01"])
        # union lines = {f:1, f:2, f:3} = 3, union branches = {f:1:0, f:2:0} = 2
        assert swarm.total_coverage == 5
        # Jaccard(lines) for a::b = |{f:1,f:2} & {f:3}| / |{f:1,f:2,f:3}| = 0/3 = 0
        # diversity_bonus = 1 - 0 = 1.0
        assert swarm.coverage_diversity_bonus == pytest.approx(1.0)

    def test_identical_coverage_no_diversity(self) -> None:
        lines = {"f:1", "f:2"}
        cov_a = _make_agent_coverage("agent-00", lines=lines)
        cov_b = _make_agent_coverage("agent-01", lines=lines)
        swarm = compute_swarm_score([], [cov_a, cov_b], ["agent-00", "agent-01"])
        # Identical coverage → Jaccard=1 → diversity_bonus=0
        assert swarm.coverage_diversity_bonus == pytest.approx(0.0)

    def test_empty_swarm(self) -> None:
        swarm = compute_swarm_score([], [], [])
        assert swarm.total_unique_crashes == 0
        assert swarm.total_coverage == 0
        assert swarm.score == 0.0
        assert swarm.individual_scores == []


# ---------------------------------------------------------------------------
# _compute_diversity_bonus
# ---------------------------------------------------------------------------


class TestComputeDiversityBonus:
    def test_single_agent_returns_zero(self) -> None:
        from parser_security_eval.scoring.coverage_agg import (
            merge_agent_coverage_from_sets,
        )

        cov = _make_agent_coverage("agent-00", lines={"f:1"})
        agg = merge_agent_coverage_from_sets([cov])
        assert _compute_diversity_bonus(agg) == 0.0

    def test_disjoint_agents_high_diversity(self) -> None:
        from parser_security_eval.scoring.coverage_agg import (
            merge_agent_coverage_from_sets,
        )

        cov_a = _make_agent_coverage("a", lines={"f:1"})
        cov_b = _make_agent_coverage("b", lines={"f:2"})
        agg = merge_agent_coverage_from_sets([cov_a, cov_b])
        # Jaccard = 0 → bonus = 1.0
        assert _compute_diversity_bonus(agg) == pytest.approx(1.0)

    def test_identical_agents_zero_diversity(self) -> None:
        from parser_security_eval.scoring.coverage_agg import (
            merge_agent_coverage_from_sets,
        )

        lines = {"f:1", "f:2"}
        cov_a = _make_agent_coverage("a", lines=lines)
        cov_b = _make_agent_coverage("b", lines=lines)
        agg = merge_agent_coverage_from_sets([cov_a, cov_b])
        assert _compute_diversity_bonus(agg) == pytest.approx(0.0)


# ---------------------------------------------------------------------------
# compute_efficiency_metrics
# ---------------------------------------------------------------------------


class TestComputeEfficiencyMetrics:
    def test_crashes_per_cpu_hour(self) -> None:
        clusters = [_make_cluster(i, ("agent-00",)) for i in range(1, 6)]
        m = compute_efficiency_metrics(clusters, [], 2.5, ["agent-00"])
        assert m.crashes_per_cpu_hour == pytest.approx(2.0)
        assert m.total_cpu_hours == 2.5

    def test_zero_cpu_hours(self) -> None:
        clusters = [_make_cluster(1, ("agent-00",))]
        m = compute_efficiency_metrics(clusters, [], 0.0, ["agent-00"])
        assert m.crashes_per_cpu_hour == 0.0
        assert m.coverage_per_cpu_hour == 0.0

    def test_coverage_per_cpu_hour(self) -> None:
        cov = _make_agent_coverage("agent-00", lines={"f:1", "f:2"}, branches={"f:1:0"})
        m = compute_efficiency_metrics([], [cov], 1.0, ["agent-00"])
        # 2 lines + 1 branch = 3 coverage / 1 hour = 3.0
        assert m.coverage_per_cpu_hour == pytest.approx(3.0)

    def test_marginal_value_curve(self) -> None:
        c1 = _make_cluster(1, ("agent-00",))
        c2 = _make_cluster(2, ("agent-00", "agent-01"))
        c3 = _make_cluster(3, ("agent-01",))
        m = compute_efficiency_metrics([c1, c2, c3], [], 1.0, ["agent-00", "agent-01"])
        # agent-00 finds c1, c2 → 2 new bugs
        # agent-01 finds c2, c3 → c2 already counted, c3 is new → 1 new bug
        assert m.marginal_value_curve == [2, 1]


# ---------------------------------------------------------------------------
# _compute_marginal_value_curve
# ---------------------------------------------------------------------------


class TestMarginalValueCurve:
    def test_empty_agents(self) -> None:
        assert _compute_marginal_value_curve([], []) == []

    def test_single_agent_all_bugs(self) -> None:
        clusters = [_make_cluster(i, ("a",)) for i in range(1, 4)]
        curve = _compute_marginal_value_curve(clusters, ["a"])
        assert curve == [3]

    def test_ordering_matters(self) -> None:
        c1 = _make_cluster(1, ("a", "b"))
        c2 = _make_cluster(2, ("b",))
        # If a goes first, a gets c1 (1 new), b gets c2 (1 new)
        curve_ab = _compute_marginal_value_curve([c1, c2], ["a", "b"])
        assert curve_ab == [1, 1]
        # If b goes first, b gets c1 and c2 (2 new), a gets 0 new
        curve_ba = _compute_marginal_value_curve([c1, c2], ["b", "a"])
        assert curve_ba == [2, 0]

    def test_agent_with_no_crashes(self) -> None:
        c1 = _make_cluster(1, ("a",))
        curve = _compute_marginal_value_curve([c1], ["a", "b"])
        assert curve == [1, 0]
