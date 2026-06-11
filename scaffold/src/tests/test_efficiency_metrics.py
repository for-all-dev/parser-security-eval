"""Tests for the resource-efficiency metrics (scorers/efficiency.py, issue #135).

Covers:
- EfficiencyInputs.as_metadata round-trip.
- vulns_per_mtok / vulns_per_fuzz_hour / token_rate pooled correctly.
- vulns_per_mtok_equiv: the kappa opportunity-cost denominator.
- Edge cases: zero resources stay 0.0 (never NaN/inf), per-sample kappa fallback.
- The "no spurious interaction" property the design hinges on.
"""

from __future__ import annotations

import math
from collections.abc import Callable

from inspect_ai.scorer import Metric, SampleScore, Score

from parser_security_eval.scorers.efficiency import (
    EFF_FUZZ_SECONDS,
    EFF_MODEL_SECONDS,
    EFF_TOKENS,
    EFF_VULNS,
    EfficiencyInputs,
    token_equivalent_total,
    token_rate,
    vulns_per_fuzz_hour,
    vulns_per_mtok,
    vulns_per_mtok_equiv,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _sample(
    *,
    vulns: int = 0,
    tokens: int = 0,
    model_seconds: float = 0.0,
    fuzz_seconds: float = 0.0,
    sample_id: str = "s",
) -> SampleScore:
    """Build a SampleScore carrying the canonical efficiency metadata."""
    inputs = EfficiencyInputs(
        vulns=vulns,
        total_tokens=tokens,
        model_seconds=model_seconds,
        fuzz_seconds=fuzz_seconds,
    )
    return SampleScore(
        score=Score(value=0.0, metadata=inputs.as_metadata()),
        sample_id=sample_id,
    )


def _value(factory: Callable[[], Metric], scores: list[SampleScore]) -> float:
    """Invoke a registered metric and return its value as a float.

    Inspect's metric factories are typed ``MetricProtocol | MetricDeprecated`` and
    return the broad ``Value`` union; our metrics always yield a float, so we
    narrow it here (with a runtime assert) to keep call sites clean.
    """
    result = factory()(scores)  # type: ignore[invalid-argument-type]
    assert isinstance(result, float)
    return result


# ---------------------------------------------------------------------------
# EfficiencyInputs
# ---------------------------------------------------------------------------


class TestEfficiencyInputs:
    def test_as_metadata_keys(self) -> None:
        md = EfficiencyInputs(
            vulns=3, total_tokens=10, model_seconds=1.5, fuzz_seconds=2.0
        ).as_metadata()
        assert md == {
            EFF_VULNS: 3.0,
            EFF_TOKENS: 10.0,
            EFF_MODEL_SECONDS: 1.5,
            EFF_FUZZ_SECONDS: 2.0,
        }

    def test_defaults_are_zero(self) -> None:
        md = EfficiencyInputs().as_metadata()
        assert all(v == 0.0 for v in md.values())


# ---------------------------------------------------------------------------
# Pure single-resource rates
# ---------------------------------------------------------------------------


class TestVulnsPerMtok:
    def test_single_sample(self) -> None:
        # 2 vulns / 0.5 Mtok = 4.0
        assert _value(vulns_per_mtok, [_sample(vulns=2, tokens=500_000)]) == 4.0

    def test_pooled_not_averaged(self) -> None:
        # Pooled: (2 + 1) / ((500_000 + 1_000_000)/1e6) = 3 / 1.5 = 2.0
        scores = [
            _sample(vulns=2, tokens=500_000, sample_id="a"),
            _sample(vulns=1, tokens=1_000_000, sample_id="b"),
        ]
        assert _value(vulns_per_mtok, scores) == 2.0
        # Averaging per-sample ratios would give (4.0 + 1.0)/2 = 2.5 — guard it.
        assert _value(vulns_per_mtok, scores) != 2.5

    def test_zero_tokens_is_zero_not_inf(self) -> None:
        result = _value(vulns_per_mtok, [_sample(vulns=5, tokens=0)])
        assert result == 0.0
        assert math.isfinite(result)


class TestVulnsPerFuzzHour:
    def test_rate(self) -> None:
        # 3 vulns over 200 fuzz-seconds = 3 / (200/3600) = 54.0 vulns/hour
        assert _value(vulns_per_fuzz_hour, [_sample(vulns=3, fuzz_seconds=200)]) == 54.0

    def test_zero_fuzz_is_zero(self) -> None:
        assert _value(vulns_per_fuzz_hour, [_sample(vulns=5, fuzz_seconds=0)]) == 0.0


class TestTokenRate:
    def test_kappa(self) -> None:
        # 500_000 tokens / 100 thinking-seconds = 5000 tok/s
        assert (
            _value(token_rate, [_sample(tokens=500_000, model_seconds=100)]) == 5000.0
        )

    def test_pooled_kappa(self) -> None:
        scores = [
            _sample(tokens=500_000, model_seconds=100, sample_id="a"),
            _sample(tokens=1_000_000, model_seconds=50, sample_id="b"),
        ]
        # (1_500_000) / (150) = 10_000 tok/s
        assert _value(token_rate, scores) == 10_000.0

    def test_zero_thinking_is_zero(self) -> None:
        assert _value(token_rate, [_sample(tokens=100, model_seconds=0)]) == 0.0


# ---------------------------------------------------------------------------
# Kappa opportunity-cost (headline metric)
# ---------------------------------------------------------------------------


class TestVulnsPerMtokEquiv:
    def test_single_sample_charges_fuzz_time_in_tokens(self) -> None:
        # kappa = 500_000/100 = 5000 tok/s.
        # token_equiv = 500_000 + 5000*200 = 1_500_000.
        # vulns_per_mtok_equiv = 2 / 1.5 = 1.3333...
        s = _sample(vulns=2, tokens=500_000, model_seconds=100, fuzz_seconds=200)
        assert token_equivalent_total([s]) == 1_500_000.0
        assert _value(vulns_per_mtok_equiv, [s]) == 2.0 / 1.5

    def test_pooled(self) -> None:
        s1 = _sample(
            vulns=2, tokens=500_000, model_seconds=100, fuzz_seconds=200, sample_id="a"
        )
        # kappa2 = 1_000_000/50 = 20_000; no fuzz so te2 = 1_000_000
        s2 = _sample(
            vulns=1, tokens=1_000_000, model_seconds=50, fuzz_seconds=0, sample_id="b"
        )
        assert token_equivalent_total([s1, s2]) == 2_500_000.0
        # pooled vulns 3 / 2.5 Mtok-equiv = 1.2
        assert _value(vulns_per_mtok_equiv, [s1, s2]) == 1.2

    def test_equiv_is_at_most_pure_token_rate(self) -> None:
        # Charging fuzz-time can only *lower* the per-resource yield, never raise
        # it — the equiv denominator >= the raw token denominator.
        s = _sample(vulns=4, tokens=1_000_000, model_seconds=10, fuzz_seconds=50)
        assert _value(vulns_per_mtok_equiv, [s]) <= _value(vulns_per_mtok, [s])

    def test_no_fuzz_equals_pure_token_rate(self) -> None:
        # With zero fuzz-time the kappa term vanishes and equiv == vulns_per_mtok.
        s = _sample(vulns=4, tokens=2_000_000, model_seconds=10, fuzz_seconds=0)
        assert _value(vulns_per_mtok_equiv, [s]) == _value(vulns_per_mtok, [s])

    def test_zero_vulns_is_zero_not_undefined(self) -> None:
        s = _sample(vulns=0, tokens=1_000_000, model_seconds=10, fuzz_seconds=100)
        result = _value(vulns_per_mtok_equiv, [s])
        assert result == 0.0
        assert math.isfinite(result)

    def test_per_sample_kappa_falls_back_to_global(self) -> None:
        # A sample with no recorded thinking time still has its fuzz-time charged,
        # using the pooled global kappa rather than being dropped.
        with_think = _sample(
            tokens=1_000_000, model_seconds=100, fuzz_seconds=0, sample_id="a"
        )  # establishes global kappa = 10_000 tok/s
        no_think = _sample(
            vulns=1, tokens=0, model_seconds=0, fuzz_seconds=50, sample_id="b"
        )
        # global kappa = 1_000_000 / 100 = 10_000.
        # te(with_think) = 1_000_000; te(no_think) = 0 + 10_000*50 = 500_000.
        assert token_equivalent_total([with_think, no_think]) == 1_500_000.0

    def test_empty_scores(self) -> None:
        assert _value(vulns_per_mtok_equiv, []) == 0.0
        assert _value(vulns_per_mtok, []) == 0.0
        assert _value(vulns_per_fuzz_hour, []) == 0.0
        assert _value(token_rate, []) == 0.0


# ---------------------------------------------------------------------------
# Design property: linear, no spurious interaction
# ---------------------------------------------------------------------------


class TestNoSpuriousInteraction:
    def test_denominator_is_linear_in_resources(self) -> None:
        # Doubling BOTH tokens and fuzz-time (same kappa) doubles the denominator
        # — degree 1, not degree 2 as a product (tokens * time) would give.
        base = _sample(tokens=1_000_000, model_seconds=100, fuzz_seconds=200)
        doubled = _sample(tokens=2_000_000, model_seconds=200, fuzz_seconds=400)
        assert token_equivalent_total([doubled]) == 2 * token_equivalent_total([base])

    def test_starving_one_resource_does_not_blow_up(self) -> None:
        # Near-zero fuzz-time must not send the metric toward infinity (the
        # failure mode of a product denominator).
        s = _sample(vulns=1, tokens=1_000_000, model_seconds=100, fuzz_seconds=0.001)
        result = _value(vulns_per_mtok_equiv, [s])
        assert math.isfinite(result)
        assert result <= _value(vulns_per_mtok, [s])
