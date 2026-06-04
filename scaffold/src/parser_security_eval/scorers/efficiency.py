"""Resource-efficiency metrics for fuzzing evals (issue #135).

What this measures
------------------
We want the incidence of vulnerabilities discovered per unit of resource spent,
as a function of model and agent architecture (the project's "core crux").  A
fuzzing run consumes *two* genuinely different resources:

  * ``tokens``      — LLM inference: analysing source, writing/repairing
                      harnesses, triaging crashes.  Priced in $/Mtok.
  * ``fuzz_seconds`` — wall-clock the *fuzzer* burns executing the target after a
                      harness compiles.  Independent of the model; priced in
                      $/CPU-hour.

The wrong way to combine them is a product (``vulns / (tokens * time)``): that
denominator is homogeneous of degree -2 (doing the same job at 2x scale looks 4x
worse), has no real-world price (there is no $/token-hour), and blows up to
infinity when either resource is starved.  A *cost* is additive, not
multiplicative — your invoice is (tokens x $/Mtok) + (CPU-hours x $/hr), a sum.

Why we charge fuzz-time in tokens (the "kappa opportunity cost")
----------------------------------------------------------------
Converting tokens -> dollars is an *informative* normalisation: the token price
covaries with the model (Opus tokens cost more because they are worth more), so
dollars are "model-size-class-adjusted tokens".  Converting CPU-time -> dollars
is *not* informative: a CPU-second is fungible commodity compute and its cloud
price is an exogenous constant that does not covary with the thing being
evaluated.  Baking that constant into the denominator arbitrarily reweights the
two terms.

So we keep everything in the currency that carries the capability signal —
tokens — and charge fuzz-time at its *opportunity cost in tokens*.  The agent is
idle while the fuzzer runs, so a fuzz-second costs the tokens the agent could
have generated in that second:

    kappa  = total_tokens / model_thinking_seconds      # tokens/sec, measured
    D      = total_tokens + kappa * fuzz_seconds         # token-equivalents

``kappa`` is endogenous — measured from the run itself (sum of model-event
working time) — so no external price ever enters.  Note that
``D == kappa * (thinking_seconds + fuzz_seconds) == kappa * total_walltime``,
i.e. the token-equivalent denominator is just vulns-per-walltime (the core crux)
expressed in the token currency, with the model's own rate as the scale.  To get
dollars, multiply by the one price you trust: ``$/vuln = D * ($/Mtok) / V``.

Pooling
-------
Rates are *pooled* across samples (sum(V) / sum(resource)), never averaged over
per-sample ratios.  A single sample that finds 1 vuln in 0.1 Mtok would
otherwise dominate, and zero-resource samples make per-sample ratios undefined.
Pooling yields the true incidence rate over the eval.

Registered metrics
-------------------
``vulns_per_mtok``        — vulns per million tokens (pure token rate)
``vulns_per_fuzz_hour``   — vulns per fuzzer wall-clock hour (pure time rate;
                            this is the CLAUDE.md "core crux" metric)
``token_rate``            — kappa: mean tokens/sec of model thinking (diagnostic)
``vulns_per_mtok_equiv``  — headline: vulns per million token-equivalents, with
                            fuzz-time charged at the kappa opportunity cost

The reciprocal of ``vulns_per_mtok_equiv`` is the expected token-equivalent
expenditure to find one vuln (the June SoW milestone); it is left as a downstream
reciprocal so the zero-vuln case stays a clean ``0.0`` rate rather than an
undefined inverse.
"""

from __future__ import annotations

import logging

from pydantic import BaseModel
from inspect_ai.scorer import Metric, SampleScore, Value, metric

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Canonical metadata keys
# ---------------------------------------------------------------------------
# The scorer stashes these on ``Score.metadata`` so the registered metrics —
# which only ever see ``Score`` objects — can recover the raw resource counts.

EFF_VULNS = "eff_vulns"  # int: deduplicated unique vulns found this sample
EFF_TOKENS = "eff_total_tokens"  # int: total tokens consumed this sample
EFF_MODEL_SECONDS = "eff_model_seconds"  # float: model thinking time (for kappa)
EFF_FUZZ_SECONDS = "eff_fuzz_seconds"  # float: fuzzer wall-clock seconds (W)


class EfficiencyInputs(BaseModel):
    """Raw per-sample resource counts feeding the efficiency metrics.

    Produced by the scorer (see ``as_metadata``) and consumed by the registered
    metrics below.  All fields are non-negative; defaults make a sample with no
    recorded activity contribute zero to every pooled rate.
    """

    vulns: int = 0
    total_tokens: int = 0
    model_seconds: float = 0.0  # sum of model-event working time (thinking)
    fuzz_seconds: float = 0.0  # sum of fuzzer run durations (W)

    def as_metadata(self) -> dict[str, float]:
        """Render to the canonical ``Score.metadata`` keys."""
        return {
            EFF_VULNS: float(self.vulns),
            EFF_TOKENS: float(self.total_tokens),
            EFF_MODEL_SECONDS: float(self.model_seconds),
            EFF_FUZZ_SECONDS: float(self.fuzz_seconds),
        }


# ---------------------------------------------------------------------------
# Pooling helpers
# ---------------------------------------------------------------------------


def _field(sample_score: SampleScore, key: str) -> float:
    """Read a numeric efficiency field from a sample's score metadata."""
    md = sample_score.score.metadata or {}
    value = md.get(key, 0.0)
    if value is None:
        return 0.0
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return float(value)
    return 0.0


def _pooled_totals(scores: list[SampleScore]) -> tuple[float, float, float, float]:
    """Return pooled (vulns, tokens, model_seconds, fuzz_seconds) over samples."""
    vulns = sum(_field(s, EFF_VULNS) for s in scores)
    tokens = sum(_field(s, EFF_TOKENS) for s in scores)
    model_seconds = sum(_field(s, EFF_MODEL_SECONDS) for s in scores)
    fuzz_seconds = sum(_field(s, EFF_FUZZ_SECONDS) for s in scores)
    return vulns, tokens, model_seconds, fuzz_seconds


def _kappa(tokens: float, model_seconds: float, fallback: float = 0.0) -> float:
    """Token-generation rate (tokens/sec); ``fallback`` when no thinking time."""
    return tokens / model_seconds if model_seconds > 0 else fallback


def token_equivalent_total(scores: list[SampleScore]) -> float:
    """Pooled token-equivalent denominator: sum_i (tokens_i + kappa_i * W_i).

    Each sample is charged its fuzz-time at *its own* measured token rate; a
    sample with no recorded thinking time falls back to the global pooled rate so
    its fuzz-time is still charged rather than dropped.
    """
    _, total_tokens, total_model_seconds, _ = _pooled_totals(scores)
    global_kappa = _kappa(total_tokens, total_model_seconds)

    total = 0.0
    for s in scores:
        tokens = _field(s, EFF_TOKENS)
        model_seconds = _field(s, EFF_MODEL_SECONDS)
        fuzz_seconds = _field(s, EFF_FUZZ_SECONDS)
        kappa = _kappa(tokens, model_seconds, fallback=global_kappa)
        total += tokens + kappa * fuzz_seconds
    return total


# ---------------------------------------------------------------------------
# Registered Inspect-AI metrics
# ---------------------------------------------------------------------------

_MILLION = 1_000_000.0
_SECONDS_PER_HOUR = 3_600.0


@metric
def vulns_per_mtok() -> Metric:
    """Pooled vulns per million tokens."""

    def metric_fn(scores: list[SampleScore]) -> Value:
        vulns, tokens, _, _ = _pooled_totals(scores)
        return vulns / (tokens / _MILLION) if tokens > 0 else 0.0

    return metric_fn


@metric
def vulns_per_fuzz_hour() -> Metric:
    """Pooled vulns per fuzzer wall-clock hour (the core-crux rate)."""

    def metric_fn(scores: list[SampleScore]) -> Value:
        vulns, _, _, fuzz_seconds = _pooled_totals(scores)
        return vulns / (fuzz_seconds / _SECONDS_PER_HOUR) if fuzz_seconds > 0 else 0.0

    return metric_fn


@metric
def token_rate() -> Metric:
    """Pooled kappa: tokens generated per second of model thinking (diagnostic)."""

    def metric_fn(scores: list[SampleScore]) -> Value:
        _, tokens, model_seconds, _ = _pooled_totals(scores)
        return _kappa(tokens, model_seconds)

    return metric_fn


@metric
def vulns_per_mtok_equiv() -> Metric:
    """Headline: pooled vulns per million token-equivalents.

    Fuzz-time is charged at the kappa opportunity cost (tokens the agent could
    have generated during the fuzzing wall-clock), so tokens and fuzz-time are
    combined in a single, exogenous-price-free token currency.
    """

    def metric_fn(scores: list[SampleScore]) -> Value:
        vulns, _, _, _ = _pooled_totals(scores)
        denom = token_equivalent_total(scores)
        return vulns / (denom / _MILLION) if denom > 0 else 0.0

    return metric_fn


# Convenience grouping for attaching to a scorer.
EFFICIENCY_METRICS: list[Metric] = [
    vulns_per_mtok(),
    vulns_per_fuzz_hour(),
    token_rate(),
    vulns_per_mtok_equiv(),
]


# ---------------------------------------------------------------------------
# Scorer-side glue
# ---------------------------------------------------------------------------


def model_thinking_seconds() -> float:
    """Sum model-event working time for the current sample (kappa's denominator).

    Reads the live Inspect transcript, so it is only meaningful inside a running
    sample's solver/scorer context.  Returns ``0.0`` (and the metrics fall back
    to the pooled rate) when no transcript is available — e.g. unit tests that
    invoke a scorer directly outside an eval.
    """
    try:
        from inspect_ai.event import ModelEvent
        from inspect_ai.log import transcript
    except ImportError:  # pragma: no cover - import guard
        return 0.0

    try:
        events = transcript().events
    except Exception:  # pragma: no cover - no active transcript (e.g. unit tests)
        return 0.0

    total = 0.0
    for event in events:
        if isinstance(event, ModelEvent) and event.working_time is not None:
            total += float(event.working_time)
    return total
