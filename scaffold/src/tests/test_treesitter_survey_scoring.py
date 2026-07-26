"""Tests for survey priority scoring (bands + gates)."""

from __future__ import annotations

from datetime import datetime, timezone

from parser_security_eval.treesitter.survey.models import GrammarRecord, RepoMetrics
from parser_security_eval.treesitter.survey.scoring import compute_priority

NOW = datetime(2026, 6, 23, tzinfo=timezone.utc)


def _rec(**kw) -> GrammarRecord:  # noqa: ANN003
    base = {
        "name": "x",
        "language_group": "x",
        "repo_url": "https://github.com/o/tree-sitter-x",
        "owner": "o",
        "repo": "tree-sitter-x",
    }
    base.update(kw)
    return GrammarRecord(**base)


def _metrics(**kw) -> RepoMetrics:  # noqa: ANN003
    base = {
        "fetched": True,
        "stars": 200,
        "is_fork": False,
        "archived": False,
        "has_issues": True,
        "pushed_at": "2026-05-01T00:00:00Z",
        "created_at": "2021-01-01T00:00:00Z",
    }
    base.update(kw)
    return RepoMetrics(**base)


def test_archived_is_excluded() -> None:
    rec = _rec(has_external_scanner=True, metrics=_metrics(archived=True))
    compute_priority(rec, NOW)
    assert rec.fuzz_priority == 0.0
    assert rec.scores["tractability"] == 0.0


def test_abandoned_is_excluded() -> None:
    rec = _rec(
        has_external_scanner=True, metrics=_metrics(pushed_at="2022-01-01T00:00:00Z")
    )
    compute_priority(rec, NOW)
    assert rec.scores["activity_gate"] == 0.0
    assert rec.fuzz_priority == 0.0


def test_scanner_beats_no_scanner() -> None:
    with_scanner = _rec(has_external_scanner=True, metrics=_metrics())
    without = _rec(has_external_scanner=False, metrics=_metrics())
    compute_priority(with_scanner, NOW)
    compute_priority(without, NOW)
    assert with_scanner.fuzz_priority > without.fuzz_priority


def test_core_org_penalized() -> None:
    niche = _rec(owner="someone", has_external_scanner=True, metrics=_metrics())
    core = _rec(
        owner="tree-sitter",
        has_external_scanner=True,
        metrics=_metrics(),
    )
    compute_priority(niche, NOW)
    compute_priority(core, NOW)
    # Core org is treated as already-fuzzed (OSS-Fuzz) → lower neglect → lower bug.
    assert core.scores["bug_likelihood"] < niche.scores["bug_likelihood"]
    assert core.scores["neglect"] < niche.scores["neglect"]


def test_already_fuzzed_grammar_deprioritized() -> None:
    fresh = _rec(has_external_scanner=True, metrics=_metrics())
    fuzzed = _rec(
        has_external_scanner=True,
        metrics=_metrics(has_fuzz_setup=True, fuzz_evidence="fuzz/fuzz_parser.cc"),
    )
    compute_priority(fresh, NOW)
    compute_priority(fuzzed, NOW)
    assert fuzzed.scores["already_fuzzed"] == 1.0
    assert fresh.scores["already_fuzzed"] == 0.0
    assert fuzzed.scores["neglect"] < fresh.scores["neglect"]
    assert fuzzed.fuzz_priority < fresh.fuzz_priority


def test_unfuzzed_scanner_beats_fuzzed_scanner_even_if_more_popular() -> None:
    # The whole point: a neglected scanner grammar should outrank a more popular
    # but already-fuzzed one.
    neglected = _rec(has_external_scanner=True, metrics=_metrics(stars=60))
    fuzzed_popular = _rec(
        has_external_scanner=True,
        metrics=_metrics(stars=2000, has_fuzz_setup=True, fuzz_evidence="fuzz/"),
    )
    compute_priority(neglected, NOW)
    compute_priority(fuzzed_popular, NOW)
    assert neglected.fuzz_priority > fuzzed_popular.fuzz_priority


def test_no_scanner_has_minimal_crash_surface() -> None:
    rec = _rec(has_external_scanner=False, metrics=_metrics())
    compute_priority(rec, NOW)
    assert rec.scores["crash_surface"] == 0.15


def test_very_popular_has_lower_bug_likelihood() -> None:
    midpop = _rec(has_external_scanner=True, metrics=_metrics(stars=150))
    superpop = _rec(has_external_scanner=True, metrics=_metrics(stars=20000))
    compute_priority(midpop, NOW)
    compute_priority(superpop, NOW)
    # More stars → more scrutiny → lower latent-bug likelihood.
    assert superpop.scores["low_scrutiny"] < midpop.scores["low_scrutiny"]
    assert superpop.scores["bug_likelihood"] < midpop.scores["bug_likelihood"]


def test_adoption_raises_impact() -> None:
    plain = _rec(has_external_scanner=True, metrics=_metrics())
    adopted = _rec(
        has_external_scanner=True,
        used_by_zed=True,
        used_by_emacs=True,
        metrics=_metrics(),
    )
    compute_priority(plain, NOW)
    compute_priority(adopted, NOW)
    assert adopted.scores["impact"] > plain.scores["impact"]
    assert adopted.fuzz_priority > plain.fuzz_priority


def test_missing_metrics_does_not_crash() -> None:
    rec = _rec(has_external_scanner=True, metrics=RepoMetrics(fetched=False))
    compute_priority(rec, NOW)
    assert 0.0 <= rec.fuzz_priority <= 100.0
    assert rec.scores["months_since_push"] == -1.0
