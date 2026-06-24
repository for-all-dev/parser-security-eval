"""Tests for registry-driven hunt candidate selection (run_loop mocked)."""

from __future__ import annotations

from pathlib import Path

from parser_security_eval.treesitter import loop as loop_mod
from parser_security_eval.treesitter.loop import run_hunt, select_hunt_candidates
from parser_security_eval.treesitter.models import Tier, TSLoopResult
from parser_security_eval.treesitter.survey.models import GrammarRecord


def _rec(name, owner, repo, *, scanner, fuzzed, prio) -> GrammarRecord:  # noqa: ANN001
    return GrammarRecord(
        name=name,
        language_group=name,
        repo_url=f"https://github.com/{owner}/{repo}",
        owner=owner,
        repo=repo,
        has_external_scanner=scanner,
        scores={"already_fuzzed": 1.0 if fuzzed else 0.0},
        fuzz_priority=prio,
    )


def _write_registry(tmp_path: Path) -> Path:
    records = [
        _rec(
            "cmake", "uyha", "tree-sitter-cmake", scanner=True, fuzzed=False, prio=50.0
        ),
        _rec(
            "fish", "ram02z", "tree-sitter-fish", scanner=True, fuzzed=False, prio=40.0
        ),
        # excluded: already fuzzed
        _rec(
            "ruby",
            "tree-sitter",
            "tree-sitter-ruby",
            scanner=True,
            fuzzed=True,
            prio=60.0,
        ),
        # excluded: no scanner
        _rec(
            "vimdoc",
            "neovim",
            "tree-sitter-vimdoc",
            scanner=False,
            fuzzed=False,
            prio=55.0,
        ),
        # excluded: archived/abandoned (priority 0)
        _rec("dead", "x", "tree-sitter-dead", scanner=True, fuzzed=False, prio=0.0),
        # duplicate repo of cmake, lower priority → deduped
        _rec(
            "cmake", "uyha", "tree-sitter-cmake", scanner=True, fuzzed=False, prio=10.0
        ),
    ]
    p = tmp_path / "registry.jsonl"
    p.write_text("\n".join(r.to_jsonl() for r in records) + "\n", encoding="utf-8")
    return p


def test_select_filters_and_orders(tmp_path: Path) -> None:
    reg = _write_registry(tmp_path)
    cands = select_hunt_candidates(reg, top_n=10)
    names = [c.name for c in cands]
    # only un-fuzzed scanner grammars, priority-ordered, deduped
    assert names == ["uyha-cmake", "ram02z-fish"]
    assert all(c.tier == Tier.less_popular for c in cands)
    assert len(names) == len(set(names))  # unique slugs


def test_select_excludes_fuzzed_noscanner_archived(tmp_path: Path) -> None:
    reg = _write_registry(tmp_path)
    cands = select_hunt_candidates(reg, top_n=10)
    repos = {c.repo_url for c in cands}
    assert "https://github.com/tree-sitter/tree-sitter-ruby" not in repos  # fuzzed
    assert "https://github.com/neovim/tree-sitter-vimdoc" not in repos  # no scanner
    assert "https://github.com/x/tree-sitter-dead" not in repos  # archived (prio 0)


def test_select_respects_top_n(tmp_path: Path) -> None:
    reg = _write_registry(tmp_path)
    assert len(select_hunt_candidates(reg, top_n=1)) == 1


def test_select_start_offset_skips_earlier_ranks(tmp_path: Path) -> None:
    reg = _write_registry(tmp_path)
    # eligible order is [uyha-cmake (50), ram02z-fish (40)]
    assert [c.name for c in select_hunt_candidates(reg, top_n=10, start=2)] == [
        "ram02z-fish"
    ]
    assert [c.name for c in select_hunt_candidates(reg, top_n=1, start=1)] == [
        "uyha-cmake"
    ]
    # start past the end → empty
    assert select_hunt_candidates(reg, top_n=10, start=3) == []


def test_run_hunt_invokes_loop_per_candidate(tmp_path: Path, monkeypatch) -> None:
    reg = _write_registry(tmp_path)
    calls: list[str] = []

    def fake_run_loop(target, **kwargs):  # noqa: ANN001, ANN202
        calls.append(target.name)
        assert kwargs["iterations"] == 1
        assert kwargs["fuzz_seconds"] == 99
        return TSLoopResult(
            grammar=target.name, tier=target.tier, language=target.language
        )

    monkeypatch.setattr(loop_mod, "run_loop", fake_run_loop)
    results = run_hunt(reg, top_n=10, fuzz_seconds=99, out_dir=tmp_path / "hunt")
    assert calls == ["uyha-cmake", "ram02z-fish"]
    assert len(results) == 2
