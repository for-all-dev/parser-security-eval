"""Tests for coverage aggregation across fuzzing agents.

All subprocess calls (llvm-profdata, llvm-cov) are mocked — no real LLVM
toolchain is required to run these tests.

Test coverage:
- CoverageProfile / AgentCoverage / AgentMarginalCoverage / AggregateCoverage
  model construction and serialisation.
- _jaccard: edge cases (empty sets, identical sets, disjoint sets).
- _extract_coverage_sets: parsing of llvm-cov export JSON.
- merge_agent_coverage_from_sets: union, marginal, Jaccard, growth curves.
- build_agent_coverage: mocked subprocess pipeline.
- merge_agent_coverage: end-to-end mocked pipeline.
- Error paths: missing profraw, mismatched binary names, tool not found,
  tool non-zero exit.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from parser_security_eval.scoring.coverage_agg import (
    AgentCoverage,
    AggregateCoverage,
    CoverageProfile,
    _extract_coverage_sets,
    _jaccard,
    _merge_profraw,
    _require_tool,
    build_agent_coverage,
    merge_agent_coverage,
    merge_agent_coverage_from_sets,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_profile(
    agent_id: str = "agent-00",
    binary_name: str = "fuzz_png",
    n_profraws: int = 1,
    tmp_path: Path | None = None,
) -> CoverageProfile:
    if tmp_path is not None:
        paths = [tmp_path / f"{agent_id}_{i}.profraw" for i in range(n_profraws)]
        for p in paths:
            p.write_bytes(b"")
    else:
        paths = [Path(f"/tmp/{agent_id}_{i}.profraw") for i in range(n_profraws)]
    return CoverageProfile(
        agent_id=agent_id,
        binary_name=binary_name,
        profraw_paths=paths,
    )


def _make_agent_coverage(
    agent_id: str = "agent-00",
    binary_name: str = "fuzz_png",
    lines: set[str] | None = None,
    branches: set[str] | None = None,
    functions: set[str] | None = None,
) -> AgentCoverage:
    return AgentCoverage(
        agent_id=agent_id,
        binary_name=binary_name,
        covered_lines=lines or set(),
        covered_branches=branches or set(),
        covered_functions=functions or set(),
        line_coverage_pct=50.0,
        branch_coverage_pct=40.0,
        function_coverage_pct=60.0,
    )


# Minimal llvm-cov export JSON structure used by several tests.
_EXPORT_JSON: dict = {
    "data": [
        {
            "files": [
                {
                    "filename": "/src/foo.c",
                    # segments: [line, col, count, hasCount, isRegionEntry, isGapRegion]
                    "segments": [
                        [10, 1, 5, True, True, False],  # covered
                        [11, 1, 0, True, True, False],  # not covered
                        [12, 1, 3, True, True, True],  # gap — ignored
                    ],
                    "branches": [
                        # [srcLine, srcCol, dstLine, dstCol, count]
                        [10, 1, 15, 1, 2],  # covered
                        [11, 1, 20, 1, 0],  # not covered
                    ],
                    "summary": {},
                }
            ],
            "functions": [
                {"name": "parse_header", "count": 3},
                {"name": "parse_body", "count": 0},
            ],
            "totals": {
                "lines": {"count": 2, "covered": 1},
                "branches": {"count": 2, "covered": 1},
                "functions": {"count": 2, "covered": 1},
            },
        }
    ]
}


# ---------------------------------------------------------------------------
# Model construction / serialisation
# ---------------------------------------------------------------------------


class TestModels:
    def test_coverage_profile_round_trip(self, tmp_path: Path) -> None:
        p = _make_profile(tmp_path=tmp_path)
        data = p.model_dump()
        restored = CoverageProfile.model_validate(data)
        assert restored.agent_id == "agent-00"
        assert len(restored.profraw_paths) == 1

    def test_agent_coverage_round_trip(self) -> None:
        cov = _make_agent_coverage(
            lines={"foo.c:10", "foo.c:11"},
            branches={"foo.c:10:1"},
            functions={"parse_header"},
        )
        data = cov.model_dump()
        restored = AgentCoverage.model_validate(data)
        assert restored.covered_lines == {"foo.c:10", "foo.c:11"}
        assert restored.covered_branches == {"foo.c:10:1"}
        assert restored.covered_functions == {"parse_header"}

    def test_aggregate_coverage_round_trip(self) -> None:
        cov_a = _make_agent_coverage("a", lines={"f:1"}, branches={"f:1:0"})
        cov_b = _make_agent_coverage("b", lines={"f:2"}, branches={"f:1:0"})
        agg = merge_agent_coverage_from_sets([cov_a, cov_b])
        data = agg.model_dump()
        restored = AggregateCoverage.model_validate(data)
        assert restored.union_line_count == 2
        assert restored.union_branch_count == 1

    def test_agent_marginal_coverage_fields(self) -> None:
        cov_a = _make_agent_coverage("a", lines={"f:1", "f:2"})
        cov_b = _make_agent_coverage("b", lines={"f:2", "f:3"})
        agg = merge_agent_coverage_from_sets([cov_a, cov_b])
        a_marginal = next(m for m in agg.per_agent if m.agent_id == "a")
        assert a_marginal.marginal_lines == {"f:1"}
        assert a_marginal.marginal_line_count == 1


# ---------------------------------------------------------------------------
# _jaccard
# ---------------------------------------------------------------------------


class TestJaccard:
    def test_identical_sets(self) -> None:
        s = {"a", "b", "c"}
        assert _jaccard(s, s) == pytest.approx(1.0)

    def test_disjoint_sets(self) -> None:
        assert _jaccard({"a", "b"}, {"c", "d"}) == pytest.approx(0.0)

    def test_partial_overlap(self) -> None:
        # |{a,b} ∩ {b,c}| / |{a,b,c}| = 1/3
        assert _jaccard({"a", "b"}, {"b", "c"}) == pytest.approx(1 / 3)

    def test_both_empty(self) -> None:
        assert _jaccard(set(), set()) == pytest.approx(1.0)

    def test_one_empty(self) -> None:
        assert _jaccard({"a"}, set()) == pytest.approx(0.0)

    def test_subset(self) -> None:
        # {a} ⊂ {a,b,c}: |{a}| / |{a,b,c}| = 1/3
        assert _jaccard({"a"}, {"a", "b", "c"}) == pytest.approx(1 / 3)


# ---------------------------------------------------------------------------
# _extract_coverage_sets
# ---------------------------------------------------------------------------


class TestExtractCoverageSets:
    def test_covered_line_extracted(self) -> None:
        cov = _extract_coverage_sets(_EXPORT_JSON, "fuzz_png", "agent-00")
        assert "/src/foo.c:10" in cov.covered_lines

    def test_uncovered_line_not_extracted(self) -> None:
        cov = _extract_coverage_sets(_EXPORT_JSON, "fuzz_png", "agent-00")
        assert "/src/foo.c:11" not in cov.covered_lines

    def test_gap_segment_ignored(self) -> None:
        cov = _extract_coverage_sets(_EXPORT_JSON, "fuzz_png", "agent-00")
        assert "/src/foo.c:12" not in cov.covered_lines

    def test_covered_branch_extracted(self) -> None:
        cov = _extract_coverage_sets(_EXPORT_JSON, "fuzz_png", "agent-00")
        assert "/src/foo.c:10:1" in cov.covered_branches

    def test_uncovered_branch_not_extracted(self) -> None:
        cov = _extract_coverage_sets(_EXPORT_JSON, "fuzz_png", "agent-00")
        assert "/src/foo.c:11:1" not in cov.covered_branches

    def test_covered_function_extracted(self) -> None:
        cov = _extract_coverage_sets(_EXPORT_JSON, "fuzz_png", "agent-00")
        assert "parse_header" in cov.covered_functions

    def test_uncovered_function_not_extracted(self) -> None:
        cov = _extract_coverage_sets(_EXPORT_JSON, "fuzz_png", "agent-00")
        assert "parse_body" not in cov.covered_functions

    def test_empty_export_json(self) -> None:
        cov = _extract_coverage_sets({"data": []}, "fuzz_png", "agent-00")
        assert cov.covered_lines == set()
        assert cov.covered_branches == set()
        assert cov.covered_functions == set()
        assert cov.line_coverage_pct == 0.0

    def test_percentages_use_totals(self) -> None:
        cov = _extract_coverage_sets(_EXPORT_JSON, "fuzz_png", "agent-00")
        # totals: 1 covered / 2 total → 50 %
        assert cov.line_coverage_pct == pytest.approx(50.0)
        assert cov.branch_coverage_pct == pytest.approx(50.0)
        assert cov.function_coverage_pct == pytest.approx(50.0)

    def test_binary_name_and_agent_id_propagated(self) -> None:
        cov = _extract_coverage_sets(_EXPORT_JSON, "fuzz_png", "my-agent")
        assert cov.binary_name == "fuzz_png"
        assert cov.agent_id == "my-agent"


# ---------------------------------------------------------------------------
# merge_agent_coverage_from_sets (pure set arithmetic)
# ---------------------------------------------------------------------------


class TestMergeAgentCoverageFromSets:
    def test_union_two_agents(self) -> None:
        a = _make_agent_coverage("a", lines={"f:1", "f:2"}, branches={"f:1:0"})
        b = _make_agent_coverage("b", lines={"f:2", "f:3"}, branches={"f:2:0"})
        agg = merge_agent_coverage_from_sets([a, b])
        assert agg.union_lines == {"f:1", "f:2", "f:3"}
        assert agg.union_branches == {"f:1:0", "f:2:0"}
        assert agg.union_line_count == 3
        assert agg.union_branch_count == 2

    def test_marginal_coverage(self) -> None:
        a = _make_agent_coverage("a", lines={"f:1", "f:2"})
        b = _make_agent_coverage("b", lines={"f:2", "f:3"})
        agg = merge_agent_coverage_from_sets([a, b])

        m_a = next(m for m in agg.per_agent if m.agent_id == "a")
        m_b = next(m for m in agg.per_agent if m.agent_id == "b")

        assert m_a.marginal_lines == {"f:1"}  # f:2 is shared
        assert m_b.marginal_lines == {"f:3"}

    def test_marginal_count_fields_consistent(self) -> None:
        a = _make_agent_coverage("a", lines={"f:1", "f:2", "f:3"})
        b = _make_agent_coverage("b", lines={"f:2"})
        agg = merge_agent_coverage_from_sets([a, b])
        m_a = next(m for m in agg.per_agent if m.agent_id == "a")
        assert m_a.marginal_line_count == len(m_a.marginal_lines)

    def test_jaccard_lines_key_sorted(self) -> None:
        a = _make_agent_coverage("agent-z", lines={"f:1"})
        b = _make_agent_coverage("agent-a", lines={"f:1"})
        agg = merge_agent_coverage_from_sets([a, b])
        # Keys should be alphabetically sorted
        assert "agent-a::agent-z" in agg.jaccard_lines

    def test_jaccard_identical_agents(self) -> None:
        a = _make_agent_coverage("a", lines={"f:1", "f:2"})
        b = _make_agent_coverage("b", lines={"f:1", "f:2"})
        agg = merge_agent_coverage_from_sets([a, b])
        key = "a::b"
        assert agg.jaccard_lines[key] == pytest.approx(1.0)

    def test_jaccard_disjoint_agents(self) -> None:
        a = _make_agent_coverage("a", lines={"f:1"})
        b = _make_agent_coverage("b", lines={"f:2"})
        agg = merge_agent_coverage_from_sets([a, b])
        key = "a::b"
        assert agg.jaccard_lines[key] == pytest.approx(0.0)

    def test_coverage_growth_curve_length(self) -> None:
        agents = [_make_agent_coverage(f"a{i}", lines={f"f:{i}"}) for i in range(5)]
        agg = merge_agent_coverage_from_sets(agents)
        assert len(agg.coverage_growth_lines) == 5
        assert len(agg.coverage_growth_branches) == 5

    def test_coverage_growth_curve_monotone(self) -> None:
        agents = [
            _make_agent_coverage("a0", lines={"f:1"}),
            _make_agent_coverage("a1", lines={"f:1", "f:2"}),
            _make_agent_coverage("a2", lines={"f:1"}),
        ]
        agg = merge_agent_coverage_from_sets(agents)
        for i in range(1, len(agg.coverage_growth_lines)):
            assert agg.coverage_growth_lines[i] >= agg.coverage_growth_lines[i - 1]

    def test_coverage_growth_first_entry_equals_first_agent(self) -> None:
        agents = [
            _make_agent_coverage("a0", lines={"f:1", "f:2"}),
            _make_agent_coverage("a1", lines={"f:3"}),
        ]
        agg = merge_agent_coverage_from_sets(agents)
        assert agg.coverage_growth_lines[0] == 2

    def test_single_agent(self) -> None:
        a = _make_agent_coverage("a", lines={"f:1"}, functions={"fn_a"})
        agg = merge_agent_coverage_from_sets([a])
        assert agg.union_lines == {"f:1"}
        assert agg.union_line_count == 1
        # Marginal for sole agent = everything it covers
        assert agg.per_agent[0].marginal_lines == {"f:1"}
        # No pairwise Jaccard for a single agent
        assert agg.jaccard_lines == {}

    def test_agent_ids_order_preserved(self) -> None:
        agents = [_make_agent_coverage(f"agent-{i:02d}") for i in range(3)]
        agg = merge_agent_coverage_from_sets(agents)
        assert agg.agent_ids == ["agent-00", "agent-01", "agent-02"]

    def test_empty_raises(self) -> None:
        with pytest.raises(ValueError, match="non-empty"):
            merge_agent_coverage_from_sets([])

    def test_mismatched_binary_names_raises(self) -> None:
        a = _make_agent_coverage("a", binary_name="fuzz_png")
        b = _make_agent_coverage("b", binary_name="fuzz_jpeg")
        with pytest.raises(ValueError, match="binary_name"):
            merge_agent_coverage_from_sets([a, b])

    def test_union_function_count(self) -> None:
        a = _make_agent_coverage("a", functions={"fn_a", "fn_shared"})
        b = _make_agent_coverage("b", functions={"fn_b", "fn_shared"})
        agg = merge_agent_coverage_from_sets([a, b])
        assert agg.union_functions == {"fn_a", "fn_b", "fn_shared"}
        assert agg.union_function_count == 3

    def test_no_pairwise_for_n_equals_1(self) -> None:
        a = _make_agent_coverage("a", lines={"f:1"})
        agg = merge_agent_coverage_from_sets([a])
        assert len(agg.jaccard_lines) == 0
        assert len(agg.jaccard_branches) == 0

    def test_three_agents_pairwise_count(self) -> None:
        agents = [_make_agent_coverage(f"a{i}") for i in range(3)]
        agg = merge_agent_coverage_from_sets(agents)
        # C(3,2) = 3 pairs
        assert len(agg.jaccard_lines) == 3


# ---------------------------------------------------------------------------
# _require_tool
# ---------------------------------------------------------------------------


class TestRequireTool:
    def test_tool_present(self) -> None:
        completed = MagicMock()
        completed.returncode = 0
        with patch("subprocess.run", return_value=completed):
            _require_tool("llvm-profdata")  # should not raise

    def test_tool_missing_raises(self) -> None:
        with patch("subprocess.run", side_effect=FileNotFoundError):
            with pytest.raises(FileNotFoundError, match="llvm-profdata"):
                _require_tool("llvm-profdata")


# ---------------------------------------------------------------------------
# _merge_profraw
# ---------------------------------------------------------------------------


class TestMergeProfraw:
    def test_calls_llvm_profdata(self, tmp_path: Path) -> None:
        profraw = tmp_path / "test.profraw"
        profraw.write_bytes(b"")
        profdata_out = tmp_path / "merged.profdata"

        completed = MagicMock()
        completed.returncode = 0
        completed.stderr = ""

        with patch("subprocess.run", return_value=completed) as mock_run:
            # First call is _require_tool, second is the actual merge.
            mock_run.return_value = completed
            _merge_profraw([profraw], profdata_out)

        # At least two calls: _require_tool + actual merge
        assert mock_run.call_count >= 1
        # The last subprocess.run call should be the merge
        merge_call_args = mock_run.call_args_list[-1][0][0]
        assert "llvm-profdata" in merge_call_args[0]
        assert "merge" in merge_call_args

    def test_nonzero_exit_raises(self, tmp_path: Path) -> None:
        profraw = tmp_path / "test.profraw"
        profdata_out = tmp_path / "merged.profdata"

        require_ok = MagicMock(returncode=0, stderr="")
        merge_fail = MagicMock(returncode=1, stderr="no profiles")

        with patch("subprocess.run", side_effect=[require_ok, merge_fail]):
            with pytest.raises(RuntimeError, match="llvm-profdata merge failed"):
                _merge_profraw([profraw], profdata_out)


# ---------------------------------------------------------------------------
# build_agent_coverage (mocked subprocess pipeline)
# ---------------------------------------------------------------------------


class TestBuildAgentCoverage:
    def _mock_subprocess(self) -> MagicMock:
        """Return a mock for subprocess.run that satisfies _require_tool calls
        and returns valid llvm-cov export JSON."""
        export_output = json.dumps(_EXPORT_JSON)

        def _side_effect(cmd: list[str], **kwargs: object) -> MagicMock:
            result = MagicMock()
            result.returncode = 0
            result.stderr = ""
            if "export" in cmd:
                result.stdout = export_output
            else:
                result.stdout = ""
            return result

        m = MagicMock(side_effect=_side_effect)
        return m

    def test_returns_agent_coverage(self, tmp_path: Path) -> None:
        profile = _make_profile(tmp_path=tmp_path)
        binary = tmp_path / "fuzz_png"
        binary.write_bytes(b"ELF")

        with patch("subprocess.run", self._mock_subprocess()):
            cov = build_agent_coverage(profile, binary)

        assert isinstance(cov, AgentCoverage)
        assert cov.agent_id == "agent-00"
        assert cov.binary_name == "fuzz_png"

    def test_no_profraw_raises(self, tmp_path: Path) -> None:
        profile = CoverageProfile(
            agent_id="a",
            binary_name="fuzz_png",
            profraw_paths=[],
        )
        binary = tmp_path / "fuzz_png"
        with pytest.raises(ValueError, match="no .profraw paths"):
            build_agent_coverage(profile, binary)

    def test_llvm_profdata_missing_raises(self, tmp_path: Path) -> None:
        profile = _make_profile(tmp_path=tmp_path)
        binary = tmp_path / "fuzz_png"
        binary.write_bytes(b"ELF")

        with patch("subprocess.run", side_effect=FileNotFoundError("llvm-profdata")):
            with pytest.raises(FileNotFoundError):
                build_agent_coverage(profile, binary)


# ---------------------------------------------------------------------------
# merge_agent_coverage (end-to-end mocked)
# ---------------------------------------------------------------------------


class TestMergeAgentCoverage:
    def _mock_subprocess_for_n_agents(self, n: int) -> MagicMock:
        export_output = json.dumps(_EXPORT_JSON)
        call_count = [0]

        def _side_effect(cmd: list[str], **kwargs: object) -> MagicMock:
            result = MagicMock()
            result.returncode = 0
            result.stderr = ""
            if "export" in cmd:
                result.stdout = export_output
            else:
                result.stdout = ""
            call_count[0] += 1
            return result

        return MagicMock(side_effect=_side_effect)

    def test_returns_aggregate_coverage(self, tmp_path: Path) -> None:
        profiles = [
            _make_profile(f"agent-{i:02d}", tmp_path=tmp_path) for i in range(3)
        ]
        binary = tmp_path / "fuzz_png"
        binary.write_bytes(b"ELF")

        with patch("subprocess.run", self._mock_subprocess_for_n_agents(3)):
            agg = merge_agent_coverage(profiles, binary)

        assert isinstance(agg, AggregateCoverage)
        assert len(agg.agent_ids) == 3
        assert agg.binary_name == "fuzz_png"

    def test_empty_profiles_raises(self, tmp_path: Path) -> None:
        binary = tmp_path / "fuzz_png"
        with pytest.raises(ValueError, match="non-empty"):
            merge_agent_coverage([], binary)

    def test_mismatched_binary_names_raises(self, tmp_path: Path) -> None:
        p1 = _make_profile("a", binary_name="fuzz_png", tmp_path=tmp_path)
        p2 = _make_profile("b", binary_name="fuzz_jpeg", tmp_path=tmp_path)
        binary = tmp_path / "fuzz_png"

        with pytest.raises(ValueError, match="binary_name"):
            merge_agent_coverage([p1, p2], binary)

    def test_growth_curve_length_equals_n_agents(self, tmp_path: Path) -> None:
        n = 4
        profiles = [
            _make_profile(f"agent-{i:02d}", tmp_path=tmp_path) for i in range(n)
        ]
        binary = tmp_path / "fuzz_png"
        binary.write_bytes(b"ELF")

        with patch("subprocess.run", self._mock_subprocess_for_n_agents(n)):
            agg = merge_agent_coverage(profiles, binary)

        assert len(agg.coverage_growth_lines) == n
        assert len(agg.coverage_growth_branches) == n
