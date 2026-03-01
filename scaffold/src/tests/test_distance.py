"""Tests for the directed-fuzzing distance metrics (callgraph and semantic)."""

from __future__ import annotations

import json
import math
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from parser_security_eval.distance.callgraph_distance import (
    DistanceMap,
    DistanceMetric,
    FunctionDistance,
    compute_callgraph_distances,
    normalise_distances,
    write_aflgo_distance_file,
)
from parser_security_eval.distance.semantic_distance import (
    PairwiseDistanceCache,
    _extract_function_body,
    compute_attention_distance,
    compute_semantic_distance_map,
    load_distance_cache,
    save_distance_cache,
)
from parser_security_eval.preprocess.callgraph import CallEdge, CallGraph, FunctionNode


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_SIMPLE_C = """\
static int inner(int x) {
    return x * 2;
}

int parse_chunk(const char *buf, int len) {
    if (len <= 0) return -1;
    return inner(len);
}

void cleanup(void *ptr) {
    free(ptr);
}
"""


def _make_linear_graph(depth: int = 4, target_name: str = "T") -> CallGraph:
    """Build a linear call chain: f0 -> f1 -> ... -> f{depth-1}."""
    nodes = [
        FunctionNode(name=f"f{i}", signature="()", file="a.c", line=i)
        for i in range(depth)
    ]
    edges = [CallEdge(caller=f"f{i}", callee=f"f{i + 1}") for i in range(depth - 1)]
    return CallGraph(
        target=target_name,
        entry_points=["f0"],
        nodes=nodes,
        edges=edges,
        depth_limit=depth,
    )


def _make_diamond_graph() -> CallGraph:
    """
    Diamond shape:
         root
        /    \\
       left  right
        \\    /
        target
    """
    nodes = [
        FunctionNode(name="root", signature="()", file="a.c", line=1),
        FunctionNode(name="left", signature="()", file="a.c", line=2),
        FunctionNode(name="right", signature="()", file="a.c", line=3),
        FunctionNode(name="target", signature="()", file="a.c", line=4),
    ]
    edges = [
        CallEdge(caller="root", callee="left"),
        CallEdge(caller="root", callee="right"),
        CallEdge(caller="left", callee="target"),
        CallEdge(caller="right", callee="target"),
    ]
    return CallGraph(
        target="diamond",
        entry_points=["root"],
        nodes=nodes,
        edges=edges,
        depth_limit=5,
    )


# ---------------------------------------------------------------------------
# callgraph_distance: compute_callgraph_distances
# ---------------------------------------------------------------------------


class TestComputeCallgraphDistances:
    def test_target_has_zero_distance(self) -> None:
        cg = _make_linear_graph(4)
        dm = compute_callgraph_distances(cg, target_functions=["f3"])
        d = dm.as_dict()
        assert d["f3"] == 0.0

    def test_linear_chain_distances(self) -> None:
        cg = _make_linear_graph(4)
        dm = compute_callgraph_distances(cg, target_functions=["f3"])
        d = dm.as_dict()
        assert d["f2"] == 1.0
        assert d["f1"] == 2.0
        assert d["f0"] == 3.0

    def test_unreachable_gets_inf(self) -> None:
        # Add an isolated node
        nodes = list(_make_linear_graph(3).nodes) + [
            FunctionNode(name="orphan", signature="()", file="a.c", line=99)
        ]
        cg = CallGraph(
            target="T",
            entry_points=["f0"],
            nodes=nodes,
            edges=[
                CallEdge(caller="f0", callee="f1"),
                CallEdge(caller="f1", callee="f2"),
            ],
            depth_limit=5,
        )
        dm = compute_callgraph_distances(cg, target_functions=["f2"])
        assert not math.isfinite(dm.as_dict()["orphan"])

    def test_multiple_targets_take_minimum(self) -> None:
        cg = _make_linear_graph(5)
        dm = compute_callgraph_distances(cg, target_functions=["f1", "f4"])
        d = dm.as_dict()
        # f0 is 1 hop from f1 (closer than 4 hops to f4)
        assert d["f0"] == 1.0

    def test_diamond_both_paths_give_distance_1(self) -> None:
        cg = _make_diamond_graph()
        dm = compute_callgraph_distances(cg, target_functions=["target"])
        d = dm.as_dict()
        # Both left and right are exactly 1 hop from target
        assert d["left"] == 1.0
        assert d["right"] == 1.0
        assert d["root"] == 2.0

    def test_metric_label(self) -> None:
        cg = _make_linear_graph(2)
        dm = compute_callgraph_distances(cg, target_functions=["f1"])
        assert dm.metric == DistanceMetric.CALLGRAPH

    def test_target_absent_from_graph(self) -> None:
        """Target function not in call graph nodes still gets distance 0."""
        cg = _make_linear_graph(2)
        dm = compute_callgraph_distances(cg, target_functions=["mystery_func"])
        assert dm.as_dict().get("mystery_func") == 0.0


# ---------------------------------------------------------------------------
# callgraph_distance: normalise_distances
# ---------------------------------------------------------------------------


class TestNormaliseDistances:
    def test_scales_to_unit_interval(self) -> None:
        dm = DistanceMap(
            target="T",
            metric=DistanceMetric.CALLGRAPH,
            entries=[
                FunctionDistance(function_name="a", distance=0.0),
                FunctionDistance(function_name="b", distance=5.0),
                FunctionDistance(function_name="c", distance=10.0),
            ],
        )
        normed = normalise_distances(dm)
        d = normed.as_dict()
        assert d["a"] == pytest.approx(0.0)
        assert d["b"] == pytest.approx(0.5)
        assert d["c"] == pytest.approx(1.0)

    def test_inf_remains_inf(self) -> None:
        dm = DistanceMap(
            target="T",
            metric=DistanceMetric.CALLGRAPH,
            entries=[
                FunctionDistance(function_name="a", distance=2.0),
                FunctionDistance(function_name="b", distance=math.inf),
            ],
        )
        normed = normalise_distances(dm)
        assert not math.isfinite(normed.as_dict()["b"])

    def test_all_zero_stays_zero(self) -> None:
        dm = DistanceMap(
            target="T",
            metric=DistanceMetric.CALLGRAPH,
            entries=[FunctionDistance(function_name="a", distance=0.0)],
        )
        normed = normalise_distances(dm)
        assert normed.as_dict()["a"] == 0.0


# ---------------------------------------------------------------------------
# callgraph_distance: write_aflgo_distance_file
# ---------------------------------------------------------------------------


class TestWriteAflgoDistanceFile:
    def test_creates_file(self, tmp_path: Path) -> None:
        dm = DistanceMap(
            target="T",
            metric=DistanceMetric.CALLGRAPH,
            entries=[FunctionDistance(function_name="parse", distance=2.0)],
        )
        out = tmp_path / "target_distance.txt"
        write_aflgo_distance_file(dm, out)
        assert out.exists()

    def test_tab_separated(self, tmp_path: Path) -> None:
        dm = DistanceMap(
            target="T",
            metric=DistanceMetric.CALLGRAPH,
            entries=[FunctionDistance(function_name="parse", distance=4.0)],
        )
        out = tmp_path / "target_distance.txt"
        write_aflgo_distance_file(dm, out, normalise=False)
        line = out.read_text().strip()
        parts = line.split("\t")
        assert len(parts) == 2
        assert parts[0] == "parse"
        assert float(parts[1]) == pytest.approx(4.0)

    def test_omits_unreachable_by_default(self, tmp_path: Path) -> None:
        dm = DistanceMap(
            target="T",
            metric=DistanceMetric.CALLGRAPH,
            entries=[
                FunctionDistance(function_name="reachable", distance=1.0),
                FunctionDistance(function_name="unreachable", distance=math.inf),
            ],
        )
        out = tmp_path / "target_distance.txt"
        write_aflgo_distance_file(dm, out, normalise=False)
        content = out.read_text()
        assert "unreachable" not in content
        assert "reachable" in content

    def test_creates_parent_dirs(self, tmp_path: Path) -> None:
        out = tmp_path / "sub" / "dir" / "target_distance.txt"
        dm = DistanceMap(
            target="T",
            metric=DistanceMetric.CALLGRAPH,
            entries=[FunctionDistance(function_name="f", distance=0.0)],
        )
        write_aflgo_distance_file(dm, out)
        assert out.exists()


# ---------------------------------------------------------------------------
# semantic_distance: _extract_function_body
# ---------------------------------------------------------------------------


class TestExtractFunctionBody:
    def test_finds_function(self) -> None:
        body = _extract_function_body(_SIMPLE_C, "inner")
        assert "return x * 2" in body

    def test_returns_placeholder_for_missing(self) -> None:
        body = _extract_function_body(_SIMPLE_C, "nonexistent_func")
        assert "not found" in body

    def test_truncates_long_body(self) -> None:
        long_func = (
            "int big(void) {\n" + "    int x = 0;\n" * 500 + "    return x;\n}\n"
        )
        body = _extract_function_body(long_func, "big", max_chars=200)
        assert "truncated" in body


# ---------------------------------------------------------------------------
# semantic_distance: PairwiseDistanceCache
# ---------------------------------------------------------------------------


class TestPairwiseDistanceCache:
    def test_symmetric_key(self) -> None:
        cache = PairwiseDistanceCache(target="T")
        cache.set("alpha", "beta", 0.42)
        assert cache.get("beta", "alpha") == pytest.approx(0.42)

    def test_missing_returns_none(self) -> None:
        cache = PairwiseDistanceCache(target="T")
        assert cache.get("a", "b") is None

    def test_overwrite(self) -> None:
        cache = PairwiseDistanceCache(target="T")
        cache.set("a", "b", 0.3)
        cache.set("a", "b", 0.7)
        assert cache.get("a", "b") == pytest.approx(0.7)


# ---------------------------------------------------------------------------
# semantic_distance: cache I/O
# ---------------------------------------------------------------------------


class TestDistanceCacheIO:
    def test_round_trip(self, tmp_path: Path) -> None:
        cache = PairwiseDistanceCache(target="libpng")
        cache.set("parse_png_header", "png_read_row", 0.15)
        save_distance_cache(tmp_path, cache)
        loaded = load_distance_cache(tmp_path)
        assert loaded.target == "libpng"
        assert loaded.get("png_read_row", "parse_png_header") == pytest.approx(0.15)

    def test_returns_empty_cache_when_missing(self, tmp_path: Path) -> None:
        cache = load_distance_cache(tmp_path / "nonexistent")
        assert cache.entries == {}

    def test_returns_empty_cache_on_corrupt_json(self, tmp_path: Path) -> None:
        (tmp_path / "distances.json").write_text("{corrupt json!!!")
        cache = load_distance_cache(tmp_path)
        assert cache.entries == {}


# ---------------------------------------------------------------------------
# semantic_distance: compute_attention_distance
# ---------------------------------------------------------------------------


def _make_mock_model(score: float, reasoning: str = "test reason") -> MagicMock:
    """Return a mock inspect_ai model that responds with a fixed score."""
    response = MagicMock()
    response.completion = json.dumps({"score": score, "reasoning": reasoning})
    mock_model = MagicMock()
    mock_model.generate = AsyncMock(return_value=response)
    return mock_model


class TestComputeAttentionDistance:
    @pytest.mark.asyncio
    async def test_identical_function_returns_zero(self) -> None:
        d = await compute_attention_distance(_SIMPLE_C, "parse_chunk", "parse_chunk")
        assert d == 0.0

    @pytest.mark.asyncio
    async def test_uses_llm_score(self) -> None:
        mock_model = _make_mock_model(0.3)
        d = await compute_attention_distance(
            _SIMPLE_C, "parse_chunk", "inner", _model=mock_model
        )
        assert d == pytest.approx(0.3)

    @pytest.mark.asyncio
    async def test_clamps_above_1(self) -> None:
        mock_model = _make_mock_model(1.5)
        d = await compute_attention_distance(
            _SIMPLE_C, "parse_chunk", "inner", _model=mock_model
        )
        assert d == pytest.approx(1.0)

    @pytest.mark.asyncio
    async def test_clamps_below_0(self) -> None:
        mock_model = _make_mock_model(-0.1)
        d = await compute_attention_distance(
            _SIMPLE_C, "parse_chunk", "inner", _model=mock_model
        )
        assert d == pytest.approx(0.0)

    @pytest.mark.asyncio
    async def test_llm_failure_returns_1(self) -> None:
        broken_model = MagicMock()
        broken_model.generate = AsyncMock(side_effect=RuntimeError("network error"))
        d = await compute_attention_distance(
            _SIMPLE_C, "parse_chunk", "inner", _model=broken_model
        )
        assert d == pytest.approx(1.0)

    @pytest.mark.asyncio
    async def test_bad_json_returns_1(self) -> None:
        response = MagicMock()
        response.completion = "not valid json {{"
        bad_model = MagicMock()
        bad_model.generate = AsyncMock(return_value=response)
        d = await compute_attention_distance(
            _SIMPLE_C, "parse_chunk", "inner", _model=bad_model
        )
        assert d == pytest.approx(1.0)


# ---------------------------------------------------------------------------
# semantic_distance: compute_semantic_distance_map
# ---------------------------------------------------------------------------


class TestComputeSemanticDistanceMap:
    @pytest.mark.asyncio
    async def test_target_functions_get_zero(self) -> None:
        cg = _make_linear_graph(3)
        mock_model = _make_mock_model(0.5)
        dm = await compute_semantic_distance_map(
            cg, target_functions=["f2"], source=_SIMPLE_C, _model=mock_model
        )
        assert dm.as_dict()["f2"] == 0.0

    @pytest.mark.asyncio
    async def test_non_target_gets_llm_score(self) -> None:
        cg = _make_linear_graph(2)
        mock_model = _make_mock_model(0.6)
        dm = await compute_semantic_distance_map(
            cg, target_functions=["f1"], source=_SIMPLE_C, _model=mock_model
        )
        assert dm.as_dict()["f0"] == pytest.approx(0.6)

    @pytest.mark.asyncio
    async def test_metric_label_is_semantic(self) -> None:
        cg = _make_linear_graph(2)
        mock_model = _make_mock_model(0.4)
        dm = await compute_semantic_distance_map(
            cg, target_functions=["f1"], source=_SIMPLE_C, _model=mock_model
        )
        assert dm.metric == DistanceMetric.SEMANTIC

    @pytest.mark.asyncio
    async def test_caches_results(self, tmp_path: Path) -> None:
        cg = _make_linear_graph(2)
        call_count = 0

        async def counting_generate(messages: object) -> MagicMock:
            nonlocal call_count
            call_count += 1
            r = MagicMock()
            r.completion = json.dumps({"score": 0.5, "reasoning": "ok"})
            return r

        mock_model = MagicMock()
        mock_model.generate = counting_generate

        # First call — should hit LLM
        await compute_semantic_distance_map(
            cg,
            target_functions=["f1"],
            source=_SIMPLE_C,
            target_dir=tmp_path,
            _model=mock_model,
        )
        first_count = call_count

        # Second call — should use cache
        call_count = 0
        await compute_semantic_distance_map(
            cg,
            target_functions=["f1"],
            source=_SIMPLE_C,
            target_dir=tmp_path,
            _model=mock_model,
        )
        assert call_count == 0, "Expected cache hit; LLM was called again"
        assert first_count > 0, "Expected at least one LLM call on first run"

    @pytest.mark.asyncio
    async def test_multiple_targets_take_minimum(self) -> None:
        cg = _make_linear_graph(3)

        async def selective_generate(messages: object) -> MagicMock:
            content = str(messages)
            score = 0.8 if "f2" in content else 0.2
            r = MagicMock()
            r.completion = json.dumps({"score": score, "reasoning": "ok"})
            return r

        mock_model = MagicMock()
        mock_model.generate = selective_generate

        dm = await compute_semantic_distance_map(
            cg,
            target_functions=["f1", "f2"],
            source=_SIMPLE_C,
            _model=mock_model,
        )
        # f0's min distance should be min(0.2, 0.8) = 0.2
        assert dm.as_dict()["f0"] == pytest.approx(0.2)
