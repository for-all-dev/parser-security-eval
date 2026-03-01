"""Tests for the pre-processing pipeline (callgraph, grammar, context_builder)."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from parser_security_eval.preprocess.callgraph import (
    CallEdge,
    CallGraph,
    FunctionNode,
    extract_callgraph,
)
from parser_security_eval.preprocess.context_builder import (
    HarnessContext,
    build_context_from_parts,
)
from parser_security_eval.preprocess.grammar import (
    FormatGrammar,
    GrammarRule,
    _build_grammar_from_dict,
    extract_grammar,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_MINIMAL_C = """\
#include <stdlib.h>

static int helper(const char *buf, int len) {
    if (len <= 0) return -1;
    return (int)buf[0];
}

int parse_entry(const unsigned char *data, size_t size) {
    if (size == 0) return 0;
    return helper((const char *)data, (int)size);
}

void cleanup(void *ptr) {
    free(ptr);
}
"""


def _make_source_dir(tmp_path: Path, c_source: str = _MINIMAL_C) -> Path:
    """Write a minimal C file into *tmp_path* and return the directory."""
    (tmp_path / "parser.c").write_text(c_source)
    return tmp_path


# ---------------------------------------------------------------------------
# CallGraph extraction
# ---------------------------------------------------------------------------


class TestExtractCallgraph:
    def test_finds_entry_point_node(self, tmp_path: Path) -> None:
        src = _make_source_dir(tmp_path)
        cg = extract_callgraph(src, entry_points=["parse_entry"], depth=5)
        assert cg.target or cg.target == str(src)
        func_names = {n.name for n in cg.nodes}
        assert "parse_entry" in func_names

    def test_finds_callee_edge(self, tmp_path: Path) -> None:
        src = _make_source_dir(tmp_path)
        cg = extract_callgraph(src, entry_points=["parse_entry"], depth=5)
        callee_names = {e.callee for e in cg.edges if e.caller == "parse_entry"}
        # helper is called from parse_entry
        assert "helper" in callee_names

    def test_depth_limit_respected(self, tmp_path: Path) -> None:
        # Build a chain: a -> b -> c -> d -> e -> f (6 levels)
        deep_c = """\
int f(void) { return 1; }
int e(void) { return f(); }
int d(void) { return e(); }
int c(void) { return d(); }
int b(void) { return c(); }
int a(void) { return b(); }
"""
        src = _make_source_dir(tmp_path, deep_c)
        cg = extract_callgraph(src, entry_points=["a"], depth=3)
        # At depth=3 we should see: a->b, b->c, c->d but NOT d->e or e->f
        callers = {e.caller for e in cg.edges}
        assert "a" in callers
        assert "b" in callers
        assert "c" in callers
        # 'd' is at depth 3, its outgoing edges are at depth 4 — excluded
        assert "d" not in callers

    def test_empty_source_dir(self, tmp_path: Path) -> None:
        # No C files — should still return a valid (possibly empty) CallGraph
        cg = extract_callgraph(tmp_path, entry_points=["missing_fn"], depth=5)
        assert isinstance(cg, CallGraph)
        assert cg.entry_points == ["missing_fn"]

    def test_raises_on_empty_entry_points(self, tmp_path: Path) -> None:
        with pytest.raises(ValueError, match="entry_points must not be empty"):
            extract_callgraph(tmp_path, entry_points=[], depth=5)

    def test_target_name_stored(self, tmp_path: Path) -> None:
        src = _make_source_dir(tmp_path)
        cg = extract_callgraph(src, entry_points=["parse_entry"], target_name="mylib")
        assert cg.target == "mylib"

    def test_callgraph_serialises_roundtrip(self, tmp_path: Path) -> None:
        src = _make_source_dir(tmp_path)
        cg = extract_callgraph(src, entry_points=["parse_entry"], depth=5)
        restored = CallGraph.model_validate_json(cg.model_dump_json())
        assert restored.entry_points == cg.entry_points
        assert len(restored.nodes) == len(cg.nodes)
        assert len(restored.edges) == len(cg.edges)


# ---------------------------------------------------------------------------
# FormatGrammar serialisation
# ---------------------------------------------------------------------------


class TestFormatGrammar:
    def _make_grammar(self) -> FormatGrammar:
        return FormatGrammar(
            target="libpng",
            format_name="PNG",
            description="Portable Network Graphics binary image format.",
            rules=[
                GrammarRule(
                    name="PNG_signature",
                    description="8-byte magic signature at file start.",
                    pattern=r"\x89PNG\r\n\x1a\n",
                    constraints=["Must be first 8 bytes of every PNG file"],
                ),
                GrammarRule(
                    name="PNG_chunk",
                    description="Variable-length data chunk.",
                    pattern="<length:uint32><type:4bytes><data:length bytes><crc:uint32>",
                    constraints=[
                        "length must be <= 2^31 - 1",
                        "CRC covers type + data",
                    ],
                ),
            ],
            magic_bytes_hex="89504e470d0a1a0a",
            max_size_hint=8 * 1024 * 1024,
            notes=["Integer overflow in length field is a common bug vector"],
        )

    def test_roundtrip_json(self) -> None:
        grammar = self._make_grammar()
        serialised = grammar.model_dump_json()
        restored = FormatGrammar.model_validate_json(serialised)
        assert restored.target == "libpng"
        assert restored.format_name == "PNG"
        assert restored.magic_bytes_hex == "89504e470d0a1a0a"
        assert restored.magic_bytes == bytes.fromhex("89504e470d0a1a0a")
        assert len(restored.rules) == 2
        assert restored.rules[0].name == "PNG_signature"
        assert restored.max_size_hint == 8 * 1024 * 1024

    def test_roundtrip_dict(self) -> None:
        grammar = self._make_grammar()
        restored = FormatGrammar.model_validate(grammar.model_dump())
        assert restored.format_name == grammar.format_name
        assert restored.notes == grammar.notes

    def test_null_magic_bytes_allowed(self) -> None:
        grammar = FormatGrammar(
            target="libxml2",
            format_name="XML",
            description="Extensible Markup Language.",
            rules=[],
            magic_bytes_hex=None,
        )
        assert grammar.magic_bytes is None
        restored = FormatGrammar.model_validate_json(grammar.model_dump_json())
        assert restored.magic_bytes is None

    def test_build_from_dict_hex_magic(self) -> None:
        data = {
            "description": "Test format",
            "rules": [],
            "magic_bytes_hex": "89504e47",
            "max_size_hint": 1024,
            "notes": ["note1"],
        }
        grammar = _build_grammar_from_dict("tgt", "FMT", data)
        assert grammar.magic_bytes_hex == "89504e47"
        assert grammar.magic_bytes == bytes.fromhex("89504e47")
        assert grammar.max_size_hint == 1024

    def test_build_from_dict_null_magic(self) -> None:
        data = {
            "description": "No magic",
            "rules": [],
            "magic_bytes_hex": None,
            "max_size_hint": None,
            "notes": [],
        }
        grammar = _build_grammar_from_dict("tgt", "FMT", data)
        assert grammar.magic_bytes is None


# ---------------------------------------------------------------------------
# extract_grammar (mocked LLM)
# ---------------------------------------------------------------------------


class TestExtractGrammar:
    """Tests for extract_grammar — LLM calls are mocked."""

    _MOCK_JSON_RESPONSE = json.dumps(
        {
            "description": "Simple test format.",
            "rules": [
                {
                    "name": "header",
                    "description": "File header.",
                    "pattern": "<magic:4><version:2>",
                    "constraints": ["magic must be 0xDEADBEEF"],
                }
            ],
            "magic_bytes_hex": "deadbeef",
            "max_size_hint": 65536,
            "notes": ["version field is big-endian"],
        }
    )

    @pytest.mark.asyncio
    async def test_returns_format_grammar(self) -> None:
        mock_response = MagicMock()
        mock_response.completion = self._MOCK_JSON_RESPONSE

        mock_model = AsyncMock()
        mock_model.generate = AsyncMock(return_value=mock_response)

        result = await extract_grammar(
            target="testlib",
            format_name="TESTFMT",
            spec_text="Fake spec text.",
            _model=mock_model,
        )

        assert isinstance(result, FormatGrammar)
        assert result.target == "testlib"
        assert result.format_name == "TESTFMT"
        assert result.description == "Simple test format."
        assert result.magic_bytes == bytes.fromhex("deadbeef")
        assert result.max_size_hint == 65536
        assert len(result.rules) == 1
        assert result.rules[0].name == "header"

    @pytest.mark.asyncio
    async def test_malformed_json_returns_empty_grammar(self) -> None:
        mock_response = MagicMock()
        mock_response.completion = "This is not JSON at all."

        mock_model = AsyncMock()
        mock_model.generate = AsyncMock(return_value=mock_response)

        result = await extract_grammar(
            target="testlib",
            format_name="TESTFMT",
            spec_text="Fake spec.",
            _model=mock_model,
        )

        # Should degrade gracefully
        assert isinstance(result, FormatGrammar)
        assert result.rules == []
        assert "failed" in result.description.lower()

    @pytest.mark.asyncio
    async def test_fenced_json_is_parsed(self) -> None:
        """LLM sometimes wraps JSON in markdown fences despite instructions."""
        fenced = f"```json\n{self._MOCK_JSON_RESPONSE}\n```"
        mock_response = MagicMock()
        mock_response.completion = fenced

        mock_model = AsyncMock()
        mock_model.generate = AsyncMock(return_value=mock_response)

        result = await extract_grammar("t", "F", "spec", _model=mock_model)

        assert result.description == "Simple test format."


# ---------------------------------------------------------------------------
# HarnessContext.to_prompt_text
# ---------------------------------------------------------------------------


class TestHarnessContextPromptText:
    def _make_context(self) -> HarnessContext:
        cg = CallGraph(
            target="libpng",
            entry_points=["png_read_png"],
            nodes=[
                FunctionNode(
                    name="png_read_png",
                    signature="(png_structrp png_ptr, png_inforp info_ptr, int transforms, png_voidp params)",
                    file="pngread.c",
                    line=1200,
                ),
                FunctionNode(
                    name="png_read_info",
                    signature="(png_structrp png_ptr, png_inforp info_ptr)",
                    file="pngread.c",
                    line=400,
                ),
            ],
            edges=[
                CallEdge(caller="png_read_png", callee="png_read_info"),
            ],
            depth_limit=5,
        )

        grammar = FormatGrammar(
            target="libpng",
            format_name="PNG",
            description="Portable Network Graphics binary format.",
            rules=[
                GrammarRule(
                    name="PNG_chunk",
                    description="Data chunk.",
                    pattern="<len:4><type:4><data><crc:4>",
                    constraints=["length <= 2^31-1"],
                )
            ],
            magic_bytes_hex="89504e470d0a1a0a",
            max_size_hint=8388608,
            notes=["CRC validation bypass is a known fuzzing target"],
        )

        return build_context_from_parts(
            target_name="libpng",
            entry_point="png_read_png",
            callgraph=cg,
            grammar=grammar,
            related_cves=["CVE-2019-7317"],
            cve_descriptions=["Use-after-free in png_image_free"],
        )

    def test_produces_non_empty_output(self) -> None:
        ctx = self._make_context()
        text = ctx.to_prompt_text()
        assert len(text) > 100

    def test_within_token_budget(self) -> None:
        ctx = self._make_context()
        text = ctx.to_prompt_text()
        # ~2k tokens; assume average 4 chars/token -> 8000 char cap
        assert len(text) <= 8000

    def test_contains_entry_point(self) -> None:
        ctx = self._make_context()
        text = ctx.to_prompt_text()
        assert "png_read_png" in text

    def test_contains_format_name(self) -> None:
        ctx = self._make_context()
        text = ctx.to_prompt_text()
        assert "PNG" in text

    def test_contains_cve(self) -> None:
        ctx = self._make_context()
        text = ctx.to_prompt_text()
        assert "CVE-2019-7317" in text

    def test_contains_magic_bytes(self) -> None:
        ctx = self._make_context()
        text = ctx.to_prompt_text()
        assert "89504e47" in text

    def test_callee_listed(self) -> None:
        ctx = self._make_context()
        text = ctx.to_prompt_text()
        assert "png_read_info" in text

    def test_long_context_truncated(self) -> None:
        ctx = self._make_context()
        # Inject a very long grammar description
        ctx.grammar.description = "A" * 10000
        text = ctx.to_prompt_text()
        assert len(text) <= 8000
        assert "truncated" in text

    def test_serialises_roundtrip(self) -> None:
        ctx = self._make_context()
        restored = HarnessContext.model_validate_json(ctx.model_dump_json())
        assert restored.entry_point == "png_read_png"
        assert restored.related_cves == ["CVE-2019-7317"]
