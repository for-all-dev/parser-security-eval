"""Unit tests for tree-sitter runtime helpers (no compiler/network needed)."""

from __future__ import annotations

from pathlib import Path

from parser_security_eval.treesitter import runtime

PARSER_C_STUB = """\
#include "tree_sitter/parser.h"
/* ... generated tables ... */
extern const TSLanguage *tree_sitter_toml(void) {
  static const TSLanguage language = {0};
  return &language;
}
"""


def test_render_harness_contains_symbol_and_entrypoint() -> None:
    src = runtime.render_harness("tree_sitter_toml")
    assert "tree_sitter_toml()" in src
    assert "LLVMFuzzerTestOneInput" in src
    assert "ts_parser_parse_string" in src


def test_detect_symbol_from_parser_definition(tmp_path: Path) -> None:
    (tmp_path / "parser.c").write_text(PARSER_C_STUB)
    assert runtime.detect_symbol(tmp_path, "tree_sitter_fallback") == "tree_sitter_toml"


def test_detect_symbol_falls_back_when_missing(tmp_path: Path) -> None:
    assert runtime.detect_symbol(tmp_path, "tree_sitter_x") == "tree_sitter_x"


def test_find_src_dir_prefers_existing_parser_c(tmp_path: Path) -> None:
    src = tmp_path / "src"
    src.mkdir()
    (src / "parser.c").write_text("// parser")
    assert runtime.find_src_dir(tmp_path) == src


def test_gather_seeds_collects_test_files_and_literals(tmp_path: Path) -> None:
    grammar = tmp_path / "grammar"
    test_dir = grammar / "test" / "corpus"
    test_dir.mkdir(parents=True)
    (test_dir / "a.txt").write_text("sample = 1\n")
    (test_dir / "b.txt").write_text("[table]\nx = true\n")
    corpus = tmp_path / "corpus"
    count = runtime.gather_seeds(grammar, corpus)
    files = list(corpus.iterdir())
    # 2 test files + the adversarial literals
    assert count == len(files)
    assert count >= 2 + 5


def test_reproduce_handles_hang_input(tmp_path: Path, monkeypatch) -> None:
    import subprocess

    def boom(*a, **k):  # noqa: ANN002, ANN003, ANN202
        raise subprocess.TimeoutExpired(cmd="fuzz", timeout=1)

    monkeypatch.setattr(runtime, "_run", boom)
    rc, out = runtime.reproduce(tmp_path / "bin", tmp_path / "timeout-1", timeout=1)
    assert rc == -1
    assert "timeout" in out.lower()


def test_libfuzzer_runner_parses_stats(tmp_path: Path, monkeypatch) -> None:
    log = "stat::number_of_executed_units: 12345\nstat::average_exec_per_sec:     678\n"

    class _CP:
        returncode = 0
        stdout = log
        stderr = ""

    monkeypatch.setattr(runtime, "_run", lambda *a, **k: _CP())
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    (corpus / "seed").write_text("x")
    runner = runtime.LibFuzzerRunner(
        binary=tmp_path / "fuzz",
        corpus_dir=corpus,
        crashes_dir=tmp_path / "crashes",
    )
    result, crashes = runner.run(5)
    assert result.total_executions == 12345
    assert result.execs_per_sec == 678.0
    assert result.crashes_found == 0
    assert crashes == []
