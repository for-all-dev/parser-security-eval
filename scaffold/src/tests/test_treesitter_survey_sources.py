"""Offline tests for survey source parsers (wiki / zed / redmonk / url normalize)."""

from __future__ import annotations

from parser_security_eval.treesitter.survey import sources

WIKI_FIXTURE = """\
Some preamble text.

| name | url | last commit date | abi | grammar.json | external scanner |
| --- | --- | --- | --- | --- | --- |
| abl | [github.com/usagi-coffee/tree-sitter-abl](https://github.com/usagi-coffee/tree-sitter-abl) | 2026-04-07 | 15 | yes | yes |
| ada | [github.com/briot/tree-sitter-ada](https://github.com/briot/tree-sitter-ada) | 2024-05-23 | 14 | yes | no |
| json | [github.com/tree-sitter/tree-sitter-json](https://github.com/tree-sitter/tree-sitter-json) | 2025-01-01 | 15 | yes | no |
"""

ZED_LOCK_FIXTURE = """\
[[package]]
name = "tree-sitter-bash"
version = "0.23.0"

[[package]]
name = "tree-sitter-heex"
version = "0.0.1"
source = "git+https://github.com/zed-industries/tree-sitter-heex?rev=1dd45142#1dd45142"
"""


def test_normalize_repo_url_variants() -> None:
    for raw in (
        "https://github.com/tree-sitter/tree-sitter-json",
        "github.com/tree-sitter/tree-sitter-json",
        "https://github.com/tree-sitter/tree-sitter-json.git",
        "https://github.com/tree-sitter/tree-sitter-json/tree/master",
    ):
        norm = sources.normalize_repo_url(raw)
        assert norm == (
            "https://github.com/tree-sitter/tree-sitter-json",
            "tree-sitter",
            "tree-sitter-json",
        )


def test_normalize_repo_url_rejects_non_github() -> None:
    assert sources.normalize_repo_url("https://gitlab.com/x/y") is None
    assert sources.normalize_repo_url("not a url") is None


def test_parse_wiki_extracts_fields() -> None:
    rows = sources.parse_wiki(WIKI_FIXTURE)
    assert len(rows) == 3
    abl = next(r for r in rows if r.name == "abl")
    assert abl.owner == "usagi-coffee"
    assert abl.repo == "tree-sitter-abl"
    assert abl.has_external_scanner is True
    assert abl.has_grammar_json is True
    assert abl.wiki_last_commit == "2026-04-07"
    assert abl.abi == "15"
    ada = next(r for r in rows if r.name == "ada")
    assert ada.has_external_scanner is False


def test_parse_zed_cargo_lock() -> None:
    repo_keys, crate_names = sources.parse_zed_cargo_lock(ZED_LOCK_FIXTURE)
    assert "zed-industries/tree-sitter-heex" in repo_keys
    assert "tree-sitter-bash" in crate_names
    assert "tree-sitter-heex" in crate_names


def test_redmonk_rank_aliases() -> None:
    assert sources.redmonk_rank("javascript") == 1
    assert sources.redmonk_rank("c_sharp") == sources.redmonk_rank("csharp")
    assert sources.redmonk_rank("bash") == sources.redmonk_rank("shell")
    assert sources.redmonk_rank("nonexistent-lang") is None


def test_repo_key_is_lowercase() -> None:
    assert sources.repo_key("Tree-Sitter", "Tree-Sitter-JSON") == (
        "tree-sitter/tree-sitter-json"
    )
