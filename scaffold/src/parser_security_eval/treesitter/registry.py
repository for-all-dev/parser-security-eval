"""Registry of tree-sitter grammar targets (popular + less-popular tiers).

Symbols are auto-detected from ``src/parser.c`` at build time unless pinned here
(needed for multi-grammar repos like yaml, whose ``grammar.json`` name is wrong).
"""

from __future__ import annotations

from parser_security_eval.treesitter.models import GrammarTarget, Tier

_GRAMMARS: list[GrammarTarget] = [
    # ---- Popular languages ---------------------------------------------------
    GrammarTarget(
        name="json",
        repo_url="https://github.com/tree-sitter/tree-sitter-json",
        tier=Tier.popular,
        language="JSON",
    ),
    GrammarTarget(
        name="python",
        repo_url="https://github.com/tree-sitter/tree-sitter-python",
        tier=Tier.popular,
        language="Python",
    ),
    GrammarTarget(
        name="javascript",
        repo_url="https://github.com/tree-sitter/tree-sitter-javascript",
        tier=Tier.popular,
        language="JavaScript",
    ),
    GrammarTarget(
        name="c",
        repo_url="https://github.com/tree-sitter/tree-sitter-c",
        tier=Tier.popular,
        language="C",
    ),
    GrammarTarget(
        name="bash",
        repo_url="https://github.com/tree-sitter/tree-sitter-bash",
        tier=Tier.popular,
        language="Bash",
    ),
    GrammarTarget(
        name="ruby",
        repo_url="https://github.com/tree-sitter/tree-sitter-ruby",
        tier=Tier.popular,
        language="Ruby",
    ),
    # ---- Less-popular languages ----------------------------------------------
    GrammarTarget(
        name="toml",
        repo_url="https://github.com/tree-sitter-grammars/tree-sitter-toml",
        tier=Tier.less_popular,
        language="TOML",
    ),
    GrammarTarget(
        name="lua",
        repo_url="https://github.com/tree-sitter-grammars/tree-sitter-lua",
        tier=Tier.less_popular,
        language="Lua",
    ),
    GrammarTarget(
        name="hcl",
        repo_url="https://github.com/tree-sitter-grammars/tree-sitter-hcl",
        tier=Tier.less_popular,
        language="HCL",
    ),
    GrammarTarget(
        name="wgsl",
        repo_url="https://github.com/szebniok/tree-sitter-wgsl",
        tier=Tier.less_popular,
        language="WGSL",
    ),
    GrammarTarget(
        name="markdown",
        repo_url="https://github.com/tree-sitter-grammars/tree-sitter-markdown",
        tier=Tier.less_popular,
        language="Markdown",
        subpath="tree-sitter-markdown",
    ),
    GrammarTarget(
        name="yaml",
        repo_url="https://github.com/tree-sitter-grammars/tree-sitter-yaml",
        tier=Tier.less_popular,
        language="YAML",
        symbol="tree_sitter_yaml",
    ),
]

REGISTRY: dict[str, GrammarTarget] = {g.name: g for g in _GRAMMARS}


def get(name: str) -> GrammarTarget:
    """Look up a grammar by registry key; raise ``KeyError`` if unknown."""
    try:
        return REGISTRY[name]
    except KeyError as exc:
        known = ", ".join(sorted(REGISTRY))
        raise KeyError(f"Unknown grammar {name!r}. Known: {known}") from exc


def by_tier(tier: Tier | None = None) -> list[GrammarTarget]:
    """Return all grammars, optionally filtered to a single tier."""
    if tier is None:
        return list(_GRAMMARS)
    return [g for g in _GRAMMARS if g.tier == tier]


def all_names() -> list[str]:
    """Return all registry keys in declaration order."""
    return [g.name for g in _GRAMMARS]
