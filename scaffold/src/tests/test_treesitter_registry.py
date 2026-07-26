"""Tests for the tree-sitter grammar registry."""

from __future__ import annotations

import pytest

from parser_security_eval.treesitter import registry
from parser_security_eval.treesitter.models import Tier


def test_registry_nonempty_and_has_both_tiers() -> None:
    assert registry.by_tier(Tier.popular)
    assert registry.by_tier(Tier.less_popular)


def test_all_names_unique() -> None:
    names = registry.all_names()
    assert len(names) == len(set(names))


def test_get_known_and_unknown() -> None:
    assert registry.get("json").name == "json"
    with pytest.raises(KeyError):
        registry.get("does-not-exist")


def test_every_target_has_https_repo() -> None:
    for g in registry.by_tier():
        assert g.repo_url.startswith("https://")
        assert g.language


def test_popular_includes_mainstream_languages() -> None:
    popular = {g.name for g in registry.by_tier(Tier.popular)}
    assert {"json", "python", "javascript", "c"} <= popular
