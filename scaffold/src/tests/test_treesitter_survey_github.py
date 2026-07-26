"""Tests for the GitHub client (mocked HTTP, no network)."""

from __future__ import annotations

from pathlib import Path

from parser_security_eval.treesitter.survey.github import (
    GitHubClient,
    detect_fuzz_setup,
)


def test_detect_fuzz_setup() -> None:
    assert detect_fuzz_setup(["src/parser.c", "grammar.js"]) == (False, "")
    assert detect_fuzz_setup(["src/parser.c", "fuzz/fuzzer.cc"]) == (
        True,
        "fuzz/fuzzer.cc",
    )
    assert detect_fuzz_setup([".github/workflows/fuzz.yml"])[0] is True
    assert detect_fuzz_setup(["test/fuzzer/run.sh"])[0] is True


REPO_JSON = {
    "stargazers_count": 321,
    "forks_count": 12,
    "fork": False,
    "archived": False,
    "disabled": False,
    "pushed_at": "2026-05-01T00:00:00Z",
    "created_at": "2021-01-01T00:00:00Z",
    "updated_at": "2026-05-02T00:00:00Z",
    "open_issues_count": 7,
    "has_issues": True,
    "license": {"spdx_id": "MIT"},
    "size": 2048,
    "topics": ["tree-sitter", "parser"],
    "subscribers_count": 9,
}
COMMIT_ACTIVITY = [{"total": t, "week": 0, "days": []} for t in ([1] * 39 + [2] * 13)]


def test_to_metrics_maps_fields() -> None:
    blob = {
        "repo": REPO_JSON,
        "commit_activity": COMMIT_ACTIVITY,
        "contributors": 5,
        "fuzz": {"has_fuzz_setup": True, "fuzz_evidence": "fuzz/fuzzer.cc"},
    }
    m = GitHubClient._to_metrics(blob)
    assert m.fetched is True
    assert m.stars == 321
    assert m.is_fork is False
    assert m.license == "MIT"
    assert m.contributors == 5
    assert m.has_fuzz_setup is True
    assert m.fuzz_evidence == "fuzz/fuzzer.cc"
    assert m.commits_last_year == 39 + 26  # 39*1 + 13*2
    assert m.commits_last_90d == 26  # last 13 weeks * 2
    assert m.active_weeks_last_year == 52


def test_fetch_metrics_caches(tmp_path: Path, monkeypatch) -> None:
    client = GitHubClient(token="x", cache_dir=tmp_path)

    # A realistic Link header contains `per_page=1` too — the parser must not
    # confuse it with the `page=` it wants.
    link = (
        "<https://api.github.com/repositories/1/contributors"
        '?per_page=1&anon=1&page=2>; rel="next", '
        "<https://api.github.com/repositories/1/contributors"
        '?per_page=1&anon=1&page=26>; rel="last"'
    )

    def fake_request(url: str):  # noqa: ANN202
        if url.endswith("/contributors?per_page=1&anon=1"):
            return 200, [{"login": "a"}], {"Link": link}
        if url.endswith("/stats/commit_activity"):
            return 200, COMMIT_ACTIVITY, {}
        return 200, REPO_JSON, {}

    monkeypatch.setattr(client, "_request", fake_request)
    m = client.fetch_metrics("o", "tree-sitter-x")
    assert m.stars == 321
    assert m.contributors == 26  # last page, not per_page=1
    assert (tmp_path / "o__tree-sitter-x.json").exists()

    # Second call must hit the cache, not the network.
    def boom(url: str):  # noqa: ANN202
        raise AssertionError("network must not be called when cache is fresh")

    monkeypatch.setattr(client, "_request", boom)
    m2 = client.fetch_metrics("o", "tree-sitter-x")
    assert m2.stars == 321


def test_fetch_metrics_404(tmp_path: Path, monkeypatch) -> None:
    client = GitHubClient(token="x", cache_dir=tmp_path)
    monkeypatch.setattr(client, "_request", lambda url: (404, None, {}))
    m = client.fetch_metrics("o", "missing")
    assert m.fetched is False
    assert "404" in m.error
