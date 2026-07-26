"""Pydantic models for the tree-sitter grammar survey/registry."""

from __future__ import annotations

from pydantic import BaseModel, Field


class WikiGrammar(BaseModel):
    """One row of the tree-sitter wiki 'List of parsers' table."""

    name: str  # language name as listed (lower-cased)
    repo_url: str  # normalized https URL (no .git, no trailing path)
    owner: str
    repo: str
    wiki_last_commit: str | None = None  # YYYY-MM-DD from the wiki snapshot
    abi: str | None = None
    has_grammar_json: bool = False
    has_external_scanner: bool = False


class RepoMetrics(BaseModel):
    """GitHub metrics for a grammar repository."""

    fetched: bool = False
    error: str = ""
    stars: int | None = None
    forks: int | None = None
    is_fork: bool | None = None
    parent: str | None = None  # "owner/repo" of the upstream if this is a fork
    archived: bool = False
    disabled: bool = False
    pushed_at: str | None = None  # ISO timestamp of last push
    created_at: str | None = None
    updated_at: str | None = None
    open_issues: int | None = None
    has_issues: bool | None = None
    license: str | None = None  # SPDX id
    size_kb: int | None = None
    topics: list[str] = Field(default_factory=list)
    subscribers: int | None = None  # watchers
    contributors: int | None = None
    commits_last_year: int | None = None
    commits_last_90d: int | None = None
    active_weeks_last_year: int | None = None  # weeks (of 52) with >=1 commit
    # Existing fuzzing infrastructure in the repo (a `fuzz/` dir, fuzzing CI,
    # oss-fuzz refs). If present, the easy crashes are likely already found.
    has_fuzz_setup: bool = False
    fuzz_evidence: str = ""  # the path that matched, for auditing


class GrammarRecord(BaseModel):
    """A fully-enriched registry entry: wiki + adoption + GitHub metrics + score."""

    # identity
    name: str  # wiki language name
    language_group: str  # canonical language label for grouping
    repo_url: str
    owner: str
    repo: str

    # from the wiki
    has_external_scanner: bool = False
    has_grammar_json: bool = False
    abi: str | None = None
    wiki_last_commit: str | None = None
    competing_impls: int = 1  # # of wiki repos for the same language group

    # adoption / impact
    used_by_zed: bool = False
    used_by_emacs: bool = False
    redmonk_rank: int | None = None  # 1 = most popular; None = unranked

    # github
    metrics: RepoMetrics = Field(default_factory=RepoMetrics)

    # scoring (all 0..1 sub-scores retained so the list can be re-weighted)
    scores: dict[str, float] = Field(default_factory=dict)
    fuzz_priority: float = 0.0  # 0..100 composite
    priority_reasons: list[str] = Field(default_factory=list)

    def to_jsonl(self) -> str:
        return self.model_dump_json()


class SurveyResult(BaseModel):
    """Aggregate output of a survey run."""

    total_grammars: int = 0
    metrics_fetched: int = 0
    metrics_failed: int = 0
    records: list[GrammarRecord] = Field(default_factory=list)
    jsonl_path: str | None = None
    csv_path: str | None = None
    priority_path: str | None = None
