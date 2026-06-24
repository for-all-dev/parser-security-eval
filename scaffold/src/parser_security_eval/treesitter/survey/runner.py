"""Orchestrate the grammar survey: collect sources, fetch metrics, score, write."""

from __future__ import annotations

import csv
from collections import Counter
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path

from parser_security_eval.treesitter.survey import sources
from parser_security_eval.treesitter.survey.github import GitHubClient, RateLimitError
from parser_security_eval.treesitter.survey.models import GrammarRecord, SurveyResult
from parser_security_eval.treesitter.survey.scoring import compute_priority
from parser_security_eval.treesitter.survey.sources import repo_key

DEFAULT_OUT_DIR = Path("results") / "treesitter"

ProgressFn = Callable[[int, int, str], None]


def _build_records(token: str | None) -> list[GrammarRecord]:
    """Collect wiki + Zed + Emacs + RedMonk into un-scored records."""
    wiki = sources.fetch_wiki_grammars(token=token)
    zed_keys, zed_basenames = sources.fetch_zed_grammars()
    emacs_keys, emacs_basenames = sources.fetch_emacs_grammars(token=token)
    per_lang = Counter(g.name for g in wiki)

    records: list[GrammarRecord] = []
    for g in wiki:
        key = repo_key(g.owner, g.repo)
        base = g.repo.lower()
        records.append(
            GrammarRecord(
                name=g.name,
                language_group=g.name,
                repo_url=g.repo_url,
                owner=g.owner,
                repo=g.repo,
                has_external_scanner=g.has_external_scanner,
                has_grammar_json=g.has_grammar_json,
                abi=g.abi,
                wiki_last_commit=g.wiki_last_commit,
                competing_impls=per_lang[g.name],
                used_by_zed=key in zed_keys or base in zed_basenames,
                used_by_emacs=key in emacs_keys or base in emacs_basenames,
                redmonk_rank=sources.redmonk_rank(g.name),
            )
        )
    return records


def run_survey(
    *,
    token: str | None = None,
    out_dir: Path = DEFAULT_OUT_DIR,
    cache_dir: Path | None = None,
    limit: int | None = None,
    refresh_days: float = 7.0,
    top_n: int = 60,
    progress: ProgressFn | None = None,
) -> SurveyResult:
    """Run the full survey and write registry.jsonl, registry.csv, priority.md."""
    records = _build_records(token)
    if limit is not None:
        records = records[:limit]

    client = GitHubClient(token=token, cache_dir=cache_dir, refresh_days=refresh_days)
    now = datetime.now(tz=timezone.utc)
    fetched = failed = 0
    rate_limited = False

    for i, rec in enumerate(records):
        if progress:
            progress(i + 1, len(records), f"{rec.owner}/{rec.repo}")
        if not rate_limited:
            try:
                rec.metrics = client.fetch_metrics(rec.owner, rec.repo)
            except RateLimitError:
                rate_limited = True  # stop hitting the API; score with what we have
            else:
                if rec.metrics.fetched:
                    fetched += 1
                elif rec.metrics.error:
                    failed += 1
        compute_priority(rec, now)

    records.sort(key=lambda r: r.fuzz_priority, reverse=True)

    out_dir.mkdir(parents=True, exist_ok=True)
    jsonl_path = out_dir / "registry.jsonl"
    csv_path = out_dir / "registry.csv"
    priority_path = out_dir / "priority.md"
    _write_jsonl(jsonl_path, records)
    _write_csv(csv_path, records)
    _write_priority_md(priority_path, records, top_n=top_n, rate_limited=rate_limited)

    return SurveyResult(
        total_grammars=len(records),
        metrics_fetched=fetched,
        metrics_failed=failed,
        records=records,
        jsonl_path=str(jsonl_path),
        csv_path=str(csv_path),
        priority_path=str(priority_path),
    )


def _write_jsonl(path: Path, records: list[GrammarRecord]) -> None:
    with path.open("w", encoding="utf-8") as fh:
        for rec in records:
            fh.write(rec.to_jsonl() + "\n")


_CSV_COLUMNS = [
    "rank",
    "name",
    "language_group",
    "repo_url",
    "fuzz_priority",
    "used_by_zed",
    "used_by_emacs",
    "redmonk_rank",
    "has_external_scanner",
    "has_fuzz_setup",
    "already_fuzzed",
    "stars",
    "forks",
    "is_fork",
    "archived",
    "pushed_at",
    "months_since_push",
    "commits_last_year",
    "commits_last_90d",
    "contributors",
    "open_issues",
    "license",
    "competing_impls",
    "impact",
    "bug_likelihood",
    "tractability",
]


def _write_csv(path: Path, records: list[GrammarRecord]) -> None:
    with path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(_CSV_COLUMNS)
        for rank, rec in enumerate(records, start=1):
            m = rec.metrics
            writer.writerow(
                [
                    rank,
                    rec.name,
                    rec.language_group,
                    rec.repo_url,
                    rec.fuzz_priority,
                    int(rec.used_by_zed),
                    int(rec.used_by_emacs),
                    rec.redmonk_rank if rec.redmonk_rank is not None else "",
                    int(rec.has_external_scanner),
                    int(m.has_fuzz_setup),
                    int(rec.scores.get("already_fuzzed", 0.0)),
                    m.stars if m.stars is not None else "",
                    m.forks if m.forks is not None else "",
                    int(m.is_fork) if m.is_fork is not None else "",
                    int(m.archived),
                    m.pushed_at or "",
                    rec.scores.get("months_since_push", ""),
                    m.commits_last_year if m.commits_last_year is not None else "",
                    m.commits_last_90d if m.commits_last_90d is not None else "",
                    m.contributors if m.contributors is not None else "",
                    m.open_issues if m.open_issues is not None else "",
                    m.license or "",
                    rec.competing_impls,
                    rec.scores.get("impact", ""),
                    rec.scores.get("bug_likelihood", ""),
                    rec.scores.get("tractability", ""),
                ]
            )


def _write_priority_md(
    path: Path, records: list[GrammarRecord], *, top_n: int, rate_limited: bool
) -> None:
    lines = [
        "# Tree-sitter fuzzing-survey priority list",
        "",
        f"Total grammars surveyed: **{len(records)}**. "
        "Ranked by `fuzz_priority` = impact × **crash-surface** (external scanner) × "
        "**neglect** (no existing fuzz harness / not OSS-Fuzz'd) × maintenance "
        "activity. Already-fuzzed and no-scanner grammars are pushed down — the "
        "goldilocks is an actively-maintained scanner grammar nobody has fuzzed yet.",
        "",
    ]
    if rate_limited:
        lines += [
            "> ⚠️ GitHub rate limit hit mid-run — some rows lack metrics. "
            "Set `GITHUB_TOKEN` and re-run (cached rows are reused).",
            "",
        ]
    lines += [
        "| # | grammar | priority | ★ | scanner | fuzzed? | zed | emacs | last push | why |",
        "| - | ------- | -------- | - | ------- | ------- | --- | ----- | --------- | --- |",
    ]
    for rank, rec in enumerate(records[:top_n], start=1):
        m = rec.metrics
        push = rec.scores.get("months_since_push", -1.0)
        push_s = (
            f"{push:.0f}mo" if isinstance(push, (int, float)) and push >= 0 else "?"
        )
        why = ", ".join(
            r for r in rec.priority_reasons if r not in {"used by Zed", "used by Emacs"}
        )[:80]
        already = rec.scores.get("already_fuzzed", 0.0)
        lines.append(
            f"| {rank} | [{rec.name}]({rec.repo_url}) | {rec.fuzz_priority:.1f} "
            f"| {m.stars if m.stars is not None else '?'} "
            f"| {'✓' if rec.has_external_scanner else ''} "
            f"| {'✓' if already else ''} "
            f"| {'✓' if rec.used_by_zed else ''} | {'✓' if rec.used_by_emacs else ''} "
            f"| {push_s} | {why} |"
        )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
