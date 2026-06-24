"""CLI commands for the tree-sitter fuzz→fix loop.

Registered as a sub-application on the main ``parser-security-eval`` CLI.

Commands:
    treesitter list
    treesitter fuzz <grammar> [--iterations N --duration S --model M --out DIR]
    treesitter sweep [--tier popular|less-popular] [--iterations N --duration S]
    treesitter survey [--token T --limit N --out DIR]  # build the priority registry
    treesitter hunt [--top N --duration S]             # fuzz top un-fuzzed scanner grammars

Run inside the project's nix-shell so clang/tree-sitter are on PATH:
    nix-shell scaffold/treesitter-shell.nix --run \\
        'cd scaffold && uv run parser-security-eval treesitter fuzz toml'
"""

from __future__ import annotations

from pathlib import Path

import typer

from parser_security_eval.treesitter import registry
from parser_security_eval.treesitter.fixer import DEFAULT_FIX_MODEL
from parser_security_eval.treesitter.loop import DEFAULT_OUT_DIR, run_loop
from parser_security_eval.treesitter.models import GrammarTarget, Tier, TSLoopResult

app = typer.Typer(
    name="treesitter",
    help="Fuzz tree-sitter grammars, fix the crashes, log JSONL, iterate.",
)


@app.command("list")
def list_grammars() -> None:
    """List the registered tree-sitter grammar targets."""
    for tier in (Tier.popular, Tier.less_popular):
        typer.echo(f"\n[{tier.value}]")
        for g in registry.by_tier(tier):
            pin = f" @{g.commit[:10]}" if g.commit else ""
            typer.echo(f"  {g.name:<12} {g.language:<12} {g.repo_url}{pin}")


def _print_summary(result: TSLoopResult) -> None:
    typer.echo(f"\n=== {result.grammar} ({result.tier.value}) ===")
    if result.build_error:
        typer.echo(f"  BUILD FAILED: {result.build_error[:300]}")
        return
    typer.echo(f"  iterations:      {len(result.iterations)}")
    typer.echo(f"  crashes found:   {result.crashes_found}")
    typer.echo(f"  unique crashes:  {len(result.unique_stack_hashes)}")
    typer.echo(f"  fixes verified:  {result.fixes_verified}")
    for it in result.iterations:
        if it.crash is None:
            continue
        fix = it.fix
        status = "no-fix"
        if fix and fix.verified:
            status = "FIXED ✓"
        elif fix and fix.applied:
            status = "patched (unverified)"
        elif fix and fix.error:
            status = f"fix-error: {fix.error[:60]}"
        typer.echo(
            f"    #{it.iteration} {it.crash.bug_class.value} "
            f"in {it.crash.implicated_file or '?'} -> {status}"
        )
    typer.echo(f"  JSONL: {result.jsonl_path}")


@app.command("fuzz")
def fuzz(
    grammar: str = typer.Argument(help="Grammar name (see `treesitter list`)"),
    iterations: int = typer.Option(5, "--iterations", "-i", help="Fuzz→fix iterations"),
    duration: int = typer.Option(
        120, "--duration", "-t", help="Seconds per fuzz window"
    ),
    model: str = typer.Option(DEFAULT_FIX_MODEL, "--model", "-m", help="Fixer model"),
    out_dir: Path = typer.Option(DEFAULT_OUT_DIR, "--out", help="JSONL output dir"),
    max_len: int = typer.Option(65536, "--max-len", help="libFuzzer -max_len"),
    commit: str | None = typer.Option(
        None, "--commit", help="Pin the grammar repo to a commit (e.g. a buggy rev)"
    ),
) -> None:
    """Run the fuzz→fix→JSONL loop against a single grammar."""
    target = registry.get(grammar)
    if commit:
        target = target.model_copy(update={"commit": commit})
    result = run_loop(
        target,
        iterations=iterations,
        fuzz_seconds=duration,
        model=model,
        out_dir=out_dir,
        max_len=max_len,
    )
    _print_summary(result)


@app.command("sweep")
def sweep(
    tier: str | None = typer.Option(
        None, "--tier", help="popular | less-popular (default: all)"
    ),
    iterations: int = typer.Option(3, "--iterations", "-i", help="Fuzz→fix iterations"),
    duration: int = typer.Option(
        120, "--duration", "-t", help="Seconds per fuzz window"
    ),
    model: str = typer.Option(DEFAULT_FIX_MODEL, "--model", "-m", help="Fixer model"),
    out_dir: Path = typer.Option(DEFAULT_OUT_DIR, "--out", help="JSONL output dir"),
) -> None:
    """Run the loop across every grammar in a tier (or all)."""
    tier_enum = Tier(tier) if tier else None
    targets: list[GrammarTarget] = registry.by_tier(tier_enum)
    typer.echo(
        f"Sweeping {len(targets)} grammars: {', '.join(t.name for t in targets)}"
    )
    for target in targets:
        result = run_loop(
            target,
            iterations=iterations,
            fuzz_seconds=duration,
            model=model,
            out_dir=out_dir,
        )
        _print_summary(result)


@app.command("survey")
def survey(
    token: str | None = typer.Option(
        None,
        "--token",
        help="GitHub token (else $GITHUB_TOKEN). Strongly recommended: "
        "metrics for ~500 repos exceed the 60 req/hr unauthenticated limit.",
        envvar="GITHUB_TOKEN",
    ),
    limit: int | None = typer.Option(
        None, "--limit", "-n", help="Only survey the first N grammars (debug)"
    ),
    out_dir: Path = typer.Option(
        Path("results") / "treesitter", "--out", help="Output dir for the registry"
    ),
    top_n: int = typer.Option(60, "--top", help="Rows in priority.md"),
    refresh_days: float = typer.Option(
        7.0, "--refresh-days", help="Re-fetch GitHub metrics older than this"
    ),
) -> None:
    """Scrape the tree-sitter wiki + Zed/Emacs + GitHub metrics into a ranked registry."""
    from parser_security_eval.treesitter.survey.runner import run_survey

    def _progress(i: int, total: int, label: str) -> None:
        if i == 1 or i % 25 == 0 or i == total:
            typer.echo(f"  [{i}/{total}] {label}", err=True)

    if not token:
        typer.echo(
            "No GitHub token — running unauthenticated (60 req/hr). "
            "Results will be cached and the run is restartable.",
            err=True,
        )
    result = run_survey(
        token=token,
        out_dir=out_dir,
        limit=limit,
        top_n=top_n,
        refresh_days=refresh_days,
        progress=_progress,
    )
    typer.echo(f"\nGrammars surveyed: {result.total_grammars}")
    typer.echo(f"Metrics fetched:   {result.metrics_fetched}")
    typer.echo(f"Metrics failed:    {result.metrics_failed}")
    typer.echo("\nTop 15 fuzzing candidates:")
    for rank, rec in enumerate(result.records[:15], start=1):
        flags = "".join(
            [
                "S" if rec.has_external_scanner else "-",
                "Z" if rec.used_by_zed else "-",
                "E" if rec.used_by_emacs else "-",
            ]
        )
        stars = rec.metrics.stars if rec.metrics.stars is not None else "?"
        typer.echo(
            f"  {rank:>2}. {rec.fuzz_priority:5.1f} [{flags}] {rec.name:<16} "
            f"{stars}★  {rec.repo_url}"
        )
    typer.echo(
        f"\nWrote:\n  {result.jsonl_path}\n  {result.csv_path}\n  {result.priority_path}"
    )


@app.command("hunt")
def hunt(
    top: int = typer.Option(10, "--top", "-n", help="How many candidates to fuzz"),
    start: int = typer.Option(
        1, "--start", "-s", help="1-based rank to begin at (skip already-hunted ranks)"
    ),
    duration: int = typer.Option(
        1800, "--duration", "-t", help="Seconds to fuzz each grammar"
    ),
    model: str = typer.Option(DEFAULT_FIX_MODEL, "--model", "-m", help="Fixer model"),
    registry: Path = typer.Option(
        Path("results") / "treesitter" / "registry.jsonl",
        "--registry",
        help="Survey registry.jsonl to pick candidates from",
    ),
    out_dir: Path = typer.Option(
        Path("results") / "treesitter" / "hunt", "--out", help="JSONL output dir"
    ),
) -> None:
    """Fuzz→fix the top un-fuzzed, scanner-bearing grammars from the survey registry."""
    from parser_security_eval.treesitter.loop import run_hunt, select_hunt_candidates

    if not registry.exists():
        typer.echo(
            f"Registry not found: {registry}\n"
            "Run `parser-security-eval treesitter survey` first.",
            err=True,
        )
        raise typer.Exit(1)

    candidates = select_hunt_candidates(registry, top, start=start)
    typer.echo(
        f"Hunting ranks {start}–{start + len(candidates) - 1} "
        f"({len(candidates)} un-fuzzed scanner grammars, {duration}s each): "
        f"{', '.join(c.name for c in candidates)}"
    )

    def _progress(i: int, total: int, label: str) -> None:
        typer.echo(f"\n[{i}/{total}] fuzzing {label} …", err=True)

    results = run_hunt(
        registry,
        top_n=top,
        start=start,
        fuzz_seconds=duration,
        model=model,
        out_dir=out_dir,
        progress=_progress,
    )

    typer.echo("\n===== HUNT SUMMARY =====")
    for res in results:
        if res.build_error:
            typer.echo(f"  {res.grammar:<28} build-failed")
            continue
        hit = next((it for it in res.iterations if it.crash is not None), None)
        if hit is None or hit.crash is None:
            fz = res.iterations[0].fuzz if res.iterations else None
            execs = fz.total_executions if fz else "?"
            typer.echo(f"  {res.grammar:<28} no crash ({execs} execs)")
        else:
            fixed = hit.fix is not None and hit.fix.verified
            typer.echo(
                f"  {res.grammar:<28} CRASH {hit.crash.bug_class.value} "
                f"-> {'FIXED ✓' if fixed else 'unverified'}"
            )
    typer.echo(f"\nJSONL written under: {out_dir}")
