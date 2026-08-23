"""CLI commands for the tree-sitter fuzz→fix loop.

Registered as a sub-application on the main ``parser-security-eval`` CLI.

Commands:
    treesitter list
    treesitter fuzz <grammar> [--iterations N --duration S --model M --out DIR]
    treesitter sweep [--tier popular|less-popular] [--iterations N --duration S]
    treesitter survey [--token T --limit N --out DIR]  # build the priority registry
    treesitter hunt [--top N --duration S]             # fuzz top un-fuzzed scanner grammars
    treesitter baseline --hybrid DIR [--out DIR]       # plain-libFuzzer ablation (no LLM)
    treesitter baseline-compare --hybrid DIR --baseline DIR  # diff the two sweeps

Run inside the project's nix-shell so clang/tree-sitter are on PATH:
    nix-shell scaffold/treesitter-shell.nix --run \\
        'cd scaffold && uv run parser-security-eval treesitter fuzz toml'
"""

from __future__ import annotations

from pathlib import Path

import typer

from parser_security_eval.treesitter import registry
from parser_security_eval.treesitter.fixer import DEFAULT_FIX_MODEL
from parser_security_eval.treesitter.harness_author import DEFAULT_HARNESS_MODEL
from parser_security_eval.treesitter.llm_loop import (
    DEFAULT_OUT_DIR as LLM_OUT_DIR,
)
from parser_security_eval.treesitter.llm_loop import (
    run_llm_loop,
)
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


@app.command("llm-fuzz")
def llm_fuzz(
    grammars: str = typer.Option(
        ...,
        "--grammars",
        "-g",
        help="Comma-separated grammar names (see `treesitter list`).",
    ),
    model: str = typer.Option(
        DEFAULT_HARNESS_MODEL, "--model", "-m", help="Harness-author model"
    ),
    window: int = typer.Option(
        300, "--window", "-t", help="Seconds per fuzz window (per iteration)"
    ),
    max_iterations: int = typer.Option(
        5, "--max-iterations", "-i", help="Max author→fuzz iterations per grammar"
    ),
    walltime: int | None = typer.Option(
        None, "--walltime", help="Optional per-grammar walltime budget (seconds)"
    ),
    reps: int = typer.Option(
        1, "--reps", help="Repetitions per grammar (for variance)"
    ),
    max_compile_retries: int = typer.Option(
        3, "--max-compile-retries", help="Compile-fix retries per iteration"
    ),
    out_dir: Path = typer.Option(LLM_OUT_DIR, "--out-dir", help="JSONL output dir"),
    max_len: int = typer.Option(65536, "--max-len", help="libFuzzer -max_len"),
) -> None:
    """LLM-in-loop fuzzing (treatment arm): the model writes/refines the harness.

    Diff against the plain-libFuzzer control with `treesitter baseline-compare
    --hybrid <out-dir> --baseline results/treesitter-baseline`.
    """
    names = [g.strip() for g in grammars.split(",") if g.strip()]
    if not names:
        typer.echo("No grammars given.", err=True)
        raise typer.Exit(1)
    for name in names:
        target = registry.get(name)
        for rep in range(reps):
            rep_out = out_dir if reps == 1 else out_dir / f"rep{rep + 1}"
            typer.echo(
                f"\n>>> llm-fuzz {name} (rep {rep + 1}/{reps}) "
                f"model={model} window={window}s x{max_iterations}"
            )
            result = run_llm_loop(
                target,
                model=model,
                window_seconds=window,
                max_iterations=max_iterations,
                walltime_budget_s=walltime,
                max_compile_retries=max_compile_retries,
                out_dir=rep_out,
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


@app.command("baseline")
def baseline(
    hybrid: Path = typer.Option(
        DEFAULT_OUT_DIR,
        "--hybrid",
        help="Hybrid sweep JSONL dir; defines the exact grammar set + per-grammar "
        "fuzzing walltime to replicate (NO LLM).",
    ),
    out_dir: Path = typer.Option(
        Path("results") / "treesitter-baseline", "--out", help="JSONL output dir"
    ),
    max_len: int = typer.Option(65536, "--max-len", help="libFuzzer -max_len"),
    jobs: int = typer.Option(
        1,
        "--jobs",
        "-j",
        help="Grammars to fuzz concurrently. Each is ~1 core; keep at/below the "
        "machine's PHYSICAL core count to preserve per-grammar throughput parity "
        "with the (serial) hybrid runs. Oversubscribing skews the comparison.",
    ),
    log_file: Path | None = typer.Option(
        None,
        "--log-file",
        help="Tee progress here too (default: <out>/baseline-run.log). "
        "`tail -f` it to watch a detached run.",
    ),
    no_fork: bool = typer.Option(
        False, "--no-fork", help="Disable libFuzzer fork mode (stop at first crash)"
    ),
) -> None:
    """Plain-libFuzzer ablation: same grammars + walltime as the hybrid, no fixer."""
    import os
    from datetime import datetime, timezone

    from parser_security_eval.treesitter.baseline import (
        run_baseline_sweep,
        targets_from_results,
    )
    from parser_security_eval.treesitter.models import TSLoopIteration

    if not hybrid.exists():
        typer.echo(f"Hybrid results dir not found: {hybrid}", err=True)
        raise typer.Exit(1)
    targets = targets_from_results(hybrid)
    if not targets:
        typer.echo(f"No fuzzable grammars found under {hybrid}", err=True)
        raise typer.Exit(1)

    # Tee every progress line to stdout AND a run log, each line timestamped so a
    # detached/`tail -f`'d run is legible. The per-grammar JSONL under <out> stays
    # the machine-readable record; this log is the human heartbeat.
    out_dir.mkdir(parents=True, exist_ok=True)
    log_path = log_file or (out_dir / "baseline-run.log")
    log_fh = log_path.open("a", encoding="utf-8", buffering=1)  # line-buffered

    def _log(msg: str) -> None:
        stamp = datetime.now(tz=timezone.utc).strftime("%H:%M:%S")
        line = f"[{stamp}] {msg}"
        typer.echo(line)
        log_fh.write(line + "\n")

    total_h = sum(t.fuzz_seconds for t in targets) / 3600
    # SMT threads don't count as full fuzzing cores; halve the logical count as a
    # physical-core estimate for the guidance below.
    physical = max(1, (os.cpu_count() or 2) // 2)
    eta_h = total_h / max(1, jobs)
    _log(
        f"baseline start: {len(targets)} grammars, {total_h:.1f} fuzzing-hours, "
        f"jobs={jobs} → ~{eta_h:.1f}h wall. plain libFuzzer, no LLM."
    )
    _log(f"log: {log_path}  |  per-grammar JSONL: {out_dir}/")
    if jobs == 1:
        _log(
            f"  tip: `-j {physical}` (this box ≈ {physical} physical cores) would cut "
            f"this to ≈ {total_h / physical:.1f}h with throughput preserved."
        )
    elif jobs > physical:
        _log(
            f"  warning: jobs={jobs} > ~{physical} physical cores — each proc is "
            "CPU-starved (fewer execs, spurious timeouts), biasing the comparison."
        )

    tally = {"crash": 0, "clean": 0, "buildfail": 0, "bugs": 0}

    def _outcome(iters: list[TSLoopIteration]) -> str:
        if iters and not any(it.built for it in iters):
            tally["buildfail"] += 1
            return "BUILD-FAILED"
        classes = [it.crash.bug_class.value for it in iters if it.crash]
        if not classes:
            tally["clean"] += 1
            return "no crash"
        tally["crash"] += 1
        tally["bugs"] += len(classes)
        return f"CRASH ×{len(classes)}: {', '.join(classes)}"

    def _progress(i: int, total: int, label: str, iters: list[TSLoopIteration]) -> None:
        _log(
            f"[{i}/{total}] {label:30} {_outcome(iters)}  "
            f"(running: {tally['crash']} crashing / {tally['bugs']} crashes, "
            f"{tally['buildfail']} build-fail)"
        )

    try:
        run_baseline_sweep(
            targets,
            out_dir=out_dir,
            max_len=max_len,
            fork=not no_fork,
            jobs=jobs,
            progress=_progress,
        )
        _log(
            f"baseline done: {tally['crash']} grammars crashed "
            f"({tally['bugs']} total crashes), {tally['clean']} clean, "
            f"{tally['buildfail']} build-failed."
        )
    finally:
        log_fh.close()

    typer.echo(f"\nJSONL written under: {out_dir}")
    typer.echo(
        "Now diff against the hybrid:\n"
        f"  parser-security-eval treesitter baseline-compare "
        f"--hybrid {hybrid} --baseline {out_dir}"
    )


@app.command("baseline-compare")
def baseline_compare(
    hybrid: Path = typer.Option(DEFAULT_OUT_DIR, "--hybrid", help="Hybrid sweep dir"),
    baseline_dir: Path = typer.Option(
        Path("results") / "treesitter-baseline", "--baseline", help="Baseline sweep dir"
    ),
) -> None:
    """Diff hybrid vs baseline sweeps on memory-safety stack hashes."""
    from parser_security_eval.treesitter.baseline_compare import compare, format_report

    for label, path in (("hybrid", hybrid), ("baseline", baseline_dir)):
        if not path.exists():
            typer.echo(f"{label} dir not found: {path}", err=True)
            raise typer.Exit(1)
    report = compare(hybrid, baseline_dir)
    typer.echo(format_report(report))


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
