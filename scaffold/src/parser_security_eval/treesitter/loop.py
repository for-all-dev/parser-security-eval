"""The fuzzer-driven fuzz→fix→JSONL loop.

For a grammar: build it, then repeatedly fuzz. A crash is the event that *triggers*
the fix phase — triage the crash, ask the fixer to patch the implicated source,
rebuild, replay the crashing input to verify, append a JSONL record, and keep
fuzzing the patched parser for the next bug.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import logfire

from parser_security_eval.telemetry import configure_telemetry
from parser_security_eval.treesitter import fixer as fixer_mod
from parser_security_eval.treesitter import runtime, triage
from parser_security_eval.treesitter.fixer import DEFAULT_FIX_MODEL, Fixer, LLMFixer
from parser_security_eval.treesitter.models import (
    GrammarTarget,
    Tier,
    TSLoopIteration,
    TSLoopResult,
)
from parser_security_eval.treesitter.registry import by_tier, get
from parser_security_eval.treesitter.runtime import (
    DEFAULT_CACHE,
    BuildSpec,
    LibFuzzerRunner,
)

DEFAULT_OUT_DIR = Path("results") / "treesitter"


def _append_jsonl(path: Path, iteration: TSLoopIteration) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(iteration.to_jsonl() + "\n")


def run_loop(
    target: GrammarTarget,
    *,
    iterations: int = 5,
    fuzz_seconds: int = 120,
    model: str = DEFAULT_FIX_MODEL,
    cache_dir: Path = DEFAULT_CACHE,
    out_dir: Path = DEFAULT_OUT_DIR,
    max_len: int = 65536,
    fixer: Fixer | None = None,
    seed_corpus: bool = True,
    max_repair_iters: int = 1,
) -> TSLoopResult:
    """Run the fuzz→fix loop for a single grammar; stream JSONL to ``out_dir``."""
    configure_telemetry()  # Logfire: instruments pydantic-ai + provider SDKs
    runtime.check_toolchain()
    result = TSLoopResult(
        grammar=target.name, tier=target.tier, language=target.language
    )
    out_path = out_dir / f"{target.name}.jsonl"
    result.jsonl_path = str(out_path)

    runtime_dir = runtime.ensure_runtime(cache_dir)
    grammar_dir = runtime.ensure_grammar(target, cache_dir)
    work_dir = cache_dir / f"_work_{target.name}"
    spec = BuildSpec(
        target=target,
        runtime_dir=runtime_dir,
        grammar_dir=grammar_dir,
        work_dir=work_dir,
    )

    build_result = runtime.build(spec)
    logfire.info(
        "build {grammar} built={built}",
        grammar=target.name,
        built=build_result.built,
        has_scanner=build_result.had_scanner,
        symbol=build_result.symbol,
    )
    if not build_result.built:
        result.build_error = build_result.compile_errors
        it = TSLoopIteration(
            iteration=0,
            grammar=target.name,
            repo_url=target.repo_url,
            tier=target.tier,
            language=target.language,
            built=False,
            notes=f"build failed: {build_result.compile_errors[:500]}",
        )
        result.iterations.append(it)
        _append_jsonl(out_path, it)
        return result

    corpus = work_dir / "corpus"
    crashes = work_dir / "crashes"
    if seed_corpus:
        runtime.gather_seeds(grammar_dir, corpus)
    runner = LibFuzzerRunner(
        binary=Path(build_result.binary_path or ""),
        corpus_dir=corpus,
        crashes_dir=crashes,
        max_len=max_len,
    )
    if fixer is None:
        fixer = LLMFixer(model=model)

    seen_hashes: set[str] = set()
    with logfire.span(
        "treesitter fuzz→fix {grammar}",
        grammar=target.name,
        tier=target.tier.value,
        repo=target.repo_url,
        iterations=iterations,
        fuzz_seconds=fuzz_seconds,
    ):
        for i in range(iterations):
            with logfire.span("ts iteration {grammar} #{i}", grammar=target.name, i=i):
                fuzz_res, new_crashes = runner.run(fuzz_seconds)
                logfire.info(
                    "fuzz window {grammar} #{i}: {execs} execs, {n} new crash(es)",
                    grammar=target.name,
                    i=i,
                    execs=fuzz_res.total_executions,
                    n=fuzz_res.crashes_found,
                    execs_per_sec=fuzz_res.execs_per_sec,
                    corpus_size=fuzz_res.corpus_size,
                    oom=fuzz_res.oom_killed,
                    timed_out=fuzz_res.timed_out,
                )
                it = TSLoopIteration(
                    iteration=i,
                    grammar=target.name,
                    repo_url=target.repo_url,
                    tier=target.tier,
                    language=target.language,
                    built=True,
                    fuzz=fuzz_res,
                )

                # Pick the first crash whose stack hash we haven't already handled.
                # Hang/OOM artifacts are classified from the libFuzzer filename
                # WITHOUT replaying them (replaying a hang would just hang again).
                chosen = None
                for cf in new_crashes:
                    if cf.name.startswith("timeout-"):
                        report = (
                            "ERROR: libFuzzer: timeout\n"
                            "Pathological parse time / hang (libFuzzer -timeout exceeded)."
                        )
                    elif cf.name.startswith("oom-"):
                        report = "ERROR: libFuzzer: out-of-memory\nrss_limit exceeded."
                    else:
                        _, report = runtime.reproduce(
                            Path(build_result.binary_path or ""), cf
                        )
                    crash = triage.triage(report, cf.read_bytes(), str(cf))
                    if crash.stack_hash and crash.stack_hash in seen_hashes:
                        continue
                    chosen = (cf, crash, report)
                    break

                if chosen is None:
                    it.notes = "no new crash this window — still fuzzing"
                    result.iterations.append(it)
                    _append_jsonl(out_path, it)
                    continue

                crash_file, crash, report = chosen
                if crash.stack_hash:
                    seen_hashes.add(crash.stack_hash)
                it.crash = crash
                logfire.warn(
                    "crash {grammar}: {bug_class} (in_scanner={in_scanner})",
                    grammar=target.name,
                    bug_class=crash.bug_class.value,
                    in_scanner=crash.in_scanner,
                    stack_hash=crash.stack_hash[:16],
                )

                # The crash triggers the fix phase.
                attempt, new_build = fixer_mod.run_fix(
                    crash,
                    crash_file,
                    target,
                    spec,
                    build_result,
                    fixer,
                    report,
                    max_repair_iters=max_repair_iters,
                )
                it.fix = attempt
                logfire.info(
                    "fix {grammar}: verified={verified}",
                    grammar=target.name,
                    verified=attempt.verified,
                    reproduced_original=attempt.reproduced_original,
                    applied=attempt.applied,
                    rebuilt=attempt.rebuilt,
                    fixer_model=attempt.model,
                    out_tokens=attempt.output_tokens,
                    error=attempt.error or None,
                    rationale=attempt.rationale or None,
                    patch=attempt.patch or None,  # the applied unified diff (solution)
                    target_file=attempt.target_file,
                )
                if new_build.built and new_build.binary_path:
                    build_result = new_build
                    runner.binary = Path(new_build.binary_path)
                if attempt.verified and crash_file.exists():
                    crash_file.unlink()  # don't re-discover a fixed crash

                result.iterations.append(it)
                _append_jsonl(out_path, it)

    return result


def run_sweep(
    tier: Tier | None = None,
    *,
    names: list[str] | None = None,
    **kwargs: object,
) -> list[TSLoopResult]:
    """Run :func:`run_loop` over every grammar in a tier (or an explicit list)."""
    targets = [get(n) for n in names] if names else by_tier(tier)
    results: list[TSLoopResult] = []
    for target in targets:
        results.append(run_loop(target, **kwargs))  # type: ignore[arg-type]
    return results


# --------------------------------------------------------------------------- #
# Registry-driven hunt: fuzz the top un-fuzzed scanner candidates from a survey
# --------------------------------------------------------------------------- #
DEFAULT_REGISTRY = DEFAULT_OUT_DIR / "registry.jsonl"
DEFAULT_HUNT_DIR = DEFAULT_OUT_DIR / "hunt"


def select_hunt_candidates(
    registry_path: Path = DEFAULT_REGISTRY,
    top_n: int = 10,
    *,
    start: int = 1,
    require_scanner: bool = True,
    exclude_fuzzed: bool = True,
) -> list[GrammarTarget]:
    """Pick a *range* of fuzzing targets from a survey ``registry.jsonl``.

    Defaults select the goldilocks set: scanner-bearing (a real crash surface),
    NOT already fuzzed, and maintained (``fuzz_priority > 0`` excludes archived/
    abandoned). Deduplicated by repo and ordered highest-priority first; the slice
    ``[start-1 : start-1+top_n]`` is returned (``start`` is 1-based) so a later run
    can skip already-hunted ranks.
    """
    from parser_security_eval.treesitter.survey.models import GrammarRecord

    records: list[GrammarRecord] = []
    with registry_path.open(encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                records.append(GrammarRecord.model_validate_json(line))

    seen: set[tuple[str, str]] = set()
    eligible: list[GrammarTarget] = []
    for r in sorted(records, key=lambda rec: rec.fuzz_priority, reverse=True):
        if require_scanner and not r.has_external_scanner:
            continue
        if exclude_fuzzed and r.scores.get("already_fuzzed", 0.0) == 1.0:
            continue
        if r.fuzz_priority <= 0:
            continue
        key = (r.owner.lower(), r.repo.lower())
        if key in seen:
            continue
        seen.add(key)
        slug = f"{r.owner}-{r.repo.removeprefix('tree-sitter-')}"
        eligible.append(
            GrammarTarget(
                name=slug,
                repo_url=r.repo_url,
                tier=Tier.less_popular,
                language=r.language_group,
            )
        )

    begin = max(0, start - 1)
    return eligible[begin : begin + top_n]


def run_hunt(
    registry_path: Path = DEFAULT_REGISTRY,
    *,
    top_n: int = 10,
    start: int = 1,
    fuzz_seconds: int = 1800,
    model: str = DEFAULT_FIX_MODEL,
    out_dir: Path = DEFAULT_HUNT_DIR,
    cache_dir: Path = DEFAULT_CACHE,
    progress: Callable[[int, int, str], None] | None = None,
) -> list[TSLoopResult]:
    """Fuzz→fix a range of un-fuzzed scanner candidates from the survey registry."""
    configure_telemetry()
    targets = select_hunt_candidates(registry_path, top_n, start=start)
    results: list[TSLoopResult] = []
    with logfire.span(
        "treesitter hunt ranks {start}-{end} ({n} grammars)",
        start=start,
        end=start + len(targets) - 1,
        n=len(targets),
        fuzz_seconds=fuzz_seconds,
    ):
        for i, target in enumerate(targets):
            if progress is not None:
                progress(i + 1, len(targets), target.name)
            try:
                results.append(
                    run_loop(
                        target,
                        iterations=1,
                        fuzz_seconds=fuzz_seconds,
                        model=model,
                        out_dir=out_dir,
                        cache_dir=cache_dir,
                    )
                )
            except Exception as exc:  # noqa: BLE001 — one grammar must not kill the campaign
                logfire.warn(
                    "hunt grammar failed {grammar}: {error}",
                    grammar=target.name,
                    error=str(exc),
                )
                failed = TSLoopResult(
                    grammar=target.name, tier=target.tier, language=target.language
                )
                failed.build_error = f"run_loop raised: {type(exc).__name__}: {exc}"
                results.append(failed)
    return results
