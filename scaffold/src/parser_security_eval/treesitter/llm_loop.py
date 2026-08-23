"""The LLM-in-loop fuzzing loop — the treatment arm of the discovery ablation.

Where :mod:`parser_security_eval.treesitter.loop` runs a FIXED-template harness and
only uses the LLM to *patch* crashes, this loop puts the LLM *in the discovery
loop*: each iteration the model writes/refines the libFuzzer harness (and seeds)
from the scanner source and the previous window's coverage feedback, we compile it
(retrying on compile errors), fuzz for a window, triage crashes, and feed coverage
back for the next iteration. The plain-libFuzzer control (`treesitter baseline`) has
no LLM anywhere; diffing the two isolates the LLM's contribution to *discovery*.

Emits the same :class:`TSLoopIteration` JSONL as the fixed-template loop, so
``baseline_compare`` works unchanged.
"""

from __future__ import annotations

import time
from pathlib import Path

import logfire

from parser_security_eval.telemetry import configure_telemetry
from parser_security_eval.treesitter import runtime, triage
from parser_security_eval.treesitter.harness_author import (
    DEFAULT_HARNESS_MODEL,
    HarnessAuthor,
    LLMHarnessAuthor,
)
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

DEFAULT_OUT_DIR = Path("results") / "treesitter-llm"


def _append_jsonl(path: Path, iteration: TSLoopIteration) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(iteration.to_jsonl() + "\n")


def _write_seeds(corpus_dir: Path, seeds: list[bytes], iteration: int) -> int:
    """Write LLM-proposed seeds into the corpus; return how many were written."""
    corpus_dir.mkdir(parents=True, exist_ok=True)
    written = 0
    for j, blob in enumerate(seeds):
        if not blob or len(blob) > 65536:
            continue
        (corpus_dir / f"llm_{iteration}_{j}").write_bytes(blob)
        written += 1
    return written


def _feedback(
    *,
    compile_ok: bool,
    compile_errors: str,
    coverage_pcs: int,
    prev_coverage: int,
    crashes_this_window: int,
    execs: int | None,
) -> str:
    """Render the previous window's outcome as prompt feedback for the next author."""
    if not compile_ok:
        return (
            "Your last harness DID NOT COMPILE. Fix the compile errors below and "
            "resubmit a complete, compilable harness.c:\n"
            f"{compile_errors[-1500:]}"
        )
    delta = coverage_pcs - prev_coverage
    lines = [
        f"- Coverage (edges/PCs reached): {coverage_pcs} "
        f"({'+' if delta >= 0 else ''}{delta} vs previous peak {prev_coverage}).",
        f"- Executions this window: {execs if execs is not None else 'unknown'}.",
        f"- New crashes this window: {crashes_this_window}.",
    ]
    if coverage_pcs == 0:
        lines.append(
            "- Coverage is 0 — the harness is NOT exercising target code (it likely "
            "self-crashes on its own input or never calls the parser). Rewrite it."
        )
    elif delta <= 0:
        lines.append(
            "- Coverage did not grow. Target different scanner states or add seeds "
            "that reach new code paths."
        )
    return "\n".join(lines)


def run_llm_loop(
    target: GrammarTarget,
    *,
    model: str = DEFAULT_HARNESS_MODEL,
    window_seconds: int = 300,
    max_iterations: int | None = 5,
    walltime_budget_s: int | None = None,
    max_compile_retries: int = 3,
    cache_dir: Path = DEFAULT_CACHE,
    out_dir: Path = DEFAULT_OUT_DIR,
    max_len: int = 65536,
    author: HarnessAuthor | None = None,
    seed_corpus: bool = True,
) -> TSLoopResult:
    """Run the LLM-in-loop fuzzing loop for one grammar; stream JSONL to ``out_dir``.

    Stops after ``max_iterations`` iterations or when ``walltime_budget_s`` (if set)
    is exhausted — whichever comes first. At least one iteration always runs.
    """
    configure_telemetry()
    runtime.check_toolchain()
    result = TSLoopResult(
        grammar=target.name, tier=target.tier, language=target.language
    )
    out_path = out_dir / f"{target.name}.jsonl"
    result.jsonl_path = str(out_path)

    runtime_dir = runtime.ensure_runtime(cache_dir)
    grammar_dir = runtime.ensure_grammar(target, cache_dir)
    work_dir = cache_dir / f"_work_llm_{target.name}"
    spec = BuildSpec(
        target=target,
        runtime_dir=runtime_dir,
        grammar_dir=grammar_dir,
        work_dir=work_dir,
    )

    # Bootstrap: a template build generates parser.c (if needed) and gives us the
    # language symbol + scanner path to hand the author. We do not fuzz this build.
    boot = runtime.build(spec)
    if not boot.built:
        result.build_error = boot.compile_errors
        it = TSLoopIteration(
            iteration=0,
            grammar=target.name,
            repo_url=target.repo_url,
            tier=target.tier,
            language=target.language,
            built=False,
            notes=f"bootstrap build failed: {boot.compile_errors[:500]}",
        )
        result.iterations.append(it)
        _append_jsonl(out_path, it)
        return result

    symbol = boot.symbol
    scanner_source = ""
    if boot.scanner_file:
        scanner_source = Path(boot.scanner_file).read_text(
            encoding="utf-8", errors="replace"
        )
    reference_harness = runtime.render_harness(symbol)

    corpus = work_dir / "corpus"
    crashes = work_dir / "crashes"
    if seed_corpus:
        runtime.gather_seeds(grammar_dir, corpus)
    runner = LibFuzzerRunner(
        binary=Path(boot.binary_path or ""),
        corpus_dir=corpus,
        crashes_dir=crashes,
        max_len=max_len,
    )
    if author is None:
        author = LLMHarnessAuthor(model=model)

    seen_hashes: set[str] = set()
    prev_harness = ""
    feedback = ""
    prev_coverage = 0
    deadline = (
        time.monotonic() + walltime_budget_s if walltime_budget_s is not None else None
    )

    with logfire.span(
        "treesitter llm-loop {grammar}",
        grammar=target.name,
        tier=target.tier.value,
        repo=target.repo_url,
        model=model,
        window_seconds=window_seconds,
    ):
        i = 0
        while True:
            if max_iterations is not None and i >= max_iterations:
                break
            if deadline is not None and time.monotonic() >= deadline and i > 0:
                break

            it = TSLoopIteration(
                iteration=i,
                grammar=target.name,
                repo_url=target.repo_url,
                tier=target.tier,
                language=target.language,
                built=False,
            )

            # --- author + compile (with retries) --------------------------------
            build_result = boot
            compiled = False
            author_notes = ""
            for attempt in range(1, max_compile_retries + 1):
                try:
                    proposal = author.propose(
                        target,
                        symbol,
                        scanner_source,
                        reference_harness,
                        previous_harness=prev_harness,
                        feedback=feedback,
                        has_scanner=boot.had_scanner,
                    )
                except Exception as exc:  # noqa: BLE001 — surface into the record
                    author_notes = f"author.propose failed: {exc}"
                    break
                if not proposal.harness_c.strip():
                    feedback = (
                        "Your last reply had no harness_c. Return a complete file."
                    )
                    author_notes = "author returned empty harness"
                    continue
                prev_harness = proposal.harness_c
                nb = runtime.build(spec, harness_override=proposal.harness_c)
                if nb.built:
                    build_result = nb
                    compiled = True
                    _write_seeds(corpus, proposal.seeds, i)
                    author_notes = proposal.rationale
                    break
                # compile failed → feed errors back and retry
                feedback = _feedback(
                    compile_ok=False,
                    compile_errors=nb.compile_errors,
                    coverage_pcs=0,
                    prev_coverage=prev_coverage,
                    crashes_this_window=0,
                    execs=None,
                )
                author_notes = f"compile failed (attempt {attempt})"

            if not compiled:
                it.notes = f"harness not compiled: {author_notes}"
                result.iterations.append(it)
                _append_jsonl(out_path, it)
                i += 1
                continue

            it.built = True
            runner.binary = Path(build_result.binary_path or "")

            # --- fuzz -----------------------------------------------------------
            fuzz_res, new_crashes = runner.run(window_seconds)
            it.fuzz = fuzz_res
            logfire.info(
                "llm fuzz window {grammar} #{i}: cov={cov} execs={execs} crashes={n}",
                grammar=target.name,
                i=i,
                cov=fuzz_res.coverage_pcs,
                execs=fuzz_res.total_executions,
                n=fuzz_res.crashes_found,
                rationale=author_notes,
            )

            # --- triage first new, unseen crash ---------------------------------
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
                chosen = crash
                if crash.stack_hash:
                    seen_hashes.add(crash.stack_hash)
                break

            if chosen is not None:
                it.crash = chosen
                logfire.warn(
                    "llm-loop crash {grammar}: {bug_class} (in_scanner={in_scanner})",
                    grammar=target.name,
                    bug_class=chosen.bug_class.value,
                    in_scanner=chosen.in_scanner,
                    stack_hash=chosen.stack_hash[:16],
                )
                it.notes = author_notes
            else:
                it.notes = f"no new crash this window — {author_notes}"

            result.iterations.append(it)
            _append_jsonl(out_path, it)

            # --- feedback for next iteration ------------------------------------
            feedback = _feedback(
                compile_ok=True,
                compile_errors="",
                coverage_pcs=fuzz_res.coverage_pcs,
                prev_coverage=prev_coverage,
                crashes_this_window=1 if chosen is not None else 0,
                execs=fuzz_res.total_executions,
            )
            prev_coverage = max(prev_coverage, fuzz_res.coverage_pcs)
            i += 1

    return result


def run_sweep(
    tier: Tier | None = None,
    *,
    names: list[str] | None = None,
    **kwargs: object,
) -> list[TSLoopResult]:
    """Run :func:`run_llm_loop` over every grammar in a tier (or an explicit list)."""
    targets = [get(n) for n in names] if names else by_tier(tier)
    results: list[TSLoopResult] = []
    for target in targets:
        results.append(run_llm_loop(target, **kwargs))  # type: ignore[arg-type]
    return results
