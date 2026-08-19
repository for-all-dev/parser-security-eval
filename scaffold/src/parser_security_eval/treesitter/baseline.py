"""Plain-libFuzzer baseline for the tree-sitter fuzz→fix loop (NO LLM).

This is the ablation for the neurosymbolic hypothesis: run the *identical* build,
seed corpus, and triage on the same grammars for the same fuzzing walltime, but
with no LLM in the loop at all — no harness synthesis (the harness is fixed) and,
crucially, no fix phase. The question it answers is narrow and load-bearing:

    Of the memory-safety bugs the hybrid loop found, how many does vanilla
    libFuzzer alone find in the same walltime?

If the answer is "the same ones", the discovery-side value of the LLM on these
targets is ~zero, and whatever value the hybrid adds lives entirely in the fix
phase (which this baseline deliberately cannot do).

Design notes:
* We fuzz in libFuzzer **fork mode** (``-fork=1 -ignore_crashes=1``) so a single
  crash does not halt the campaign — the process keeps finding *distinct* crashes
  across the whole window, which is the fair analogue of the hybrid patching bug
  #1 to unblock discovery of bug #2. Without this the baseline would be handicapped
  exactly where the LLM might have helped, biasing the comparison toward the LLM.
* Crashes are deduplicated by the same stack-hash triage the hybrid uses, so the
  two JSONL streams are directly comparable.
* Output reuses :class:`TSLoopIteration` with ``fix=None`` so existing analysis
  tooling reads baseline and hybrid runs the same way; ``iteration`` is the
  ordinal of the distinct crash within the grammar.
"""

from __future__ import annotations

import json
import threading
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path

from parser_security_eval.treesitter import runtime, triage
from parser_security_eval.treesitter.models import (
    GrammarTarget,
    Tier,
    TSCrash,
    TSLoopIteration,
)
from parser_security_eval.treesitter.runtime import (
    DEFAULT_CACHE,
    BuildSpec,
    LibFuzzerRunner,
)

DEFAULT_OUT_DIR = Path("results") / "treesitter-baseline"

# Bound on how many raw crash artifacts we replay+triage per grammar. Fork mode
# with -ignore_crashes writes one artifact per crash *occurrence*, not per unique
# bug, so a flappy target can emit hundreds of duplicates. We dedup by stack hash
# as we go and stop once this many artifacts have been examined; if the cap is hit
# it is recorded in the record's ``notes`` (never silently dropped).
MAX_ARTIFACTS_TRIAGED = 300


@dataclass
class BaselineTarget:
    """A grammar to baseline, plus the fuzzing walltime to grant it."""

    target: GrammarTarget
    fuzz_seconds: int


def targets_from_results(results_dir: Path) -> list[BaselineTarget]:
    """Reconstruct the exact hybrid target set from its JSONL outputs.

    Each ``<grammar>.jsonl`` produced by the hybrid loop carries ``grammar``,
    ``repo_url``, ``tier`` and ``language`` on every record; summing each
    grammar's ``fuzz.duration_seconds`` across iterations gives the fuzzing
    walltime the hybrid actually spent (LLM/rebuild time excluded — which is
    generous to the baseline). Grammars whose only record is a build failure are
    skipped (nothing to fuzz).
    """
    out: list[BaselineTarget] = []
    for path in sorted(results_dir.glob("*.jsonl")):
        first: dict[str, object] | None = None
        walltime = 0
        built_any = False
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            rec = json.loads(line)
            first = first or rec
            if rec.get("built"):
                built_any = True
            fuzz = rec.get("fuzz") or {}
            walltime += int(fuzz.get("duration_seconds") or 0)
        if first is None or not built_any or walltime <= 0:
            continue
        out.append(
            BaselineTarget(
                target=GrammarTarget(
                    name=str(first["grammar"]),
                    repo_url=str(first["repo_url"]),
                    tier=Tier(first["tier"]),
                    language=str(first.get("language") or ""),
                ),
                fuzz_seconds=walltime,
            )
        )
    return out


def _classify_without_replay(crash_file: Path) -> str | None:
    """Return a synthetic sanitizer report for hang/OOM artifacts, else None.

    Replaying a hang would just hang again and replaying an OOM would just OOM, so
    (mirroring the hybrid loop) we classify these from the libFuzzer filename.
    """
    if crash_file.name.startswith("timeout-"):
        return (
            "ERROR: libFuzzer: timeout\n"
            "Pathological parse time / hang (libFuzzer -timeout exceeded)."
        )
    if crash_file.name.startswith("oom-"):
        return "ERROR: libFuzzer: out-of-memory\nrss_limit exceeded."
    return None


def _distinct_crashes(
    binary: Path, crash_files: list[Path]
) -> tuple[list[TSCrash], bool]:
    """Triage crash artifacts, dedup by stack hash; return (crashes, capped)."""
    seen: set[str] = set()
    crashes: list[TSCrash] = []
    capped = False
    for i, cf in enumerate(crash_files):
        if i >= MAX_ARTIFACTS_TRIAGED:
            capped = True
            break
        report = _classify_without_replay(cf)
        if report is None:
            _, report = runtime.reproduce(binary, cf)
        crash = triage.triage(report, cf.read_bytes(), str(cf))
        key = crash.stack_hash or f"nohash:{cf.name}"
        if key in seen:
            continue
        seen.add(key)
        crashes.append(crash)
    return crashes, capped


def _append_jsonl(path: Path, iteration: TSLoopIteration) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(iteration.to_jsonl() + "\n")


def run_baseline_grammar(
    target: GrammarTarget,
    *,
    fuzz_seconds: int,
    cache_dir: Path = DEFAULT_CACHE,
    out_dir: Path = DEFAULT_OUT_DIR,
    max_len: int = 65536,
    seed_corpus: bool = True,
    fork: bool = True,
) -> list[TSLoopIteration]:
    """Fuzz one grammar with plain libFuzzer (no fixer); stream JSONL records.

    Emits one JSONL line per *distinct* crash (``fix=None``), or a single
    ``crash=None`` line if nothing crashed. Returns the emitted iterations.
    """
    runtime.check_toolchain()
    out_path = out_dir / f"{target.name}.jsonl"

    runtime_dir = runtime.ensure_runtime(cache_dir)
    grammar_dir = runtime.ensure_grammar(target, cache_dir)
    # Separate work dir from the hybrid's so we never fuzz a patched binary.
    work_dir = cache_dir / f"_baseline_{target.name}"
    spec = BuildSpec(
        target=target,
        runtime_dir=runtime_dir,
        grammar_dir=grammar_dir,
        work_dir=work_dir,
    )

    build_result = runtime.build(spec)
    if not build_result.built:
        it = TSLoopIteration(
            iteration=0,
            grammar=target.name,
            repo_url=target.repo_url,
            tier=target.tier,
            language=target.language,
            built=False,
            notes=f"baseline build failed: {build_result.compile_errors[:500]}",
        )
        _append_jsonl(out_path, it)
        return [it]

    corpus = work_dir / "corpus"
    crashes = work_dir / "crashes"
    if seed_corpus:
        runtime.gather_seeds(grammar_dir, corpus)

    # Fork mode keeps discovering distinct crashes past the first one — the fair
    # analogue of the hybrid patching bug #1 to reach bug #2.
    extra = ["-fork=1", "-ignore_crashes=1"] if fork else []
    runner = LibFuzzerRunner(
        binary=Path(build_result.binary_path or ""),
        corpus_dir=corpus,
        crashes_dir=crashes,
        max_len=max_len,
        extra_flags=extra,
    )
    fuzz_res, new_crashes = runner.run(fuzz_seconds)

    binary = Path(build_result.binary_path or "")
    distinct, capped = _distinct_crashes(binary, new_crashes)

    note_cap = (
        f" [capped at {MAX_ARTIFACTS_TRIAGED} artifacts triaged]" if capped else ""
    )
    emitted: list[TSLoopIteration] = []
    if not distinct:
        it = TSLoopIteration(
            iteration=0,
            grammar=target.name,
            repo_url=target.repo_url,
            tier=target.tier,
            language=target.language,
            built=True,
            fuzz=fuzz_res,
            notes="baseline: no crash (plain libFuzzer, no-fix)" + note_cap,
        )
        _append_jsonl(out_path, it)
        return [it]

    for idx, crash in enumerate(distinct):
        # Attach the fuzz stats only to the first record to avoid double-counting
        # walltime/execs when aggregating across a grammar's records.
        it = TSLoopIteration(
            iteration=idx,
            grammar=target.name,
            repo_url=target.repo_url,
            tier=target.tier,
            language=target.language,
            built=True,
            fuzz=fuzz_res if idx == 0 else None,
            crash=crash,
            fix=None,
            notes="baseline: plain libFuzzer, no-fix" + (note_cap if idx == 0 else ""),
        )
        _append_jsonl(out_path, it)
        emitted.append(it)
    return emitted


def _run_one(
    bt: BaselineTarget,
    *,
    cache_dir: Path,
    out_dir: Path,
    max_len: int,
    fork: bool,
) -> list[TSLoopIteration]:
    """Run one grammar, converting any exception into a build-failure record."""
    try:
        return run_baseline_grammar(
            bt.target,
            fuzz_seconds=bt.fuzz_seconds,
            cache_dir=cache_dir,
            out_dir=out_dir,
            max_len=max_len,
            fork=fork,
        )
    except Exception as exc:  # noqa: BLE001 — one grammar must not kill the sweep
        it = TSLoopIteration(
            iteration=0,
            grammar=bt.target.name,
            repo_url=bt.target.repo_url,
            tier=bt.target.tier,
            language=bt.target.language,
            built=False,
            notes=f"baseline raised: {type(exc).__name__}: {exc}",
        )
        _append_jsonl(out_dir / f"{bt.target.name}.jsonl", it)
        return [it]


def run_baseline_sweep(
    targets: list[BaselineTarget],
    *,
    cache_dir: Path = DEFAULT_CACHE,
    out_dir: Path = DEFAULT_OUT_DIR,
    max_len: int = 65536,
    fork: bool = True,
    jobs: int = 1,
    progress: Callable[[int, int, str], None] | None = None,
) -> dict[str, list[TSLoopIteration]]:
    """Run :func:`run_baseline_grammar` over a target set; keep going on error.

    ``jobs`` grammars run concurrently. Each fuzz process is ~1 core (libFuzzer
    ``-fork=1``), so to preserve per-grammar throughput parity with the (serial,
    single-core) hybrid runs, keep ``jobs`` at or below the machine's *physical*
    core count — oversubscribing starves each process of CPU (fewer execs/sec and
    spurious wall-clock timeouts) and of RAM (``jobs`` × ``rss_limit`` peak).
    """
    jobs = max(1, jobs)
    results: dict[str, list[TSLoopIteration]] = {}

    if jobs == 1:
        for i, bt in enumerate(targets):
            if progress is not None:
                progress(i + 1, len(targets), bt.target.name)
            results[bt.target.name] = _run_one(
                bt, cache_dir=cache_dir, out_dir=out_dir, max_len=max_len, fork=fork
            )
        return results

    # Clone the shared tree-sitter runtime ONCE up front: concurrent first-time
    # clones into the same dir would race. Per-grammar clones/work dirs are unique.
    runtime.ensure_runtime(cache_dir)

    done = 0
    lock = threading.Lock()
    with ThreadPoolExecutor(max_workers=jobs) as pool:
        futures = {
            pool.submit(
                _run_one,
                bt,
                cache_dir=cache_dir,
                out_dir=out_dir,
                max_len=max_len,
                fork=fork,
            ): bt
            for bt in targets
        }
        for fut in as_completed(futures):
            bt = futures[fut]
            results[bt.target.name] = fut.result()
            if progress is not None:
                with lock:
                    done += 1
                    progress(done, len(targets), bt.target.name)
    return results
