"""Compare a plain-libFuzzer baseline sweep against the hybrid fuzz→fix sweep.

Reads two dirs of ``<grammar>.jsonl`` files — the hybrid loop's output and the
:mod:`parser_security_eval.treesitter.baseline` output — and answers the ablation
question per grammar and in aggregate:

    Which distinct bugs (by stack hash) did the hybrid find that the baseline
    also found, and vice versa?

The headline number for the writeup is the *memory-safety* overlap: of the bugs
the hybrid found that are genuine memory-safety issues (buffer overflows, SEGV,
use-after-free, leaks in hand-written scanner code — NOT bare timeout/OOM
resource exhaustion), how many did vanilla libFuzzer also surface. High overlap ⇒
the LLM added no discovery-side value on these targets.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from parser_security_eval.treesitter.models import BugClass

# Resource-exhaustion classes are DoS-ish, share a generic stack hash, and are not
# the memory-safety bugs the writeup is about. Kept in the per-grammar tables but
# excluded from the headline overlap.
_RESOURCE_CLASSES = {BugClass.oom.value, BugClass.timeout.value}


# A crash only counts as a finding *about the target* if its stack actually
# entered target code: the grammar's own sources, or the tree-sitter runtime
# driving them. Frames confined to the generated harness plus libc/libFuzzer mean
# the harness overflowed its own buffer before parsing anything.
#
# This is not cosmetic. Only the LLM arm writes its own harness, so only the LLM
# arm can produce self-inflicted crashes — they would land wholly in the
# ``hybrid_only`` column and read as discovery uplift. Filtering here (rather than
# at fuzz time) keeps it retroactive: the frames are already persisted.
_TARGET_PATH_MARKERS = (
    "/src/parser.c",
    "/src/scanner.c",
    "/src/scanner.cc",
    "tree-sitter/lib/src/",
)
_TARGET_SYMBOL_PREFIXES = ("ts_", "tree_sitter_")


# Frames belonging to the sanitizer/libFuzzer crash machinery or bare libc. A
# stack made *only* of these is an unwind failure (libFuzzer's "deadly signal"
# path commonly reports just its own handler), not evidence about where the bug
# is — so it must not be judged as a harness bug. Confirmed empirically: typst's
# c6f014c21c9d has a handler-only stack and was found by BOTH arms, and the
# control cannot produce harness bugs because it never writes a harness.
_HANDLER_MARKERS = (
    "__sanitizer_",
    "fuzzer::",
    "FuzzerLoop.cpp",
    "PrintStackTrace",
    "CrashCallback",
    "/libc.so",
    "libc.so.6",
)


def is_handler_only(frames: list[str]) -> bool:
    """True if every frame is sanitizer/libFuzzer/libc scaffolding."""
    if not frames:
        return False
    return all(any(m in f for m in _HANDLER_MARKERS) for f in frames)


def reaches_target(frames: list[str]) -> bool:
    """True if any frame is in grammar source or the tree-sitter runtime.

    Frames are ``"<symbol> <path>:<line>"``. Matching on either the path or the
    symbol keeps genuine bugs that unwind entirely through the runtime, while
    excluding stacks that never leave ``harness.c``/libc/libFuzzer.
    """
    for frame in frames:
        if any(marker in frame for marker in _TARGET_PATH_MARKERS):
            return True
        symbol = frame.split(" ", 1)[0]
        if symbol.startswith(_TARGET_SYMBOL_PREFIXES):
            return True
    return False


def _is_memory_safety(bug_class: str, in_scanner: bool) -> bool:
    if bug_class in _RESOURCE_CLASSES:
        return False
    if bug_class == BugClass.unknown.value:
        # An "unknown" class only counts if it landed in hand-written scanner code.
        return in_scanner
    return True


def function_key(frames: list[str]) -> str:
    """Stable key from the frames' *symbols only*, dropping file:line.

    ``stack_hash`` includes line numbers, so one leaking function reached from two
    call sites inside itself hashes as two bugs (sql's ``scan_dollar_string_tag``
    at scanner.c:67 and :72 are the same defect). Collapsing to symbols fixes the
    overcount. The trade-off is that two genuinely distinct bugs in one large
    function now collide; for hand-written tree-sitter scanners — small functions,
    few of them — that is the rarer error.
    """
    symbols = [f.split(" ", 1)[0] for f in frames if f.strip()]
    return "|".join(symbols)


@dataclass
class GrammarCrashes:
    """Distinct crashes a sweep found for one grammar, keyed by stack hash."""

    grammar: str
    # stack_hash -> (bug_class, in_scanner)
    crashes: dict[str, tuple[str, bool]] = field(default_factory=dict)
    # Crashes dropped by :func:`reaches_target` — kept (not discarded) so the
    # report can state how many were excluded instead of silently shrinking.
    harness_only: dict[str, tuple[str, bool]] = field(default_factory=dict)
    # Real crashes whose stack could not be attributed (handler-only unwind).
    # Counted as findings — dropping them loses genuine bugs — but tracked apart
    # so a report can say how much of the total rests on unattributed stacks.
    unattributed: set[str] = field(default_factory=set)

    def mem_hashes(self) -> set[str]:
        return {
            h for h, (bc, scan) in self.crashes.items() if _is_memory_safety(bc, scan)
        }

    def all_hashes(self) -> set[str]:
        return set(self.crashes)


def rep_names(results_dir: Path) -> list[str]:
    """Names of the per-rep subdirs in a sweep dir, or ``[]`` if it is flat.

    ``--reps N`` writes ``rep1/``..``repN/``; ``--reps 1`` writes flat. Both the
    hybrid and the (budget-matched) baseline mirror the same layout.
    """
    return sorted(p.name for p in results_dir.glob("rep*") if p.is_dir())


def sweep_files(results_dir: Path) -> list[Path]:
    """Every ``<grammar>.jsonl`` in a sweep, flat layout or ``rep*/`` layout.

    Globbing only the top level would silently return nothing for a ``--reps N``
    sweep, which reads as "this arm found no bugs" rather than as an error.
    """
    return sorted(results_dir.glob("*.jsonl")) + sorted(
        results_dir.glob("rep*/*.jsonl")
    )


def load_sweep(results_dir: Path) -> dict[str, GrammarCrashes]:
    """Load a sweep dir into ``{grammar: GrammarCrashes}`` (deduped by stack hash).

    Reps are *pooled*: a bug counts as found by the arm if any rep found it. Use
    :func:`compare_by_rep` for the per-rep breakdown.
    """
    out: dict[str, GrammarCrashes] = {}
    for path in sweep_files(results_dir):
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            rec = json.loads(line)
            grammar = str(rec["grammar"])
            gc = out.setdefault(grammar, GrammarCrashes(grammar=grammar))
            crash = rec.get("crash")
            if not crash:
                continue
            # Recompute the stack hash from the stored frames rather than trusting
            # the persisted ``stack_hash``: logs written before frame normalization
            # carry non-portable hashes (absolute paths, binary offsets, runtime
            # line drift) that never match across two independent sweeps. Passing
            # the stored frames back through the current (normalizing) ``stack_hash``
            # makes old and new logs comparable. Frameless crashes (timeout/OOM,
            # excluded from the memory-safety headline) keep their stored hash.
            frames = crash.get("top_frames") or []
            # Key on symbols, not file:line, so one function reached from two of
            # its own call sites is one bug (see :func:`function_key`). Falls back
            # to the line-sensitive hash only when there are no frames at all.
            h = function_key(frames) if frames else (crash.get("stack_hash") or "")
            if not h:
                continue
            entry = (
                str(crash.get("bug_class") or BugClass.unknown.value),
                bool(crash.get("in_scanner")),
            )
            # Frameless crashes (timeout/OOM) have no stack to judge and are
            # already outside the memory-safety headline; leave them alone.
            if frames and not reaches_target(frames):
                if is_handler_only(frames):
                    # Unwind failure, not a harness bug: keep it as a finding.
                    gc.crashes[h] = entry
                    gc.unattributed.add(h)
                else:
                    gc.harness_only[h] = entry
            else:
                gc.crashes[h] = entry
    return out


@dataclass
class GrammarComparison:
    grammar: str
    hybrid_mem: set[str]
    baseline_mem: set[str]

    @property
    def shared(self) -> set[str]:
        return self.hybrid_mem & self.baseline_mem

    @property
    def hybrid_only(self) -> set[str]:
        return self.hybrid_mem - self.baseline_mem

    @property
    def baseline_only(self) -> set[str]:
        return self.baseline_mem - self.hybrid_mem


@dataclass
class ComparisonReport:
    per_grammar: list[GrammarComparison]
    # Crashes excluded by :func:`reaches_target`, per arm. Reported, not hidden:
    # a large hybrid number means the model kept writing broken harnesses, which
    # is itself a result about the treatment.
    hybrid_harness_only: int = 0
    baseline_harness_only: int = 0
    # Counted in the totals above, but resting on stacks we could not attribute.
    hybrid_unattributed: int = 0
    baseline_unattributed: int = 0

    @property
    def hybrid_mem_total(self) -> int:
        return sum(len(g.hybrid_mem) for g in self.per_grammar)

    @property
    def baseline_mem_total(self) -> int:
        return sum(len(g.baseline_mem) for g in self.per_grammar)

    @property
    def shared_total(self) -> int:
        return sum(len(g.shared) for g in self.per_grammar)

    @property
    def hybrid_only_total(self) -> int:
        return sum(len(g.hybrid_only) for g in self.per_grammar)

    @property
    def baseline_only_total(self) -> int:
        return sum(len(g.baseline_only) for g in self.per_grammar)


def compare(hybrid_dir: Path, baseline_dir: Path) -> ComparisonReport:
    """Diff the two sweeps on memory-safety stack hashes, per grammar and total."""
    hybrid = load_sweep(hybrid_dir)
    baseline = load_sweep(baseline_dir)
    grammars = sorted(set(hybrid) | set(baseline))
    per_grammar: list[GrammarComparison] = []
    for g in grammars:
        h = hybrid.get(g, GrammarCrashes(grammar=g)).mem_hashes()
        b = baseline.get(g, GrammarCrashes(grammar=g)).mem_hashes()
        if not h and not b:
            continue
        per_grammar.append(GrammarComparison(grammar=g, hybrid_mem=h, baseline_mem=b))
    return ComparisonReport(
        per_grammar=per_grammar,
        hybrid_harness_only=sum(len(g.harness_only) for g in hybrid.values()),
        baseline_harness_only=sum(len(g.harness_only) for g in baseline.values()),
        hybrid_unattributed=sum(len(g.unattributed) for g in hybrid.values()),
        baseline_unattributed=sum(len(g.unattributed) for g in baseline.values()),
    )


def compare_by_rep(
    hybrid_dir: Path, baseline_dir: Path
) -> list[tuple[str, ComparisonReport]]:
    """Compare rep-by-rep, so the overlap gets a spread instead of one number.

    Pairing repN against repN is meaningful because the control's budget is
    derived per-rep from the matching treatment rep (see
    ``baseline.targets_from_results``), so the two are equal-fuzz-seconds by
    construction. Only reps present in *both* sweeps are paired; a rep the
    baseline has not run yet is skipped rather than scored as "baseline found
    nothing", which would fabricate uplift.
    """
    h_reps, b_reps = rep_names(hybrid_dir), rep_names(baseline_dir)
    shared_reps = [r for r in h_reps if r in b_reps]
    if not shared_reps:
        return [("pooled", compare(hybrid_dir, baseline_dir))]
    return [(rep, compare(hybrid_dir / rep, baseline_dir / rep)) for rep in shared_reps]


def format_rep_reports(reports: list[tuple[str, ComparisonReport]]) -> str:
    """Per-rep overlap counts plus the spread, for the pooled table's header."""
    if len(reports) <= 1:
        return ""
    lines = [f"{'rep':10} {'hybrid':>6} {'baseln':>6} {'shared':>6} {'hyb-only':>8}"]
    lines.append("-" * 40)
    for rep, rep_report in reports:
        lines.append(
            f"{rep:10} {rep_report.hybrid_mem_total:>6} "
            f"{rep_report.baseline_mem_total:>6} {rep_report.shared_total:>6} "
            f"{rep_report.hybrid_only_total:>8}"
        )
    lines.append("-" * 40)
    only = [r.hybrid_only_total for _, r in reports]
    lines.append(
        f"hybrid-only across reps: min={min(only)} max={max(only)} "
        f"(n={len(only)} reps). A result that holds in one rep and not the others "
        f"is noise, not uplift."
    )
    return "\n".join(lines)


def format_report(report: ComparisonReport) -> str:
    """Render a plain-text table + headline overlap for the terminal / writeup."""
    lines: list[str] = []
    lines.append(
        f"{'grammar':30} {'hybrid':>6} {'baseln':>6} {'shared':>6} "
        f"{'hyb-only':>8} {'base-only':>9}"
    )
    lines.append("-" * 72)
    for g in sorted(report.per_grammar, key=lambda x: x.grammar):
        lines.append(
            f"{g.grammar:30} {len(g.hybrid_mem):>6} {len(g.baseline_mem):>6} "
            f"{len(g.shared):>6} {len(g.hybrid_only):>8} {len(g.baseline_only):>9}"
        )
    lines.append("-" * 72)
    lines.append(
        f"{'TOTAL (memory-safety bugs)':30} {report.hybrid_mem_total:>6} "
        f"{report.baseline_mem_total:>6} {report.shared_total:>6} "
        f"{report.hybrid_only_total:>8} {report.baseline_only_total:>9}"
    )
    if report.hybrid_mem_total:
        pct = 100.0 * report.shared_total / report.hybrid_mem_total
        lines.append("")
        lines.append(
            f"Baseline reproduced {report.shared_total}/{report.hybrid_mem_total} "
            f"({pct:.0f}%) of the hybrid's memory-safety bugs; "
            f"{report.hybrid_only_total} found only by the hybrid, "
            f"{report.baseline_only_total} only by the baseline."
        )
    if report.hybrid_harness_only or report.baseline_harness_only:
        lines.append("")
        lines.append(
            f"Excluded as harness bugs (stack never entered target code): "
            f"{report.hybrid_harness_only} hybrid, "
            f"{report.baseline_harness_only} baseline. Only the hybrid writes its "
            f"own harness, so these would otherwise count as hybrid-only uplift."
        )
    if report.hybrid_unattributed or report.baseline_unattributed:
        lines.append(
            f"Included but unattributed (handler-only stack, unwind failed): "
            f"{report.hybrid_unattributed} hybrid, "
            f"{report.baseline_unattributed} baseline."
        )
    return "\n".join(lines)
