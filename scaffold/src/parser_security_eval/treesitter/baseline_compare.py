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


def _is_memory_safety(bug_class: str, in_scanner: bool) -> bool:
    if bug_class in _RESOURCE_CLASSES:
        return False
    if bug_class == BugClass.unknown.value:
        # An "unknown" class only counts if it landed in hand-written scanner code.
        return in_scanner
    return True


@dataclass
class GrammarCrashes:
    """Distinct crashes a sweep found for one grammar, keyed by stack hash."""

    grammar: str
    # stack_hash -> (bug_class, in_scanner)
    crashes: dict[str, tuple[str, bool]] = field(default_factory=dict)

    def mem_hashes(self) -> set[str]:
        return {
            h for h, (bc, scan) in self.crashes.items() if _is_memory_safety(bc, scan)
        }

    def all_hashes(self) -> set[str]:
        return set(self.crashes)


def load_sweep(results_dir: Path) -> dict[str, GrammarCrashes]:
    """Load a sweep dir into ``{grammar: GrammarCrashes}`` (deduped by stack hash)."""
    out: dict[str, GrammarCrashes] = {}
    for path in sorted(results_dir.glob("*.jsonl")):
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
            h = crash.get("stack_hash") or ""
            if not h:
                continue
            gc.crashes[h] = (
                str(crash.get("bug_class") or BugClass.unknown.value),
                bool(crash.get("in_scanner")),
            )
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
    return ComparisonReport(per_grammar=per_grammar)


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
    return "\n".join(lines)
