"""Read/write/format interface for per-target agent memory."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from parser_security_eval.memory.models import (
    CoverageSnapshot,
    CrashSummary,
    HarnessRecord,
    Hypothesis,
    TargetMemory,
)

# Walk up from __file__ to find the repo root, then the targets/ directory.
_REPO_ROOT = Path(__file__).parent
for _p in Path(__file__).parents:
    if (_p / "targets").is_dir():
        _REPO_ROOT = _p
        break

_DEFAULT_TARGETS_DIR = _REPO_ROOT / "targets"


def _resolve_targets_dir(targets_dir: Path | None) -> Path:
    return targets_dir if targets_dir is not None else _DEFAULT_TARGETS_DIR


def load_memory(target: str, targets_dir: Path | None = None) -> TargetMemory:
    """Load from targets/<target>/memory.json. Returns empty TargetMemory if not found."""
    memory_path = _resolve_targets_dir(targets_dir) / target / "memory.json"
    if not memory_path.exists():
        return TargetMemory(target_name=target)
    raw = memory_path.read_text(encoding="utf-8")
    return TargetMemory.model_validate_json(raw)


def save_memory(memory: TargetMemory, targets_dir: Path | None = None) -> None:
    """Persist to targets/<target>/memory.json. Creates file if needed."""
    memory_path = _resolve_targets_dir(targets_dir) / memory.target_name / "memory.json"
    memory_path.parent.mkdir(parents=True, exist_ok=True)
    memory_path.write_text(
        memory.model_dump_json(indent=2),
        encoding="utf-8",
    )


def memory_to_context(memory: TargetMemory, max_tokens: int = 2000) -> str:
    """
    Format memory as a concise LLM-readable context block.

    Includes:
    - Summary: N hypotheses tried, M crashes found, best coverage achieved
    - Recent hypotheses (most recent first, truncated to fit token budget)
    - Unique crashes found (stack hashes + CWE if known)
    - Harness variants tried (compile success rate, best coverage)
    - Coverage trend (last 5 snapshots)

    Estimates tokens as len(text) // 4. Truncates oldest entries to fit budget.
    """
    lines: list[str] = []

    # --- Summary block ---
    best_branch = max((s.branch_pct for s in memory.coverage_history), default=0.0)
    compile_successes = sum(1 for h in memory.harness_variants if h.compile_success)
    total_harnesses = len(memory.harness_variants)
    lines.append(f"=== Agent Memory: {memory.target_name} ===")
    lines.append(
        f"Hypotheses tried: {len(memory.hypotheses_tried)} | "
        f"Crashes found: {len(memory.crashes_found)} | "
        f"Best branch coverage: {best_branch:.1%}"
    )
    if total_harnesses > 0:
        lines.append(
            f"Harness variants: {total_harnesses} total, "
            f"{compile_successes}/{total_harnesses} compiled successfully"
        )
    lines.append("")

    # --- Coverage trend (last 5 snapshots) ---
    if memory.coverage_history:
        lines.append("--- Coverage trend (last 5 snapshots) ---")
        for snap in sorted(memory.coverage_history, key=lambda s: s.timestamp)[-5:]:
            harness_note = f" [harness={snap.harness_id}]" if snap.harness_id else ""
            lines.append(
                f"  {snap.timestamp.strftime('%Y-%m-%dT%H:%M:%S')} | "
                f"line={snap.line_pct:.1%} branch={snap.branch_pct:.1%}{harness_note}"
            )
        lines.append("")

    # --- Crashes found ---
    if memory.crashes_found:
        lines.append("--- Crashes found ---")
        for crash in memory.crashes_found:
            cwe_note = f" ({crash.cwe})" if crash.cwe else ""
            sev_note = f" [{crash.severity}]" if crash.severity else ""
            patched_note = " [PATCHED]" if crash.patched else ""
            lines.append(
                f"  {crash.stack_hash}{cwe_note}{sev_note}{patched_note} "
                f"@ {crash.entry_point} "
                f"({crash.found_at.strftime('%Y-%m-%dT%H:%M:%S')})"
            )
        lines.append("")

    # --- Harness variants ---
    if memory.harness_variants:
        lines.append("--- Harness variants ---")
        for harness in sorted(memory.harness_variants, key=lambda h: h.created_at):
            status = "OK" if harness.compile_success else "FAIL"
            lines.append(
                f"  [{status}] id={harness.id[:12]} ep={harness.entry_point} "
                f"iters={harness.compile_iterations} crashes={harness.crashes_found} "
                f"cov={harness.coverage_achieved:.1%}"
            )
        lines.append("")

    header = "\n".join(lines)

    # --- Hypotheses: most recent first, truncate to fit budget ---
    hypotheses_sorted = sorted(
        memory.hypotheses_tried, key=lambda h: h.created_at, reverse=True
    )

    hyp_header = "--- Hypotheses tried (most recent first) ---\n"
    hyp_lines: list[str] = []
    for hyp in hypotheses_sorted:
        crash_note = " [CRASHED]" if hyp.led_to_crash else ""
        harness_note = f" harness={hyp.harness_id}" if hyp.harness_id else ""
        hyp_lines.append(
            f"  [{hyp.created_at.strftime('%Y-%m-%dT%H:%M:%S')}]{crash_note} "
            f"ep={hyp.entry_point}{harness_note} delta={hyp.coverage_delta:+.3f}\n"
            f"    desc: {hyp.description}\n"
            f"    notes: {hyp.notes}"
        )

    # Fit within token budget: estimate tokens as len(text) // 4
    budget_chars = max_tokens * 4
    used = len(header) + len(hyp_header)

    kept_hyp_lines: list[str] = []
    for hyp_line in hyp_lines:
        cost = len(hyp_line) + 1  # +1 for newline
        if used + cost > budget_chars:
            break
        kept_hyp_lines.append(hyp_line)
        used += cost

    if hypotheses_sorted:
        full = header + hyp_header + "\n".join(kept_hyp_lines)
        if len(kept_hyp_lines) < len(hyp_lines):
            full += f"\n  ... ({len(hyp_lines) - len(kept_hyp_lines)} older hypotheses omitted)"
    else:
        full = header + "(No hypotheses recorded yet.)"

    return full


def add_hypothesis(
    target: str, hypothesis: Hypothesis, targets_dir: Path | None = None
) -> None:
    """Convenience: load, append, save."""
    memory = load_memory(target, targets_dir)
    memory.hypotheses_tried.append(hypothesis)
    memory.last_updated = datetime.now(tz=timezone.utc)
    save_memory(memory, targets_dir)


def add_crash(
    target: str, crash: CrashSummary, targets_dir: Path | None = None
) -> None:
    """Convenience: load, append (dedup by stack_hash), save."""
    memory = load_memory(target, targets_dir)
    existing_hashes = {c.stack_hash for c in memory.crashes_found}
    if crash.stack_hash not in existing_hashes:
        memory.crashes_found.append(crash)
        memory.last_updated = datetime.now(tz=timezone.utc)
        save_memory(memory, targets_dir)


def add_harness(
    target: str, harness: HarnessRecord, targets_dir: Path | None = None
) -> None:
    """Convenience: load, append (dedup by source_hash), save."""
    memory = load_memory(target, targets_dir)
    existing_hashes = {h.source_hash for h in memory.harness_variants}
    if harness.source_hash not in existing_hashes:
        memory.harness_variants.append(harness)
        memory.last_updated = datetime.now(tz=timezone.utc)
        save_memory(memory, targets_dir)


def add_coverage_snapshot(
    target: str, snapshot: CoverageSnapshot, targets_dir: Path | None = None
) -> None:
    """Convenience: load, append, save."""
    memory = load_memory(target, targets_dir)
    memory.coverage_history.append(snapshot)
    memory.last_updated = datetime.now(tz=timezone.utc)
    save_memory(memory, targets_dir)
