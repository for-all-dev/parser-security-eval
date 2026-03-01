"""Tests for the per-target agent memory system."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from pathlib import Path

import pytest

from parser_security_eval.memory.merge import merge_memories
from parser_security_eval.memory.models import (
    CoverageSnapshot,
    CrashSummary,
    HarnessRecord,
    Hypothesis,
    TargetMemory,
)
from parser_security_eval.memory.store import (
    add_coverage_snapshot,
    add_crash,
    add_harness,
    add_hypothesis,
    load_memory,
    memory_to_context,
    save_memory,
)


def _now() -> datetime:
    return datetime.now(tz=timezone.utc)


def _make_hypothesis(
    h_id: str | None = None,
    entry_point: str = "xmlParseElement",
    led_to_crash: bool = False,
    coverage_delta: float = 0.01,
    description: str = "Try deeply nested XML elements to trigger stack overflow",
    notes: str = "Did not crash; coverage improved slightly",
) -> Hypothesis:
    return Hypothesis(
        id=h_id or str(uuid.uuid4()),
        description=description,
        entry_point=entry_point,
        harness_id=None,
        led_to_crash=led_to_crash,
        coverage_delta=coverage_delta,
        notes=notes,
        created_at=_now(),
    )


def _make_crash(
    stack_hash: str = "abc123", cwe: str | None = "CWE-122"
) -> CrashSummary:
    return CrashSummary(
        id=stack_hash,
        stack_hash=stack_hash,
        cwe=cwe,
        severity="high",
        entry_point="xmlParseElement",
        crash_file=None,
        found_at=_now(),
    )


def _make_harness(source_hash: str = "deadbeef") -> HarnessRecord:
    return HarnessRecord(
        id=source_hash,
        source_hash=source_hash,
        entry_point="xmlParseElement",
        compile_success=True,
        compile_iterations=1,
        crashes_found=0,
        coverage_achieved=0.42,
        created_at=_now(),
    )


def _make_snapshot(branch_pct: float = 0.5) -> CoverageSnapshot:
    return CoverageSnapshot(
        timestamp=_now(),
        line_pct=0.6,
        branch_pct=branch_pct,
        harness_id=None,
    )


# ---------------------------------------------------------------------------
# load / save round-trip
# ---------------------------------------------------------------------------


class TestLoadSaveRoundTrip:
    def test_empty_memory_round_trip(self, tmp_path: Path) -> None:
        memory = TargetMemory(target_name="libxml2")
        save_memory(memory, targets_dir=tmp_path)
        loaded = load_memory("libxml2", targets_dir=tmp_path)
        assert loaded.target_name == "libxml2"
        assert loaded.hypotheses_tried == []
        assert loaded.crashes_found == []
        assert loaded.harness_variants == []
        assert loaded.coverage_history == []

    def test_full_memory_round_trip(self, tmp_path: Path) -> None:
        memory = TargetMemory(
            target_name="libxml2",
            hypotheses_tried=[_make_hypothesis()],
            crashes_found=[_make_crash()],
            harness_variants=[_make_harness()],
            coverage_history=[_make_snapshot()],
        )
        save_memory(memory, targets_dir=tmp_path)
        loaded = load_memory("libxml2", targets_dir=tmp_path)

        assert len(loaded.hypotheses_tried) == 1
        assert len(loaded.crashes_found) == 1
        assert len(loaded.harness_variants) == 1
        assert len(loaded.coverage_history) == 1
        assert loaded.crashes_found[0].stack_hash == "abc123"
        assert loaded.harness_variants[0].source_hash == "deadbeef"

    def test_hypothesis_fields_preserved(self, tmp_path: Path) -> None:
        hyp = _make_hypothesis(led_to_crash=True, coverage_delta=0.05)
        memory = TargetMemory(target_name="libpng", hypotheses_tried=[hyp])
        save_memory(memory, targets_dir=tmp_path)
        loaded = load_memory("libpng", targets_dir=tmp_path)
        loaded_hyp = loaded.hypotheses_tried[0]
        assert loaded_hyp.led_to_crash is True
        assert loaded_hyp.coverage_delta == pytest.approx(0.05)


# ---------------------------------------------------------------------------
# empty memory when file does not exist
# ---------------------------------------------------------------------------


class TestLoadMissingFile:
    def test_returns_empty_target_memory(self, tmp_path: Path) -> None:
        memory = load_memory("nonexistent_target", targets_dir=tmp_path)
        assert isinstance(memory, TargetMemory)
        assert memory.target_name == "nonexistent_target"
        assert memory.hypotheses_tried == []
        assert memory.crashes_found == []

    def test_target_dir_does_not_exist(self, tmp_path: Path) -> None:
        # Requesting a target whose directory doesn't exist yet should still work
        memory = load_memory("brand_new_target", targets_dir=tmp_path)
        assert memory.target_name == "brand_new_target"


# ---------------------------------------------------------------------------
# memory_to_context token budget
# ---------------------------------------------------------------------------


class TestMemoryToContext:
    def test_empty_memory_returns_string(self) -> None:
        memory = TargetMemory(target_name="libxml2")
        ctx = memory_to_context(memory)
        assert "libxml2" in ctx
        assert isinstance(ctx, str)

    def test_stays_within_token_budget(self) -> None:
        """A large memory with many hypotheses must fit within the requested budget."""
        hyps = [
            _make_hypothesis(
                description="x" * 200,
                notes="n" * 200,
            )
            for _ in range(100)
        ]
        memory = TargetMemory(target_name="libxml2", hypotheses_tried=hyps)
        max_tokens = 500
        ctx = memory_to_context(memory, max_tokens=max_tokens)
        estimated_tokens = len(ctx) // 4
        # Allow a small overage (one extra entry may push past by a bit) but
        # verify it's meaningfully bounded.
        assert estimated_tokens <= max_tokens * 1.5

    def test_includes_summary_stats(self) -> None:
        memory = TargetMemory(
            target_name="libxml2",
            hypotheses_tried=[_make_hypothesis()],
            crashes_found=[_make_crash()],
            harness_variants=[_make_harness()],
            coverage_history=[_make_snapshot(branch_pct=0.75)],
        )
        ctx = memory_to_context(memory)
        assert "1" in ctx  # counts show up
        assert "libxml2" in ctx

    def test_coverage_trend_shown(self) -> None:
        snaps = [_make_snapshot(branch_pct=0.1 * i) for i in range(1, 8)]
        memory = TargetMemory(target_name="libxml2", coverage_history=snaps)
        ctx = memory_to_context(memory)
        assert "Coverage trend" in ctx

    def test_crashes_shown(self) -> None:
        memory = TargetMemory(
            target_name="libxml2",
            crashes_found=[_make_crash(stack_hash="deadc0de", cwe="CWE-122")],
        )
        ctx = memory_to_context(memory)
        assert "deadc0de" in ctx
        assert "CWE-122" in ctx


# ---------------------------------------------------------------------------
# merge_memories deduplication
# ---------------------------------------------------------------------------


class TestMergeMemories:
    def test_merge_no_additions(self) -> None:
        base = TargetMemory(
            target_name="libxml2",
            hypotheses_tried=[_make_hypothesis("h1")],
            crashes_found=[_make_crash("s1")],
        )
        merged = merge_memories(base)
        assert len(merged.hypotheses_tried) == 1
        assert len(merged.crashes_found) == 1

    def test_merge_deduplicates_hypotheses_by_id(self) -> None:
        hyp = _make_hypothesis("shared-id")
        base = TargetMemory(target_name="libxml2", hypotheses_tried=[hyp])
        other = TargetMemory(target_name="libxml2", hypotheses_tried=[hyp])
        merged = merge_memories(base, other)
        assert len(merged.hypotheses_tried) == 1

    def test_merge_deduplicates_crashes_by_stack_hash(self) -> None:
        crash = _make_crash("same-hash")
        base = TargetMemory(target_name="libxml2", crashes_found=[crash])
        other = TargetMemory(target_name="libxml2", crashes_found=[crash])
        merged = merge_memories(base, other)
        assert len(merged.crashes_found) == 1

    def test_merge_deduplicates_harnesses_by_source_hash(self) -> None:
        harness = _make_harness("same-src-hash")
        base = TargetMemory(target_name="libxml2", harness_variants=[harness])
        other = TargetMemory(target_name="libxml2", harness_variants=[harness])
        merged = merge_memories(base, other)
        assert len(merged.harness_variants) == 1

    def test_merge_unions_unique_items(self) -> None:
        base = TargetMemory(
            target_name="libxml2",
            hypotheses_tried=[_make_hypothesis("h1")],
            crashes_found=[_make_crash("c1")],
            harness_variants=[_make_harness("src1")],
        )
        other1 = TargetMemory(
            target_name="libxml2",
            hypotheses_tried=[_make_hypothesis("h2")],
            crashes_found=[_make_crash("c2")],
            harness_variants=[_make_harness("src2")],
        )
        other2 = TargetMemory(
            target_name="libxml2",
            hypotheses_tried=[_make_hypothesis("h3")],
            crashes_found=[_make_crash("c3")],
            harness_variants=[_make_harness("src3")],
        )
        merged = merge_memories(base, other1, other2)
        assert len(merged.hypotheses_tried) == 3
        assert len(merged.crashes_found) == 3
        assert len(merged.harness_variants) == 3

    def test_merge_sorts_coverage_by_timestamp(self) -> None:
        import time

        snap1 = _make_snapshot(0.1)
        time.sleep(0.01)
        snap2 = _make_snapshot(0.2)
        time.sleep(0.01)
        snap3 = _make_snapshot(0.3)

        base = TargetMemory(target_name="libxml2", coverage_history=[snap3, snap1])
        other = TargetMemory(target_name="libxml2", coverage_history=[snap2])
        merged = merge_memories(base, other)
        timestamps = [s.timestamp for s in merged.coverage_history]
        assert timestamps == sorted(timestamps)

    def test_merge_sets_last_updated(self) -> None:
        base = TargetMemory(target_name="libxml2")
        merged = merge_memories(base)
        assert isinstance(merged.last_updated, datetime)


# ---------------------------------------------------------------------------
# add_crash deduplication
# ---------------------------------------------------------------------------


class TestAddCrash:
    def test_adds_new_crash(self, tmp_path: Path) -> None:
        add_crash("libxml2", _make_crash("hash1"), targets_dir=tmp_path)
        memory = load_memory("libxml2", targets_dir=tmp_path)
        assert len(memory.crashes_found) == 1

    def test_deduplicates_by_stack_hash(self, tmp_path: Path) -> None:
        add_crash("libxml2", _make_crash("same-hash"), targets_dir=tmp_path)
        add_crash("libxml2", _make_crash("same-hash"), targets_dir=tmp_path)
        memory = load_memory("libxml2", targets_dir=tmp_path)
        assert len(memory.crashes_found) == 1

    def test_adds_distinct_hashes(self, tmp_path: Path) -> None:
        add_crash("libxml2", _make_crash("hash-a"), targets_dir=tmp_path)
        add_crash("libxml2", _make_crash("hash-b"), targets_dir=tmp_path)
        memory = load_memory("libxml2", targets_dir=tmp_path)
        assert len(memory.crashes_found) == 2


# ---------------------------------------------------------------------------
# add_hypothesis
# ---------------------------------------------------------------------------


class TestAddHypothesis:
    def test_appends_hypothesis(self, tmp_path: Path) -> None:
        add_hypothesis("libxml2", _make_hypothesis(), targets_dir=tmp_path)
        add_hypothesis("libxml2", _make_hypothesis(), targets_dir=tmp_path)
        memory = load_memory("libxml2", targets_dir=tmp_path)
        assert len(memory.hypotheses_tried) == 2


# ---------------------------------------------------------------------------
# add_harness deduplication
# ---------------------------------------------------------------------------


class TestAddHarness:
    def test_deduplicates_by_source_hash(self, tmp_path: Path) -> None:
        add_harness("libxml2", _make_harness("src-hash"), targets_dir=tmp_path)
        add_harness("libxml2", _make_harness("src-hash"), targets_dir=tmp_path)
        memory = load_memory("libxml2", targets_dir=tmp_path)
        assert len(memory.harness_variants) == 1


# ---------------------------------------------------------------------------
# add_coverage_snapshot
# ---------------------------------------------------------------------------


class TestAddCoverageSnapshot:
    def test_appends_snapshots(self, tmp_path: Path) -> None:
        add_coverage_snapshot("libxml2", _make_snapshot(0.3), targets_dir=tmp_path)
        add_coverage_snapshot("libxml2", _make_snapshot(0.5), targets_dir=tmp_path)
        memory = load_memory("libxml2", targets_dir=tmp_path)
        assert len(memory.coverage_history) == 2
