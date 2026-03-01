"""Merge utilities for combining N agent memory fragments into one shared memory."""

from __future__ import annotations

from datetime import datetime, timezone

from parser_security_eval.memory.models import TargetMemory


def merge_memories(base: TargetMemory, *additions: TargetMemory) -> TargetMemory:
    """
    Merge multiple TargetMemory objects into one.

    - Deduplicates: hypotheses by id, crashes by stack_hash, harnesses by source_hash
    - Sorts coverage_history by timestamp
    - Sets last_updated to now
    """
    # Start from copies of base lists
    hypotheses_by_id = {h.id: h for h in base.hypotheses_tried}
    crashes_by_hash = {c.stack_hash: c for c in base.crashes_found}
    harnesses_by_hash = {h.source_hash: h for h in base.harness_variants}
    coverage_history = list(base.coverage_history)

    for addition in additions:
        for hyp in addition.hypotheses_tried:
            if hyp.id not in hypotheses_by_id:
                hypotheses_by_id[hyp.id] = hyp

        for crash in addition.crashes_found:
            if crash.stack_hash not in crashes_by_hash:
                crashes_by_hash[crash.stack_hash] = crash

        for harness in addition.harness_variants:
            if harness.source_hash not in harnesses_by_hash:
                harnesses_by_hash[harness.source_hash] = harness

        coverage_history.extend(addition.coverage_history)

    return TargetMemory(
        target_name=base.target_name,
        hypotheses_tried=list(hypotheses_by_id.values()),
        crashes_found=list(crashes_by_hash.values()),
        harness_variants=list(harnesses_by_hash.values()),
        coverage_history=sorted(coverage_history, key=lambda s: s.timestamp),
        last_updated=datetime.now(tz=timezone.utc),
    )
