"""Tests for cross-agent crash deduplication (scoring/dedup.py)."""

from __future__ import annotations

from pathlib import Path

import pytest

from parser_security_eval.scoring.dedup import (
    CrashCluster,
    CrashDeduplicator,
    CrashReport,
    DeduplicatorConfig,
    DeduplicatorQueues,
    DeduplicationStrategy,
    FuzzerEngine,
    InterestingInput,
    _compute_stack_hash,
    _normalise_frame,
    deduplicate_crashes,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_crash(
    agent_id: str = "agent-00",
    frames: list[str] | None = None,
    engine: FuzzerEngine = FuzzerEngine.LIBFUZZER,
    crash_input: bytes = b"\x00",
    sanitizer_output: str = "",
    execution_trace: str = "",
    target: str = "libxml2",
    crash_type: str = "heap-buffer-overflow",
) -> CrashReport:
    return CrashReport(
        agent_id=agent_id,
        crash_input=crash_input,
        stack_frames=frames if frames is not None else [],
        engine=engine,
        sanitizer_output=sanitizer_output,
        execution_trace=execution_trace,
        target=target,
        crash_type=crash_type,
    )


def _shared_frames(n: int = 5) -> list[str]:
    return ["#0 parse_chunk src/parser.c:42"] + [
        f"#{i} caller_{i} src/parser.c:{100 + i}" for i in range(1, n)
    ]


# ---------------------------------------------------------------------------
# DeduplicatorConfig
# ---------------------------------------------------------------------------


class TestDeduplicatorConfig:
    def test_defaults(self) -> None:
        cfg = DeduplicatorConfig()
        assert cfg.stack_frame_depth == 5
        assert cfg.strategy == DeduplicationStrategy.STACK_HASH

    def test_strict_preset(self) -> None:
        cfg = DeduplicatorConfig(stack_frame_depth=3)
        assert cfg.stack_frame_depth == 3

    def test_loose_preset(self) -> None:
        cfg = DeduplicatorConfig(stack_frame_depth=10)
        assert cfg.stack_frame_depth == 10

    def test_frame_depth_bounds(self) -> None:
        with pytest.raises(Exception):
            DeduplicatorConfig(stack_frame_depth=0)

    def test_round_trip(self) -> None:
        cfg = DeduplicatorConfig(stack_frame_depth=7)
        restored = DeduplicatorConfig.model_validate(cfg.model_dump())
        assert restored.stack_frame_depth == 7


# ---------------------------------------------------------------------------
# CrashReport
# ---------------------------------------------------------------------------


class TestCrashReport:
    def test_basic_fields(self) -> None:
        crash = _make_crash("agent-01", frames=["#0 foo bar.c:1"])
        assert crash.agent_id == "agent-01"
        assert crash.stack_frames == ["#0 foo bar.c:1"]
        assert crash.engine == FuzzerEngine.LIBFUZZER

    def test_optional_path(self, tmp_path: Path) -> None:
        p = tmp_path / "crash-001"
        p.write_bytes(b"\xff")
        crash = CrashReport(
            agent_id="agent-00",
            crash_input=b"\xff",
            crash_input_path=p,
        )
        assert crash.crash_input_path == p

    def test_empty_frames_default(self) -> None:
        crash = _make_crash()
        assert crash.stack_frames == []

    def test_stores_sanitizer_output(self) -> None:
        crash = _make_crash(sanitizer_output="ASAN: heap-buffer-overflow")
        assert "heap-buffer-overflow" in crash.sanitizer_output

    def test_stores_execution_trace(self) -> None:
        crash = _make_crash(execution_trace="0xdeadbeef 0xcafebabe")
        assert "0xdeadbeef" in crash.execution_trace


# ---------------------------------------------------------------------------
# CrashCluster
# ---------------------------------------------------------------------------


class TestCrashCluster:
    def test_size_singleton(self) -> None:
        crash = _make_crash()
        cluster = CrashCluster(
            cluster_id=1,
            stack_hash="abc123",
            representative=crash,
        )
        assert cluster.size == 1

    def test_size_with_members(self) -> None:
        crash = _make_crash()
        m1 = _make_crash("agent-01")
        m2 = _make_crash("agent-02")
        cluster = CrashCluster(
            cluster_id=1,
            stack_hash="abc123",
            representative=crash,
            members=[m1, m2],
        )
        assert cluster.size == 3

    def test_agent_set_property(self) -> None:
        crash = _make_crash("agent-00")
        cluster = CrashCluster(
            cluster_id=1,
            stack_hash="abc",
            representative=crash,
            agent_ids=("agent-00", "agent-01"),
        )
        assert cluster.agent_set == frozenset({"agent-00", "agent-01"})

    def test_agent_set_is_frozenset(self) -> None:
        crash = _make_crash()
        cluster = CrashCluster(
            cluster_id=1,
            stack_hash="abc",
            representative=crash,
            agent_ids=("agent-00",),
        )
        assert isinstance(cluster.agent_set, frozenset)

    def test_round_trip(self) -> None:
        crash = _make_crash("agent-00", frames=["#0 foo x.c:1"])
        cluster = CrashCluster(
            cluster_id=42,
            stack_hash="deadbeef",
            representative=crash,
            agent_ids=("agent-00", "agent-01"),
            sanitizer_output="ASAN output here",
            execution_trace="pc1 pc2",
        )
        restored = CrashCluster.model_validate(cluster.model_dump())
        assert restored.cluster_id == 42
        assert restored.stack_hash == "deadbeef"
        assert restored.agent_ids == ("agent-00", "agent-01")
        assert restored.sanitizer_output == "ASAN output here"
        assert restored.execution_trace == "pc1 pc2"


# ---------------------------------------------------------------------------
# _normalise_frame
# ---------------------------------------------------------------------------


class TestNormaliseFrame:
    def test_libfuzzer_strips_address(self) -> None:
        frame = "#0 0x5555557abc in parse_chunk src/parser.c:42"
        norm = _normalise_frame(frame, FuzzerEngine.LIBFUZZER)
        assert "0x5555557abc" not in norm
        assert "parse_chunk" in norm

    def test_afl_strips_address(self) -> None:
        frame = "  #1 0xdeadbeef in parse_document src/parser.c:200"
        norm = _normalise_frame(frame, FuzzerEngine.AFL_PLUS_PLUS)
        assert "0xdeadbeef" not in norm
        assert "parse_document" in norm

    def test_same_function_different_engines_equivalent(self) -> None:
        libfuzzer_frame = "#0 0xAAAA in parse_chunk src/parser.c:42"
        afl_frame = "#0 0xBBBB in parse_chunk src/parser.c:42"
        n1 = _normalise_frame(libfuzzer_frame, FuzzerEngine.LIBFUZZER)
        n2 = _normalise_frame(afl_frame, FuzzerEngine.AFL_PLUS_PLUS)
        assert n1 == n2

    def test_unknown_engine_strips_hex(self) -> None:
        frame = "#3 0xdeadbeef in some_func /path/to/file.c:99"
        norm = _normalise_frame(frame, FuzzerEngine.UNKNOWN)
        assert "0xdeadbeef" not in norm

    def test_generic_asan_fallback(self) -> None:
        frame = "#2 0x1234abcd in malloc_wrapper /libc.so"
        norm = _normalise_frame(frame, FuzzerEngine.UNKNOWN)
        assert "0x1234abcd" not in norm
        assert "malloc_wrapper" in norm


# ---------------------------------------------------------------------------
# _compute_stack_hash
# ---------------------------------------------------------------------------


class TestComputeStackHash:
    def test_deterministic(self) -> None:
        frames = ["#0 parse_chunk src/parser.c:42", "#1 caller src/main.c:10"]
        h1 = _compute_stack_hash(frames, FuzzerEngine.LIBFUZZER, depth=2)
        h2 = _compute_stack_hash(frames, FuzzerEngine.LIBFUZZER, depth=2)
        assert h1 == h2

    def test_different_frames_different_hash(self) -> None:
        frames_a = ["#0 func_a x.c:1"]
        frames_b = ["#0 func_b x.c:1"]
        h_a = _compute_stack_hash(frames_a, FuzzerEngine.LIBFUZZER, depth=1)
        h_b = _compute_stack_hash(frames_b, FuzzerEngine.LIBFUZZER, depth=1)
        assert h_a != h_b

    def test_depth_truncates_frames(self) -> None:
        """Only top *depth* frames are hashed; extra frames are ignored."""
        base = ["#0 func_a x.c:1", "#1 func_b x.c:2"]
        extra_a = base + ["#2 extra_a x.c:3"]
        extra_b = base + ["#2 extra_b x.c:99"]
        h_a = _compute_stack_hash(extra_a, FuzzerEngine.LIBFUZZER, depth=2)
        h_b = _compute_stack_hash(extra_b, FuzzerEngine.LIBFUZZER, depth=2)
        assert h_a == h_b

    def test_empty_frames_produces_hash(self) -> None:
        h = _compute_stack_hash([], FuzzerEngine.LIBFUZZER, depth=5)
        assert len(h) == 64  # SHA-256 hex digest

    def test_cross_engine_same_function_same_hash(self) -> None:
        """Same function found by libFuzzer and AFL++ should produce same hash."""
        libfuzzer_frame = "#0 0xAAAA in parse_chunk src/parser.c:42"
        afl_frame = "#0 0xBBBB in parse_chunk src/parser.c:42"
        h_lf = _compute_stack_hash([libfuzzer_frame], FuzzerEngine.LIBFUZZER, depth=1)
        h_afl = _compute_stack_hash([afl_frame], FuzzerEngine.AFL_PLUS_PLUS, depth=1)
        assert h_lf == h_afl


# ---------------------------------------------------------------------------
# CrashDeduplicator — basic ingestion
# ---------------------------------------------------------------------------


class TestCrashDeduplicatorBasic:
    def test_first_crash_is_new(self) -> None:
        dedup = CrashDeduplicator()
        crash = _make_crash("agent-00", frames=["#0 foo x.c:1"])
        is_new, cluster = dedup.ingest_crash(crash)
        assert is_new is True
        assert cluster.cluster_id == 1

    def test_duplicate_crash_is_not_new(self) -> None:
        dedup = CrashDeduplicator()
        frames = ["#0 foo x.c:1", "#1 bar x.c:2"]
        c1 = _make_crash("agent-00", frames=frames)
        c2 = _make_crash("agent-01", frames=frames)
        is_new_1, _ = dedup.ingest_crash(c1)
        is_new_2, _ = dedup.ingest_crash(c2)
        assert is_new_1 is True
        assert is_new_2 is False

    def test_distinct_crashes_are_both_new(self) -> None:
        dedup = CrashDeduplicator()
        c1 = _make_crash("agent-00", frames=["#0 func_a x.c:1"])
        c2 = _make_crash("agent-00", frames=["#0 func_b x.c:2"])
        is_new_1, _ = dedup.ingest_crash(c1)
        is_new_2, _ = dedup.ingest_crash(c2)
        assert is_new_1 is True
        assert is_new_2 is True
        assert dedup.n_unique_crashes == 2

    def test_duplicate_added_to_members(self) -> None:
        dedup = CrashDeduplicator()
        frames = ["#0 foo x.c:1"]
        c1 = _make_crash("agent-00", frames=frames)
        c2 = _make_crash("agent-01", frames=frames)
        dedup.ingest_crash(c1)
        _, cluster = dedup.ingest_crash(c2)
        assert cluster.size == 2
        assert cluster.representative.agent_id == "agent-00"
        assert cluster.members[0].agent_id == "agent-01"

    def test_attribution_tracks_multiple_agents(self) -> None:
        dedup = CrashDeduplicator()
        frames = ["#0 foo x.c:1"]
        for agent_id in ("agent-00", "agent-01", "agent-02"):
            dedup.ingest_crash(_make_crash(agent_id, frames=frames))
        _, cluster = dedup.ingest_crash(_make_crash("agent-03", frames=frames))
        assert cluster.agent_set == frozenset(
            {"agent-00", "agent-01", "agent-02", "agent-03"}
        )

    def test_n_unique_crashes_counter(self) -> None:
        dedup = CrashDeduplicator()
        for i in range(5):
            dedup.ingest_crash(_make_crash("agent-00", frames=[f"#0 func_{i} x.c:{i}"]))
        assert dedup.n_unique_crashes == 5


# ---------------------------------------------------------------------------
# CrashDeduplicator — interesting inputs queue
# ---------------------------------------------------------------------------


class TestInterestingInputsQueue:
    def test_enqueue_interesting_input(self) -> None:
        dedup = CrashDeduplicator()
        inp = InterestingInput(
            agent_id="agent-00",
            input_bytes=b"\xde\xad",
            new_edges=12,
            target="libpng",
        )
        dedup.ingest_interesting_input(inp)
        assert dedup.n_interesting_inputs == 1

    def test_multiple_interesting_inputs_all_kept(self) -> None:
        dedup = CrashDeduplicator()
        for i in range(5):
            dedup.ingest_interesting_input(
                InterestingInput(
                    agent_id=f"agent-{i:02d}",
                    input_bytes=bytes([i]),
                    new_edges=i + 1,
                )
            )
        assert dedup.n_interesting_inputs == 5

    def test_interesting_inputs_separate_from_crashes(self) -> None:
        dedup = CrashDeduplicator()
        dedup.ingest_crash(_make_crash("agent-00", frames=["#0 foo x.c:1"]))
        dedup.ingest_interesting_input(
            InterestingInput(agent_id="agent-01", input_bytes=b"\x00")
        )
        assert dedup.n_unique_crashes == 1
        assert dedup.n_interesting_inputs == 1


# ---------------------------------------------------------------------------
# DeduplicatorQueues snapshot
# ---------------------------------------------------------------------------


class TestDeduplicatorQueues:
    def test_queues_returns_snapshot(self) -> None:
        dedup = CrashDeduplicator()
        dedup.ingest_crash(_make_crash("agent-00", frames=["#0 foo x.c:1"]))
        dedup.ingest_interesting_input(
            InterestingInput(agent_id="agent-01", input_bytes=b"\x01")
        )
        qs = dedup.queues()
        assert isinstance(qs, DeduplicatorQueues)
        assert qs.n_unique_crashes == 1
        assert qs.n_interesting_inputs == 1

    def test_queues_are_independent(self) -> None:
        """Unique crashes and interesting inputs are in separate lists."""
        dedup = CrashDeduplicator()
        dedup.ingest_crash(_make_crash("agent-00", frames=["#0 foo x.c:1"]))
        dedup.ingest_interesting_input(
            InterestingInput(agent_id="agent-00", input_bytes=b"\xff")
        )
        qs = dedup.queues()
        assert len(qs.unique_crashes) == 1
        assert len(qs.interesting_inputs) == 1
        # Make sure they are different types
        assert isinstance(qs.unique_crashes[0], CrashCluster)
        assert isinstance(qs.interesting_inputs[0], InterestingInput)

    def test_empty_state(self) -> None:
        dedup = CrashDeduplicator()
        qs = dedup.queues()
        assert qs.n_unique_crashes == 0
        assert qs.n_interesting_inputs == 0
        assert qs.unique_crashes == []
        assert qs.interesting_inputs == []

    def test_snapshot_not_live(self) -> None:
        """Modifying the deduplicator after queues() does not update old snapshot."""
        dedup = CrashDeduplicator()
        dedup.ingest_crash(_make_crash("agent-00", frames=["#0 foo x.c:1"]))
        qs = dedup.queues()
        # Ingest another crash after taking snapshot
        dedup.ingest_crash(_make_crash("agent-01", frames=["#0 bar x.c:2"]))
        # Old snapshot should still have 1 unique crash
        assert qs.n_unique_crashes == 1
        # But deduplicator now has 2
        assert dedup.n_unique_crashes == 2


# ---------------------------------------------------------------------------
# Stack-frame depth granularity
# ---------------------------------------------------------------------------


class TestStackFrameDepthGranularity:
    def test_strict_depth_3(self) -> None:
        """With depth=3, crashes that share only the top 3 frames are grouped."""
        cfg = DeduplicatorConfig(stack_frame_depth=3)
        dedup = CrashDeduplicator(cfg)
        shared = ["#0 parse_chunk x.c:1", "#1 caller x.c:2", "#2 main x.c:3"]
        c1 = _make_crash("agent-00", frames=shared + ["#3 extra_a x.c:99"])
        c2 = _make_crash("agent-01", frames=shared + ["#3 extra_b x.c:100"])
        dedup.ingest_crash(c1)
        is_new, _ = dedup.ingest_crash(c2)
        assert is_new is False  # same top-3 frames
        assert dedup.n_unique_crashes == 1

    def test_loose_depth_10(self) -> None:
        """With depth=10, crashes that share only top 3 frames but differ at frame 4
        are counted as distinct."""
        cfg = DeduplicatorConfig(stack_frame_depth=10)
        dedup = CrashDeduplicator(cfg)
        shared = ["#0 parse_chunk x.c:1", "#1 caller x.c:2", "#2 main x.c:3"]
        c1 = _make_crash("agent-00", frames=shared + ["#3 extra_a x.c:99"])
        c2 = _make_crash("agent-01", frames=shared + ["#3 extra_b x.c:100"])
        dedup.ingest_crash(c1)
        is_new, _ = dedup.ingest_crash(c2)
        assert is_new is True  # differ at frame #3 within depth=10
        assert dedup.n_unique_crashes == 2

    def test_depth_irrelevant_when_few_frames(self) -> None:
        """When a crash has fewer frames than depth, all frames are used."""
        cfg = DeduplicatorConfig(stack_frame_depth=10)
        dedup = CrashDeduplicator(cfg)
        # Only 2 frames, same for both
        frames = ["#0 foo x.c:1", "#1 bar x.c:2"]
        c1 = _make_crash("agent-00", frames=frames)
        c2 = _make_crash("agent-01", frames=frames)
        dedup.ingest_crash(c1)
        is_new, _ = dedup.ingest_crash(c2)
        assert is_new is False


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


class TestEdgeCases:
    def test_same_bug_different_stack_depths(self) -> None:
        """Crashes sharing top N frames but differing in depth are grouped (default N=5)."""
        base = [f"#0 func_{i} x.c:{i}" for i in range(5)]
        c1 = _make_crash("agent-00", frames=base)
        c2 = _make_crash("agent-01", frames=base + ["#5 deep_frame x.c:99"])
        dedup = CrashDeduplicator()
        dedup.ingest_crash(c1)
        is_new, _ = dedup.ingest_crash(c2)
        assert is_new is False

    def test_same_location_different_crash_type(self) -> None:
        """Two bugs at the same source line but with different stack frames
        (e.g. different call path) → different hashes → separate clusters."""
        frames_a = ["#0 heap_overflow x.c:42", "#1 caller_a x.c:10"]
        frames_b = ["#0 use_after_free x.c:42", "#1 caller_b x.c:20"]
        c1 = _make_crash("agent-00", frames=frames_a)
        c2 = _make_crash("agent-00", frames=frames_b)
        dedup = CrashDeduplicator()
        dedup.ingest_crash(c1)
        is_new, _ = dedup.ingest_crash(c2)
        assert is_new is True

    def test_empty_stack_trace_all_group_together(self) -> None:
        """Multiple crashes with empty stack traces all hash identically."""
        dedup = CrashDeduplicator()
        for i in range(4):
            dedup.ingest_crash(_make_crash(f"agent-{i:02d}", frames=[]))
        assert dedup.n_unique_crashes == 1
        clusters = dedup.queues().unique_crashes
        assert clusters[0].size == 4

    def test_cross_engine_same_function_grouped(self) -> None:
        """Same bug found by libFuzzer and AFL++ → same cluster."""
        libfuzzer_frame = "#0 0xAAAA in parse_chunk src/parser.c:42"
        afl_frame = "#0 0xBBBB in parse_chunk src/parser.c:42"
        c1 = _make_crash(
            "agent-00", frames=[libfuzzer_frame], engine=FuzzerEngine.LIBFUZZER
        )
        c2 = _make_crash(
            "agent-01", frames=[afl_frame], engine=FuzzerEngine.AFL_PLUS_PLUS
        )
        dedup = CrashDeduplicator()
        dedup.ingest_crash(c1)
        is_new, _ = dedup.ingest_crash(c2)
        assert is_new is False
        assert dedup.n_unique_crashes == 1

    def test_reset_clears_state(self) -> None:
        dedup = CrashDeduplicator()
        for i in range(3):
            dedup.ingest_crash(
                _make_crash(f"agent-{i:02d}", frames=[f"#0 f_{i} x.c:{i}"])
            )
        dedup.ingest_interesting_input(
            InterestingInput(agent_id="agent-00", input_bytes=b"\x00")
        )
        assert dedup.n_unique_crashes == 3
        assert dedup.n_interesting_inputs == 1
        dedup.reset()
        assert dedup.n_unique_crashes == 0
        assert dedup.n_interesting_inputs == 0

    def test_single_crash_singleton_cluster(self) -> None:
        dedup = CrashDeduplicator()
        crash = _make_crash("agent-00", frames=["#0 foo x.c:1"])
        is_new, cluster = dedup.ingest_crash(crash)
        assert is_new is True
        assert cluster.size == 1
        assert cluster.agent_ids == ("agent-00",)


# ---------------------------------------------------------------------------
# CrashReport stores full sanitizer output and execution trace
# ---------------------------------------------------------------------------


class TestFullOutputStorage:
    def test_sanitizer_output_stored_in_cluster(self) -> None:
        asan_output = (
            "=================================================================\n"
            "==12345==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x...\n"
            "READ of size 4 at 0x... thread T0\n"
            "    #0 0xAAAA in parse_chunk src/parser.c:42\n"
        )
        crash = _make_crash(
            "agent-00",
            frames=["#0 parse_chunk src/parser.c:42"],
            sanitizer_output=asan_output,
        )
        dedup = CrashDeduplicator()
        _, cluster = dedup.ingest_crash(crash)
        assert "AddressSanitizer" in cluster.sanitizer_output

    def test_execution_trace_stored_in_cluster(self) -> None:
        trace = "0xdeadbeef\n0xcafebabe\n0xfeedf00d"
        crash = _make_crash(
            "agent-00",
            frames=["#0 parse_chunk src/parser.c:42"],
            execution_trace=trace,
        )
        dedup = CrashDeduplicator()
        _, cluster = dedup.ingest_crash(crash)
        assert "0xdeadbeef" in cluster.execution_trace

    def test_trace_from_representative_preserved(self) -> None:
        """The representative's trace is stored; duplicates do not overwrite it."""
        trace_1 = "trace-from-agent-00"
        trace_2 = "trace-from-agent-01"
        frames = ["#0 foo x.c:1"]
        c1 = _make_crash("agent-00", frames=frames, execution_trace=trace_1)
        c2 = _make_crash("agent-01", frames=frames, execution_trace=trace_2)
        dedup = CrashDeduplicator()
        _, cluster = dedup.ingest_crash(c1)
        dedup.ingest_crash(c2)
        # Representative was c1; its trace is stored in the cluster
        assert cluster.execution_trace == trace_1


# ---------------------------------------------------------------------------
# deduplicate_crashes (functional API)
# ---------------------------------------------------------------------------


class TestDeduplicateCrashes:
    def test_empty_input(self) -> None:
        clusters = deduplicate_crashes([])
        assert clusters == []

    def test_all_duplicates_one_cluster(self) -> None:
        frames = ["#0 foo x.c:1", "#1 bar x.c:2"]
        crashes = [_make_crash(f"agent-{i:02d}", frames=frames) for i in range(5)]
        clusters = deduplicate_crashes(crashes)
        assert len(clusters) == 1
        assert clusters[0].size == 5

    def test_all_unique_n_clusters(self) -> None:
        crashes = [
            _make_crash("agent-00", frames=[f"#0 func_{i} x.c:{i}"]) for i in range(6)
        ]
        clusters = deduplicate_crashes(crashes)
        assert len(clusters) == 6
        assert all(c.size == 1 for c in clusters)

    def test_mixed_duplicates_and_unique(self) -> None:
        shared = ["#0 foo x.c:1"]
        crashes = [
            _make_crash("agent-00", frames=shared),
            _make_crash("agent-01", frames=shared),
            _make_crash("agent-02", frames=["#0 bar x.c:2"]),
        ]
        clusters = deduplicate_crashes(crashes)
        assert len(clusters) == 2
        sizes = sorted(c.size for c in clusters)
        assert sizes == [1, 2]

    def test_attribution_correct(self) -> None:
        shared = ["#0 foo x.c:1"]
        crashes = [
            _make_crash("agent-00", frames=shared),
            _make_crash("agent-01", frames=shared),
        ]
        clusters = deduplicate_crashes(crashes)
        assert len(clusters) == 1
        assert clusters[0].agent_set == frozenset({"agent-00", "agent-01"})

    def test_cluster_ids_start_at_1(self) -> None:
        crashes = [
            _make_crash("agent-00", frames=[f"#0 f_{i} x.c:{i}"]) for i in range(3)
        ]
        clusters = deduplicate_crashes(crashes)
        ids = [c.cluster_id for c in clusters]
        assert min(ids) == 1

    def test_custom_config_strict(self) -> None:
        """With depth=1, crashes sharing only the top frame are grouped."""
        cfg = DeduplicatorConfig(stack_frame_depth=1)
        shared_top = ["#0 parse_chunk x.c:42"]
        crashes = [
            _make_crash("agent-00", frames=shared_top + [f"#1 different_{i} x.c:{i}"])
            for i in range(4)
        ]
        clusters = deduplicate_crashes(crashes, config=cfg)
        assert len(clusters) == 1
        assert clusters[0].size == 4

    def test_returns_list_of_crash_clusters(self) -> None:
        crashes = [_make_crash("agent-00", frames=["#0 foo x.c:1"])]
        clusters = deduplicate_crashes(crashes)
        assert all(isinstance(c, CrashCluster) for c in clusters)
