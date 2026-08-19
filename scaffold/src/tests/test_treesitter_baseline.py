"""Tests for the plain-libFuzzer baseline (no LLM, no patching)."""

from __future__ import annotations

import json
from pathlib import Path

from parser_security_eval.treesitter import baseline, runtime, triage
from parser_security_eval.treesitter.models import (
    BugClass,
    GrammarTarget,
    Tier,
    TSBuildResult,
    TSCrash,
    TSFuzzResult,
)


def _target() -> GrammarTarget:
    return GrammarTarget(
        name="demo",
        repo_url="https://example/demo",
        tier=Tier.popular,
        language="Demo",
    )


def test_targets_from_results_sums_fuzz_walltime(tmp_path: Path) -> None:
    """targets_from_results reconstructs baseline targets with summed walltime."""
    results_dir = tmp_path / "results"
    results_dir.mkdir()

    # Write a JSONL with two iterations for the same grammar.
    jsonl_path = results_dir / "demo.jsonl"
    jsonl_path.write_text(
        json.dumps(
            {
                "grammar": "demo",
                "repo_url": "https://example/demo",
                "tier": "popular",
                "language": "Demo",
                "built": True,
                "fuzz": {"duration_seconds": 600},
                "crash": None,
            }
        )
        + "\n"
        + json.dumps(
            {
                "grammar": "demo",
                "repo_url": "https://example/demo",
                "tier": "popular",
                "language": "Demo",
                "built": True,
                "fuzz": {"duration_seconds": 400},
                "crash": None,
            }
        )
        + "\n"
    )

    targets = baseline.targets_from_results(results_dir)
    assert len(targets) == 1
    assert targets[0].target.name == "demo"
    assert targets[0].fuzz_seconds == 1000  # 600 + 400
    assert targets[0].target.tier == Tier.popular


def test_targets_from_results_skips_build_failure(tmp_path: Path) -> None:
    """Grammars with only build failures (built=False) are skipped."""
    results_dir = tmp_path / "results"
    results_dir.mkdir()

    jsonl_path = results_dir / "broken.jsonl"
    jsonl_path.write_text(
        json.dumps(
            {
                "grammar": "broken",
                "repo_url": "https://example/broken",
                "tier": "less-popular",
                "language": "Broken",
                "built": False,
                "notes": "build failed",
            }
        )
        + "\n"
    )

    targets = baseline.targets_from_results(results_dir)
    assert len(targets) == 0


def test_targets_from_results_skips_zero_walltime(tmp_path: Path) -> None:
    """Grammars with zero total fuzz walltime are skipped."""
    results_dir = tmp_path / "results"
    results_dir.mkdir()

    jsonl_path = results_dir / "idle.jsonl"
    jsonl_path.write_text(
        json.dumps(
            {
                "grammar": "idle",
                "repo_url": "https://example/idle",
                "tier": "popular",
                "language": "Idle",
                "built": True,
                "fuzz": {"duration_seconds": 0},
            }
        )
        + "\n"
    )

    targets = baseline.targets_from_results(results_dir)
    assert len(targets) == 0


def test_targets_from_results_requires_at_least_one_successful_build(
    tmp_path: Path,
) -> None:
    """A grammar with some failed and some successful builds is included."""
    results_dir = tmp_path / "results"
    results_dir.mkdir()

    jsonl_path = results_dir / "mixed.jsonl"
    jsonl_path.write_text(
        json.dumps(
            {
                "grammar": "mixed",
                "repo_url": "https://example/mixed",
                "tier": "popular",
                "language": "Mixed",
                "built": False,
            }
        )
        + "\n"
        + json.dumps(
            {
                "grammar": "mixed",
                "repo_url": "https://example/mixed",
                "tier": "popular",
                "language": "Mixed",
                "built": True,
                "fuzz": {"duration_seconds": 100},
            }
        )
        + "\n"
    )

    targets = baseline.targets_from_results(results_dir)
    assert len(targets) == 1
    assert targets[0].fuzz_seconds == 100


def test_targets_from_results_tier_enum_parsing(tmp_path: Path) -> None:
    """Tier values in JSONL (string) are parsed as Tier enums."""
    results_dir = tmp_path / "results"
    results_dir.mkdir()

    for tier_str, tier_enum in [
        ("popular", Tier.popular),
        ("less-popular", Tier.less_popular),
    ]:
        jsonl_path = results_dir / f"grammar_{tier_str}.jsonl"
        jsonl_path.write_text(
            json.dumps(
                {
                    "grammar": f"grammar_{tier_str}",
                    "repo_url": "https://example/g",
                    "tier": tier_str,
                    "language": "Test",
                    "built": True,
                    "fuzz": {"duration_seconds": 100},
                }
            )
            + "\n"
        )

    targets = baseline.targets_from_results(results_dir)
    assert len(targets) == 2
    found = {t.target.name: t.target.tier for t in targets}
    assert found[f"grammar_{tier_str}"] == tier_enum


def test_classify_without_replay_timeout(tmp_path: Path) -> None:
    """Crash file with timeout- prefix returns a string containing 'timeout'."""
    crash_file = tmp_path / "timeout-123abc"
    crash_file.write_bytes(b"")

    result = baseline._classify_without_replay(crash_file)
    assert result is not None
    assert "timeout" in result.lower()


def test_classify_without_replay_oom(tmp_path: Path) -> None:
    """Crash file with oom- prefix returns a string containing 'out-of-memory'."""
    crash_file = tmp_path / "oom-xyz"
    crash_file.write_bytes(b"")

    result = baseline._classify_without_replay(crash_file)
    assert result is not None
    assert "out-of-memory" in result.lower()


def test_classify_without_replay_regular_crash(tmp_path: Path) -> None:
    """Crash file with crash- prefix returns None (needs replay)."""
    crash_file = tmp_path / "crash-abc123"
    crash_file.write_bytes(b"")

    result = baseline._classify_without_replay(crash_file)
    assert result is None


def test_distinct_crashes_deduplicates_by_stack_hash(
    tmp_path: Path, monkeypatch
) -> None:
    """Three artifacts with two distinct stack hashes -> two distinct crashes."""
    binary = tmp_path / "fuzz"
    binary.write_bytes(b"fake binary")

    crash_files = [
        tmp_path / "crash-1",
        tmp_path / "crash-2",
        tmp_path / "crash-3",
    ]
    for cf in crash_files:
        cf.write_bytes(b"crash data")

    # Mock runtime.reproduce to always return success
    call_count = {"n": 0}

    def fake_reproduce(bin_path: Path, crash_path: Path) -> tuple[int, str]:
        call_count["n"] += 1
        return 1, "ERROR: libFuzzer: crash\n    #0 frame\n"

    monkeypatch.setattr(runtime, "reproduce", fake_reproduce)

    # Mock triage.triage to return crashes with controlled stack hashes.
    # Crashes 1 and 2 share a hash; crash 3 is different.
    def fake_triage(report: str, crash_input: bytes, crash_file: str = "") -> TSCrash:
        if "crash-1" in crash_file or "crash-2" in crash_file:
            return TSCrash(
                bug_class=BugClass.heap_buffer_overflow,
                stack_hash="aaaa",
                asan_summary="heap-buffer-overflow",
            )
        else:
            return TSCrash(
                bug_class=BugClass.segv,
                stack_hash="bbbb",
                asan_summary="SEGV",
            )

    monkeypatch.setattr(triage, "triage", fake_triage)

    crashes, capped = baseline._distinct_crashes(binary, crash_files)

    assert len(crashes) == 2  # Two distinct hashes
    assert crashes[0].stack_hash == "aaaa"
    assert crashes[1].stack_hash == "bbbb"
    assert capped is False
    assert call_count["n"] == 3  # All three reproduced (no timeout/oom classification)


def test_distinct_crashes_skips_timeout_and_oom_without_replay(
    tmp_path: Path, monkeypatch
) -> None:
    """timeout-/oom- crashes classified without calling runtime.reproduce."""
    binary = tmp_path / "fuzz"
    binary.write_bytes(b"fake binary")

    crash_files = [
        tmp_path / "timeout-1",
        tmp_path / "oom-2",
        tmp_path / "crash-3",
    ]
    for cf in crash_files:
        cf.write_bytes(b"")

    # Record calls to reproduce; should only be called once (for crash-3).
    reproduce_calls = []

    def fake_reproduce(bin_path: Path, crash_path: Path) -> tuple[int, str]:
        reproduce_calls.append(str(crash_path))
        return 1, "ERROR: heap-buffer-overflow\n    #0 frame\n"

    monkeypatch.setattr(runtime, "reproduce", fake_reproduce)

    def fake_triage(report: str, crash_input: bytes, crash_file: str = "") -> TSCrash:
        # Return distinct stack hashes so dedup doesn't collapse them
        if "timeout" in crash_file:
            return TSCrash(
                bug_class=BugClass.timeout,
                stack_hash="timeout_hash",
                asan_summary="timeout",
            )
        elif "oom" in crash_file:
            return TSCrash(
                bug_class=BugClass.oom,
                stack_hash="oom_hash",
                asan_summary="oom",
            )
        else:
            return TSCrash(
                bug_class=BugClass.heap_buffer_overflow,
                stack_hash="crash_hash",
                asan_summary="heap-buffer-overflow",
            )

    monkeypatch.setattr(triage, "triage", fake_triage)

    crashes, capped = baseline._distinct_crashes(binary, crash_files)

    assert len(crashes) == 3
    assert capped is False
    # Only crash-3 should have called reproduce
    assert len(reproduce_calls) == 1
    assert "crash-3" in reproduce_calls[0]


def test_distinct_crashes_capped_when_exceeds_max(tmp_path: Path, monkeypatch) -> None:
    """If artifact count exceeds MAX_ARTIFACTS_TRIAGED, capped=True."""
    binary = tmp_path / "fuzz"
    binary.write_bytes(b"fake binary")

    # Create more crash files than MAX_ARTIFACTS_TRIAGED.
    crash_files = [tmp_path / f"crash-{i}" for i in range(10)]
    for cf in crash_files:
        cf.write_bytes(b"")

    # Temporarily set MAX_ARTIFACTS_TRIAGED to a small value.
    monkeypatch.setattr(baseline, "MAX_ARTIFACTS_TRIAGED", 3)

    def fake_reproduce(bin_path: Path, crash_path: Path) -> tuple[int, str]:
        return 1, "ERROR: crash\n    #0 frame\n"

    monkeypatch.setattr(runtime, "reproduce", fake_reproduce)

    def fake_triage(report: str, crash_input: bytes, crash_file: str = "") -> TSCrash:
        return TSCrash(
            bug_class=BugClass.heap_buffer_overflow,
            stack_hash=f"hash_{crash_file}",
        )

    monkeypatch.setattr(triage, "triage", fake_triage)

    crashes, capped = baseline._distinct_crashes(binary, crash_files)

    assert len(crashes) == 3  # Stopped at MAX_ARTIFACTS_TRIAGED
    assert capped is True


def test_run_baseline_grammar_happy_path(tmp_path: Path, monkeypatch) -> None:
    """Happy path: build succeeds, fuzzing finds distinct crashes."""
    cache = tmp_path / "cache"
    out_dir = tmp_path / "out"
    target = _target()

    monkeypatch.setattr(runtime, "check_toolchain", lambda **k: None)
    monkeypatch.setattr(runtime, "ensure_runtime", lambda c: tmp_path / "rt")
    monkeypatch.setattr(runtime, "ensure_grammar", lambda t, c: tmp_path / "grammar")
    monkeypatch.setattr(runtime, "gather_seeds", lambda *a, **k: 0)
    monkeypatch.setattr(
        runtime,
        "build",
        lambda spec: TSBuildResult(
            built=True,
            binary_path=str(tmp_path / "fuzz"),
        ),
    )

    # Mock LibFuzzerRunner.run to return fuzz stats and two crash files.
    def fake_runner_run(self: runtime.LibFuzzerRunner, duration: int):  # noqa: ANN001
        self.crashes_dir.mkdir(parents=True, exist_ok=True)
        c1 = self.crashes_dir / "crash-1"
        c2 = self.crashes_dir / "crash-2"
        c1.write_bytes(b"crash1")
        c2.write_bytes(b"crash2")
        return TSFuzzResult(duration_seconds=duration, crashes_found=2), [c1, c2]

    monkeypatch.setattr(runtime.LibFuzzerRunner, "run", fake_runner_run)

    # Mock _distinct_crashes to return two distinct crashes.
    crashes = [
        TSCrash(
            bug_class=BugClass.heap_buffer_overflow,
            stack_hash="hash1",
            asan_summary="overflow",
        ),
        TSCrash(
            bug_class=BugClass.segv,
            stack_hash="hash2",
            asan_summary="segv",
        ),
    ]
    monkeypatch.setattr(baseline, "_distinct_crashes", lambda *a: (crashes, False))

    iterations = baseline.run_baseline_grammar(
        target,
        fuzz_seconds=100,
        cache_dir=cache,
        out_dir=out_dir,
    )

    # Should emit one iteration per distinct crash.
    assert len(iterations) == 2
    assert iterations[0].crash is not None
    assert iterations[1].crash is not None
    assert iterations[0].fix is None
    assert iterations[1].fix is None
    assert iterations[0].built is True
    assert iterations[1].built is True
    assert iterations[0].grammar == "demo"
    assert iterations[1].grammar == "demo"

    # Fuzz stats attached only to first record.
    assert iterations[0].fuzz is not None
    assert iterations[0].fuzz.duration_seconds == 100
    assert iterations[1].fuzz is None

    # Check JSONL file written.
    jsonl_path = out_dir / "demo.jsonl"
    assert jsonl_path.exists()
    lines = jsonl_path.read_text().strip().splitlines()
    assert len(lines) == 2
    rec0 = json.loads(lines[0])
    rec1 = json.loads(lines[1])
    assert rec0["crash"] is not None
    assert rec0["fuzz"] is not None
    assert rec1["crash"] is not None
    assert rec1["fuzz"] is None


def test_run_baseline_grammar_no_crashes(tmp_path: Path, monkeypatch) -> None:
    """Fuzzing finds no crashes -> single record with crash=None."""
    cache = tmp_path / "cache"
    out_dir = tmp_path / "out"
    target = _target()

    monkeypatch.setattr(runtime, "check_toolchain", lambda **k: None)
    monkeypatch.setattr(runtime, "ensure_runtime", lambda c: tmp_path / "rt")
    monkeypatch.setattr(runtime, "ensure_grammar", lambda t, c: tmp_path / "grammar")
    monkeypatch.setattr(runtime, "gather_seeds", lambda *a, **k: 0)
    monkeypatch.setattr(
        runtime,
        "build",
        lambda spec: TSBuildResult(
            built=True,
            binary_path=str(tmp_path / "fuzz"),
        ),
    )

    def fake_runner_run(self: runtime.LibFuzzerRunner, duration: int):  # noqa: ANN001
        return TSFuzzResult(duration_seconds=duration, crashes_found=0), []

    monkeypatch.setattr(runtime.LibFuzzerRunner, "run", fake_runner_run)
    monkeypatch.setattr(baseline, "_distinct_crashes", lambda *a: ([], False))

    iterations = baseline.run_baseline_grammar(
        target,
        fuzz_seconds=50,
        cache_dir=cache,
        out_dir=out_dir,
    )

    # Single iteration with no crash.
    assert len(iterations) == 1
    assert iterations[0].crash is None
    assert iterations[0].fuzz is not None
    assert iterations[0].built is True
    assert "no crash" in iterations[0].notes.lower()


def test_run_baseline_grammar_build_failure(tmp_path: Path, monkeypatch) -> None:
    """Build fails -> single record with built=False."""
    cache = tmp_path / "cache"
    out_dir = tmp_path / "out"
    target = _target()

    monkeypatch.setattr(runtime, "check_toolchain", lambda **k: None)
    monkeypatch.setattr(runtime, "ensure_runtime", lambda c: tmp_path / "rt")
    monkeypatch.setattr(runtime, "ensure_grammar", lambda t, c: tmp_path / "grammar")
    monkeypatch.setattr(
        runtime,
        "build",
        lambda spec: TSBuildResult(
            built=False,
            compile_errors="undefined symbol 'tree_sitter_demo'",
        ),
    )

    iterations = baseline.run_baseline_grammar(
        target,
        fuzz_seconds=100,
        cache_dir=cache,
        out_dir=out_dir,
    )

    # Single iteration, build failed.
    assert len(iterations) == 1
    assert iterations[0].built is False
    assert iterations[0].fuzz is None
    assert iterations[0].crash is None
    assert "build failed" in iterations[0].notes.lower()
    assert "undefined symbol" in iterations[0].notes

    # JSONL written.
    jsonl_path = out_dir / "demo.jsonl"
    assert jsonl_path.exists()
    lines = jsonl_path.read_text().strip().splitlines()
    assert len(lines) == 1
    rec = json.loads(lines[0])
    assert rec["built"] is False


def test_run_baseline_grammar_capped_note(tmp_path: Path, monkeypatch) -> None:
    """Capping note appears only on first iteration."""
    cache = tmp_path / "cache"
    out_dir = tmp_path / "out"
    target = _target()

    monkeypatch.setattr(runtime, "check_toolchain", lambda **k: None)
    monkeypatch.setattr(runtime, "ensure_runtime", lambda c: tmp_path / "rt")
    monkeypatch.setattr(runtime, "ensure_grammar", lambda t, c: tmp_path / "grammar")
    monkeypatch.setattr(runtime, "gather_seeds", lambda *a, **k: 0)
    monkeypatch.setattr(
        runtime,
        "build",
        lambda spec: TSBuildResult(
            built=True,
            binary_path=str(tmp_path / "fuzz"),
        ),
    )

    def fake_runner_run(self: runtime.LibFuzzerRunner, duration: int):  # noqa: ANN001
        self.crashes_dir.mkdir(parents=True, exist_ok=True)
        crashes = [self.crashes_dir / f"crash-{i}" for i in range(2)]
        for c in crashes:
            c.write_bytes(b"")
        return TSFuzzResult(duration_seconds=duration, crashes_found=2), crashes

    monkeypatch.setattr(runtime.LibFuzzerRunner, "run", fake_runner_run)

    crashes = [
        TSCrash(bug_class=BugClass.heap_buffer_overflow, stack_hash="h1"),
        TSCrash(bug_class=BugClass.segv, stack_hash="h2"),
    ]
    monkeypatch.setattr(baseline, "_distinct_crashes", lambda *a: (crashes, True))

    iterations = baseline.run_baseline_grammar(
        target,
        fuzz_seconds=100,
        cache_dir=cache,
        out_dir=out_dir,
    )

    assert len(iterations) == 2
    # Capping note on first iteration.
    assert "capped" in iterations[0].notes.lower()
    # No capping note on second iteration.
    assert "capped" not in iterations[1].notes.lower()
