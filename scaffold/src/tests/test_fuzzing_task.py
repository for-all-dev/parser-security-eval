"""Tests for the live fuzzing Inspect-AI task.

No Docker or real model required — all sandbox calls are mocked.
"""

from __future__ import annotations

import stat
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from parser_security_eval.models.fuzzing import (
    CoverageDelta,
    FuzzingResult,
    HarnessRecord,
    LiveFuzzingSessionResult,
)
from parser_security_eval.tasks.fuzzing import (
    MAX_REPAIR_ITERS,
    CYCLE_CAP_SECONDS,
    RED_TEAM_LIVE_PROMPT,
    _build_session_result,
    _compute_score,
    _extract_stack_hash,
    _make_add_seed_tool,
    _make_compile_harness_tool,
    _make_get_crash_info_tool,
    _make_get_fuzzer_stats_tool,
    _make_refine_harness_tool,
    _make_start_fuzzing_tool,
    _make_write_harness_tool,
    live_fuzzing,
    live_fuzzing_scorer,
    live_fuzzing_solver,
    load_live_fuzzing_dataset,
    load_session_memory,
    save_session_memory,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

MINIMAL_METADATA = """\
name: testparser
format_type: binary
language: c
ossfuzz_project: null
fuzz_targets:
  - fuzz_testparser
cwe_hints:
  - CWE-125
  - CWE-787
has_corpus: false
has_dictionary: false
"""

MINIMAL_BUILD_SH = """\
#!/bin/bash -eu
cd /src/testparser
make -j$(nproc)
$CXX $CXXFLAGS -o $OUT/fuzz_testparser fuzz.cc -L. -ltestparser $LIB_FUZZING_ENGINE
"""

MINIMAL_HARNESS = """\
#include <stdint.h>
#include <stddef.h>
#include "testparser.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    testparser_parse(data, size);
    return 0;
}
"""

ASAN_CRASH_OUTPUT = """\
=================================================================
==12345==ERROR: AddressSanitizer: heap-buffer-overflow on address 0xdeadbeef
READ of size 4 at 0xdeadbeef
    #0 0x7f1234 in parse_chunk /src/testparser/parser.c:42
    #1 0x7f5678 in testparser_parse /src/testparser/api.c:10
    #2 0x7f9abc in LLVMFuzzerTestOneInput /src/harness_testparser.cc:8
SUMMARY: AddressSanitizer: heap-buffer-overflow
"""


@pytest.fixture
def target_dir(tmp_path: Path) -> Path:
    """Create a minimal target directory for testing."""
    d = tmp_path / "testparser"
    d.mkdir()
    (d / "metadata.yaml").write_text(MINIMAL_METADATA)
    build_sh = d / "build.sh"
    build_sh.write_text(MINIMAL_BUILD_SH)
    build_sh.chmod(build_sh.stat().st_mode | stat.S_IXUSR)
    (d / "Dockerfile").write_text("FROM gcr.io/oss-fuzz-base/base-builder\n")
    (d / "testparser.h").write_text(
        "void testparser_parse(const uint8_t *data, size_t size);\n"
    )
    return d


@pytest.fixture
def fresh_session_state() -> dict:
    """Return a fresh session_state dict."""
    return {
        "pending_harness": "",
        "harness_written": False,
        "compiled": False,
        "compile_errors": "",
        "fuzz_target": "",
        "repair_iterations": 0,
        "last_harness_first_try": False,
        "seeds_added": [],
        "all_crash_hashes": {},
        "last_fuzz_result": None,
        "cycle_count": 0,
        "refinement_log": [],
        "harness_records": [],
        "fuzzing_cycles": [],
        "current_entry_point": "",
    }


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class TestHarnessRecord:
    def test_first_try_success_false_by_default(self) -> None:
        r = HarnessRecord(
            entry_point="parse_chunk",
            code="int LLVMFuzzerTestOneInput(...) {}",
            compile_success=True,
            repair_iterations=2,
        )
        assert r.first_try_success is False

    def test_first_try_success_true_when_set(self) -> None:
        r = HarnessRecord(
            entry_point="parse_chunk",
            code="int LLVMFuzzerTestOneInput(...) {}",
            compile_success=True,
            repair_iterations=0,
            first_try_success=True,
        )
        assert r.first_try_success is True


class TestFuzzingResult:
    def test_defaults(self) -> None:
        r = FuzzingResult(duration_seconds=300)
        assert r.crashes_found == 0
        assert r.timed_out is False
        assert r.oom_killed is False
        assert r.unique_crash_hashes == {}


class TestCoverageDelta:
    def test_line_delta(self) -> None:
        d = CoverageDelta(line_pct_before=10.0, line_pct_after=25.0)
        assert d.line_delta == pytest.approx(15.0)

    def test_branch_delta(self) -> None:
        d = CoverageDelta(branch_pct_before=5.0, branch_pct_after=8.5)
        assert d.branch_delta == pytest.approx(3.5)


class TestLiveFuzzingSessionResult:
    def test_first_try_rate_zero_when_no_harnesses(self) -> None:
        r = LiveFuzzingSessionResult(
            target_name="x", engine="libfuzzer", total_harnesses_attempted=0
        )
        assert r.first_try_compile_rate == 0.0

    def test_first_try_rate_calculated(self) -> None:
        r = LiveFuzzingSessionResult(
            target_name="x",
            engine="libfuzzer",
            total_harnesses_attempted=4,
            harnesses_compiled_first_try=3,
        )
        assert r.first_try_compile_rate == pytest.approx(0.75)

    def test_mean_repair_iterations(self) -> None:
        r = LiveFuzzingSessionResult(
            target_name="x",
            engine="libfuzzer",
            total_harnesses_attempted=2,
            total_repair_iterations=6,
        )
        assert r.mean_repair_iterations == pytest.approx(3.0)


# ---------------------------------------------------------------------------
# _extract_stack_hash
# ---------------------------------------------------------------------------


class TestExtractStackHash:
    def test_consistent_for_same_output(self) -> None:
        h1 = _extract_stack_hash(ASAN_CRASH_OUTPUT)
        h2 = _extract_stack_hash(ASAN_CRASH_OUTPUT)
        assert h1 == h2

    def test_different_for_different_stacks(self) -> None:
        other = ASAN_CRASH_OUTPUT.replace("parse_chunk", "different_func")
        assert _extract_stack_hash(ASAN_CRASH_OUTPUT) != _extract_stack_hash(other)

    def test_returns_string(self) -> None:
        assert isinstance(_extract_stack_hash(ASAN_CRASH_OUTPUT), str)

    def test_fallback_for_no_frames(self) -> None:
        """When no stack frames are found, hash the full output."""
        h = _extract_stack_hash("no frames here")
        assert isinstance(h, str)
        assert len(h) == 16  # sha256 truncated to 16 chars

    def test_top_n_frames_respected(self) -> None:
        """Hash should use at most top_n frames."""
        h_top1 = _extract_stack_hash(ASAN_CRASH_OUTPUT, top_n=1)
        h_top2 = _extract_stack_hash(ASAN_CRASH_OUTPUT, top_n=2)
        # Different top_n may produce different hashes (first frame vs first 2)
        assert isinstance(h_top1, str)
        assert isinstance(h_top2, str)


# ---------------------------------------------------------------------------
# Tool: write_harness
# ---------------------------------------------------------------------------


class TestWriteHarnessTool:
    @pytest.mark.asyncio
    async def test_accepts_valid_harness(self, fresh_session_state: dict) -> None:
        t = _make_write_harness_tool(fresh_session_state)
        result = await t(code=MINIMAL_HARNESS)
        assert "Harness staged" in result
        assert fresh_session_state["harness_written"] is True
        assert fresh_session_state["compiled"] is False

    @pytest.mark.asyncio
    async def test_rejects_missing_entry_point(self, fresh_session_state: dict) -> None:
        t = _make_write_harness_tool(fresh_session_state)
        result = await t(code="int main() { return 0; }")
        assert "ERROR" in result
        assert fresh_session_state["harness_written"] is False

    @pytest.mark.asyncio
    async def test_resets_compiled_flag(self, fresh_session_state: dict) -> None:
        fresh_session_state["compiled"] = True
        t = _make_write_harness_tool(fresh_session_state)
        await t(code=MINIMAL_HARNESS)
        assert fresh_session_state["compiled"] is False


# ---------------------------------------------------------------------------
# Tool: compile_harness
# ---------------------------------------------------------------------------


class TestCompileHarnessTool:
    def _make_mock_sandbox(self, rc: int = 0) -> MagicMock:
        sandbox = MagicMock()
        sandbox.exec = AsyncMock(
            return_value=(rc, "", "error output" if rc != 0 else "")
        )
        sandbox.copy_in = AsyncMock(return_value=None)
        return sandbox

    @pytest.mark.asyncio
    async def test_requires_harness_first(self, fresh_session_state: dict) -> None:
        sandbox = self._make_mock_sandbox()
        t = _make_compile_harness_tool(
            sandbox, fresh_session_state, "testparser", "libfuzzer", "address"
        )
        result = await t()
        assert "No harness written" in result

    @pytest.mark.asyncio
    async def test_success_sets_compiled_flag(self, fresh_session_state: dict) -> None:
        fresh_session_state["harness_written"] = True
        fresh_session_state["pending_harness"] = MINIMAL_HARNESS
        sandbox = self._make_mock_sandbox(rc=0)
        t = _make_compile_harness_tool(
            sandbox, fresh_session_state, "testparser", "libfuzzer", "address"
        )
        result = await t()
        assert "succeeded" in result
        assert fresh_session_state["compiled"] is True
        assert fresh_session_state["fuzz_target"] == "harness_testparser_agent"

    @pytest.mark.asyncio
    async def test_failure_increments_repair_count(
        self, fresh_session_state: dict
    ) -> None:
        fresh_session_state["harness_written"] = True
        fresh_session_state["pending_harness"] = MINIMAL_HARNESS
        sandbox = self._make_mock_sandbox(rc=1)
        t = _make_compile_harness_tool(
            sandbox, fresh_session_state, "testparser", "libfuzzer", "address"
        )
        await t()
        assert fresh_session_state["repair_iterations"] == 1
        assert fresh_session_state["compiled"] is False

    @pytest.mark.asyncio
    async def test_failure_shows_remaining_budget(
        self, fresh_session_state: dict
    ) -> None:
        fresh_session_state["harness_written"] = True
        fresh_session_state["pending_harness"] = MINIMAL_HARNESS
        sandbox = self._make_mock_sandbox(rc=1)
        t = _make_compile_harness_tool(
            sandbox, fresh_session_state, "testparser", "libfuzzer", "address"
        )
        result = await t()
        assert "repair attempts remaining" in result

    @pytest.mark.asyncio
    async def test_first_try_flag_set_on_success(
        self, fresh_session_state: dict
    ) -> None:
        fresh_session_state["harness_written"] = True
        fresh_session_state["pending_harness"] = MINIMAL_HARNESS
        fresh_session_state["repair_iterations"] = 0
        sandbox = self._make_mock_sandbox(rc=0)
        t = _make_compile_harness_tool(
            sandbox, fresh_session_state, "testparser", "libfuzzer", "address"
        )
        await t()
        assert fresh_session_state["last_harness_first_try"] is True

    @pytest.mark.asyncio
    async def test_not_first_try_after_repairs(self, fresh_session_state: dict) -> None:
        fresh_session_state["harness_written"] = True
        fresh_session_state["pending_harness"] = MINIMAL_HARNESS
        fresh_session_state["repair_iterations"] = 2
        sandbox = self._make_mock_sandbox(rc=0)
        t = _make_compile_harness_tool(
            sandbox, fresh_session_state, "testparser", "libfuzzer", "address"
        )
        await t()
        assert fresh_session_state["last_harness_first_try"] is False


# ---------------------------------------------------------------------------
# Tool: add_seed
# ---------------------------------------------------------------------------


class TestAddSeedTool:
    def _make_sandbox(self) -> MagicMock:
        sandbox = MagicMock()
        sandbox.exec = AsyncMock(return_value=(0, "", ""))
        sandbox.copy_in = AsyncMock(return_value=None)
        return sandbox

    @pytest.mark.asyncio
    async def test_valid_hex_seed(self, fresh_session_state: dict) -> None:
        sandbox = self._make_sandbox()
        t = _make_add_seed_tool(sandbox, fresh_session_state)
        result = await t(data_hex="504b0304", filename="zip_header")
        assert "added" in result
        assert len(fresh_session_state["seeds_added"]) == 1

    @pytest.mark.asyncio
    async def test_invalid_hex_returns_error(self, fresh_session_state: dict) -> None:
        sandbox = self._make_sandbox()
        t = _make_add_seed_tool(sandbox, fresh_session_state)
        result = await t(data_hex="GGGG", filename="bad")
        assert "Invalid hex" in result

    @pytest.mark.asyncio
    async def test_filename_sanitized(self, fresh_session_state: dict) -> None:
        sandbox = self._make_sandbox()
        t = _make_add_seed_tool(sandbox, fresh_session_state)
        result = await t(data_hex="00", filename="../../etc/passwd")
        assert "added" in result
        # Filename should be sanitized (no slashes)
        added_name = fresh_session_state["seeds_added"][0]
        assert "/" not in added_name

    @pytest.mark.asyncio
    async def test_multiple_seeds_accumulate(self, fresh_session_state: dict) -> None:
        sandbox = self._make_sandbox()
        t = _make_add_seed_tool(sandbox, fresh_session_state)
        await t(data_hex="01", filename="seed1")
        await t(data_hex="02", filename="seed2")
        assert len(fresh_session_state["seeds_added"]) == 2


# ---------------------------------------------------------------------------
# Tool: start_fuzzing
# ---------------------------------------------------------------------------


class TestStartFuzzingTool:
    def _make_sandbox_with_campaign(
        self,
        crash_files: list[Path] | None = None,
        execs: float = 1000.0,
        corpus_size: int = 10,
    ) -> MagicMock:
        from parser_security_eval.sandbox.campaign import CampaignResult, FuzzingStats

        sandbox = MagicMock()
        sandbox.exec = AsyncMock(return_value=(1, "", ""))  # crash re-run → exit 1
        stats = FuzzingStats(
            execs_per_sec=execs,
            corpus_size=corpus_size,
            crashes_found=len(crash_files or []),
            engine="libfuzzer",
        )
        campaign_result = CampaignResult(
            target_name="testparser",
            engine="libfuzzer",
            duration_seconds=60,
            crash_files=crash_files or [],
            coverage_raw_profiles=[],
            stats=stats,
        )
        mock_campaign = AsyncMock()
        mock_campaign.run = AsyncMock(return_value=campaign_result)
        return sandbox, mock_campaign

    @pytest.mark.asyncio
    async def test_requires_compiled_harness(self, fresh_session_state: dict) -> None:
        sandbox = MagicMock()
        t = _make_start_fuzzing_tool(sandbox, fresh_session_state)
        result = await t(duration_seconds=60)
        assert "not compiled" in result.lower()

    @pytest.mark.asyncio
    async def test_caps_duration(self, fresh_session_state: dict) -> None:
        """Duration above CYCLE_CAP_SECONDS should be clamped."""
        fresh_session_state["compiled"] = True
        fresh_session_state["fuzz_target"] = "harness_testparser_agent"

        sandbox, mock_campaign = self._make_sandbox_with_campaign()

        captured_duration: list[int] = []

        class CaptureCampaign:
            def __init__(
                self,
                sandbox: object,
                fuzz_target: str,
                duration_seconds: int,
                corpus_dir: str,
            ) -> None:
                captured_duration.append(duration_seconds)

            async def run(self) -> object:
                from parser_security_eval.sandbox.campaign import (
                    CampaignResult,
                    FuzzingStats,
                )

                return CampaignResult(
                    target_name="t",
                    engine="libfuzzer",
                    duration_seconds=captured_duration[0],
                    crash_files=[],
                    coverage_raw_profiles=[],
                    stats=FuzzingStats(engine="libfuzzer"),
                )

        with patch(
            "parser_security_eval.tasks.fuzzing.FuzzingCampaign",
            side_effect=CaptureCampaign,
        ):
            t = _make_start_fuzzing_tool(sandbox, fresh_session_state)
            await t(duration_seconds=9999)

        assert captured_duration[0] == CYCLE_CAP_SECONDS

    @pytest.mark.asyncio
    async def test_increments_cycle_count(self, fresh_session_state: dict) -> None:
        fresh_session_state["compiled"] = True
        fresh_session_state["fuzz_target"] = "harness_testparser_agent"

        from parser_security_eval.sandbox.campaign import CampaignResult, FuzzingStats

        mock_result = CampaignResult(
            target_name="testparser",
            engine="libfuzzer",
            duration_seconds=60,
            crash_files=[],
            coverage_raw_profiles=[],
            stats=FuzzingStats(engine="libfuzzer"),
        )
        sandbox = MagicMock()

        with patch(
            "parser_security_eval.tasks.fuzzing.FuzzingCampaign"
        ) as MockCampaign:
            mock_instance = AsyncMock()
            mock_instance.run = AsyncMock(return_value=mock_result)
            MockCampaign.return_value = mock_instance

            t = _make_start_fuzzing_tool(sandbox, fresh_session_state)
            await t(duration_seconds=60)

        assert fresh_session_state["cycle_count"] == 1


# ---------------------------------------------------------------------------
# Tool: get_fuzzer_stats
# ---------------------------------------------------------------------------


class TestGetFuzzerStatsTool:
    @pytest.mark.asyncio
    async def test_no_run_yet(self, fresh_session_state: dict) -> None:
        t = _make_get_fuzzer_stats_tool(fresh_session_state)
        result = await t()
        assert "No fuzzing run completed" in result

    @pytest.mark.asyncio
    async def test_shows_stats_after_run(self, fresh_session_state: dict) -> None:
        fresh_session_state["last_fuzz_result"] = FuzzingResult(
            duration_seconds=300,
            execs_per_sec=2500.0,
            corpus_size=42,
            crashes_found=3,
        )
        fresh_session_state["cycle_count"] = 1
        fresh_session_state["all_crash_hashes"] = {"a": "x", "b": "y", "c": "z"}

        t = _make_get_fuzzer_stats_tool(fresh_session_state)
        result = await t()
        assert "2500" in result
        assert "42" in result
        assert "3" in result


# ---------------------------------------------------------------------------
# Tool: get_crash_info
# ---------------------------------------------------------------------------


class TestGetCrashInfoTool:
    @pytest.mark.asyncio
    async def test_no_crashes(self, fresh_session_state: dict) -> None:
        t = _make_get_crash_info_tool(fresh_session_state)
        result = await t(crash_id="abc123")
        assert "No crashes" in result

    @pytest.mark.asyncio
    async def test_returns_known_crash(self, fresh_session_state: dict) -> None:
        fresh_session_state["all_crash_hashes"] = {"abc123": ASAN_CRASH_OUTPUT}
        t = _make_get_crash_info_tool(fresh_session_state)
        result = await t(crash_id="abc123")
        assert "heap-buffer-overflow" in result

    @pytest.mark.asyncio
    async def test_unknown_id_lists_available(self, fresh_session_state: dict) -> None:
        fresh_session_state["all_crash_hashes"] = {"xyz": "output"}
        t = _make_get_crash_info_tool(fresh_session_state)
        result = await t(crash_id="unknown")
        assert "xyz" in result


# ---------------------------------------------------------------------------
# Tool: refine_harness
# ---------------------------------------------------------------------------


class TestRefineHarnessTool:
    @pytest.mark.asyncio
    async def test_accepts_valid_refinement(self, fresh_session_state: dict) -> None:
        t = _make_refine_harness_tool(fresh_session_state)
        result = await t(code=MINIMAL_HARNESS, reason="fixed null check")
        assert "refined" in result
        assert fresh_session_state["pending_harness"] == MINIMAL_HARNESS
        assert fresh_session_state["repair_iterations"] == 0

    @pytest.mark.asyncio
    async def test_rejects_missing_entry_point(self, fresh_session_state: dict) -> None:
        t = _make_refine_harness_tool(fresh_session_state)
        result = await t(code="void foo() {}", reason="test")
        assert "ERROR" in result

    @pytest.mark.asyncio
    async def test_resets_compiled_flag(self, fresh_session_state: dict) -> None:
        fresh_session_state["compiled"] = True
        t = _make_refine_harness_tool(fresh_session_state)
        await t(code=MINIMAL_HARNESS)
        assert fresh_session_state["compiled"] is False

    @pytest.mark.asyncio
    async def test_logs_reason(self, fresh_session_state: dict) -> None:
        t = _make_refine_harness_tool(fresh_session_state)
        await t(code=MINIMAL_HARNESS, reason="improved seed handling")
        log = fresh_session_state["refinement_log"]
        assert "improved seed handling" in log


# ---------------------------------------------------------------------------
# _build_session_result
# ---------------------------------------------------------------------------


class TestBuildSessionResult:
    def test_empty_session(self) -> None:
        state: dict = {
            "all_crash_hashes": {},
            "harness_records": [],
            "fuzzing_cycles": [],
            "last_fuzz_result": None,
            "cycle_count": 0,
        }
        result = _build_session_result("testparser", "libfuzzer", state)
        assert result.total_unique_crashes == 0
        assert result.total_cycles == 0

    def test_crash_count_from_hashes(self) -> None:
        state: dict = {
            "all_crash_hashes": {"h1": "x", "h2": "y"},
            "harness_records": [],
            "fuzzing_cycles": [],
            "last_fuzz_result": None,
            "cycle_count": 2,
        }
        result = _build_session_result("testparser", "libfuzzer", state)
        assert result.total_unique_crashes == 2
        assert result.total_cycles == 2

    def test_harness_compile_stats(self) -> None:
        records = [
            HarnessRecord(
                entry_point="a",
                code="...",
                compile_success=True,
                first_try_success=True,
                repair_iterations=0,
            ),
            HarnessRecord(
                entry_point="b",
                code="...",
                compile_success=True,
                first_try_success=False,
                repair_iterations=3,
            ),
        ]
        state: dict = {
            "all_crash_hashes": {},
            "harness_records": records,
            "fuzzing_cycles": [],
            "last_fuzz_result": None,
            "cycle_count": 2,
        }
        result = _build_session_result("testparser", "libfuzzer", state)
        assert result.total_harnesses_attempted == 2
        assert result.harnesses_compiled_first_try == 1
        assert result.total_repair_iterations == 3


# ---------------------------------------------------------------------------
# _compute_score
# ---------------------------------------------------------------------------


class TestComputeScore:
    def _result(
        self, crashes: int = 0, rate: float = 1.0, cov: float = 0.0
    ) -> LiveFuzzingSessionResult:
        attempted = max(1, int(1 / rate)) if rate > 0 else 1
        first_try = int(attempted * rate)
        return LiveFuzzingSessionResult(
            target_name="t",
            engine="libfuzzer",
            total_unique_crashes=crashes,
            final_line_coverage_pct=cov,
            total_harnesses_attempted=attempted,
            harnesses_compiled_first_try=first_try,
        )

    def test_zero_score_for_empty(self) -> None:
        # No crashes, no coverage, no compiled harnesses → 0.0
        r = LiveFuzzingSessionResult(
            target_name="t",
            engine="libfuzzer",
            total_unique_crashes=0,
            final_line_coverage_pct=0.0,
            total_harnesses_attempted=0,
            harnesses_compiled_first_try=0,
        )
        assert _compute_score(r) == pytest.approx(0.0)

    def test_crash_weight_40_percent(self) -> None:
        # 10 crashes → crash_score=1.0; no coverage; rate=1.0
        s = _compute_score(self._result(crashes=10, rate=1.0, cov=0.0))
        # 0.40*1.0 + 0.30*1.0 + 0.30*0.0 = 0.70
        assert s == pytest.approx(0.70)

    def test_saturates_at_10_crashes(self) -> None:
        s1 = _compute_score(self._result(crashes=10))
        s2 = _compute_score(self._result(crashes=100))
        assert s1 == pytest.approx(s2)

    def test_coverage_contributes_30_percent(self) -> None:
        # no crashes; perfect compile; 100% coverage
        s = _compute_score(self._result(crashes=0, rate=1.0, cov=100.0))
        # 0.40*0 + 0.30*1.0 + 0.30*1.0 = 0.60
        assert s == pytest.approx(0.60)

    def test_score_bounded_zero_to_one(self) -> None:
        s = _compute_score(self._result(crashes=99, rate=1.0, cov=100.0))
        assert 0.0 <= s <= 1.0


# ---------------------------------------------------------------------------
# load_live_fuzzing_dataset
# ---------------------------------------------------------------------------


class TestLoadLiveFuzzingDataset:
    def test_loads_single_sample(self, target_dir: Path) -> None:
        samples = load_live_fuzzing_dataset(str(target_dir.parent), "testparser")
        assert len(samples) == 1

    def test_sample_id(self, target_dir: Path) -> None:
        samples = load_live_fuzzing_dataset(str(target_dir.parent), "testparser")
        assert samples[0].id == "live-fuzzing-testparser"

    def test_sample_input_contains_target_name(self, target_dir: Path) -> None:
        samples = load_live_fuzzing_dataset(str(target_dir.parent), "testparser")
        assert "testparser" in samples[0].input

    def test_sample_input_contains_cwe_hints(self, target_dir: Path) -> None:
        samples = load_live_fuzzing_dataset(str(target_dir.parent), "testparser")
        assert "CWE-125" in samples[0].input

    def test_sample_input_contains_build_script(self, target_dir: Path) -> None:
        samples = load_live_fuzzing_dataset(str(target_dir.parent), "testparser")
        assert "make -j" in samples[0].input

    def test_sample_metadata_keys(self, target_dir: Path) -> None:
        samples = load_live_fuzzing_dataset(str(target_dir.parent), "testparser")
        meta = samples[0].metadata
        assert meta is not None
        assert "target_name" in meta
        assert "fuzz_targets" in meta
        assert meta["target_name"] == "testparser"

    def test_missing_target_raises(self, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError, match="Target directory not found"):
            load_live_fuzzing_dataset(str(tmp_path), "nonexistent")

    def test_sample_input_includes_source_header(self, target_dir: Path) -> None:
        samples = load_live_fuzzing_dataset(str(target_dir.parent), "testparser")
        # testparser.h was created in fixture
        assert "testparser.h" in samples[0].input


# ---------------------------------------------------------------------------
# Memory stubs
# ---------------------------------------------------------------------------


class TestMemoryStubs:
    def test_load_returns_dict(self) -> None:
        result = load_session_memory("testparser")
        assert isinstance(result, dict)

    def test_save_does_not_raise(self) -> None:
        save_session_memory("testparser", {"key": "value"})


# ---------------------------------------------------------------------------
# System prompt
# ---------------------------------------------------------------------------


class TestSystemPrompt:
    def test_prompt_contains_four_phases(self) -> None:
        assert "ANALYZE" in RED_TEAM_LIVE_PROMPT
        assert "SYNTHESIZE" in RED_TEAM_LIVE_PROMPT
        assert "FUZZ" in RED_TEAM_LIVE_PROMPT
        assert "TRIAGE" in RED_TEAM_LIVE_PROMPT

    def test_prompt_references_cycle_cap(self) -> None:
        assert str(CYCLE_CAP_SECONDS) in RED_TEAM_LIVE_PROMPT

    def test_prompt_references_repair_budget(self) -> None:
        assert str(MAX_REPAIR_ITERS) in RED_TEAM_LIVE_PROMPT

    def test_prompt_mentions_per_function_targeting(self) -> None:
        assert "entry-point" in RED_TEAM_LIVE_PROMPT.lower()

    def test_prompt_mentions_reachability(self) -> None:
        assert "eachab" in RED_TEAM_LIVE_PROMPT  # "Reachability"


# ---------------------------------------------------------------------------
# live_fuzzing_solver
# ---------------------------------------------------------------------------


class TestLiveFuzzingSolver:
    def test_returns_callable(self) -> None:
        s = live_fuzzing_solver()
        assert callable(s)


# ---------------------------------------------------------------------------
# live_fuzzing_scorer
# ---------------------------------------------------------------------------


class TestLiveFuzzingScorer:
    def test_returns_list(self) -> None:
        scorers = live_fuzzing_scorer()
        assert isinstance(scorers, list)
        assert len(scorers) == 1

    def test_scorer_is_callable(self) -> None:
        scorers = live_fuzzing_scorer()
        assert callable(scorers[0])

    @pytest.mark.asyncio
    async def test_no_session_state_scores_zero(self) -> None:
        scorers = live_fuzzing_scorer()
        score_fn = scorers[0]

        state = MagicMock()
        state.metadata = {}  # no _session_state key

        target = MagicMock()
        target.text = "testparser"

        result = await score_fn(state, target)
        assert result.value == 0.0
        assert "No session state" in (result.explanation or "")

    @pytest.mark.asyncio
    async def test_scores_crashes_and_compiles(self) -> None:
        scorers = live_fuzzing_scorer()
        score_fn = scorers[0]

        session_state = {
            "all_crash_hashes": {f"h{i}": f"asan{i}" for i in range(5)},
            "harness_records": [
                HarnessRecord(
                    entry_point="f",
                    code="...",
                    compile_success=True,
                    first_try_success=True,
                    repair_iterations=0,
                )
            ],
            "fuzzing_cycles": [],
            "last_fuzz_result": None,
            "cycle_count": 1,
        }

        state = MagicMock()
        state.metadata = {
            "target_name": "testparser",
            "_session_state": session_state,
        }
        target = MagicMock()

        result = await score_fn(state, target)
        assert result.value is not None
        assert 0.0 <= float(result.value) <= 1.0
        # 5 crashes → crash_score=0.5; 1/1 first try compile → compile_score=1.0; no cov
        # 0.4*0.5 + 0.3*1.0 + 0.3*0.0 = 0.50
        assert float(result.value) == pytest.approx(0.50)


# ---------------------------------------------------------------------------
# live_fuzzing task
# ---------------------------------------------------------------------------


class TestLiveFuzzingTask:
    def test_creates_task(self, target_dir: Path) -> None:
        from inspect_ai import Task

        t = live_fuzzing(
            targets_dir=str(target_dir.parent),
            target="testparser",
            fuzzing_engine="libfuzzer",
            sanitizer="address",
        )
        assert isinstance(t, Task)

    def test_task_has_dataset(self, target_dir: Path) -> None:
        t = live_fuzzing(
            targets_dir=str(target_dir.parent),
            target="testparser",
        )
        assert t.dataset is not None

    def test_missing_target_raises(self, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError):
            live_fuzzing(
                targets_dir=str(tmp_path),
                target="doesnotexist",
            )

    def test_task_message_limit_generous(self, target_dir: Path) -> None:
        """The task should allow many messages for multi-cycle runs."""
        t = live_fuzzing(
            targets_dir=str(target_dir.parent),
            target="testparser",
        )
        assert t.message_limit is not None
        assert t.message_limit >= 60
