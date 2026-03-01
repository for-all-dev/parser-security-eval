"""Tests for the live fuzzing Inspect-AI task — no Docker or model required."""

from __future__ import annotations

import asyncio
import base64
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from inspect_ai.scorer import Score, Target

from parser_security_eval.sandbox.campaign import CampaignResult, FuzzingStats
from parser_security_eval.tasks.fuzzing import (
    FuzzingState,
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
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

MINIMAL_METADATA = """\
name: testlib
format_type: binary-image
language: c
ossfuzz_project: null
fuzz_targets:
  - fuzz_testlib
has_corpus: false
has_dictionary: false
"""

MINIMAL_BUILD_SH = """\
#!/bin/bash -eu
cd /src/testlib
make -j$(nproc)
$CXX $CXXFLAGS -o $OUT/fuzz_testlib fuzz.cc -L. -ltestlib $LIB_FUZZING_ENGINE
"""

MINIMAL_HARNESS = """\
#include <stdint.h>
#include <stddef.h>
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  return 0;
}
"""


@pytest.fixture
def target_dir(tmp_path: Path) -> Path:
    """Create a minimal target directory for testing."""
    d = tmp_path / "testlib"
    d.mkdir()
    (d / "metadata.yaml").write_text(MINIMAL_METADATA)
    (d / "build.sh").write_text(MINIMAL_BUILD_SH)
    (d / "Dockerfile").write_text("FROM gcr.io/oss-fuzz-base/base-builder\n")
    return d


@pytest.fixture
def target_dir_with_harness(target_dir: Path) -> Path:
    """Target directory that also has an existing harness file."""
    (target_dir / "fuzz_testlib.cc").write_text(MINIMAL_HARNESS)
    return target_dir


def _make_mock_sandbox() -> MagicMock:
    """Build a mock DockerSandbox that accepts async calls."""
    sandbox = MagicMock()
    sandbox.exec = AsyncMock(return_value=(0, "", ""))
    sandbox.copy_in = AsyncMock(return_value=None)
    sandbox.copy_out = AsyncMock(return_value=None)
    return sandbox


def _make_empty_campaign() -> CampaignResult:
    """Build a CampaignResult with no crashes."""
    return CampaignResult(
        target_name="testlib",
        engine="libfuzzer",
        duration_seconds=10,
        crash_files=[],
        coverage_raw_profiles=[],
        stats=FuzzingStats(
            execs_per_sec=1000.0,
            total_execs=10000,
            corpus_size=5,
            crashes_found=0,
        ),
    )


def _make_crash_campaign(tmp_path: Path, n_crashes: int = 2) -> CampaignResult:
    """Build a CampaignResult with *n_crashes* crash files on disk."""
    crash_files = []
    for i in range(n_crashes):
        p = tmp_path / f"crash-{i}"
        p.write_bytes(b"\x00\x01\x02" * 10)
        crash_files.append(p)
    return CampaignResult(
        target_name="testlib",
        engine="libfuzzer",
        duration_seconds=10,
        crash_files=crash_files,
        coverage_raw_profiles=[],
        stats=FuzzingStats(
            execs_per_sec=900.0,
            total_execs=9000,
            corpus_size=10,
            crashes_found=n_crashes,
        ),
    )


def _tool_str(result: object) -> str:
    """Cast a tool result to str for assertion helpers."""
    return str(result)


# ---------------------------------------------------------------------------
# load_live_fuzzing_dataset
# ---------------------------------------------------------------------------


class TestLoadLiveFuzzingDataset:
    def test_returns_non_empty_list(self, target_dir: Path) -> None:
        samples = load_live_fuzzing_dataset(str(target_dir.parent), "testlib")
        assert len(samples) >= 1

    def test_returns_sample_with_input(self, target_dir: Path) -> None:
        samples = load_live_fuzzing_dataset(str(target_dir.parent), "testlib")
        sample = samples[0]
        assert isinstance(sample.input, str)
        assert len(sample.input) > 0

    def test_sample_input_contains_target_info(self, target_dir: Path) -> None:
        samples = load_live_fuzzing_dataset(str(target_dir.parent), "testlib")
        s = str(samples[0].input)
        assert "testlib" in s
        assert "binary-image" in s
        assert "LLVMFuzzerTestOneInput" in s

    def test_sample_id(self, target_dir: Path) -> None:
        samples = load_live_fuzzing_dataset(str(target_dir.parent), "testlib")
        assert samples[0].id == "live-fuzzing-testlib"

    def test_sample_target_is_fuzz_target(self, target_dir: Path) -> None:
        samples = load_live_fuzzing_dataset(str(target_dir.parent), "testlib")
        assert samples[0].target == "fuzz_testlib"

    def test_sample_metadata_keys(self, target_dir: Path) -> None:
        samples = load_live_fuzzing_dataset(str(target_dir.parent), "testlib")
        meta = samples[0].metadata
        assert meta is not None
        assert meta["target_name"] == "testlib"
        assert "format_type" in meta
        assert "language" in meta
        assert "fuzz_targets" in meta
        assert "targets_dir" in meta

    def test_includes_build_script(self, target_dir: Path) -> None:
        samples = load_live_fuzzing_dataset(str(target_dir.parent), "testlib")
        assert "make -j" in str(samples[0].input)

    def test_includes_existing_harnesses(self, target_dir_with_harness: Path) -> None:
        samples = load_live_fuzzing_dataset(
            str(target_dir_with_harness.parent), "testlib"
        )
        s = str(samples[0].input)
        assert "Existing harnesses" in s
        assert "fuzz_testlib.cc" in s

    def test_missing_target_raises(self, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError, match="Target directory not found"):
            load_live_fuzzing_dataset(str(tmp_path), "nonexistent")


# ---------------------------------------------------------------------------
# FuzzingState dataclass
# ---------------------------------------------------------------------------


class TestFuzzingState:
    def test_default_values(self) -> None:
        s = FuzzingState()
        assert s.sandbox is None
        assert s.harness_written is False
        assert s.harness_compiled is False
        assert s.campaigns == []
        assert s.last_stats is None

    def test_can_assign_sandbox(self) -> None:
        s = FuzzingState()
        mock = MagicMock()
        s.sandbox = mock
        assert s.sandbox is mock

    def test_campaigns_list_is_independent(self) -> None:
        a = FuzzingState()
        b = FuzzingState()
        a.campaigns.append(_make_empty_campaign())
        assert len(b.campaigns) == 0


# ---------------------------------------------------------------------------
# Tool: write_harness — returns string, sets state.harness_written
# ---------------------------------------------------------------------------


class TestWriteHarnessTool:
    def test_returns_string(self) -> None:
        state = FuzzingState(sandbox=_make_mock_sandbox())
        t = _make_write_harness_tool(state, "testlib")
        result = asyncio.run(t(MINIMAL_HARNESS))
        assert isinstance(result, str)

    def test_sets_harness_written(self) -> None:
        state = FuzzingState(sandbox=_make_mock_sandbox())
        t = _make_write_harness_tool(state, "testlib")
        asyncio.run(t(MINIMAL_HARNESS))
        assert state.harness_written is True

    def test_returns_success_message(self) -> None:
        state = FuzzingState(sandbox=_make_mock_sandbox())
        t = _make_write_harness_tool(state, "testlib")
        result = _tool_str(asyncio.run(t(MINIMAL_HARNESS)))
        assert "Harness written" in result

    def test_resets_compiled_flag(self) -> None:
        state = FuzzingState(sandbox=_make_mock_sandbox(), harness_compiled=True)
        t = _make_write_harness_tool(state, "testlib")
        asyncio.run(t(MINIMAL_HARNESS))
        assert state.harness_compiled is False

    def test_error_when_no_sandbox(self) -> None:
        state = FuzzingState(sandbox=None)
        t = _make_write_harness_tool(state, "testlib")
        result = _tool_str(asyncio.run(t(MINIMAL_HARNESS)))
        assert "Error" in result


# ---------------------------------------------------------------------------
# Tool: compile_harness — returns string
# ---------------------------------------------------------------------------


class TestCompileHarnessTool:
    def test_returns_string(self) -> None:
        sandbox = _make_mock_sandbox()
        sandbox.exec = AsyncMock(return_value=(0, "ok", ""))
        state = FuzzingState(sandbox=sandbox, harness_written=True)
        t = _make_compile_harness_tool(state, "testlib", "libfuzzer")
        result = asyncio.run(t())
        assert isinstance(result, str)

    def test_returns_success_on_exit_zero(self) -> None:
        sandbox = _make_mock_sandbox()
        sandbox.exec = AsyncMock(return_value=(0, "", ""))
        state = FuzzingState(sandbox=sandbox, harness_written=True)
        t = _make_compile_harness_tool(state, "testlib", "libfuzzer")
        result = _tool_str(asyncio.run(t()))
        assert "succeeded" in result
        assert state.harness_compiled is True

    def test_returns_error_on_compile_failure(self) -> None:
        sandbox = _make_mock_sandbox()
        sandbox.exec = AsyncMock(return_value=(1, "", "error: undeclared identifier\n"))
        state = FuzzingState(sandbox=sandbox, harness_written=True)
        t = _make_compile_harness_tool(state, "testlib", "libfuzzer")
        result = _tool_str(asyncio.run(t()))
        assert "FAILED" in result
        assert state.harness_compiled is False

    def test_error_when_no_harness_written(self) -> None:
        state = FuzzingState(sandbox=_make_mock_sandbox(), harness_written=False)
        t = _make_compile_harness_tool(state, "testlib", "libfuzzer")
        result = _tool_str(asyncio.run(t()))
        assert "Error" in result

    def test_error_when_no_sandbox(self) -> None:
        state = FuzzingState(sandbox=None, harness_written=True)
        t = _make_compile_harness_tool(state, "testlib", "libfuzzer")
        result = _tool_str(asyncio.run(t()))
        assert "Error" in result


# ---------------------------------------------------------------------------
# Tool: add_seed — returns string
# ---------------------------------------------------------------------------


class TestAddSeedTool:
    def test_returns_string(self) -> None:
        state = FuzzingState(sandbox=_make_mock_sandbox())
        t = _make_add_seed_tool(state)
        data = base64.b64encode(b"hello").decode()
        result = asyncio.run(t(data, "seed.bin"))
        assert isinstance(result, str)

    def test_returns_seed_added_on_success(self) -> None:
        sandbox = _make_mock_sandbox()
        sandbox.exec = AsyncMock(return_value=(0, "", ""))
        state = FuzzingState(sandbox=sandbox)
        t = _make_add_seed_tool(state)
        data = base64.b64encode(b"\x00\x01\x02").decode()
        result = _tool_str(asyncio.run(t(data, "myseed.bin")))
        assert "Seed added" in result
        assert "myseed.bin" in result

    def test_returns_error_for_invalid_base64(self) -> None:
        state = FuzzingState(sandbox=_make_mock_sandbox())
        t = _make_add_seed_tool(state)
        result = _tool_str(asyncio.run(t("not-valid-base64!!!", "seed.bin")))
        assert "Error" in result

    def test_error_when_no_sandbox(self) -> None:
        state = FuzzingState(sandbox=None)
        t = _make_add_seed_tool(state)
        data = base64.b64encode(b"x").decode()
        result = _tool_str(asyncio.run(t(data, "x.bin")))
        assert "Error" in result


# ---------------------------------------------------------------------------
# Tool: start_fuzzing — returns string
# ---------------------------------------------------------------------------


class TestStartFuzzingTool:
    def test_returns_string(self, tmp_path: Path) -> None:
        sandbox = _make_mock_sandbox()
        sandbox.exec = AsyncMock(return_value=(0, "", ""))
        state = FuzzingState(
            sandbox=sandbox, harness_written=True, harness_compiled=True
        )
        campaign_result = _make_empty_campaign()
        with patch(
            "parser_security_eval.tasks.fuzzing.FuzzingCampaign"
        ) as MockCampaign:
            instance = AsyncMock()
            instance.run = AsyncMock(return_value=campaign_result)
            MockCampaign.return_value = instance
            t = _make_start_fuzzing_tool(state, "testlib", "libfuzzer", max_rounds=3)
            result = asyncio.run(t(10))
        assert isinstance(result, str)

    def test_appends_campaign_to_state(self, tmp_path: Path) -> None:
        sandbox = _make_mock_sandbox()
        state = FuzzingState(
            sandbox=sandbox, harness_written=True, harness_compiled=True
        )
        campaign_result = _make_empty_campaign()
        with patch(
            "parser_security_eval.tasks.fuzzing.FuzzingCampaign"
        ) as MockCampaign:
            instance = AsyncMock()
            instance.run = AsyncMock(return_value=campaign_result)
            MockCampaign.return_value = instance
            t = _make_start_fuzzing_tool(state, "testlib", "libfuzzer", max_rounds=3)
            asyncio.run(t(10))
        assert len(state.campaigns) == 1

    def test_budget_exhausted_message(self) -> None:
        state = FuzzingState(
            sandbox=_make_mock_sandbox(),
            harness_written=True,
            harness_compiled=True,
            campaigns=[
                _make_empty_campaign(),
                _make_empty_campaign(),
                _make_empty_campaign(),
            ],
        )
        t = _make_start_fuzzing_tool(state, "testlib", "libfuzzer", max_rounds=3)
        result = _tool_str(asyncio.run(t(10))).lower()
        assert "budget" in result or "exhausted" in result

    def test_error_when_not_compiled(self) -> None:
        state = FuzzingState(
            sandbox=_make_mock_sandbox(),
            harness_written=True,
            harness_compiled=False,
        )
        t = _make_start_fuzzing_tool(state, "testlib", "libfuzzer", max_rounds=3)
        result = _tool_str(asyncio.run(t(10)))
        assert "Error" in result

    def test_error_when_no_sandbox(self) -> None:
        state = FuzzingState(sandbox=None, harness_written=True, harness_compiled=True)
        t = _make_start_fuzzing_tool(state, "testlib", "libfuzzer", max_rounds=3)
        result = _tool_str(asyncio.run(t(10)))
        assert "Error" in result


# ---------------------------------------------------------------------------
# Tool: get_fuzzer_stats — returns string
# ---------------------------------------------------------------------------


class TestGetFuzzerStatsTool:
    def test_returns_string(self) -> None:
        state = FuzzingState()
        t = _make_get_fuzzer_stats_tool(state)
        result = asyncio.run(t())
        assert isinstance(result, str)

    def test_no_campaigns_message(self) -> None:
        state = FuzzingState()
        t = _make_get_fuzzer_stats_tool(state)
        result = _tool_str(asyncio.run(t()))
        assert "No campaigns" in result

    def test_shows_stats_after_campaign(self) -> None:
        state = FuzzingState()
        state.campaigns.append(_make_empty_campaign())
        state.last_stats = state.campaigns[-1].stats
        t = _make_get_fuzzer_stats_tool(state)
        result = _tool_str(asyncio.run(t()))
        assert "1" in result  # at least 1 campaign


# ---------------------------------------------------------------------------
# Tool: get_crash_info — returns string
# ---------------------------------------------------------------------------


class TestGetCrashInfoTool:
    def test_returns_string(self) -> None:
        state = FuzzingState(sandbox=_make_mock_sandbox())
        t = _make_get_crash_info_tool(state, "testlib")
        result = asyncio.run(t("crash-0"))
        assert isinstance(result, str)

    def test_no_crashes_returns_message(self) -> None:
        state = FuzzingState(sandbox=_make_mock_sandbox())
        t = _make_get_crash_info_tool(state, "testlib")
        result = _tool_str(asyncio.run(t("crash-0")))
        assert "No crashes" in result

    def test_returns_crash_info(self, tmp_path: Path) -> None:
        sandbox = _make_mock_sandbox()
        sandbox.exec = AsyncMock(
            return_value=(1, "", "ERROR: AddressSanitizer: heap-buffer-overflow")
        )
        state = FuzzingState(sandbox=sandbox)
        state.campaigns.append(_make_crash_campaign(tmp_path, n_crashes=1))
        t = _make_get_crash_info_tool(state, "testlib")
        result = _tool_str(asyncio.run(t("crash-0")))
        assert isinstance(result, str)
        assert "crash" in result.lower()

    def test_invalid_crash_id_returns_error(self, tmp_path: Path) -> None:
        state = FuzzingState(sandbox=_make_mock_sandbox())
        state.campaigns.append(_make_crash_campaign(tmp_path, n_crashes=1))
        t = _make_get_crash_info_tool(state, "testlib")
        result = _tool_str(asyncio.run(t("crash-99")))
        assert "range" in result or "Error" in result


# ---------------------------------------------------------------------------
# Tool: refine_harness — returns string
# ---------------------------------------------------------------------------


class TestRefineHarnessTool:
    def test_returns_string(self) -> None:
        sandbox = _make_mock_sandbox()
        sandbox.exec = AsyncMock(return_value=(0, "", ""))
        state = FuzzingState(sandbox=sandbox)
        t = _make_refine_harness_tool(state, "testlib", "libfuzzer")
        result = asyncio.run(t(MINIMAL_HARNESS))
        assert isinstance(result, str)

    def test_returns_success_on_compile_ok(self) -> None:
        sandbox = _make_mock_sandbox()
        sandbox.exec = AsyncMock(return_value=(0, "", ""))
        state = FuzzingState(sandbox=sandbox)
        t = _make_refine_harness_tool(state, "testlib", "libfuzzer")
        result = _tool_str(asyncio.run(t(MINIMAL_HARNESS))).lower()
        assert "compiled" in result or "updated" in result
        assert state.harness_compiled is True

    def test_returns_error_on_compile_failure(self) -> None:
        sandbox = _make_mock_sandbox()
        sandbox.exec = AsyncMock(return_value=(1, "", "error: bad\n"))
        state = FuzzingState(sandbox=sandbox, harness_written=True)
        t = _make_refine_harness_tool(state, "testlib", "libfuzzer")
        result = _tool_str(asyncio.run(t(MINIMAL_HARNESS)))
        assert "FAILED" in result
        assert state.harness_compiled is False

    def test_error_when_no_sandbox(self) -> None:
        state = FuzzingState(sandbox=None)
        t = _make_refine_harness_tool(state, "testlib", "libfuzzer")
        result = _tool_str(asyncio.run(t(MINIMAL_HARNESS)))
        assert "Error" in result


# ---------------------------------------------------------------------------
# live_fuzzing_scorer — no crashes -> 0.0
# ---------------------------------------------------------------------------


class TestLiveFuzzingScorer:
    def _make_state_with_no_campaigns(self) -> MagicMock:
        """Build a TaskState mock whose store has a FuzzingState with no campaigns."""
        fuzzing_state = FuzzingState()
        store = MagicMock()
        store.get = MagicMock(return_value=fuzzing_state)

        state = MagicMock()
        state.store = store
        return state

    def _make_state_with_campaigns(self, campaigns: list[CampaignResult]) -> MagicMock:
        """Build a TaskState mock with pre-populated campaigns."""
        fuzzing_state = FuzzingState()
        fuzzing_state.campaigns = campaigns
        if campaigns:
            fuzzing_state.last_stats = campaigns[-1].stats

        store = MagicMock()
        store.get = MagicMock(return_value=fuzzing_state)

        state = MagicMock()
        state.store = store
        return state

    def _run_scorer(self, state: MagicMock) -> Score:
        scorer_fn = live_fuzzing_scorer()
        target = Target("fuzz_testlib")
        result = asyncio.run(scorer_fn(state, target))
        assert result is not None
        return result

    def test_no_campaigns_returns_zero(self) -> None:
        state = self._make_state_with_no_campaigns()
        result = self._run_scorer(state)
        assert result.value == 0.0

    def test_no_state_returns_zero(self) -> None:
        store = MagicMock()
        store.get = MagicMock(return_value=None)
        state = MagicMock()
        state.store = store
        result = self._run_scorer(state)
        assert result.value == 0.0

    def test_no_crashes_scores_zero(self) -> None:
        state = self._make_state_with_campaigns([_make_empty_campaign()])
        result = self._run_scorer(state)
        assert result.value == 0.0

    def test_crashes_increase_score(self, tmp_path: Path) -> None:
        campaign = _make_crash_campaign(tmp_path, n_crashes=5)
        state = self._make_state_with_campaigns([campaign])
        result = self._run_scorer(state)
        assert isinstance(result.value, float)
        assert result.value > 0.0
        assert result.value <= 1.0

    def test_five_crashes_max_crash_component(self, tmp_path: Path) -> None:
        """5 unique crashes => crash_score=1.0; combined = 0.7 * 1.0 + 0.3 * 0.0 = 0.7."""
        campaign = _make_crash_campaign(tmp_path, n_crashes=5)
        state = self._make_state_with_campaigns([campaign])
        result = self._run_scorer(state)
        assert isinstance(result.value, float)
        assert abs(result.value - 0.7) < 1e-9

    def test_score_metadata_keys(self, tmp_path: Path) -> None:
        campaign = _make_crash_campaign(tmp_path, n_crashes=2)
        state = self._make_state_with_campaigns([campaign])
        result = self._run_scorer(state)
        meta = result.metadata
        assert meta is not None
        assert "unique_crashes" in meta
        assert "coverage_pct" in meta
        assert "rounds_completed" in meta
        assert "total_executions" in meta

    def test_explanation_contains_crashes(self, tmp_path: Path) -> None:
        campaign = _make_crash_campaign(tmp_path, n_crashes=3)
        state = self._make_state_with_campaigns([campaign])
        result = self._run_scorer(state)
        assert "unique_crashes=3" in (result.explanation or "")


# ---------------------------------------------------------------------------
# live_fuzzing task smoke test
# ---------------------------------------------------------------------------


class TestLiveFuzzingTask:
    def test_creates_task(self, target_dir: Path) -> None:
        from inspect_ai import Task

        t = live_fuzzing(
            targets_dir=str(target_dir.parent),
            target="testlib",
            engine="libfuzzer",
            max_rounds=2,
            round_duration=30,
        )
        assert isinstance(t, Task)

    def test_task_has_dataset(self, target_dir: Path) -> None:
        t = live_fuzzing(
            targets_dir=str(target_dir.parent),
            target="testlib",
        )
        assert t.dataset is not None

    def test_missing_target_raises(self, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError):
            live_fuzzing(
                targets_dir=str(tmp_path),
                target="nonexistent",
            )


# ---------------------------------------------------------------------------
# live_fuzzing_solver smoke test
# ---------------------------------------------------------------------------


class TestLiveFuzzingSolver:
    def test_returns_callable_solver(self, target_dir: Path) -> None:
        s = live_fuzzing_solver(
            targets_dir=str(target_dir.parent),
            target="testlib",
            engine="libfuzzer",
            max_rounds=3,
        )
        assert callable(s)
