"""Tests for FuzzingCampaign — mocked DockerSandbox, no real Docker required."""

from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from parser_security_eval.sandbox.campaign import (
    AFLPlusPlusEngine,
    CampaignResult,
    FuzzingCampaign,
    FuzzingStats,
    HonggfuzzEngine,
    LibFuzzerEngine,
)
from parser_security_eval.sandbox.docker import DockerSandbox, SandboxConfig


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_sandbox(engine: str = "libfuzzer") -> DockerSandbox:
    config = SandboxConfig(
        target_name="test-target",
        target_dir=Path("/tmp/targets/test-target"),
        engine=engine,
    )
    sandbox = DockerSandbox(config)
    sandbox._container_id = "test-container-123"
    return sandbox


# ---------------------------------------------------------------------------
# LibFuzzerEngine.parse_stats
# ---------------------------------------------------------------------------


class TestLibFuzzerEngineParseStats:
    SAMPLE_LOG = """\
INFO: Seed: 12345
INFO: Loaded 1 modules   (100 guards): 100 [0x1234, 0x5678),
#0      READ units: 1
#2      INITED cov: 30 ft: 31 corp: 1/1b exec/s: 0 rss: 30Mb
#512    pulse  cov: 31 ft: 32 corp: 10/22b exec/s: 512 rss: 32Mb
#1024   pulse  cov: 31 ft: 32 corp: 10/22b exec/s: 1024 rss: 33Mb
stat::number_of_executed_units: 75000
stat::average_exec_per_sec: 2500
stat::new_units_added:        42
stat::slowest_unit_time_sec:  0
stat::peak_rss_mb:            64
stat::corpus_size:     120
stat::crash_count:     2
"""

    def test_parses_total_execs(self) -> None:
        engine = LibFuzzerEngine()
        stats = engine.parse_stats(self.SAMPLE_LOG)
        assert stats.total_execs == 75000

    def test_parses_execs_per_sec(self) -> None:
        engine = LibFuzzerEngine()
        stats = engine.parse_stats(self.SAMPLE_LOG)
        assert stats.execs_per_sec == 2500.0

    def test_parses_corpus_size(self) -> None:
        engine = LibFuzzerEngine()
        stats = engine.parse_stats(self.SAMPLE_LOG)
        assert stats.corpus_size == 120

    def test_parses_crashes_found(self) -> None:
        engine = LibFuzzerEngine()
        stats = engine.parse_stats(self.SAMPLE_LOG)
        assert stats.crashes_found == 2

    def test_engine_name_set(self) -> None:
        engine = LibFuzzerEngine()
        stats = engine.parse_stats(self.SAMPLE_LOG)
        assert stats.engine == "libfuzzer"

    def test_empty_log_returns_defaults(self) -> None:
        engine = LibFuzzerEngine()
        stats = engine.parse_stats("")
        assert stats.total_execs is None
        assert stats.execs_per_sec is None
        assert stats.corpus_size is None
        assert stats.crashes_found == 0

    def test_partial_log(self) -> None:
        log = "stat::number_of_executed_units: 5000\n"
        engine = LibFuzzerEngine()
        stats = engine.parse_stats(log)
        assert stats.total_execs == 5000
        assert stats.execs_per_sec is None

    def test_returns_fuzzingstats_instance(self) -> None:
        engine = LibFuzzerEngine()
        stats = engine.parse_stats(self.SAMPLE_LOG)
        assert isinstance(stats, FuzzingStats)


# ---------------------------------------------------------------------------
# AFLPlusPlusEngine.build_command
# ---------------------------------------------------------------------------


class TestAFLPlusPlusEngineBuildCommand:
    def test_basic_command_contains_afl_fuzz(self) -> None:
        engine = AFLPlusPlusEngine()
        cmd = engine.build_command("fuzz_xml", "/out/corpus", 300, [])
        assert "afl-fuzz" in cmd

    def test_corpus_dir_in_command(self) -> None:
        engine = AFLPlusPlusEngine()
        cmd = engine.build_command("fuzz_xml", "/out/corpus", 300, [])
        assert "/out/corpus" in cmd

    def test_fuzz_target_in_command(self) -> None:
        engine = AFLPlusPlusEngine()
        cmd = engine.build_command("fuzz_xml", "/out/corpus", 300, [])
        assert "/out/fuzz_xml" in cmd

    def test_duration_in_timeout_prefix(self) -> None:
        engine = AFLPlusPlusEngine()
        cmd = engine.build_command("fuzz_xml", "/out/corpus", 120, [])
        assert "timeout 120" in cmd

    def test_output_dir_in_command(self) -> None:
        engine = AFLPlusPlusEngine()
        cmd = engine.build_command("fuzz_xml", "/out/corpus", 300, [])
        assert "/out/crashes" in cmd

    def test_extra_flags_appended(self) -> None:
        engine = AFLPlusPlusEngine()
        cmd = engine.build_command("fuzz_xml", "/out/corpus", 300, ["-d", "-p exploit"])
        assert "-d" in cmd
        assert "-p exploit" in cmd

    def test_no_extra_flags(self) -> None:
        engine = AFLPlusPlusEngine()
        cmd = engine.build_command("fuzz_xml", "/out/corpus", 300, [])
        # Should not have trailing spaces or None in the command
        assert cmd.strip() == cmd.rstrip()


# ---------------------------------------------------------------------------
# FuzzingCampaign.run — OOM detection
# ---------------------------------------------------------------------------


class TestFuzzingCampaignOOM:
    @pytest.mark.asyncio
    async def test_oom_killed_sets_flag(self) -> None:
        """exit_code=137 should result in oom_killed=True."""
        sandbox = _make_sandbox(engine="libfuzzer")

        async def mock_exec(
            command: str, timeout: int | None = None
        ) -> tuple[int, str, str]:
            if command.startswith("mkdir"):
                return (0, "", "")
            # Simulate OOM kill: exit code 137.
            return (137, "", "Killed")

        with (
            patch.object(sandbox, "exec", side_effect=mock_exec),
            patch.object(
                sandbox,
                "collect_crashes",
                new_callable=AsyncMock,
                return_value=[],
            ),
        ):
            campaign = FuzzingCampaign(
                sandbox=sandbox,
                fuzz_target="fuzz_target",
                duration_seconds=60,
            )
            result = await campaign.run()

        assert result.oom_killed is True
        assert result.timed_out is False
        assert isinstance(result, CampaignResult)

    @pytest.mark.asyncio
    async def test_oom_killed_exit_code_137_not_timed_out(self) -> None:
        """OOM kill must not also set timed_out."""
        sandbox = _make_sandbox(engine="libfuzzer")

        async def mock_exec(
            command: str, timeout: int | None = None
        ) -> tuple[int, str, str]:
            if command.startswith("mkdir"):
                return (0, "", "")
            return (137, "", "")

        with (
            patch.object(sandbox, "exec", side_effect=mock_exec),
            patch.object(
                sandbox,
                "collect_crashes",
                new_callable=AsyncMock,
                return_value=[],
            ),
        ):
            campaign = FuzzingCampaign(sandbox=sandbox, fuzz_target="fuzz_target")
            result = await campaign.run()

        assert result.oom_killed is True
        assert result.timed_out is False


# ---------------------------------------------------------------------------
# FuzzingCampaign.run — timeout detection
# ---------------------------------------------------------------------------


class TestFuzzingCampaignTimeout:
    @pytest.mark.asyncio
    async def test_timeout_sets_flag(self) -> None:
        """exit_code=-1 from _run helper should result in timed_out=True."""
        sandbox = _make_sandbox(engine="libfuzzer")

        async def mock_exec(
            command: str, timeout: int | None = None
        ) -> tuple[int, str, str]:
            if command.startswith("mkdir"):
                return (0, "", "")
            # Simulate the -1 exit code that _run() returns on asyncio.TimeoutError.
            return (-1, "", "timeout")

        with (
            patch.object(sandbox, "exec", side_effect=mock_exec),
            patch.object(
                sandbox,
                "collect_crashes",
                new_callable=AsyncMock,
                return_value=[],
            ),
        ):
            campaign = FuzzingCampaign(
                sandbox=sandbox,
                fuzz_target="fuzz_target",
                duration_seconds=60,
            )
            result = await campaign.run()

        assert result.timed_out is True
        assert result.oom_killed is False

    @pytest.mark.asyncio
    async def test_timeout_exit_code_minus_one_not_oom(self) -> None:
        """Timeout (-1) must not also set oom_killed."""
        sandbox = _make_sandbox(engine="libfuzzer")

        async def mock_exec(
            command: str, timeout: int | None = None
        ) -> tuple[int, str, str]:
            if command.startswith("mkdir"):
                return (0, "", "")
            return (-1, "", "timeout")

        with (
            patch.object(sandbox, "exec", side_effect=mock_exec),
            patch.object(
                sandbox,
                "collect_crashes",
                new_callable=AsyncMock,
                return_value=[],
            ),
        ):
            campaign = FuzzingCampaign(sandbox=sandbox, fuzz_target="fuzz_target")
            result = await campaign.run()

        assert result.timed_out is True
        assert result.oom_killed is False


# ---------------------------------------------------------------------------
# FuzzingCampaign.run — successful run
# ---------------------------------------------------------------------------


class TestFuzzingCampaignSuccess:
    LIBFUZZER_LOG = (
        "stat::number_of_executed_units: 50000\n"
        "stat::average_exec_per_sec: 1000\n"
        "stat::corpus_size: 30\n"
        "stat::crash_count: 0\n"
    )

    @pytest.mark.asyncio
    async def test_successful_run_result_shape(self) -> None:
        sandbox = _make_sandbox(engine="libfuzzer")
        crash_path = Path("/tmp/crashes-test-target-xyz/crash-abc")

        call_count = 0

        async def mock_exec(
            command: str, timeout: int | None = None
        ) -> tuple[int, str, str]:
            nonlocal call_count
            call_count += 1
            if command.startswith("mkdir"):
                return (0, "", "")
            if "profraw" in command:
                return (0, "", "")
            return (0, self.LIBFUZZER_LOG, "")

        with (
            patch.object(sandbox, "exec", side_effect=mock_exec),
            patch.object(
                sandbox,
                "collect_crashes",
                new_callable=AsyncMock,
                return_value=[crash_path],
            ),
        ):
            campaign = FuzzingCampaign(
                sandbox=sandbox,
                fuzz_target="fuzz_xml",
                duration_seconds=120,
            )
            result = await campaign.run()

        assert result.target_name == "test-target"
        assert result.engine == "libfuzzer"
        assert result.duration_seconds == 120
        assert result.timed_out is False
        assert result.oom_killed is False
        assert result.crash_files == [crash_path]
        assert result.stats.total_execs == 50000
        assert result.stats.execs_per_sec == 1000.0
        assert result.stats.corpus_size == 30

    @pytest.mark.asyncio
    async def test_crash_count_matches_collected_files(self) -> None:
        sandbox = _make_sandbox(engine="libfuzzer")
        crashes = [
            Path("/tmp/crashes/crash-aaa"),
            Path("/tmp/crashes/crash-bbb"),
        ]

        async def mock_exec(
            command: str, timeout: int | None = None
        ) -> tuple[int, str, str]:
            if command.startswith("mkdir"):
                return (0, "", "")
            if "profraw" in command:
                return (0, "", "")
            return (0, "", "")

        with (
            patch.object(sandbox, "exec", side_effect=mock_exec),
            patch.object(
                sandbox,
                "collect_crashes",
                new_callable=AsyncMock,
                return_value=crashes,
            ),
        ):
            campaign = FuzzingCampaign(sandbox=sandbox, fuzz_target="fuzz_xml")
            result = await campaign.run()

        assert result.stats.crashes_found == 2

    @pytest.mark.asyncio
    async def test_afl_engine_uses_afl_command(self) -> None:
        sandbox = _make_sandbox(engine="afl")
        captured_commands: list[str] = []

        async def mock_exec(
            command: str, timeout: int | None = None
        ) -> tuple[int, str, str]:
            captured_commands.append(command)
            if command.startswith("mkdir"):
                return (0, "", "")
            if "profraw" in command:
                return (0, "", "")
            return (0, "", "")

        with (
            patch.object(sandbox, "exec", side_effect=mock_exec),
            patch.object(
                sandbox,
                "collect_crashes",
                new_callable=AsyncMock,
                return_value=[],
            ),
        ):
            campaign = FuzzingCampaign(sandbox=sandbox, fuzz_target="fuzz_xml")
            result = await campaign.run()

        fuzzer_cmd = next(c for c in captured_commands if "afl-fuzz" in c)
        assert "afl-fuzz" in fuzzer_cmd
        assert result.engine == "afl"


# ---------------------------------------------------------------------------
# HonggfuzzEngine basic checks
# ---------------------------------------------------------------------------


class TestHonggfuzzEngine:
    def test_build_command_contains_honggfuzz(self) -> None:
        engine = HonggfuzzEngine()
        cmd = engine.build_command("fuzz_target", "/out/corpus", 300, [])
        assert "honggfuzz" in cmd

    def test_crash_glob(self) -> None:
        engine = HonggfuzzEngine()
        assert ".fuzz" in engine.crash_glob()

    def test_coverage_glob(self) -> None:
        engine = HonggfuzzEngine()
        assert ".profraw" in engine.coverage_glob()
