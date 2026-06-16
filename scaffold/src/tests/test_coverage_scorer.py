"""Tests for coverage scorer — mocked sandbox, no Docker required."""

from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from parser_security_eval.sandbox.docker import DockerSandbox, SandboxConfig
from parser_security_eval.scorers.coverage import (
    CoverageResult,
    _parse_coverage_report,
    _parse_libfuzzer_stats,
    generate_coverage_report,
    run_fuzzer_and_measure,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_sandbox(**overrides: object) -> DockerSandbox:
    defaults: dict[str, object] = {
        "target_name": "libpng",
        "target_dir": Path("/tmp/targets/libpng"),
    }
    defaults.update(overrides)
    config = SandboxConfig(**defaults)  # type: ignore[arg-type]
    sandbox = DockerSandbox(config)
    sandbox._container_id = "c123"
    return sandbox


LIBFUZZER_OUTPUT = """\
INFO: Seed: 1234567890
INFO: Loaded 1 modules   (1234 inline 8-bit counters)
INFO: -max_total_time is not provided; libFuzzer will not stop on its own.
#2\tINIT cov: 10 ft: 10 corp: 1/1b exec/s: 0 rss: 30Mb
#1024\tpulse  cov: 150 ft: 200 corp: 50/2Kb exec/s: 512 rss: 40Mb
#50000\tpulse  cov: 200 ft: 300 corp: 100/5Kb exec/s: 1250 rss: 50Mb
stat::number_of_executed_inputs: 50000
stat::average_exec_per_sec:     1250
stat::new_units_added:          100
stat::slowest_unit_time_sec:    0
stat::peak_rss_mb:              50
"""

LLVM_COV_REPORT = """\
Filename                      Regions    Missed Regions     Cover   Functions  Missed Functions  Cover   Lines  Missed Lines     Cover   Branches   Missed Branches     Cover
---                           ---        ---                ---     ---        ---               ---     ---    ---              ---     ---        ---                 ---
/src/libpng/png.c             100        20                 80.00%  50         10                80.00%  200    40               80.00%  150        30                  80.00%
/src/libpng/pngread.c         80         40                 50.00%  30         15                50.00%  100    50               50.00%  60         30                  50.00%
---                           ---        ---                ---     ---        ---               ---     ---    ---              ---     ---        ---                 ---
TOTAL                         180        60                 66.67%  80         25                68.75%  300    90               70.00%  210        60                  71.43%
"""

LLVM_COV_REPORT_NO_BRANCHES = """\
Filename                      Regions    Missed Regions     Cover   Functions  Missed Functions  Cover   Lines  Missed Lines     Cover
---
/src/libpng/png.c             100        20                 80.00%  50         10                80.00%  200    40               80.00%
---
TOTAL                         100        20                 80.00%  50         10                80.00%  200    40               80.00%
"""


# ---------------------------------------------------------------------------
# Unit: _parse_libfuzzer_stats
# ---------------------------------------------------------------------------


class TestParseLibfuzzerStats:
    def test_parses_final_stats(self) -> None:
        total, execs_sec = _parse_libfuzzer_stats(LIBFUZZER_OUTPUT)
        assert total == 50000
        assert execs_sec == 1250.0

    def test_fallback_to_progress_lines(self) -> None:
        output = "#100\tpulse exec/s: 200\n#5000\tDONE exec/s: 500\n"
        total, execs_sec = _parse_libfuzzer_stats(output)
        assert total == 5000
        assert execs_sec == 500.0

    def test_empty_output(self) -> None:
        total, execs_sec = _parse_libfuzzer_stats("")
        assert total == 0
        assert execs_sec == 0.0

    def test_only_total(self) -> None:
        output = "stat::number_of_executed_inputs: 999\n"
        total, execs_sec = _parse_libfuzzer_stats(output)
        assert total == 999
        assert execs_sec == 0.0


# ---------------------------------------------------------------------------
# Unit: _parse_coverage_report
# ---------------------------------------------------------------------------


class TestParseCoverageReport:
    def test_full_report_with_branches(self) -> None:
        line_pct, branch_pct, func_pct = _parse_coverage_report(LLVM_COV_REPORT)
        assert func_pct == pytest.approx(68.75)
        assert line_pct == pytest.approx(70.0)
        assert branch_pct == pytest.approx(71.43)

    def test_report_without_branches(self) -> None:
        line_pct, branch_pct, func_pct = _parse_coverage_report(
            LLVM_COV_REPORT_NO_BRANCHES
        )
        assert func_pct == pytest.approx(80.0)
        assert line_pct == pytest.approx(80.0)
        assert branch_pct == 0.0

    def test_empty_report(self) -> None:
        line_pct, branch_pct, func_pct = _parse_coverage_report("")
        assert line_pct == 0.0
        assert branch_pct == 0.0
        assert func_pct == 0.0

    def test_single_percentage(self) -> None:
        report = "TOTAL  100  20  80.00%\n"
        line_pct, branch_pct, func_pct = _parse_coverage_report(report)
        assert line_pct == pytest.approx(80.0)


# ---------------------------------------------------------------------------
# Integration: generate_coverage_report
# ---------------------------------------------------------------------------


class TestGenerateCoverageReport:
    @pytest.mark.asyncio
    async def test_success(self) -> None:
        sandbox = _make_sandbox()
        with patch.object(sandbox, "exec", new_callable=AsyncMock) as mock_exec:
            mock_exec.side_effect = [
                (0, "", ""),  # coverage build
                (0, "", ""),  # mkdir /tmp/cov
                (0, "", ""),  # replay corpus
                (0, "", ""),  # llvm-profdata merge
                (0, LLVM_COV_REPORT, ""),  # llvm-cov report
            ]
            result = await generate_coverage_report(sandbox, "fuzz_png", "/out/corpus")

        assert result["line_coverage_pct"] == pytest.approx(70.0)
        assert result["function_coverage_pct"] == pytest.approx(68.75)
        assert result["branch_coverage_pct"] == pytest.approx(71.43)
        assert "TOTAL" in result["report"]

        # Verify coverage build command includes instrumentation flags.
        build_cmd = mock_exec.call_args_list[0][0][0]
        assert "-fprofile-instr-generate" in build_cmd
        assert "-fcoverage-mapping" in build_cmd

    @pytest.mark.asyncio
    async def test_build_failure_raises(self) -> None:
        sandbox = _make_sandbox()
        with patch.object(sandbox, "exec", new_callable=AsyncMock) as mock_exec:
            mock_exec.return_value = (1, "", "compile error")
            with pytest.raises(RuntimeError, match="Coverage build failed"):
                await generate_coverage_report(sandbox, "fuzz_png", "/out/corpus")

    @pytest.mark.asyncio
    async def test_profdata_merge_failure_raises(self) -> None:
        sandbox = _make_sandbox()
        with patch.object(sandbox, "exec", new_callable=AsyncMock) as mock_exec:
            mock_exec.side_effect = [
                (0, "", ""),  # coverage build
                (0, "", ""),  # mkdir
                (0, "", ""),  # replay
                (1, "", "no profile files"),  # merge fails
            ]
            with pytest.raises(RuntimeError, match="llvm-profdata merge failed"):
                await generate_coverage_report(sandbox, "fuzz_png", "/out/corpus")

    @pytest.mark.asyncio
    async def test_llvm_cov_report_failure_raises(self) -> None:
        sandbox = _make_sandbox()
        with patch.object(sandbox, "exec", new_callable=AsyncMock) as mock_exec:
            mock_exec.side_effect = [
                (0, "", ""),  # coverage build
                (0, "", ""),  # mkdir
                (0, "", ""),  # replay
                (0, "", ""),  # merge
                (1, "", "bad profile"),  # report fails
            ]
            with pytest.raises(RuntimeError, match="llvm-cov report failed"):
                await generate_coverage_report(sandbox, "fuzz_png", "/out/corpus")


# ---------------------------------------------------------------------------
# Integration: run_fuzzer_and_measure
# ---------------------------------------------------------------------------


class TestRunFuzzerAndMeasure:
    @pytest.mark.asyncio
    async def test_full_pipeline(self) -> None:
        sandbox = _make_sandbox()
        with (
            patch.object(sandbox, "run_fuzzer", new_callable=AsyncMock) as mock_fuzz,
            patch.object(
                sandbox, "collect_crashes", new_callable=AsyncMock
            ) as mock_crashes,
            patch.object(sandbox, "exec", new_callable=AsyncMock) as mock_exec,
        ):
            mock_fuzz.return_value = (0, LIBFUZZER_OUTPUT)
            mock_crashes.return_value = [Path("/tmp/crash-1"), Path("/tmp/crash-2")]
            mock_exec.side_effect = [
                (0, "", ""),  # coverage build
                (0, "", ""),  # mkdir /tmp/cov
                (0, "", ""),  # replay corpus
                (0, "", ""),  # llvm-profdata merge
                (0, LLVM_COV_REPORT, ""),  # llvm-cov report
            ]

            result = await run_fuzzer_and_measure(
                sandbox,
                "fuzz_png",
                corpus_dir="/out/corpus",
                duration_seconds=60,
                engine="libfuzzer",
            )

        assert isinstance(result, CoverageResult)
        assert result.line_coverage_pct == pytest.approx(70.0)
        assert result.branch_coverage_pct == pytest.approx(71.43)
        assert result.function_coverage_pct == pytest.approx(68.75)
        assert result.unique_crashes == 2
        assert result.total_executions == 50000
        assert result.execs_per_sec == 1250.0

        # Verify fuzzer was called with correct args.
        mock_fuzz.assert_awaited_once_with(
            "fuzz_png", duration_seconds=60, corpus_dir="/out/corpus"
        )

    @pytest.mark.asyncio
    async def test_no_crashes(self) -> None:
        sandbox = _make_sandbox()
        with (
            patch.object(sandbox, "run_fuzzer", new_callable=AsyncMock) as mock_fuzz,
            patch.object(
                sandbox, "collect_crashes", new_callable=AsyncMock
            ) as mock_crashes,
            patch.object(sandbox, "exec", new_callable=AsyncMock) as mock_exec,
        ):
            mock_fuzz.return_value = (0, LIBFUZZER_OUTPUT)
            mock_crashes.return_value = []
            mock_exec.side_effect = [
                (0, "", ""),
                (0, "", ""),
                (0, "", ""),
                (0, "", ""),
                (0, LLVM_COV_REPORT_NO_BRANCHES, ""),
            ]

            result = await run_fuzzer_and_measure(
                sandbox, "fuzz_png", duration_seconds=30
            )

        assert result.unique_crashes == 0
        assert result.line_coverage_pct == pytest.approx(80.0)
        assert result.branch_coverage_pct == 0.0

    @pytest.mark.asyncio
    async def test_unsupported_engine_raises(self) -> None:
        sandbox = _make_sandbox()
        with pytest.raises(NotImplementedError, match="afl"):
            await run_fuzzer_and_measure(sandbox, "fuzz_png", engine="afl")

    @pytest.mark.asyncio
    async def test_default_args(self) -> None:
        sandbox = _make_sandbox()
        with (
            patch.object(sandbox, "run_fuzzer", new_callable=AsyncMock) as mock_fuzz,
            patch.object(
                sandbox, "collect_crashes", new_callable=AsyncMock
            ) as mock_crashes,
            patch.object(sandbox, "exec", new_callable=AsyncMock) as mock_exec,
        ):
            mock_fuzz.return_value = (0, LIBFUZZER_OUTPUT)
            mock_crashes.return_value = []
            mock_exec.side_effect = [
                (0, "", ""),
                (0, "", ""),
                (0, "", ""),
                (0, "", ""),
                (0, LLVM_COV_REPORT, ""),
            ]

            await run_fuzzer_and_measure(sandbox, "fuzz_png")

        # Verify defaults: corpus_dir="/out/corpus", duration=300, engine="libfuzzer"
        mock_fuzz.assert_awaited_once_with(
            "fuzz_png", duration_seconds=300, corpus_dir="/out/corpus"
        )
