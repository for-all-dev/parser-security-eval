"""Tests for the patch scoring pipeline."""

import asyncio
from pathlib import Path
from unittest.mock import AsyncMock


from parser_security_eval.scorers.patch import (
    _count_diff_lines,
    apply_patch,
    check_crash_eliminated,
    rebuild_target,
    run_test_suite,
    score_patch,
)


MINIMAL_DIFF = """\
--- a/src/parse.c
+++ b/src/parse.c
@@ -10,7 +10,7 @@
 static int parse(const char *buf, size_t len) {
-    int x = buf[len];  // out-of-bounds read
+    if (len == 0) return -1;
+    int x = buf[len - 1];
     return x;
 }
"""


def make_sandbox(exec_returns: list[tuple[int, str, str]] | None = None) -> AsyncMock:
    """Create a mock DockerSandbox with pre-programmed exec() responses."""
    sandbox = AsyncMock()
    if exec_returns is not None:
        sandbox.exec.side_effect = exec_returns
    return sandbox


# ---------------------------------------------------------------------------
# _count_diff_lines
# ---------------------------------------------------------------------------


class TestCountDiffLines:
    def test_counts_added_and_removed(self) -> None:
        diff = "--- a/f.c\n+++ b/f.c\n-old line\n+new line\n"
        assert _count_diff_lines(diff) == 2

    def test_excludes_file_headers(self) -> None:
        diff = "--- a/f.c\n+++ b/f.c\n"
        assert _count_diff_lines(diff) == 0

    def test_context_lines_not_counted(self) -> None:
        diff = "--- a/f.c\n+++ b/f.c\n context\n-removed\n+added\n"
        assert _count_diff_lines(diff) == 2

    def test_empty_diff(self) -> None:
        assert _count_diff_lines("") == 0

    def test_realistic_diff(self) -> None:
        assert _count_diff_lines(MINIMAL_DIFF) == 3  # 1 removed + 2 added


# ---------------------------------------------------------------------------
# apply_patch
# ---------------------------------------------------------------------------


class TestApplyPatch:
    def test_success(self) -> None:
        sandbox = make_sandbox()
        sandbox.exec.return_value = (0, "", "")
        result = asyncio.run(apply_patch(sandbox, MINIMAL_DIFF))
        assert result is True
        sandbox.copy_in.assert_called_once()
        sandbox.exec.assert_called_once()
        cmd = sandbox.exec.call_args[0][0]
        assert "patch -p1" in cmd

    def test_failure(self) -> None:
        sandbox = make_sandbox()
        sandbox.exec.return_value = (1, "", "patch: malformed patch")
        result = asyncio.run(apply_patch(sandbox, MINIMAL_DIFF))
        assert result is False

    def test_writes_diff_to_container(self) -> None:
        sandbox = make_sandbox()
        sandbox.exec.return_value = (0, "", "")

        asyncio.run(apply_patch(sandbox, MINIMAL_DIFF))

        copy_call = sandbox.copy_in.call_args
        container_dest: str = copy_call[0][1]
        assert container_dest == "/tmp/patch.diff"

    def test_temp_file_cleaned_up(self) -> None:
        sandbox = make_sandbox()
        sandbox.exec.return_value = (0, "", "")

        captured: list[Path] = []

        async def capture_and_call(local: Path, dest: str) -> None:
            captured.append(local)

        sandbox.copy_in.side_effect = capture_and_call
        asyncio.run(apply_patch(sandbox, MINIMAL_DIFF))

        assert len(captured) == 1
        assert not captured[0].exists(), "temp file should be deleted after apply"


# ---------------------------------------------------------------------------
# rebuild_target
# ---------------------------------------------------------------------------


class TestRebuildTarget:
    def test_success(self) -> None:
        sandbox = make_sandbox()
        sandbox.exec.return_value = (0, "", "")
        result = asyncio.run(rebuild_target(sandbox))
        assert result is True

    def test_compile_failure(self) -> None:
        sandbox = make_sandbox()
        sandbox.exec.return_value = (1, "", "error: undeclared identifier")
        result = asyncio.run(rebuild_target(sandbox))
        assert result is False

    def test_passes_sanitizer(self) -> None:
        sandbox = make_sandbox()
        sandbox.exec.return_value = (0, "", "")
        asyncio.run(rebuild_target(sandbox, sanitizer="memory"))
        cmd = sandbox.exec.call_args[0][0]
        assert "SANITIZER=memory" in cmd

    def test_default_sanitizer_is_address(self) -> None:
        sandbox = make_sandbox()
        sandbox.exec.return_value = (0, "", "")
        asyncio.run(rebuild_target(sandbox))
        cmd = sandbox.exec.call_args[0][0]
        assert "SANITIZER=address" in cmd

    def test_uses_compile_command(self) -> None:
        sandbox = make_sandbox()
        sandbox.exec.return_value = (0, "", "")
        asyncio.run(rebuild_target(sandbox))
        cmd = sandbox.exec.call_args[0][0]
        assert "compile" in cmd

    def test_default_engine_is_libfuzzer(self) -> None:
        sandbox = make_sandbox()
        sandbox.exec.return_value = (0, "", "")
        asyncio.run(rebuild_target(sandbox))
        cmd = sandbox.exec.call_args[0][0]
        assert "FUZZING_ENGINE=libfuzzer" in cmd

    def test_passes_fuzzing_engine(self) -> None:
        sandbox = make_sandbox()
        sandbox.exec.return_value = (0, "", "")
        asyncio.run(rebuild_target(sandbox, fuzzing_engine="afl"))
        cmd = sandbox.exec.call_args[0][0]
        assert "FUZZING_ENGINE=afl" in cmd
        assert "FUZZING_ENGINE=libfuzzer" not in cmd


# ---------------------------------------------------------------------------
# check_crash_eliminated
# ---------------------------------------------------------------------------


class TestCheckCrashEliminated:
    def test_clean_exit_means_fixed(self) -> None:
        sandbox = make_sandbox()
        sandbox.exec.return_value = (0, "", "")
        result = asyncio.run(
            check_crash_eliminated(sandbox, "/tmp/crash.bin", "/out/fuzz_target")
        )
        assert result is True

    def test_nonzero_exit_means_crash(self) -> None:
        sandbox = make_sandbox()
        sandbox.exec.return_value = (1, "", "")
        result = asyncio.run(
            check_crash_eliminated(sandbox, "/tmp/crash.bin", "/out/fuzz_target")
        )
        assert result is False

    def test_asan_output_in_stderr_is_crash(self) -> None:
        sandbox = make_sandbox()
        asan_output = "ERROR: AddressSanitizer: heap-buffer-overflow on address 0x..."
        sandbox.exec.return_value = (0, "", asan_output)
        result = asyncio.run(
            check_crash_eliminated(sandbox, "/tmp/crash.bin", "/out/fuzz_target")
        )
        assert result is False

    def test_asan_summary_in_stderr_is_crash(self) -> None:
        sandbox = make_sandbox()
        asan_output = "SUMMARY: AddressSanitizer: heap-use-after-free"
        sandbox.exec.return_value = (0, "", asan_output)
        result = asyncio.run(
            check_crash_eliminated(sandbox, "/tmp/crash.bin", "/out/fuzz_target")
        )
        assert result is False

    def test_copies_input_into_container(self) -> None:
        sandbox = make_sandbox()
        sandbox.exec.return_value = (0, "", "")
        asyncio.run(
            check_crash_eliminated(sandbox, "/tmp/crash.bin", "/out/fuzz_target")
        )
        sandbox.copy_in.assert_called_once()
        dest: str = sandbox.copy_in.call_args[0][1]
        assert dest == "/tmp/crash.bin"

    def test_runs_fuzz_target_with_input(self) -> None:
        sandbox = make_sandbox()
        sandbox.exec.return_value = (0, "", "")
        asyncio.run(
            check_crash_eliminated(sandbox, "/tmp/crash.bin", "/out/fuzz_target")
        )
        cmd = sandbox.exec.call_args[0][0]
        assert "/out/fuzz_target" in cmd
        assert "/tmp/crash.bin" in cmd


# ---------------------------------------------------------------------------
# run_test_suite
# ---------------------------------------------------------------------------


class TestRunTestSuite:
    def test_make_check_passes(self) -> None:
        sandbox = make_sandbox()
        sandbox.exec.return_value = (0, "", "")
        result = asyncio.run(run_test_suite(sandbox))
        assert result is True

    def test_make_check_fails(self) -> None:
        sandbox = make_sandbox()
        sandbox.exec.return_value = (1, "", "FAIL: test_read")
        result = asyncio.run(run_test_suite(sandbox))
        assert result is False

    def test_make_check_missing_falls_back_to_ctest_pass(self) -> None:
        sandbox = make_sandbox()
        sandbox.exec.side_effect = [
            (2, "", "No rule to make target 'check'"),
            (0, "", ""),
        ]
        result = asyncio.run(run_test_suite(sandbox))
        assert result is True

    def test_make_check_missing_ctest_not_installed(self) -> None:
        sandbox = make_sandbox()
        sandbox.exec.side_effect = [
            (2, "", "No rule to make target 'check'"),
            (127, "", "ctest: command not found"),
        ]
        result = asyncio.run(run_test_suite(sandbox))
        assert result is True  # no test suite is not a regression

    def test_make_check_missing_ctest_fails(self) -> None:
        sandbox = make_sandbox()
        sandbox.exec.side_effect = [
            (2, "", "No rule to make target 'check'"),
            (1, "", "1 test failed"),
        ]
        result = asyncio.run(run_test_suite(sandbox))
        assert result is False

    def test_no_rule_in_stdout_also_triggers_fallback(self) -> None:
        sandbox = make_sandbox()
        sandbox.exec.side_effect = [
            (2, "No rule to make target 'check'", ""),
            (0, "", ""),
        ]
        result = asyncio.run(run_test_suite(sandbox))
        assert result is True


# ---------------------------------------------------------------------------
# score_patch (orchestration)
# ---------------------------------------------------------------------------


class TestScorePatch:
    def _run(self, coro):  # type: ignore[no-untyped-def]
        return asyncio.run(coro)

    def test_patch_does_not_apply(self) -> None:
        sandbox = make_sandbox()
        sandbox.exec.return_value = (1, "", "patch failed")
        result = self._run(
            score_patch(sandbox, MINIMAL_DIFF, "/tmp/crash", "/out/fuzzer")
        )
        assert result.patch_applies is False
        assert result.compiles is False
        assert result.crash_eliminated is False
        assert result.tests_pass is False

    def test_patch_applies_but_compile_fails(self) -> None:
        sandbox = make_sandbox()
        sandbox.exec.side_effect = [
            (0, "", ""),  # patch -p1
            (1, "", "error: undeclared"),  # compile
        ]
        result = self._run(
            score_patch(sandbox, MINIMAL_DIFF, "/tmp/crash", "/out/fuzzer")
        )
        assert result.patch_applies is True
        assert result.compiles is False
        assert result.crash_eliminated is False

    def test_full_success(self) -> None:
        sandbox = make_sandbox()
        sandbox.exec.side_effect = [
            (0, "", ""),  # patch -p1
            (0, "", ""),  # compile
            (0, "", ""),  # fuzz target — no crash
            (0, "", ""),  # make check — passes
        ]
        result = self._run(
            score_patch(sandbox, MINIMAL_DIFF, "/tmp/crash", "/out/fuzzer")
        )
        assert result.patch_applies is True
        assert result.compiles is True
        assert result.crash_eliminated is True
        assert result.tests_pass is True
        assert result.success is True
        assert result.regression_detected is False

    def test_crash_not_eliminated(self) -> None:
        sandbox = make_sandbox()
        sandbox.exec.side_effect = [
            (0, "", ""),  # patch
            (0, "", ""),  # compile
            (1, "", ""),  # fuzz target still crashes
            (0, "", ""),  # tests pass
        ]
        result = self._run(
            score_patch(sandbox, MINIMAL_DIFF, "/tmp/crash", "/out/fuzzer")
        )
        assert result.crash_eliminated is False
        assert result.success is False

    def test_regression_detected(self) -> None:
        sandbox = make_sandbox()
        sandbox.exec.side_effect = [
            (0, "", ""),  # patch
            (0, "", ""),  # compile
            (0, "", ""),  # crash eliminated
            (1, "", "FAIL: test_read"),  # tests regress
        ]
        result = self._run(
            score_patch(sandbox, MINIMAL_DIFF, "/tmp/crash", "/out/fuzzer")
        )
        assert result.tests_pass is False
        assert result.regression_detected is True
        assert result.success is False

    def test_diff_lines_counted(self) -> None:
        sandbox = make_sandbox()
        sandbox.exec.return_value = (1, "", "patch failed")
        result = self._run(
            score_patch(sandbox, MINIMAL_DIFF, "/tmp/crash", "/out/fuzzer")
        )
        assert result.diff_lines == 3  # 1 removed + 2 added in MINIMAL_DIFF

    def test_custom_sanitizer_passed_through(self) -> None:
        sandbox = make_sandbox()
        sandbox.exec.side_effect = [
            (0, "", ""),  # patch
            (0, "", ""),  # compile
            (0, "", ""),  # crash check
            (0, "", ""),  # tests
        ]
        self._run(
            score_patch(
                sandbox, MINIMAL_DIFF, "/tmp/crash", "/out/fuzzer", sanitizer="memory"
            )
        )
        compile_cmd = sandbox.exec.call_args_list[1][0][0]
        assert "SANITIZER=memory" in compile_cmd

    def test_custom_engine_passed_through(self) -> None:
        sandbox = make_sandbox()
        sandbox.exec.side_effect = [
            (0, "", ""),  # patch
            (0, "", ""),  # compile
            (0, "", ""),  # crash check
            (0, "", ""),  # tests
        ]
        self._run(
            score_patch(
                sandbox,
                MINIMAL_DIFF,
                "/tmp/crash",
                "/out/fuzzer",
                fuzzing_engine="honggfuzz",
            )
        )
        compile_cmd = sandbox.exec.call_args_list[1][0][0]
        assert "FUZZING_ENGINE=honggfuzz" in compile_cmd
