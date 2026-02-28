"""Scorers for evaluating patches against vulnerabilities.

Pipeline:
1. Apply the patch to the vulnerable source inside the sandbox
2. Rebuild with sanitizers
3. Run the triggering input — does it still crash?
4. Run the test suite — any regressions?
"""

import tempfile
from pathlib import Path

from parser_security_eval.models.scoring import PatchResult
from parser_security_eval.sandbox.docker import DockerSandbox


def _count_diff_lines(patch_diff: str) -> int:
    """Count changed lines (+/-) in a unified diff, excluding file headers."""
    return sum(
        1
        for line in patch_diff.splitlines()
        if (line.startswith("+") or line.startswith("-"))
        and not line.startswith("+++")
        and not line.startswith("---")
    )


async def apply_patch(sandbox: DockerSandbox, patch_diff: str) -> bool:
    """Apply a unified diff to the source tree in the sandbox.

    Runs ``patch -p1`` from ``/src/<target>`` so that diffs with paths like
    ``--- a/SAX2.c`` resolve correctly against the oss-fuzz source layout.
    Returns True if the patch applied cleanly.
    """
    with tempfile.NamedTemporaryFile(mode="w", suffix=".diff", delete=False) as f:
        f.write(patch_diff)
        tmp_path = Path(f.name)

    src_dir = f"/src/{sandbox.config.target_name}"
    try:
        await sandbox.copy_in(tmp_path, "/tmp/patch.diff")
        exit_code, _, _ = await sandbox.exec(
            f"cd {src_dir} && patch -p1 --fuzz=3 < /tmp/patch.diff"
        )
        return exit_code == 0
    finally:
        tmp_path.unlink(missing_ok=True)


async def rebuild_target(
    sandbox: DockerSandbox,
    sanitizer: str = "address",
    fuzzing_engine: str = "libfuzzer",
) -> bool:
    """Rebuild the parser target with the specified sanitizer and fuzzing engine.

    Returns True if compilation succeeded.
    """
    exit_code, _, _ = await sandbox.exec(
        f"env SANITIZER={sanitizer} FUZZING_ENGINE={fuzzing_engine} FUZZING_LANGUAGE=c compile"
    )
    return exit_code == 0


async def check_crash_eliminated(
    sandbox: DockerSandbox,
    triggering_input_path: str,
    fuzz_target_binary: str,
) -> bool:
    """Run the triggering input against the patched binary.

    Returns True if the binary no longer crashes (clean exit, no ASAN output).
    """
    local_input = Path(triggering_input_path)
    container_input = f"/tmp/{local_input.name}"
    await sandbox.copy_in(local_input, container_input)

    exit_code, _, stderr = await sandbox.exec(f"{fuzz_target_binary} {container_input}")
    asan_crash = (
        "ERROR: AddressSanitizer" in stderr or "SUMMARY: AddressSanitizer" in stderr
    )
    return exit_code == 0 and not asan_crash


async def run_test_suite(sandbox: DockerSandbox) -> bool:
    """Run the target's test suite in the sandbox.

    Tries make check (autotools convention), falls back to ctest (cmake).
    Returns True if tests pass or no test suite is present.
    """
    exit_code, stdout, stderr = await sandbox.exec("make check")
    if exit_code == 0:
        return True

    combined = stdout + stderr
    if "No rule to make target" in combined:
        # make check not available; try ctest (cmake projects)
        exit_code, _, _ = await sandbox.exec("ctest --output-on-failure")
        if exit_code == 0:
            return True
        if exit_code == 127:  # ctest not installed — no test suite, not a regression
            return True
        return False

    return False


async def score_patch(
    sandbox: DockerSandbox,
    patch_diff: str,
    triggering_input_path: str,
    fuzz_target_binary: str,
    sanitizer: str = "address",
    fuzzing_engine: str = "libfuzzer",
) -> PatchResult:
    """Full scoring pipeline for a patch.

    Short-circuits early if the patch doesn't apply or doesn't compile.
    """
    diff_lines = _count_diff_lines(patch_diff)

    patch_applies = await apply_patch(sandbox, patch_diff)
    if not patch_applies:
        return PatchResult(
            patch_applies=False,
            compiles=False,
            crash_eliminated=False,
            tests_pass=False,
            diff_lines=diff_lines,
        )

    compiles = await rebuild_target(sandbox, sanitizer, fuzzing_engine)
    if not compiles:
        return PatchResult(
            patch_applies=True,
            compiles=False,
            crash_eliminated=False,
            tests_pass=False,
            diff_lines=diff_lines,
        )

    crash_eliminated = await check_crash_eliminated(
        sandbox, triggering_input_path, fuzz_target_binary
    )
    tests_pass = await run_test_suite(sandbox)

    return PatchResult(
        patch_applies=True,
        compiles=True,
        crash_eliminated=crash_eliminated,
        tests_pass=tests_pass,
        diff_lines=diff_lines,
        regression_detected=not tests_pass,
    )
