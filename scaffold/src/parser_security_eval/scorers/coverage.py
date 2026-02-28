"""Scorers for evaluating fuzz harness coverage.

After a fuzz harness is compiled and run for a fixed duration,
measure the code coverage achieved by replaying the generated
corpus through a coverage-instrumented build.
"""

import re
from dataclasses import dataclass

from parser_security_eval.sandbox.docker import DockerSandbox


@dataclass
class CoverageResult:
    """Coverage metrics from a fuzzing run."""

    line_coverage_pct: float
    branch_coverage_pct: float
    function_coverage_pct: float
    unique_crashes: int
    total_executions: int
    execs_per_sec: float


# ---------------------------------------------------------------------------
# Parsing helpers
# ---------------------------------------------------------------------------


def _parse_libfuzzer_stats(output: str) -> tuple[int, float]:
    """Extract execution count and speed from libFuzzer ``-print_final_stats`` output.

    Returns ``(total_executions, execs_per_sec)``.
    """
    total = 0
    execs_sec = 0.0

    # libFuzzer final stats line: ``stat::number_of_executed_inputs: 12345``
    m = re.search(r"stat::number_of_executed_inputs:\s*(\d+)", output)
    if m:
        total = int(m.group(1))

    # Speed from final stats: ``stat::average_exec_per_sec:\s*(\d+)``
    m = re.search(r"stat::average_exec_per_sec:\s*(\d+)", output)
    if m:
        execs_sec = float(m.group(1))

    # Fallback: parse the last ``#NNN`` counter and ``exec/s: NNN`` from progress lines.
    if total == 0:
        for m_iter in re.finditer(r"#(\d+)", output):
            val = int(m_iter.group(1))
            if val > total:
                total = val

    if execs_sec == 0.0:
        last_match = None
        for last_match in re.finditer(r"exec/s[:\s]+(\d+)", output):
            pass
        if last_match:
            execs_sec = float(last_match.group(1))

    return total, execs_sec


def _parse_coverage_report(report: str) -> tuple[float, float, float]:
    """Parse ``llvm-cov report`` output and return (line%, branch%, function%).

    The TOTAL row emits percentages in the order:
    Region Cover | Function Cover | Line Cover | Branch Cover (if present).
    """
    line_pct = 0.0
    branch_pct = 0.0
    func_pct = 0.0

    for line in report.splitlines():
        if not line.strip().startswith("TOTAL"):
            continue
        pcts = re.findall(r"([\d.]+)%", line)
        if len(pcts) >= 3:
            # Columns: Region Cover%, Function Cover%, Line Cover%
            func_pct = float(pcts[1])
            line_pct = float(pcts[2])
        elif len(pcts) == 2:
            func_pct = float(pcts[0])
            line_pct = float(pcts[1])
        elif len(pcts) == 1:
            line_pct = float(pcts[0])
        # Branch cover is the 4th percentage when ``-show-branch-summary`` is used.
        if len(pcts) >= 4:
            branch_pct = float(pcts[3])
        break

    return line_pct, branch_pct, func_pct


# ---------------------------------------------------------------------------
# Coverage-instrumented build + replay
# ---------------------------------------------------------------------------

_COV_BUILD_CMD = (
    "export CC=clang CXX=clang++ "
    'CFLAGS="-fprofile-instr-generate -fcoverage-mapping -O1 -fno-omit-frame-pointer" '
    'CXXFLAGS="-fprofile-instr-generate -fcoverage-mapping -O1 -fno-omit-frame-pointer" '
    "LIB_FUZZING_ENGINE=/usr/lib/libFuzzer.a "
    "SRC=/src OUT=/out/cov WORK=/work/cov "
    "&& mkdir -p /out/cov /work/cov "
    "&& bash /src/build.sh"
)


async def generate_coverage_report(
    sandbox: DockerSandbox,
    fuzz_target_binary: str,
    corpus_dir: str,
) -> dict:
    """Generate an llvm-cov coverage report from a corpus.

    Steps:
    1. Build a coverage-instrumented binary (``-fprofile-instr-generate
       -fcoverage-mapping``, no sanitizers).
    2. Replay every corpus input through it.
    3. Merge raw profiles with ``llvm-profdata merge``.
    4. Emit a summary via ``llvm-cov report``.

    Returns a dict with ``line_coverage_pct``, ``branch_coverage_pct``,
    ``function_coverage_pct``, and the raw ``report`` text.
    """
    # 1. Coverage build
    rc, _, stderr = await sandbox.exec(_COV_BUILD_CMD, timeout=600)
    if rc != 0:
        raise RuntimeError(f"Coverage build failed (rc={rc}): {stderr}")

    cov_binary = f"/out/cov/{fuzz_target_binary}"

    # 2. Replay corpus — each input produces a raw .profraw file.
    replay_cmd = (
        f"cd {corpus_dir} && "
        "for f in *; do "
        f'  LLVM_PROFILE_FILE="/tmp/cov/%p-%m.profraw" {cov_binary} "$f" 2>/dev/null || true; '
        "done"
    )
    await sandbox.exec("mkdir -p /tmp/cov", timeout=10)
    await sandbox.exec(replay_cmd, timeout=300)

    # 3. Merge profiles
    merge_cmd = (
        "llvm-profdata merge -sparse /tmp/cov/*.profraw -o /tmp/cov/merged.profdata"
    )
    rc, _, stderr = await sandbox.exec(merge_cmd, timeout=60)
    if rc != 0:
        raise RuntimeError(f"llvm-profdata merge failed (rc={rc}): {stderr}")

    # 4. Generate report
    report_cmd = (
        f"llvm-cov report {cov_binary} "
        "-instr-profile=/tmp/cov/merged.profdata "
        "-show-branch-summary"
    )
    rc, stdout, stderr = await sandbox.exec(report_cmd, timeout=60)
    if rc != 0:
        raise RuntimeError(f"llvm-cov report failed (rc={rc}): {stderr}")

    line_pct, branch_pct, func_pct = _parse_coverage_report(stdout)

    return {
        "line_coverage_pct": line_pct,
        "branch_coverage_pct": branch_pct,
        "function_coverage_pct": func_pct,
        "report": stdout,
    }


# ---------------------------------------------------------------------------
# Top-level scorer entry point
# ---------------------------------------------------------------------------


async def run_fuzzer_and_measure(
    sandbox: DockerSandbox,
    fuzz_target_binary: str,
    corpus_dir: str = "/out/corpus",
    duration_seconds: int = 300,
    engine: str = "libfuzzer",
) -> CoverageResult:
    """Run a fuzzer for a fixed duration and collect coverage metrics.

    1. Run the fuzzer (via the sandbox) to build a corpus and discover crashes.
    2. Build a separate coverage-instrumented binary.
    3. Replay the corpus through the coverage binary.
    4. Return a :class:`CoverageResult`.
    """
    if engine != "libfuzzer":
        raise NotImplementedError(
            f"Engine {engine!r} not yet supported for coverage measurement"
        )

    # --- Step 1: fuzz ---
    _rc, output = await sandbox.run_fuzzer(
        fuzz_target_binary,
        duration_seconds=duration_seconds,
        corpus_dir=corpus_dir,
    )
    total_execs, execs_sec = _parse_libfuzzer_stats(output)

    # Count crashes produced.
    crash_paths = await sandbox.collect_crashes()
    unique_crashes = len(crash_paths)

    # --- Step 2-3: coverage measurement ---
    cov = await generate_coverage_report(sandbox, fuzz_target_binary, corpus_dir)

    return CoverageResult(
        line_coverage_pct=cov["line_coverage_pct"],
        branch_coverage_pct=cov["branch_coverage_pct"],
        function_coverage_pct=cov["function_coverage_pct"],
        unique_crashes=unique_crashes,
        total_executions=total_execs,
        execs_per_sec=execs_sec,
    )
