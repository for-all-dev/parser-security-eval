"""Live fuzzing campaign runner.

A *campaign* is one complete, time-bounded fuzzing run against a single fuzz
target: the fuzzer starts inside the sandbox, runs for a configurable duration
(default 300 s), then stops and hands back all artifacts — crash inputs,
coverage profiles, and execution statistics.

This module sits above ``DockerSandbox``.  Where ``DockerSandbox.run_fuzzer()``
is a thin wrapper that fires a command and returns raw output,
``FuzzingCampaign`` adds:

- **Engine abstraction** — ``FuzzerEngine`` implementations translate a common
  interface into engine-specific shell commands (libFuzzer, AFL++, Honggfuzz).
  New engines can be added by implementing the four-method protocol and
  registering them in ``_ENGINES``.
- **OOM / timeout detection** — exit code 137 (SIGKILL from the OOM killer)
  and -1 (our asyncio timeout) are surfaced as explicit boolean flags on
  ``CampaignResult`` rather than buried in exit codes.
- **Artifact collection** — crash inputs and ``.profraw`` coverage profiles are
  copied out of the container into a local temp directory and returned as
  ``Path`` lists for downstream processing.
- **Stats parsing** — engine-specific log parsers extract executions/sec,
  total executions, corpus size, and crash count into a structured
  ``FuzzingStats`` model.

Typical usage::

    async with DockerSandbox(config) as sandbox:
        await sandbox.build_target()
        result = await FuzzingCampaign(sandbox, "libxml2_xml_read_memory_fuzzer").run()
        print(result.stats.execs_per_sec, len(result.crash_files))
"""

import re
import tempfile
from pathlib import Path
from typing import Protocol

from pydantic import BaseModel

from parser_security_eval.log import get_log
from parser_security_eval.sandbox.docker import DockerSandbox

log = get_log(__name__)


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


class FuzzingStats(BaseModel):
    """Parsed stats from a fuzzing run."""

    execs_per_sec: float | None = None
    total_execs: int | None = None
    corpus_size: int | None = None
    crashes_found: int = 0
    # Peak code-coverage the fuzzer discovered (libFuzzer "cov:" = number of
    # covered PCs/edges). >0 means the harness actually reaches target code; 0
    # means it never got past its own entry (e.g. crashes on its own input).
    # NOT a line-coverage percentage (that needs an instrumented build).
    coverage_pcs: int = 0
    engine: str = ""


class CampaignResult(BaseModel):
    """Result of a completed fuzzing campaign."""

    target_name: str
    engine: str
    duration_seconds: int
    crash_files: list[Path]  # local paths to collected crash artifacts
    coverage_raw_profiles: list[
        Path
    ]  # local paths to .profraw files (empty if not available)
    stats: FuzzingStats
    timed_out: bool = False
    oom_killed: bool = False
    raw_log: str = ""


# ---------------------------------------------------------------------------
# Fuzzer engine protocol and concrete implementations
# ---------------------------------------------------------------------------


class FuzzerEngine(Protocol):
    """Protocol for fuzzer engine implementations."""

    def build_command(
        self,
        fuzz_target: str,
        corpus_dir: str,
        duration: int,
        extra_flags: list[str],
    ) -> str:
        """Build the shell command to run the fuzzer."""
        ...

    def parse_stats(self, log: str) -> FuzzingStats:
        """Parse fuzzer output log into FuzzingStats."""
        ...

    def crash_glob(self) -> str:
        """Glob pattern inside the container for crash files."""
        ...

    def coverage_glob(self) -> str:
        """Glob pattern for .profraw coverage files."""
        ...


class LibFuzzerEngine(FuzzerEngine):
    """libFuzzer engine implementation."""

    def build_command(
        self,
        fuzz_target: str,
        corpus_dir: str,
        duration: int,
        extra_flags: list[str],
    ) -> str:
        flags = " ".join(extra_flags) if extra_flags else ""
        cmd = (
            f"timeout {duration} "
            f"/out/{fuzz_target} "
            f"{corpus_dir} "
            f"-artifact_prefix=/out/crashes/ "
            f"-max_total_time={duration} "
            f"-print_final_stats=1"
        )
        if flags:
            cmd += f" {flags}"
        return cmd

    def parse_stats(self, log: str) -> FuzzingStats:
        """Parse libFuzzer stat:: lines from the log.

        libFuzzer emits lines like:
          stat::number_of_executed_units: 12345
          stat::average_exec_per_sec: 1234
          stat::corpus_size: 56
          stat::crash_count: 0
        """
        stats = FuzzingStats(engine="libfuzzer")
        for line in log.splitlines():
            line = line.strip()
            if not line.startswith("stat::"):
                continue
            # Format: "stat::<key>: <value>"
            rest = line[len("stat::") :]
            if ":" not in rest:
                continue
            key, _, value_str = rest.partition(":")
            key = key.strip()
            value_str = value_str.strip()
            try:
                value = int(value_str)
            except ValueError:
                try:
                    value_f = float(value_str)
                except ValueError:
                    continue
                if key == "average_exec_per_sec":
                    stats.execs_per_sec = value_f
                continue

            if key == "number_of_executed_units":
                stats.total_execs = value
            elif key == "average_exec_per_sec":
                stats.execs_per_sec = float(value)
            elif key == "corpus_size":
                stats.corpus_size = value
            elif key == "crash_count":
                stats.crashes_found = value

        # Peak coverage: libFuzzer prints running lines like
        #   "#1024 NEW    cov: 567 ft: 890 corp: ..."
        # where cov: is the number of covered PCs/edges. Take the max seen.
        cov_values = [int(m) for m in re.findall(r"\bcov:\s*(\d+)", log)]
        if cov_values:
            stats.coverage_pcs = max(cov_values)

        return stats

    def crash_glob(self) -> str:
        return "/out/crashes/crash-* /out/crashes/leak-* /out/crashes/timeout-*"

    def coverage_glob(self) -> str:
        return "/out/*.profraw"


class AFLPlusPlusEngine(FuzzerEngine):
    """AFL++ engine implementation."""

    def build_command(
        self,
        fuzz_target: str,
        corpus_dir: str,
        duration: int,
        extra_flags: list[str],
    ) -> str:
        flags = " ".join(extra_flags) if extra_flags else ""
        cmd = (
            f"timeout {duration} "
            f"afl-fuzz -i {corpus_dir} -o /out/crashes "
            f"-V {duration} "
            f"-- /out/{fuzz_target}"
        )
        if flags:
            cmd += f" {flags}"
        return cmd

    def parse_stats(self, log: str) -> FuzzingStats:
        """Parse AFL++ fuzzer_stats output.

        AFL++ writes a fuzzer_stats file; we parse key: value lines from the log.
        """
        stats = FuzzingStats(engine="afl++")
        for line in log.splitlines():
            line = line.strip()
            if ":" not in line:
                continue
            key, _, value_str = line.partition(":")
            key = key.strip()
            value_str = value_str.strip()
            try:
                value = int(value_str)
            except ValueError:
                try:
                    value_f = float(value_str)
                except ValueError:
                    continue
                if key == "execs_per_sec":
                    stats.execs_per_sec = value_f
                continue

            if key == "execs_done":
                stats.total_execs = value
            elif key == "execs_per_sec":
                stats.execs_per_sec = float(value)
            elif key == "corpus_count":
                stats.corpus_size = value
            elif key == "saved_crashes":
                stats.crashes_found = value
            elif key == "unique_crashes":
                stats.crashes_found = value

        return stats

    def crash_glob(self) -> str:
        return "/out/crashes/crashes/id:*"

    def coverage_glob(self) -> str:
        return "/out/*.profraw"


class HonggfuzzEngine(FuzzerEngine):
    """Honggfuzz engine implementation."""

    def build_command(
        self,
        fuzz_target: str,
        corpus_dir: str,
        duration: int,
        extra_flags: list[str],
    ) -> str:
        flags = " ".join(extra_flags) if extra_flags else ""
        cmd = (
            f"timeout {duration} "
            f"honggfuzz -f {corpus_dir} -W /out/crashes "
            f"--run_time {duration} "
            f"-- /out/{fuzz_target}"
        )
        if flags:
            cmd += f" {flags}"
        return cmd

    def parse_stats(self, log: str) -> FuzzingStats:
        """Parse honggfuzz log output for stats."""
        stats = FuzzingStats(engine="honggfuzz")
        for line in log.splitlines():
            line = line.strip()
            # honggfuzz emits lines like: "Iterations: 12345" and similar
            if ":" not in line:
                continue
            key, _, value_str = line.partition(":")
            key = key.strip().lower()
            value_str = value_str.strip()
            try:
                value = int(value_str)
            except ValueError:
                try:
                    value_f = float(value_str)
                except ValueError:
                    continue
                if "speed" in key or "exec" in key:
                    stats.execs_per_sec = value_f
                continue

            if "iter" in key:
                stats.total_execs = value
            elif "speed" in key or "exec" in key:
                stats.execs_per_sec = float(value)
            elif "corpus" in key:
                stats.corpus_size = value
            elif "crash" in key:
                stats.crashes_found = value

        return stats

    def crash_glob(self) -> str:
        return "/out/crashes/*.fuzz"

    def coverage_glob(self) -> str:
        return "/out/*.profraw"


# ---------------------------------------------------------------------------
# Engine registry
# ---------------------------------------------------------------------------

_ENGINES: dict[str, FuzzerEngine] = {
    "libfuzzer": LibFuzzerEngine(),
    "afl": AFLPlusPlusEngine(),
    "afl++": AFLPlusPlusEngine(),
    "honggfuzz": HonggfuzzEngine(),
}


def _get_engine(engine_name: str) -> FuzzerEngine:
    """Return the engine implementation for the given name."""
    engine = _ENGINES.get(engine_name)
    if engine is None:
        log.warn("unknown engine, falling back to libfuzzer", engine=engine_name)
        return _ENGINES["libfuzzer"]
    return engine


# ---------------------------------------------------------------------------
# FuzzingCampaign
# ---------------------------------------------------------------------------


class FuzzingCampaign:
    """Orchestrates a complete fuzzing campaign in a DockerSandbox.

    Preferred higher-level alternative to DockerSandbox.run_fuzzer().
    Handles OOM/timeout detection, stats parsing, and artifact collection.
    """

    def __init__(
        self,
        sandbox: DockerSandbox,
        fuzz_target: str,
        duration_seconds: int = 300,
        corpus_dir: str = "/out/corpus",
        extra_flags: list[str] | None = None,
    ) -> None:
        self.sandbox = sandbox
        self.fuzz_target = fuzz_target
        self.duration_seconds = duration_seconds
        self.corpus_dir = corpus_dir
        self.extra_flags = extra_flags or []

    async def run(self) -> CampaignResult:
        """Execute the fuzzing campaign and return a CampaignResult."""
        engine_name = self.sandbox.config.engine
        engine = _get_engine(engine_name)

        log.info(
            "starting fuzzing campaign",
            target=self.fuzz_target,
            engine=engine_name,
            duration_s=self.duration_seconds,
        )

        # 1. Ensure corpus dir and crash dir exist in container.
        await self.sandbox.exec(f"mkdir -p /out/crashes {self.corpus_dir}")

        # 2. Build the fuzzer command.
        cmd = engine.build_command(
            self.fuzz_target,
            self.corpus_dir,
            self.duration_seconds,
            self.extra_flags,
        )

        # 3. Run the fuzzer with a safety margin timeout for OOM/hang detection.
        exec_timeout = self.duration_seconds + 60
        log.debug("running fuzzer command", exec_timeout_s=exec_timeout, command=cmd)
        rc, stdout, stderr = await self.sandbox.exec(cmd, timeout=exec_timeout)
        raw_log = stdout + "\n" + stderr

        # 4. Detect OOM-kill (exit code 137 = 128 + SIGKILL) and timeout (-1).
        oom_killed = rc == 137
        timed_out = rc == -1

        if oom_killed:
            log.warn("fuzzer OOM-killed", exit_code=137, target=self.fuzz_target)
        elif timed_out:
            log.warn("fuzzer timed out", exit_code=-1, target=self.fuzz_target)
        else:
            log.info("fuzzer exited", exit_code=rc, target=self.fuzz_target)

        # 5. Parse stats from log output.
        stats = engine.parse_stats(raw_log)
        stats.engine = engine_name

        # 6. Collect crash files using the existing collect_crashes() method.
        crash_files = await self.sandbox.collect_crashes()
        stats.crashes_found = len(crash_files)
        log.info("collected crash files", crash_files=len(crash_files))

        # 7. Collect .profraw coverage files.
        coverage_raw_profiles = await self._collect_profraw_files()
        log.info(
            "collected coverage profiles",
            coverage_profiles=len(coverage_raw_profiles),
        )

        return CampaignResult(
            target_name=self.sandbox.config.target_name,
            engine=engine_name,
            duration_seconds=self.duration_seconds,
            crash_files=crash_files,
            coverage_raw_profiles=coverage_raw_profiles,
            stats=stats,
            timed_out=timed_out,
            oom_killed=oom_killed,
            raw_log=raw_log,
        )

    async def _collect_profraw_files(self) -> list[Path]:
        """Collect .profraw coverage files from the container."""
        rc, stdout, _stderr = await self.sandbox.exec(
            "find /out -name '*.profraw' -type f 2>/dev/null"
        )
        if rc != 0 or not stdout.strip():
            return []

        profraw_files: list[Path] = []
        local_dir = Path(
            tempfile.mkdtemp(prefix=f"profraw-{self.sandbox.config.target_name}-")
        )
        for line in stdout.strip().splitlines():
            container_path = line.strip()
            if not container_path:
                continue
            filename = Path(container_path).name
            local_path = local_dir / filename
            try:
                await self.sandbox.copy_out(container_path, local_path)
                profraw_files.append(local_path)
            except RuntimeError as e:
                log.warn(
                    "failed to copy profraw file",
                    path=container_path,
                    error=str(e),
                )

        return profraw_files
