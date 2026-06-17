"""Live fuzzing task: single-agent Analyze→Synthesize→Fuzz→Triage loop.

The agent receives parser source + metadata, then cycles through four phases:

  1. Analyze   — read source, identify CWE-relevant entry-points
  2. Synthesize — write a LLVMFuzzerTestOneInput harness for one entry-point;
                  repair compile errors with a budget of up to MAX_REPAIR_ITERS
                  retries
  3. Fuzz      — run the fuzzer for up to CYCLE_CAP_SECONDS (30 min) via
                 start_fuzzing(); collect stats and crashes
  4. Triage    — inspect crashes, update harness or move to next entry-point

The loop repeats until the overall budget is exhausted (message_limit) or the
agent explicitly finishes.

Per-function targeting: one harness per CWE-relevant entry-point, not one
per library.

Memory integration: load_session_memory() / save_session_memory() are stubbed
with clear TODOs pending the interface from issue #73.
"""

from __future__ import annotations

import hashlib
import re
import tempfile
from pathlib import Path
from typing import Any

import yaml
from inspect_ai import Task, task
from inspect_ai.dataset import MemoryDataset, Sample
from inspect_ai.scorer import Score, Scorer, mean, scorer
from inspect_ai.solver import (
    Generate,
    Solver,
    TaskState,
    solver,
    system_message,
    use_tools,
)
from inspect_ai.tool import Tool, tool

from parser_security_eval import prompts
from parser_security_eval.log import get_log
from parser_security_eval.memory.store import (
    load_memory,
    memory_to_context,
)
from parser_security_eval.models.fuzzing import (
    FuzzingCycle,
    FuzzingResult,
    HarnessRecord,
    LiveFuzzingSessionResult,
)
from parser_security_eval.sandbox.campaign import FuzzingCampaign
from parser_security_eval.sandbox.docker import DockerSandbox, SandboxConfig
from parser_security_eval.scorers.efficiency import (
    EFFICIENCY_METRICS,
    EfficiencyInputs,
    model_thinking_seconds,
)

log = get_log(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

CYCLE_CAP_SECONDS = 1800  # 30-minute hard cap per fuzzing run
MAX_REPAIR_ITERS = 5  # max compile-fix iterations before giving up
MAX_STACK_FRAMES = 5  # top-N frames used for crash deduplication

# ---------------------------------------------------------------------------
# Memory stub (issue #73)
# ---------------------------------------------------------------------------


def load_session_memory(target_name: str) -> str:
    """Load and format persistent memory for a target at session start.

    Returns a formatted context string (via memory_to_context) ready to
    inject into the agent's user prompt, or an empty string if no prior
    memory exists for this target.
    """
    mem = load_memory(target_name)
    if not mem.hypotheses_tried and not mem.crashes_found and not mem.harness_variants:
        return ""
    return memory_to_context(mem)


def save_session_memory(target_name: str, session_state: dict[str, Any]) -> None:
    """Persist session state into the target's TargetMemory store.

    Writes harness records and crash summaries discovered during this
    session so they are available to future agent invocations.
    """
    from datetime import UTC, datetime

    from parser_security_eval.memory.models import (
        CrashSummary,
    )
    from parser_security_eval.memory.models import (
        HarnessRecord as MemHarnessRecord,
    )
    from parser_security_eval.memory.store import add_crash, add_harness

    for hr in session_state.get("harness_records", []):
        add_harness(
            target_name,
            MemHarnessRecord(
                id=hr.source_hash,
                source_hash=hr.source_hash,
                entry_point=hr.entry_point,
                compile_success=hr.compile_success,
                compile_iterations=hr.repair_iterations,
                crashes_found=hr.crashes_found,
                coverage_achieved=0.0,
                created_at=datetime.now(UTC),
            ),
        )
    for stack_hash in session_state.get("all_crash_hashes", {}):
        add_crash(
            target_name,
            CrashSummary(
                id=stack_hash,
                stack_hash=stack_hash,
                entry_point=session_state.get("current_entry_point", "unknown"),
                found_at=datetime.now(UTC),
            ),
        )


# ---------------------------------------------------------------------------
# Crash deduplication helpers
# ---------------------------------------------------------------------------


def _extract_stack_hash(asan_output: str, top_n: int = MAX_STACK_FRAMES) -> str:
    """Compute a deduplication hash from the top N ASAN stack frames.

    Extracts function names from lines like:
        #0 0xADDR in function_name /path/file.c:123
    Hashes the top-N function names for deduplication.
    """
    frames: list[str] = []
    for m in re.finditer(r"#\d+\s+0x[0-9a-f]+\s+in\s+(\S+)", asan_output):
        frames.append(m.group(1))
        if len(frames) >= top_n:
            break

    if not frames:
        # Fallback: hash the full output to avoid losing unique crashes
        return hashlib.sha256(asan_output.encode()).hexdigest()[:16]

    signature = "|".join(frames)
    return hashlib.sha256(signature.encode()).hexdigest()[:16]


# ---------------------------------------------------------------------------
# Tool factories (close over mutable state stored in session_state dict)
# ---------------------------------------------------------------------------


def _make_write_harness_tool(session_state: dict[str, Any]) -> Tool:
    """Tool: write a LLVMFuzzerTestOneInput harness file."""

    @tool
    def write_harness() -> Tool:
        async def execute(code: str) -> str:
            """Write a fuzz harness implementing LLVMFuzzerTestOneInput.

            Overwrites any previously written harness. The harness will be
            placed at /src/harness_agent.cc in the sandbox.

            Args:
                code: Complete C/C++ source file content.
            """
            if "LLVMFuzzerTestOneInput" not in code:
                return (
                    "ERROR: harness must implement "
                    "LLVMFuzzerTestOneInput(const uint8_t *data, size_t size). "
                    "Rewrite and try again."
                )

            session_state["pending_harness"] = code
            session_state["harness_written"] = True
            session_state["compiled"] = False
            session_state["compile_errors"] = ""
            return (
                "Harness staged. Call compile_harness() to build it. "
                f"({len(code.splitlines())} lines)"
            )

        return execute

    return write_harness()


def _make_compile_harness_tool(
    sandbox: DockerSandbox,
    session_state: dict[str, Any],
    target_name: str,
    engine: str,
    sanitizer: str,
) -> Tool:
    """Tool: compile the staged harness with ASAN; return errors on failure."""

    @tool
    def compile_harness() -> Tool:
        async def execute() -> str:
            """Compile the harness written by write_harness().

            Builds with clang + AddressSanitizer and the selected fuzzing engine.
            Returns 'Compilation succeeded.' or compiler errors for repair.
            Takes no arguments.
            """
            if not session_state.get("harness_written"):
                return "No harness written yet. Call write_harness(code) first."

            code = session_state.get("pending_harness", "")

            # Write the harness into the container
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".cc", delete=False
            ) as tmp:
                tmp.write(code)
                tmp_path = Path(tmp.name)

            try:
                await sandbox.copy_in(tmp_path, f"/src/harness_{target_name}.cc")
            finally:
                tmp_path.unlink(missing_ok=True)

            # Compile: mimics OSS-Fuzz compile step; use engine-specific fuzzing lib
            if engine == "afl":
                lib_fuzzing_engine = "/usr/lib/afl/afl-compiler-rt.o"
            elif engine == "honggfuzz":
                lib_fuzzing_engine = "/src/honggfuzz/honggfuzz.a"
            else:
                lib_fuzzing_engine = "-fsanitize=fuzzer"

            compile_cmd = (
                f"clang++ -fsanitize=address,fuzzer -fno-omit-frame-pointer -g "
                f"-std=c++11 -I/src/{target_name} "
                f"/src/harness_{target_name}.cc "
                f"-o /out/harness_{target_name}_agent "
                f"{lib_fuzzing_engine} "
                f"-L/out -L/work/lib "
                f"2>&1"
            )
            rc, stdout, stderr = await sandbox.exec(compile_cmd, timeout=120)
            combined = (stdout + "\n" + stderr).strip()

            repair_count = session_state.get("repair_iterations", 0)

            if rc == 0:
                session_state["compiled"] = True
                session_state["compile_errors"] = ""
                session_state["fuzz_target"] = f"harness_{target_name}_agent"
                first_try = repair_count == 0
                session_state["last_harness_first_try"] = first_try
                return "Compilation succeeded."

            # Compilation failed
            session_state["compiled"] = False
            session_state["compile_errors"] = combined
            session_state["repair_iterations"] = repair_count + 1

            lines = combined.splitlines()
            tail = "\n".join(lines[-60:])
            remaining = MAX_REPAIR_ITERS - session_state["repair_iterations"]
            return (
                f"Compilation FAILED (exit {rc}). "
                f"{remaining} repair attempts remaining.\n{tail}"
            )

        return execute

    return compile_harness()


def _make_add_seed_tool(sandbox: DockerSandbox, session_state: dict[str, Any]) -> Tool:
    """Tool: add a seed input to the corpus (hex-encoded bytes)."""

    @tool
    def add_seed() -> Tool:
        async def execute(data_hex: str, filename: str) -> str:
            """Add a seed input to the fuzzer corpus.

            The seed is provided as a hex-encoded byte string so it can be
            embedded safely in JSON tool calls.

            Args:
                data_hex: Hex-encoded bytes, e.g. '504b0304' for a ZIP header.
                filename: Filename to use in /out/corpus/, e.g. 'seed_xml_basic'.
            """
            try:
                raw = bytes.fromhex(data_hex)
            except ValueError as e:
                return f"Invalid hex data: {e}"

            # Ensure corpus dir exists
            await sandbox.exec("mkdir -p /out/corpus")

            # Write bytes into corpus
            safe_name = re.sub(r"[^a-zA-Z0-9_\-.]", "_", filename)[:64]
            with tempfile.NamedTemporaryFile(delete=False, suffix="_seed") as tmp:
                tmp.write(raw)
                tmp_path = Path(tmp.name)

            try:
                await sandbox.copy_in(tmp_path, f"/out/corpus/{safe_name}")
            finally:
                tmp_path.unlink(missing_ok=True)

            seeds: list[str] = session_state.setdefault("seeds_added", [])
            seeds.append(safe_name)
            return (
                f"Seed '{safe_name}' added to corpus ({len(raw)} bytes). "
                f"Total seeds: {len(seeds)}."
            )

        return execute

    return add_seed()


def _make_start_fuzzing_tool(
    sandbox: DockerSandbox,
    session_state: dict[str, Any],
    max_duration: int = CYCLE_CAP_SECONDS,
    target_name: str = "unknown",
) -> Tool:
    """Tool: start the fuzzer for up to max_duration seconds."""

    @tool
    def start_fuzzing() -> Tool:
        async def execute(duration_seconds: int = 300) -> str:
            """Run the fuzzer campaign for the specified duration.

            The duration is capped at the experiment-configured maximum.
            After the run you MUST call get_fuzzer_stats() and, if crashes
            were found, get_crash_info(crash_id) before fuzzing again.

            Args:
                duration_seconds: How long to fuzz in seconds. Values
                    above the configured cap are silently clamped.
            """
            if not session_state.get("compiled"):
                return (
                    "Harness not compiled. "
                    "Call write_harness() then compile_harness() first."
                )

            capped = max(1, min(duration_seconds, max_duration))
            fuzz_target = session_state.get("fuzz_target", "")
            if not fuzz_target:
                return "No compiled fuzz target found. Compile the harness first."

            campaign = FuzzingCampaign(
                sandbox=sandbox,
                fuzz_target=fuzz_target,
                duration_seconds=capped,
                corpus_dir="/out/corpus",
            )
            result = await campaign.run()

            # Collect ASAN output for newly found crashes
            new_crash_hashes: dict[str, str] = {}
            for crash_path in result.crash_files:
                # Re-run the crash input through the binary to get ASAN output.
                # collect_crashes() copied each crash OUT to a host tempdir, but
                # sandbox.exec runs INSIDE the container -- so we must copy the
                # crash back in and run the in-container path. (Running the host
                # path made the binary fail with "no such file", and that error
                # string got mis-stored as the crash's ASAN output and hashed as a
                # distinct "unique crash" -- inflating the vuln count with noise.)
                container_crash = "/tmp/_crash_repro_input"
                await sandbox.copy_in(crash_path, container_crash)
                rc, stdout, stderr = await sandbox.exec(
                    f"/out/{fuzz_target} {container_crash}",
                    timeout=30,
                )
                asan_out = stdout + "\n" + stderr
                h = _extract_stack_hash(asan_out)
                if h not in session_state.get("all_crash_hashes", {}):
                    new_crash_hashes[h] = asan_out[:2000]

            all_hashes: dict[str, str] = session_state.setdefault(
                "all_crash_hashes", {}
            )
            all_hashes.update(new_crash_hashes)

            # Store last run result for get_fuzzer_stats()
            fuzz_result = FuzzingResult(
                duration_seconds=capped,
                execs_per_sec=result.stats.execs_per_sec,
                corpus_size=result.stats.corpus_size,
                crashes_found=len(all_hashes),
                unique_crash_hashes=dict(new_crash_hashes),
                timed_out=result.timed_out,
                oom_killed=result.oom_killed,
                raw_log=result.raw_log[:4000],
            )
            session_state["last_fuzz_result"] = fuzz_result
            session_state["cycle_count"] = session_state.get("cycle_count", 0) + 1
            # Accumulate fuzzer wall-clock (W) for the efficiency metrics. We use
            # the capped duration the campaign was asked to run for — a
            # deterministic, single-core CPU-seconds proxy (issue #135).
            session_state["total_fuzz_seconds"] = (
                session_state.get("total_fuzz_seconds", 0.0) + capped
            )

            # Emit one structured record per completed cycle so Logfire owns the
            # live research curves (execs/s, crashes, coverage over time) for the
            # #114 dashboard (issue #147). Static message template so Logfire
            # groups by message; the per-cycle numbers ride as attributes.
            # `fuzz_seconds` for this cycle is `capped` — the wall-clock the
            # campaign was asked to run for (same CPU-seconds proxy accumulated
            # into total_fuzz_seconds above).
            log.info(
                "fuzz cycle complete",
                target=target_name,
                cycle=session_state["cycle_count"],
                execs_per_sec=result.stats.execs_per_sec,
                total_execs=result.stats.total_execs,
                crashes_total=len(all_hashes),
                crashes_new=len(new_crash_hashes),
                coverage_profiles=len(result.coverage_raw_profiles),
                fuzz_seconds=float(capped),
                total_fuzz_seconds=session_state["total_fuzz_seconds"],
            )

            summary_parts = [
                f"Fuzzing run complete ({capped}s).",
                f"Execs/sec: {result.stats.execs_per_sec or 'N/A'}",
                f"Corpus size: {result.stats.corpus_size or 'N/A'}",
                f"New unique crashes this run: {len(new_crash_hashes)}",
                f"Total unique crashes: {len(all_hashes)}",
            ]
            if result.timed_out:
                summary_parts.append("WARNING: fuzzer timed out.")
            if result.oom_killed:
                summary_parts.append("WARNING: fuzzer was OOM-killed.")
            if new_crash_hashes:
                summary_parts.append(f"Crash IDs: {list(new_crash_hashes.keys())}")
                summary_parts.append(
                    "Call get_crash_info(crash_id) to inspect each crash."
                )

            return "\n".join(summary_parts)

        return execute

    return start_fuzzing()


def _make_get_fuzzer_stats_tool(session_state: dict[str, Any]) -> Tool:
    """Tool: return execution stats from the last fuzzing run."""

    @tool
    def get_fuzzer_stats() -> Tool:
        async def execute() -> str:
            """Return execs/sec, corpus size, crashes found, and coverage delta
            from the most recent fuzzing run. Takes no arguments.
            """
            result: FuzzingResult | None = session_state.get("last_fuzz_result")
            if result is None:
                return "No fuzzing run completed yet. Call start_fuzzing() first."

            lines = [
                f"=== Fuzzer Stats (cycle {session_state.get('cycle_count', 0)}) ===",
                f"Duration: {result.duration_seconds}s",
                f"Execs/sec: {result.execs_per_sec or 'N/A'}",
                f"Corpus size: {result.corpus_size or 'N/A'}",
                f"Total unique crashes: {len(session_state.get('all_crash_hashes', {}))}",
                f"Timed out: {result.timed_out}",
                f"OOM killed: {result.oom_killed}",
            ]

            # Coverage delta placeholder — requires a coverage-instrumented build
            # (the scorers/coverage.py path). Shown if coverage data is available.
            cov_delta = session_state.get("coverage_delta")
            if cov_delta is not None:
                lines.append(
                    f"Coverage: line {cov_delta['line_before']:.1f}% → "
                    f"{cov_delta['line_after']:.1f}% "
                    f"(Δ {cov_delta['line_after'] - cov_delta['line_before']:+.1f}%)"
                )

            return "\n".join(lines)

        return execute

    return get_fuzzer_stats()


def _make_get_crash_info_tool(session_state: dict[str, Any]) -> Tool:
    """Tool: return crash artifact + ASAN output for a given crash ID."""

    @tool
    def get_crash_info() -> Tool:
        async def execute(crash_id: str) -> str:
            """Return the ASAN output and execution trace for a crash.

            Args:
                crash_id: The stack-hash ID returned by start_fuzzing()
                    (e.g. 'a3f8b2c1').
            """
            all_hashes: dict[str, str] = session_state.get("all_crash_hashes", {})
            if not all_hashes:
                return "No crashes collected yet."

            if crash_id in all_hashes:
                asan_out = all_hashes[crash_id]
                return (
                    f"=== Crash {crash_id} ===\n"
                    f"{asan_out[:3000]}\n"
                    "(truncated if > 3000 chars)"
                )

            available = list(all_hashes.keys())
            return f"Crash ID '{crash_id}' not found. Available IDs: {available}"

        return execute

    return get_crash_info()


def _make_refine_harness_tool(
    session_state: dict[str, Any],
) -> Tool:
    """Tool: rewrite the harness and signal that we are starting a new iteration."""

    @tool
    def refine_harness() -> Tool:
        async def execute(code: str, reason: str = "") -> str:
            """Rewrite the harness based on crash analysis or coverage feedback.

            This is equivalent to write_harness() but semantically signals
            that this is a refinement of the previous harness rather than
            a new entry-point targeting.  The old harness is discarded.

            After calling this, call compile_harness() to rebuild.

            Args:
                code: The new, improved harness source.
                reason: Brief note on what changed (logged for scoring).
            """
            if "LLVMFuzzerTestOneInput" not in code:
                return (
                    "ERROR: refined harness must still implement "
                    "LLVMFuzzerTestOneInput. Rewrite and try again."
                )

            session_state["pending_harness"] = code
            session_state["harness_written"] = True
            session_state["compiled"] = False
            session_state["compile_errors"] = ""
            # Reset repair counter for the new harness
            session_state["repair_iterations"] = 0

            refinement_log: list[str] = session_state.setdefault("refinement_log", [])
            refinement_log.append(reason or "(no reason given)")

            return (
                f"Harness refined ({len(code.splitlines())} lines). "
                "Call compile_harness() to rebuild."
            )

        return execute

    return refine_harness()


# ---------------------------------------------------------------------------
# Dataset loading
# ---------------------------------------------------------------------------


def _load_target_metadata(target_dir: Path) -> dict[str, Any]:
    """Load metadata.yaml from a target directory."""
    metadata_path = target_dir / "metadata.yaml"
    if not metadata_path.exists():
        raise FileNotFoundError(f"No metadata.yaml in {target_dir}")
    with open(metadata_path) as f:
        return yaml.safe_load(f)


def _read_build_sh(target_dir: Path) -> str:
    build_sh = target_dir / "build.sh"
    if build_sh.exists():
        return build_sh.read_text(errors="replace")
    return ""


def _collect_source_snippets(target_dir: Path, max_files: int = 8) -> str:
    """Collect a representative set of source file headers for context.

    Returns a formatted string with the first 60 lines of each file.
    """
    snippets: list[str] = []
    count = 0
    for pattern in ("*.h", "*.c", "*.cc", "*.cpp"):
        for path in sorted(target_dir.glob(pattern)):
            if count >= max_files:
                break
            lines = path.read_text(errors="replace").splitlines()[:60]
            snippets.append(
                f"\n### {path.name} (first {len(lines)} lines)\n"
                f"```c\n{chr(10).join(lines)}\n```"
            )
            count += 1
    return "\n".join(snippets) if snippets else "(no source files found in target dir)"


def load_live_fuzzing_dataset(
    targets_dir: str,
    target: str,
) -> list[Sample]:
    """Build an Inspect-AI Sample for a live-fuzzing session.

    One sample per target — the agent will run multiple harness cycles
    within a single task sample using the tool-call loop.
    """
    targets_root = Path(targets_dir)
    target_dir = targets_root / target

    if not target_dir.exists():
        raise FileNotFoundError(f"Target directory not found: {target_dir}")

    metadata = _load_target_metadata(target_dir)
    build_sh = _read_build_sh(target_dir)
    source_snippets = _collect_source_snippets(target_dir)

    target_name: str = metadata.get("name", target)
    fuzz_targets: list[str] = metadata.get("fuzz_targets", [])
    cwe_hints: list[str] = metadata.get("cwe_hints", [])

    # Load persistent memory from prior sessions
    mem_context = load_session_memory(target_name)
    memory_section = (
        "\n## Previous session notes\n" + mem_context + "\n" if mem_context else ""
    )

    user_prompt = prompts.load(
        "fuzzing.user",
        target_name=target_name,
        format_type=metadata.get("format_type", "unknown"),
        language=metadata.get("language", "c"),
        ossfuzz_project=metadata.get("ossfuzz_project", "N/A"),
        fuzz_targets=fuzz_targets,
        cwe_hints=cwe_hints or "(none provided — discover from source)",
        build_sh=build_sh,
        source_snippets=source_snippets,
        memory_section=memory_section,
    )

    sample = Sample(
        input=user_prompt,
        target=target_name,  # used by scorer as the target identifier
        id=f"live-fuzzing-{target}",
        metadata={
            "target_name": target_name,
            "target": target,
            "targets_dir": str(targets_root.resolve()),
            "format_type": metadata.get("format_type", "unknown"),
            "language": metadata.get("language", "c"),
            "ossfuzz_project": metadata.get("ossfuzz_project"),
            "fuzz_targets": fuzz_targets,
        },
    )
    return [sample]


# ---------------------------------------------------------------------------
# Solver
# ---------------------------------------------------------------------------


@solver
def live_fuzzing_solver(
    targets_root: str = "targets",
    fuzzing_engine: str = "libfuzzer",
    sanitizer: str = "address",
    max_fuzz_duration: int = CYCLE_CAP_SECONDS,
) -> Solver:
    """Agentic solver for the live fuzzing loop.

    Spins up a DockerSandbox, registers all tools, injects the system prompt,
    then runs a generate(tool_calls="loop") loop.  The agent drives all four
    phases using the provided tools.
    """

    async def solve(state: TaskState, generate: Generate) -> TaskState:
        meta = state.metadata or {}
        target_name: str = meta.get("target_name", meta.get("target", ""))
        target: str = meta.get("target", target_name)

        target_dir = Path(targets_root) / target

        config = SandboxConfig(
            target_name=target_name,
            target_dir=target_dir,
            sanitizer=sanitizer,
            engine=fuzzing_engine,
        )

        # Mutable state shared across tool closures for this sample
        session_state: dict[str, Any] = {
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
            "total_fuzz_seconds": 0.0,  # accumulated fuzzer wall-clock (W, issue #135)
            "refinement_log": [],
            "harness_records": [],  # list[HarnessRecord] accumulated across cycles
            "fuzzing_cycles": [],  # list[FuzzingCycle]
            "current_entry_point": "",
        }

        def _stash_session_state(st: TaskState) -> TaskState:
            """Persist session_state on both store and metadata so the scorer
            can always find it — even if the solver is interrupted by a
            message/token/time limit."""
            if st.metadata is None:
                st.metadata = {}
            st.metadata["_session_state"] = session_state
            st.store.set("_session_state", session_state)
            return st

        async with DockerSandbox(config) as sandbox:
            # Build the target so libraries are available for harness linking
            log.info("building target inside sandbox", target=target_name)
            build_ok = await sandbox.build_target()
            if not build_ok:
                log.warn("target build failed", target=target_name)
                system_prompt = prompts.load(
                    "fuzzing.system",
                    max_repair=MAX_REPAIR_ITERS,
                    cycle_cap=CYCLE_CAP_SECONDS,
                )
                state = await system_message(system_prompt)(state, generate)
                from inspect_ai.model import ChatMessageUser

                state.messages.append(
                    ChatMessageUser(
                        content=(
                            state.messages[0].content
                            if state.messages
                            else f"Target: {target_name}"
                        )
                    )
                )
                return _stash_session_state(state)

            # Ensure corpus and crash dirs exist
            await sandbox.exec("mkdir -p /out/corpus /out/crashes")

            tools: list[Tool] = [
                _make_write_harness_tool(session_state),
                _make_compile_harness_tool(
                    sandbox, session_state, target_name, fuzzing_engine, sanitizer
                ),
                _make_add_seed_tool(sandbox, session_state),
                _make_start_fuzzing_tool(
                    sandbox, session_state, max_fuzz_duration, target_name
                ),
                _make_get_fuzzer_stats_tool(session_state),
                _make_get_crash_info_tool(session_state),
                _make_refine_harness_tool(session_state),
            ]

            system_prompt = prompts.load(
                "fuzzing.system",
                max_repair=MAX_REPAIR_ITERS,
                cycle_cap=CYCLE_CAP_SECONDS,
            )
            state = await system_message(system_prompt)(state, generate)
            state = await use_tools(tools)(state, generate)
            try:
                state = await generate(state, tool_calls="loop", max_tokens=16384)
            except BaseException:
                # Message/token/time limit exceptions interrupt generate().
                # Stash session_state before re-raising so the scorer can
                # still read whatever progress the agent made.
                _stash_session_state(state)
                raise

        _stash_session_state(state)

        # Persist session memory for future runs
        save_session_memory(target_name, session_state)

        return state

    return solve


# ---------------------------------------------------------------------------
# Scorer
# ---------------------------------------------------------------------------


def _build_session_result(
    target_name: str,
    engine: str,
    session_state: dict[str, Any],
) -> LiveFuzzingSessionResult:
    """Construct a LiveFuzzingSessionResult from session_state."""
    all_crash_hashes: dict[str, str] = session_state.get("all_crash_hashes", {})
    harness_records: list[HarnessRecord] = session_state.get("harness_records", [])

    total_attempted = len(harness_records) or max(
        1, session_state.get("cycle_count", 0)
    )
    compiled_first_try = sum(1 for h in harness_records if h.first_try_success)
    total_repairs = sum(h.repair_iterations for h in harness_records)

    # Aggregate fuzzing cycles
    fuzzing_cycles: list[FuzzingCycle] = session_state.get("fuzzing_cycles", [])

    return LiveFuzzingSessionResult(
        target_name=target_name,
        engine=engine,
        total_cycles=session_state.get("cycle_count", 0),
        cycles=fuzzing_cycles,
        total_unique_crashes=len(all_crash_hashes),
        all_crash_hashes=all_crash_hashes,
        final_line_coverage_pct=0.0,  # populated by coverage scorer if available
        final_branch_coverage_pct=0.0,
        total_harnesses_attempted=total_attempted,
        harnesses_compiled_first_try=compiled_first_try,
        total_repair_iterations=total_repairs,
    )


def _compute_score(result: LiveFuzzingSessionResult) -> float:
    """Compute a composite 0–1 score from the session result.

    Weights:
    - 40%  unique crashes found (log-scaled, saturates at 10 crashes → 1.0)
    - 30%  first-try compile rate
    - 30%  line coverage % (if available; 0 if coverage data absent)
    """
    crash_score = min(1.0, result.total_unique_crashes / 10.0)

    compile_score = result.first_try_compile_rate

    coverage_score = min(1.0, result.final_line_coverage_pct / 100.0)

    return 0.40 * crash_score + 0.30 * compile_score + 0.30 * coverage_score


def live_fuzzing_scorer(
    targets_root: str = "targets",
    fuzzing_engine: str = "libfuzzer",
) -> list[Scorer]:
    """Scorers measuring unique crashes, compile success rate, and coverage.

    Returns a single composite scorer. The score is a weighted combination of:
    - Unique crashes (deduplicated by stack hash, top-5 frames)
    - First-try harness compile rate
    - Line coverage % from llvm-cov (0 if not available)
    """

    @scorer(metrics=[mean(), *EFFICIENCY_METRICS])
    def _live_fuzzing_scorer() -> Scorer:
        async def score(state: TaskState, target: object) -> Score:
            meta: dict[str, Any] = state.metadata or {}
            target_name: str = meta.get("target_name", meta.get("target", "unknown"))
            # Check both store (preferred, survives limit exceptions) and
            # metadata (fallback) for session state.
            session_state: dict[str, Any] = state.store.get(
                "_session_state", {}
            ) or meta.get("_session_state", {})

            if not session_state:
                # Still record resources spent so per-token/-time rates are not
                # silently inflated by samples that produced no session state.
                empty_inputs = EfficiencyInputs(
                    vulns=0,
                    total_tokens=state.token_usage,
                    model_seconds=model_thinking_seconds(),
                    fuzz_seconds=0.0,
                )
                return Score(
                    value=0.0,
                    explanation=(
                        "No session state found — agent did not complete any cycles."
                    ),
                    metadata=empty_inputs.as_metadata(),
                )

            result = _build_session_result(target_name, fuzzing_engine, session_state)

            numeric = _compute_score(result)

            # Resource accounting for the efficiency metrics (issue #135):
            # vulns = deduplicated crashes; tokens = whole-sample LLM usage;
            # model_seconds = thinking time (kappa denominator); fuzz_seconds = W.
            eff_inputs = EfficiencyInputs(
                vulns=result.total_unique_crashes,
                total_tokens=state.token_usage,
                model_seconds=model_thinking_seconds(),
                fuzz_seconds=float(session_state.get("total_fuzz_seconds", 0.0)),
            )

            explanation = (
                f"unique_crashes={result.total_unique_crashes}, "
                f"cycles={result.total_cycles}, "
                f"first_try_compile_rate={result.first_try_compile_rate:.2f}, "
                f"mean_repair_iters={result.mean_repair_iterations:.1f}, "
                f"line_coverage={result.final_line_coverage_pct:.1f}%, "
                f"branch_coverage={result.final_branch_coverage_pct:.1f}%, "
                f"tokens={eff_inputs.total_tokens}, "
                f"fuzz_seconds={eff_inputs.fuzz_seconds:.0f}"
            )

            return Score(
                value=numeric,
                explanation=explanation,
                metadata={
                    "unique_crashes": result.total_unique_crashes,
                    "total_cycles": result.total_cycles,
                    "first_try_compile_rate": result.first_try_compile_rate,
                    "mean_repair_iterations": result.mean_repair_iterations,
                    "final_line_coverage_pct": result.final_line_coverage_pct,
                    "final_branch_coverage_pct": result.final_branch_coverage_pct,
                    "total_harnesses_attempted": result.total_harnesses_attempted,
                    "harnesses_compiled_first_try": result.harnesses_compiled_first_try,
                    **eff_inputs.as_metadata(),
                },
            )

        return score

    return [_live_fuzzing_scorer()]


# ---------------------------------------------------------------------------
# Task
# ---------------------------------------------------------------------------


@task
def live_fuzzing(
    targets_dir: str = "targets",
    target: str = "libxml2",
    fuzzing_engine: str = "libfuzzer",
    sanitizer: str = "address",
    fuzz_duration: int = CYCLE_CAP_SECONDS,
    message_limit: int = 120,
) -> Task:
    """Inspect-AI task: single-agent live fuzzing with Analyze→Synthesize→Fuzz→Triage.

    The agent receives parser source + metadata, writes per-function harnesses,
    runs the fuzzer for up to fuzz_duration-second cycles, triages crashes, and
    refines.

    Run with:
        inspect eval tasks/fuzzing.py -T target=libxml2
        inspect eval tasks/fuzzing.py -T target=libpng -T fuzzing_engine=afl
        inspect eval tasks/fuzzing.py -T target=libxml2 -T fuzz_duration=60

    Args:
        targets_dir: Root directory containing parser target definitions.
        target: Name of the parser target (subdirectory of targets_dir).
        fuzzing_engine: Fuzzing engine — 'libfuzzer', 'afl', or 'honggfuzz'.
        sanitizer: Sanitizer — 'address', 'undefined', or 'memory'.
        fuzz_duration: Max seconds per fuzzing cycle (caps agent's choice).
        message_limit: Max agent messages before stopping.
    """
    dataset = load_live_fuzzing_dataset(targets_dir, target)

    return Task(
        dataset=MemoryDataset(dataset),
        solver=live_fuzzing_solver(
            targets_root=targets_dir,
            fuzzing_engine=fuzzing_engine,
            sanitizer=sanitizer,
            max_fuzz_duration=fuzz_duration,
        ),
        scorer=live_fuzzing_scorer(
            targets_root=targets_dir,
            fuzzing_engine=fuzzing_engine,
        ),
        message_limit=message_limit,
    )
