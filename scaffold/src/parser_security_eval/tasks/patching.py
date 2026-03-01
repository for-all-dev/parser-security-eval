"""Vulnerability patching task: given a crash report + source, generate a patch.

This is the core blue-team eval task. The agent receives:
- ASAN crash report (crash type, stack trace, sanitizer output)
- Triggering input (the actual bytes that cause the crash)
- Parser source code (the vulnerable version)

The agent must:
- Identify the root cause
- Generate a minimal patch (as a diff)
- The patch is then scored by: compiles? crash eliminated? tests pass?
"""

import json
import random
import re
import tempfile
from pathlib import Path

import yaml
from inspect_ai import Task, task
from inspect_ai.dataset import Sample
from inspect_ai.model import ChatMessageAssistant
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
from parser_security_eval.models.vulnerability import VulnerabilityRecord
from parser_security_eval.sandbox.docker import DockerSandbox, SandboxConfig
from parser_security_eval.scorers.patch import PatchResult, score_patch


def _extract_crash_line(
    crash_report: str, filename: str, content: str | None = None
) -> int | None:
    """Parse ASAN stack frames to find an anchor line number for *filename*.

    Strategy 1: look for ``file.c:123`` patterns in the stack trace for the
    exact basename of *filename*.

    Strategy 2 (fallback): parse all function names from ASAN frames
    (``in <funcname> `` patterns), then scan *content* line by line for the
    first line that looks like a C function definition for any of those names
    (``funcname(`` pattern).  This handles the common case where the crash
    surface is in a different file from the fix site.
    """
    basename = Path(filename).name
    # Strategy 1: exact file:line match
    for m in re.finditer(rf"{re.escape(basename)}:(\d+)", crash_report):
        return int(m.group(1))

    # Strategy 2: match ASAN frame function names against source content
    if content is not None:
        # Extract all function names from ASAN frames: "    #N 0xADDR in funcname "
        func_names: list[str] = re.findall(r"\bin (\w+)\s", crash_report)
        if func_names:
            # Build a set for O(1) lookup; preserve order via the list
            func_set = set(func_names)
            for lineno, line in enumerate(content.splitlines(), start=1):
                # Match a C function definition: funcname( at the start of a token
                # Use word boundary so "foo" doesn't match "foobar("
                for name in func_set:
                    if re.search(rf"\b{re.escape(name)}\s*\(", line):
                        return lineno

    return None


def _truncate_source(
    content: str,
    filename: str,
    crash_report: str | None,
    max_lines: int = 600,
) -> str:
    """Window source around the crash site, or return the first *max_lines*."""
    lines = content.splitlines(keepends=True)
    if len(lines) <= max_lines:
        return content

    anchor: int | None = None
    if crash_report:
        anchor = _extract_crash_line(crash_report, filename, content)

    if anchor is not None:
        half = max_lines // 2
        start = max(0, anchor - half)
        end = min(len(lines), start + max_lines)
        start = max(0, end - max_lines)  # readjust if near end
    else:
        start = 0
        end = max_lines

    truncated = lines[start:end]
    header = f"[lines {start + 1}–{end} of {len(lines)}]\n"
    return header + "".join(truncated)


def _extract_diff(text: str) -> str | None:
    """Extract a unified diff from model output.

    Handles both fenced code blocks (```diff ... ```) and bare diffs.
    """
    # Prefer explicit ```diff or ``` fenced blocks containing a unified diff
    fenced = re.search(
        r"```(?:diff)?\n(---\s\S.*?\n\+\+\+\s\S.*?\n.*?)```", text, re.DOTALL
    )
    if fenced:
        return fenced.group(1)

    # Fall back to bare unified diff: starts with --- line, followed by +++ line
    bare = re.search(
        r"^(--- \S.*\n\+\+\+ \S.*\n(?:(?:@@|[ +\-\\]).*\n?)*)",
        text,
        re.MULTILINE,
    )
    if bare:
        return bare.group(1)

    return None


def _extract_diff_from_state(state: TaskState) -> str | None:
    """Find the last diff in any assistant message, falling back to output.completion.

    Scans assistant messages in reverse so we pick up the most recent working
    diff even if the model kept iterating after producing one.

    Three-pass fallback strategy:
    1. Text content of assistant messages (in reverse order).
    2. ``try_patch`` tool call ``diff`` arguments (in reverse order) — handles
       the case where the message limit was hit with a tool result as the last
       message, leaving ``state.output.completion`` empty.
    3. ``state.output.completion`` itself.
    """
    # Pass 1: text content of assistant messages
    for msg in reversed(state.messages):
        if isinstance(msg, ChatMessageAssistant):
            text = msg.text
            diff = _extract_diff(text)
            if diff:
                return diff

    # Pass 2: try_patch tool call arguments
    for msg in reversed(state.messages):
        if isinstance(msg, ChatMessageAssistant) and msg.tool_calls:
            for tc in reversed(msg.tool_calls):
                if tc.function == "try_patch":
                    diff_arg: str | None = tc.arguments.get("diff")
                    if diff_arg and diff_arg.lstrip().startswith(("---", "+++")):
                        return diff_arg

    # Pass 3: output.completion (covers the case where the last generate()
    # produced text that didn't make it into messages yet)
    return _extract_diff(state.output.completion)


def _patch_result_to_score(result: PatchResult) -> float:
    """Convert a PatchResult to a 0–1 numeric score.

    Partial credit reflects where in the pipeline the patch succeeded.
    """
    if not result.patch_applies:
        return 0.0
    if not result.compiles:
        return 0.2
    if not result.crash_eliminated:
        return 0.5
    if not result.tests_pass:
        return 0.7
    return 1.0


def _resolve_fuzz_binary(target_dir: Path, target_name: str) -> str:
    """Resolve the primary fuzz target binary path inside the container.

    Reads fuzz_targets from metadata.yaml; falls back to convention.
    """
    metadata_path = target_dir / "metadata.yaml"
    if metadata_path.exists():
        meta = yaml.safe_load(metadata_path.read_text())
        fuzz_targets: list[str] = meta.get("fuzz_targets", [])
        if fuzz_targets:
            return f"/out/{fuzz_targets[0]}"
    return f"/out/{target_name}_fuzzer"


def _make_try_patch_tool(sandbox: DockerSandbox) -> Tool:
    """Create a tool that applies a unified diff to the source tree."""
    src_dir = f"/src/{sandbox.config.target_name}"

    @tool
    def try_patch() -> Tool:
        async def execute(diff: str) -> str:
            """Apply a unified diff patch to the source tree.

            Resets the source tree before applying so retries are clean.

            Args:
                diff: The unified diff to apply (e.g. output of git diff).
            """
            # Reset source tree for a clean slate
            await sandbox.exec(f"cd {src_dir} && git checkout .")
            # Write the diff to a temp file inside the container
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".diff", delete=False
            ) as f:
                f.write(diff)
                tmp_path = Path(f.name)
            try:
                await sandbox.copy_in(tmp_path, "/tmp/patch.diff")
            finally:
                tmp_path.unlink(missing_ok=True)
            exit_code, stdout, stderr = await sandbox.exec(
                f"cd {src_dir} && patch -p1 --fuzz=3 < /tmp/patch.diff"
            )
            combined = (stdout + "\n" + stderr).strip()
            if exit_code == 0:
                return f"Patch applied successfully.\n{combined}"
            return f"Patch REJECTED (exit {exit_code}):\n{combined}"

        return execute

    return try_patch()


def _make_compile_tool(sandbox: DockerSandbox, sanitizer: str, engine: str) -> Tool:
    """Create a tool that rebuilds the target with sanitizers."""

    @tool
    def compile_target() -> Tool:
        async def execute() -> str:
            """Rebuild the fuzz target with sanitizers enabled. Takes no arguments."""
            exit_code, stdout, stderr = await sandbox.exec(
                f"env SANITIZER={sanitizer} FUZZING_ENGINE={engine} "
                "FUZZING_LANGUAGE=c compile"
            )
            if exit_code == 0:
                return "Compilation succeeded."
            # Return tail of output so the model can see errors
            lines = (stdout + "\n" + stderr).strip().splitlines()
            tail = "\n".join(lines[-80:])
            return f"Compilation FAILED (exit {exit_code}):\n{tail}"

        return execute

    return compile_target()


def _make_read_source_tool(sandbox: DockerSandbox) -> Tool:
    """Create a tool that reads a file from the source tree in the container."""
    src_dir = f"/src/{sandbox.config.target_name}"

    @tool
    def read_source_file() -> Tool:
        async def execute(
            file_path: str, start_line: int = 1, end_line: int = 200
        ) -> str:
            """Read lines from a source file in the container.

            Use this to inspect the actual file contents when patches fail to apply.
            This helps you see the exact whitespace, line numbers, and content.

            Args:
                file_path: Path relative to the source root (e.g. "parser.c").
                start_line: First line to read (1-indexed, default 1).
                end_line: Last line to read (inclusive, default 200).
            """
            full_path = f"{src_dir}/{file_path}"
            exit_code, stdout, stderr = await sandbox.exec(
                f"sed -n '{start_line},{end_line}p' '{full_path}'"
            )
            if exit_code != 0:
                return f"ERROR reading {file_path}: {stderr.strip()}"
            total_rc, total_out, _ = await sandbox.exec(f"wc -l < '{full_path}'")
            total_lines = total_out.strip() if total_rc == 0 else "?"
            header = f"[{file_path} lines {start_line}-{end_line} of {total_lines}]\n"
            return header + stdout

        return execute

    return read_source_file()


def _make_run_crash_tool(
    sandbox: DockerSandbox,
    fuzz_binary: str,
    crash_input_container_path: str,
) -> Tool:
    """Create a tool that runs the triggering input against the rebuilt binary."""

    @tool
    def run_crash_input() -> Tool:
        async def execute() -> str:
            """Run the triggering crash input against the patched binary. Takes no arguments.

            Returns whether the crash is eliminated or the ASAN output.
            """
            exit_code, stdout, stderr = await sandbox.exec(
                f"{fuzz_binary} {crash_input_container_path}"
            )
            combined = stdout + "\n" + stderr
            sanitizer_crash = (
                "ERROR: AddressSanitizer" in combined
                or "SUMMARY: AddressSanitizer" in combined
                or "SUMMARY: UndefinedBehaviorSanitizer" in combined
                or "runtime error:" in combined
            )
            if exit_code == 0 and not sanitizer_crash:
                return "CRASH ELIMINATED - no sanitizer errors detected."
            # Truncate sanitizer output
            lines = combined.strip().splitlines()
            tail = "\n".join(lines[-60:])
            return f"CRASH DETECTED (exit {exit_code}):\n{tail}"

        return execute

    return run_crash_input()


def load_patching_dataset(
    benchmark_dir: str,
    target: str | None = None,
    ready_only: bool = False,
    seed: int | None = None,
) -> list[Sample]:
    """Load vulnerability records as Inspect-AI samples.

    Reads benchmark_dir/metadata.json, filters by target if given,
    and constructs one Sample per VulnerabilityRecord.

    Pipeline order:
      1. Filter by target (if provided)
      2. Filter by ready_only (if True)
      3. Shuffle with seed (if provided) — before any limit is applied
         Note: inspect_eval(limit=N) selects the first N samples from
         Task(dataset=...) in list order, so we must shuffle here rather
         than relying on inspect_ai's sample_shuffle parameter, in order
         to guarantee that --limit picks from the shuffled order.
    """
    bdir = Path(benchmark_dir)
    metadata_path = bdir / "metadata.json"

    if not metadata_path.exists():
        return []

    raw = json.loads(metadata_path.read_text())
    records = [VulnerabilityRecord.model_validate(r) for r in raw["records"]]

    if target is not None:
        records = [r for r in records if r.target == target]

    if ready_only:
        records = [
            r
            for r in records
            if r.crash_input_path
            and r.crash_report_path
            and r.reference_patch_path
            and r.vulnerable_source_paths
        ]

    if seed is not None:
        random.Random(seed).shuffle(records)

    samples: list[Sample] = []
    for record in records:
        input_parts: list[str] = [
            f"Vulnerability ID: {record.id}",
            f"Target: {record.target}",
            f"Crash Type: {record.crash_type}",
            f"Sanitizer: {record.sanitizer}",
            f"Affected File: {record.affected_file}",
        ]
        if record.affected_function:
            input_parts.append(f"Affected Function: {record.affected_function}")
        if record.cwe:
            input_parts.append(f"CWE: {record.cwe}")
        if record.root_cause:
            input_parts.append(f"\nRoot Cause Hint: {record.root_cause}")

        if record.crash_report_path:
            report_path = bdir / record.crash_report_path
            if report_path.exists():
                input_parts.append(f"\n--- Crash Report ---\n{report_path.read_text()}")

        if record.crash_input_path:
            input_parts.append(f"\nTriggering Input: {record.crash_input_path}")

        if record.vulnerable_source_ref:
            input_parts.append(f"Vulnerable Source Ref: {record.vulnerable_source_ref}")

        # Load crash report text for crash-line anchoring in truncation
        crash_report_text: str | None = None
        if record.crash_report_path:
            rp = bdir / record.crash_report_path
            if rp.exists():
                crash_report_text = rp.read_text()

        # Include vulnerable source files
        if record.vulnerable_source_paths:
            input_parts.append("\n--- Vulnerable Source Code ---")
            for repo_path, bench_rel in record.vulnerable_source_paths.items():
                src_path = bdir / bench_rel
                if not src_path.exists():
                    continue
                content = src_path.read_text(errors="replace")
                content = _truncate_source(content, repo_path, crash_report_text)
                input_parts.append(f"\nSource: {repo_path}\n```c\n{content}\n```")

        # Target is the reference (ground-truth) patch
        reference_patch = ""
        if record.reference_patch_path:
            patch_path = bdir / record.reference_patch_path
            if patch_path.exists():
                reference_patch = patch_path.read_text()

        samples.append(
            Sample(
                input="\n".join(input_parts),
                target=reference_patch,
                id=record.id,
                metadata={
                    "vuln_id": record.id,
                    "target": record.target,
                    "sanitizer": str(record.sanitizer),
                    "crash_input_path": (
                        str(record.crash_input_path)
                        if record.crash_input_path
                        else None
                    ),
                    "benchmark_dir": benchmark_dir,
                    "vulnerable_source_paths": (
                        record.vulnerable_source_paths
                        if record.vulnerable_source_paths
                        else {}
                    ),
                    "vulnerable_source_ref": record.vulnerable_source_ref,
                },
            )
        )

    return samples


@solver
def patching_solver(
    targets_root: str = "targets",
    fuzzing_engine: str = "libfuzzer",
    benchmark_dir: str = "benchmark",
) -> Solver:
    """Solver that gives the model tools to iteratively patch vulnerabilities.

    Spins up a Docker sandbox per-sample and provides try_patch, compile_target,
    and run_crash_input tools in a generate(tool_calls="loop") loop.
    """

    async def solve(state: TaskState, generate: Generate) -> TaskState:
        meta = state.metadata or {}
        target_name: str = meta.get("target", "")
        sanitizer: str = meta.get("sanitizer", "address")
        crash_input_path: str | None = meta.get("crash_input_path")
        vuln_source_paths: dict[str, str] = meta.get("vulnerable_source_paths", {})
        vuln_ref: str | None = meta.get("vulnerable_source_ref")

        target_dir = Path(targets_root) / target_name
        fuzz_binary = _resolve_fuzz_binary(target_dir, target_name)

        config = SandboxConfig(
            target_name=target_name,
            target_dir=target_dir,
            sanitizer=sanitizer,
            engine=fuzzing_engine,
        )

        async with DockerSandbox(config) as sandbox:
            # Copy crash input into the sandbox
            container_crash_path = "/tmp/crash_input"
            if crash_input_path:
                local = Path(benchmark_dir) / crash_input_path
                if local.exists():
                    await sandbox.copy_in(local, container_crash_path)

            src_dir = f"/src/{target_name}"
            compile_cmd = (
                f"env SANITIZER={sanitizer} FUZZING_ENGINE={fuzzing_engine} "
                "FUZZING_LANGUAGE=c compile"
            )

            if vuln_ref:
                # Checkout the exact vulnerable commit so the source tree,
                # headers, and build system are all self-consistent.
                await sandbox.exec(f"cd {src_dir} && git checkout {vuln_ref}")
                # Build with the vulnerable source.
                await sandbox.exec(compile_cmd, timeout=config.timeout_seconds)
            else:
                # Fallback: build HEAD first, then swap in vulnerable files.
                await sandbox.exec(compile_cmd, timeout=config.timeout_seconds)
                for repo_path, bench_rel in vuln_source_paths.items():
                    local_src = Path(benchmark_dir) / bench_rel
                    if local_src.exists():
                        container_dest = f"{src_dir}/{repo_path}"
                        parent = str(Path(container_dest).parent)
                        await sandbox.exec(f"mkdir -p {parent}")
                        await sandbox.copy_in(local_src, container_dest)
                await sandbox.exec(compile_cmd, timeout=config.timeout_seconds)

            # Commit the vulnerable state so `git checkout .` in
            # try_patch resets to the vulnerable version, not HEAD.
            await sandbox.exec(
                f"cd {src_dir} && git add -A && "
                "git -c user.email=eval@local -c user.name=eval "
                "commit -m 'vulnerable baseline' --allow-empty"
            )

            # Build tools that close over this sandbox
            tools: list[Tool] = [
                _make_try_patch_tool(sandbox),
                _make_compile_tool(sandbox, sanitizer, fuzzing_engine),
                _make_run_crash_tool(sandbox, fuzz_binary, container_crash_path),
                _make_read_source_tool(sandbox),
            ]

            # Inject system prompt
            state = await system_message(prompts.load("patching.system"))(
                state, generate
            )

            # Register tools and run the agentic loop
            state = await use_tools(tools)(state, generate)
            state = await generate(state, tool_calls="loop", max_tokens=16384)

        return state

    return solve


def patching_scorer(
    targets_root: str = "targets",
    fuzzing_engine: str = "libfuzzer",
) -> list[Scorer]:
    """Scorer pipeline: apply patch, rebuild, verify crash, run tests.

    Wraps score_patch() from scorers/patch.py inside a DockerSandbox.
    Returns partial credit (0.0–1.0) based on how far through the
    pipeline the patch succeeds.

    fuzzing_engine selects the OSS-fuzz engine used to compile and run
    the fuzz target (libfuzzer, afl, honggfuzz, centipede).
    """

    @scorer(metrics=[mean()])
    def _patch_scorer() -> Scorer:
        async def score(state, target) -> Score:
            meta: dict = state.metadata or {}
            vuln_target: str = meta.get("target", "")
            benchmark_dir: str = meta.get("benchmark_dir", "benchmark")
            sanitizer: str = meta.get("sanitizer", "address")
            crash_input_path: str | None = meta.get("crash_input_path")
            vuln_source_paths: dict[str, str] = meta.get("vulnerable_source_paths", {})

            patch_diff = _extract_diff_from_state(state)

            if patch_diff is None:
                return Score(
                    value=0.0,
                    explanation="No unified diff found in model output.",
                )

            if not crash_input_path:
                return Score(
                    value=0.0,
                    explanation="No triggering input path in sample metadata.",
                )

            triggering_input = str(Path(benchmark_dir) / crash_input_path)
            target_dir = Path(targets_root) / vuln_target
            fuzz_binary = _resolve_fuzz_binary(target_dir, vuln_target)

            config = SandboxConfig(
                target_name=vuln_target,
                target_dir=target_dir,
                sanitizer=sanitizer,
                engine=fuzzing_engine,
            )

            async with DockerSandbox(config) as sandbox:
                src_dir = f"/src/{vuln_target}"
                compile_cmd = (
                    f"env SANITIZER={sanitizer} FUZZING_ENGINE={fuzzing_engine} "
                    "FUZZING_LANGUAGE=c compile"
                )

                # Mirror the solver setup: checkout vulnerable ref or
                # swap in vulnerable source files.
                vuln_ref: str | None = meta.get("vulnerable_source_ref")
                if vuln_ref:
                    await sandbox.exec(f"cd {src_dir} && git checkout {vuln_ref}")
                    await sandbox.exec(compile_cmd, timeout=config.timeout_seconds)
                else:
                    await sandbox.exec(compile_cmd, timeout=config.timeout_seconds)
                    for repo_path, bench_rel in vuln_source_paths.items():
                        local_src = Path(benchmark_dir) / bench_rel
                        if local_src.exists():
                            container_dest = f"{src_dir}/{repo_path}"
                            parent = str(Path(container_dest).parent)
                            await sandbox.exec(f"mkdir -p {parent}")
                            await sandbox.copy_in(local_src, container_dest)
                    await sandbox.exec(compile_cmd, timeout=config.timeout_seconds)

                result = await score_patch(
                    sandbox=sandbox,
                    patch_diff=patch_diff,
                    triggering_input_path=triggering_input,
                    fuzz_target_binary=fuzz_binary,
                    sanitizer=sanitizer,
                    fuzzing_engine=fuzzing_engine,
                )

            numeric = _patch_result_to_score(result)
            explanation = (
                f"patch_applies={result.patch_applies}, "
                f"compiles={result.compiles}, "
                f"crash_eliminated={result.crash_eliminated}, "
                f"tests_pass={result.tests_pass}, "
                f"diff_lines={result.diff_lines}"
            )
            return Score(value=numeric, explanation=explanation)

        return score

    return [_patch_scorer()]


@task
def vulnerability_patching(
    benchmark_dir: str = "benchmark",
    target: str | None = None,
    targets_root: str = "targets",
    fuzzing_engine: str = "libfuzzer",
    ready_only: bool = False,
    seed: int | None = None,
) -> Task:
    """Inspect-AI task: patch parser vulnerabilities given crash reports.

    Run with:
        inspect eval tasks/patching.py -T benchmark_dir=benchmark
        inspect eval tasks/patching.py -T benchmark_dir=benchmark -T target=libpng
        inspect eval tasks/patching.py -T benchmark_dir=benchmark -T fuzzing_engine=afl
    """
    samples = load_patching_dataset(
        benchmark_dir, target, ready_only=ready_only, seed=seed
    )
    if not samples:
        filter_msg = f" for target '{target}'" if target else ""
        raise ValueError(
            f"No vulnerability records found in '{benchmark_dir}'{filter_msg}. "
            "Run the dataset curator first or check your benchmark_dir path."
        )
    return Task(
        dataset=samples,
        solver=patching_solver(
            targets_root=targets_root,
            fuzzing_engine=fuzzing_engine,
            benchmark_dir=benchmark_dir,
        ),
        scorer=patching_scorer(
            targets_root=targets_root, fuzzing_engine=fuzzing_engine
        ),
        message_limit=60,
    )
