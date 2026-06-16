"""Coverage aggregation across N fuzzing agents.

Merges llvm-cov raw profiles from multiple agents into a unified coverage map.
Reports:
- Union coverage (total lines/branches/functions reached by any agent)
- Per-agent marginal coverage (what each agent added beyond the others)
- Pairwise Jaccard similarity matrix between agents

Coverage is **per-binary**: merge only within the same binary, report separately
across binaries.  Different harnesses compile to different binaries and their
edge maps are not comparable.

Design notes
------------
``llvm-profdata merge`` combines raw ``.profraw`` files into a single
``.profdata`` index.  Then ``llvm-cov export --format=json`` exports a
structured JSON that enumerates every function, every line, and every branch
with their hit counts.  From that JSON we derive:

- A *covered line set* for each agent (line_key = ``"file:line"``).
- A *covered branch set* for each agent (branch_key = ``"file:line:col"``).
- A *covered function set* for each agent (qualified function name).

Union/marginal/Jaccard are then plain set operations.

If ``llvm-profdata`` is not installed, all functions that invoke it raise
``FileNotFoundError`` with a clear message rather than silently returning
zeroes.
"""

from __future__ import annotations

import json
import subprocess
import tempfile
from pathlib import Path

from pydantic import BaseModel

from parser_security_eval.log import get_log

log = get_log(__name__)

# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


class CoverageProfile(BaseModel):
    """Raw coverage profile for one agent against one binary.

    Attributes:
        agent_id: Identifier of the agent that produced this profile.
        binary_name: Name of the fuzz-target binary (e.g. ``"fuzz_png"``).
        profraw_paths: Absolute paths to the ``.profraw`` files collected
            from the agent's fuzzing run.  There may be several — one per
            process execution — or just one if the agent used
            ``LLVM_PROFILE_FILE`` with ``%p`` or ``%m`` expansions.
    """

    agent_id: str
    binary_name: str
    profraw_paths: list[Path]


class AgentCoverage(BaseModel):
    """Derived coverage sets for one agent against one binary.

    These sets are used for union/marginal/Jaccard computation.

    Attributes:
        agent_id: Identifier of the agent.
        binary_name: Name of the fuzz-target binary.
        covered_lines: Set of ``"file:line"`` strings that were hit.
        covered_branches: Set of ``"file:line:col"`` strings that were hit.
        covered_functions: Set of qualified function names that were called.
        line_coverage_pct: Percentage of instrumented lines covered.
        branch_coverage_pct: Percentage of instrumented branches covered.
        function_coverage_pct: Percentage of instrumented functions covered.
    """

    agent_id: str
    binary_name: str
    covered_lines: set[str]
    covered_branches: set[str]
    covered_functions: set[str]
    line_coverage_pct: float
    branch_coverage_pct: float
    function_coverage_pct: float

    model_config = {"arbitrary_types_allowed": True}


class AgentMarginalCoverage(BaseModel):
    """The marginal coverage contributed by one agent.

    Attributes:
        agent_id: Identifier of the agent.
        binary_name: Name of the fuzz-target binary.
        marginal_lines: Lines hit by this agent but by no other agent.
        marginal_branches: Branches hit by this agent but by no other agent.
        marginal_functions: Functions called by this agent but by no other.
        marginal_line_count: ``len(marginal_lines)``.
        marginal_branch_count: ``len(marginal_branches)``.
        marginal_function_count: ``len(marginal_functions)``.
    """

    agent_id: str
    binary_name: str
    marginal_lines: set[str]
    marginal_branches: set[str]
    marginal_functions: set[str]
    marginal_line_count: int
    marginal_branch_count: int
    marginal_function_count: int

    model_config = {"arbitrary_types_allowed": True}


class AggregateCoverage(BaseModel):
    """Aggregate coverage result for N agents against one binary.

    Attributes:
        binary_name: Name of the fuzz-target binary.
        agent_ids: Ordered list of agent identifiers.
        union_lines: All lines hit by at least one agent.
        union_branches: All branches hit by at least one agent.
        union_functions: All functions hit by at least one agent.
        union_line_count: ``len(union_lines)``.
        union_branch_count: ``len(union_branches)``.
        union_function_count: ``len(union_functions)``.
        per_agent: Per-agent marginal coverage breakdown.
        jaccard_lines: Pairwise Jaccard similarity on covered *lines*.
            Keyed as ``"agent_a::agent_b"`` (alphabetical order).
        jaccard_branches: Pairwise Jaccard similarity on covered *branches*.
        coverage_growth_lines: Cumulative union line count as each agent is
            added (in ``agent_ids`` order).  Useful for plotting growth curves.
        coverage_growth_branches: Same but for branches.
    """

    binary_name: str
    agent_ids: list[str]
    union_lines: set[str]
    union_branches: set[str]
    union_functions: set[str]
    union_line_count: int
    union_branch_count: int
    union_function_count: int
    per_agent: list[AgentMarginalCoverage]
    jaccard_lines: dict[str, float]
    jaccard_branches: dict[str, float]
    coverage_growth_lines: list[int]
    coverage_growth_branches: list[int]

    model_config = {"arbitrary_types_allowed": True}


# ---------------------------------------------------------------------------
# llvm-profdata / llvm-cov helpers
# ---------------------------------------------------------------------------


def _require_tool(tool: str) -> None:
    """Raise ``FileNotFoundError`` if *tool* is not on PATH.

    Args:
        tool: Executable name to check (e.g. ``"llvm-profdata"``).

    Raises:
        FileNotFoundError: If the tool cannot be found.
    """
    try:
        subprocess.run(
            [tool, "--version"],
            check=True,
            capture_output=True,
        )
    except FileNotFoundError:
        raise FileNotFoundError(
            f"{tool!r} not found on PATH. "
            "Install the LLVM toolchain (e.g. 'apt install llvm' or "
            "'brew install llvm') and ensure llvm-profdata and llvm-cov "
            "are accessible."
        ) from None


def _merge_profraw(
    profraw_paths: list[Path],
    output_profdata: Path,
    *,
    sparse: bool = True,
) -> None:
    """Run ``llvm-profdata merge`` to combine raw profiles.

    Args:
        profraw_paths: List of ``.profraw`` files to merge.
        output_profdata: Destination ``.profdata`` file.
        sparse: Pass ``-sparse`` flag to ``llvm-profdata`` (recommended for
            fuzz profiles; keeps the file compact).

    Raises:
        FileNotFoundError: If ``llvm-profdata`` is not installed.
        RuntimeError: If ``llvm-profdata merge`` exits with a non-zero code.
    """
    _require_tool("llvm-profdata")

    cmd: list[str] = ["llvm-profdata", "merge"]
    if sparse:
        cmd.append("-sparse")
    cmd += [str(p) for p in profraw_paths]
    cmd += ["-o", str(output_profdata)]

    log.debug("Running: %s", " ".join(cmd))
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(
            f"llvm-profdata merge failed (rc={result.returncode}): {result.stderr}"
        )


def _export_coverage_json(
    binary_path: Path,
    profdata_path: Path,
) -> dict:
    """Run ``llvm-cov export`` and return the parsed JSON.

    Args:
        binary_path: Path to the instrumented binary.
        profdata_path: Merged ``.profdata`` file produced by
            ``llvm-profdata merge``.

    Returns:
        Parsed JSON dict from ``llvm-cov export --format=json``.

    Raises:
        FileNotFoundError: If ``llvm-cov`` is not installed.
        RuntimeError: If ``llvm-cov export`` exits with a non-zero code.
    """
    _require_tool("llvm-cov")

    cmd = [
        "llvm-cov",
        "export",
        str(binary_path),
        f"-instr-profile={profdata_path}",
        "--format=json",
        "--summary-only",
    ]

    log.debug("Running: %s", " ".join(cmd))
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(
            f"llvm-cov export failed (rc={result.returncode}): {result.stderr}"
        )

    return json.loads(result.stdout)


def _export_coverage_json_full(
    binary_path: Path,
    profdata_path: Path,
) -> dict:
    """Run ``llvm-cov export`` WITHOUT ``--summary-only`` to get line/branch data.

    Args:
        binary_path: Path to the instrumented binary.
        profdata_path: Merged ``.profdata`` file.

    Returns:
        Parsed JSON dict (full export with function/line/branch detail).

    Raises:
        FileNotFoundError: If ``llvm-cov`` is not installed.
        RuntimeError: If ``llvm-cov export`` exits with a non-zero code.
    """
    _require_tool("llvm-cov")

    cmd = [
        "llvm-cov",
        "export",
        str(binary_path),
        f"-instr-profile={profdata_path}",
        "--format=json",
    ]

    log.debug("Running: %s", " ".join(cmd))
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(
            f"llvm-cov export failed (rc={result.returncode}): {result.stderr}"
        )

    return json.loads(result.stdout)


# ---------------------------------------------------------------------------
# Coverage set extraction
# ---------------------------------------------------------------------------


def _extract_coverage_sets(
    export_json: dict,
    binary_name: str,
    agent_id: str,
) -> AgentCoverage:
    """Convert ``llvm-cov export`` JSON into an :class:`AgentCoverage`.

    The ``llvm-cov export`` JSON has this structure (abbreviated)::

        {
          "data": [{
            "files": [{
              "filename": "/src/foo.c",
              "segments": [[line, col, count, hasCount, isRegionEntry, isGapRegion], ...],
              "branches": [[srcLine, srcCol, dstLine, dstCol, count, ...], ...],
              "summary": { "lines": {"covered": N, "count": M}, ... }
            }],
            "functions": [{"name": "...", "count": N, ...}],
            "totals": {"lines": ..., "branches": ..., "functions": ...}
          }]
        }

    A *segment* has a hit count > 0 if ``hasCount`` is true and ``count > 0``.
    A *branch* is covered if its ``count > 0``.

    Args:
        export_json: Parsed JSON from ``llvm-cov export``.
        binary_name: Name of the binary (used to populate the model).
        agent_id: Agent identifier (used to populate the model).

    Returns:
        :class:`AgentCoverage` with populated sets and summary percentages.
    """
    covered_lines: set[str] = set()
    covered_branches: set[str] = set()
    covered_functions: set[str] = set()

    total_lines = 0
    total_branches = 0
    total_functions = 0

    for data_item in export_json.get("data", []):
        # --- Lines from segments ---
        for file_info in data_item.get("files", []):
            filename = file_info.get("filename", "")

            for segment in file_info.get("segments", []):
                # segment: [line, col, count, hasCount, isRegionEntry, isGapRegion]
                if len(segment) < 6:
                    continue
                line_no, _col, count, has_count, _is_region_entry, is_gap = segment
                if is_gap:
                    continue
                total_lines += 1
                if has_count and count > 0:
                    covered_lines.add(f"{filename}:{line_no}")

            # --- Branches ---
            for branch in file_info.get("branches", []):
                # branch: [srcLine, srcCol, dstLine, dstCol, count, ...]
                if len(branch) < 5:
                    continue
                src_line, src_col, _dst_line, _dst_col, count = branch[:5]
                total_branches += 1
                if count > 0:
                    covered_branches.add(f"{filename}:{src_line}:{src_col}")

        # --- Functions ---
        for func in data_item.get("functions", []):
            name = func.get("name", "")
            count = func.get("count", 0)
            total_functions += 1
            if count > 0:
                covered_functions.add(name)

        # Prefer summary totals when available (more accurate than
        # counting segments which can double-count inlined code).
        totals = data_item.get("totals", {})
        if totals:
            total_lines = totals.get("lines", {}).get("count", total_lines)
            total_branches = totals.get("branches", {}).get("count", total_branches)
            total_functions = totals.get("functions", {}).get("count", total_functions)

    line_pct = 100.0 * len(covered_lines) / total_lines if total_lines > 0 else 0.0
    branch_pct = (
        100.0 * len(covered_branches) / total_branches if total_branches > 0 else 0.0
    )
    func_pct = (
        100.0 * len(covered_functions) / total_functions if total_functions > 0 else 0.0
    )

    return AgentCoverage(
        agent_id=agent_id,
        binary_name=binary_name,
        covered_lines=covered_lines,
        covered_branches=covered_branches,
        covered_functions=covered_functions,
        line_coverage_pct=line_pct,
        branch_coverage_pct=branch_pct,
        function_coverage_pct=func_pct,
    )


# ---------------------------------------------------------------------------
# Jaccard similarity
# ---------------------------------------------------------------------------


def _jaccard(a: set[str], b: set[str]) -> float:
    """Compute Jaccard similarity between two sets.

    Returns 1.0 if both sets are empty (identical empty coverage).

    Args:
        a: First set.
        b: Second set.

    Returns:
        ``|a ∩ b| / |a ∪ b|`` in ``[0.0, 1.0]``.
    """
    if not a and not b:
        return 1.0
    union = a | b
    if not union:
        return 1.0
    return len(a & b) / len(union)


# ---------------------------------------------------------------------------
# Main public API
# ---------------------------------------------------------------------------


def build_agent_coverage(
    profile: CoverageProfile,
    binary_path: Path,
) -> AgentCoverage:
    """Merge raw profiles for one agent and extract coverage sets.

    Runs ``llvm-profdata merge`` on the agent's ``.profraw`` files, then
    ``llvm-cov export`` on the instrumented binary to produce an
    :class:`AgentCoverage` with line/branch/function sets.

    Args:
        profile: The agent's :class:`CoverageProfile` containing ``.profraw``
            paths and the binary name.
        binary_path: Filesystem path to the instrumented binary matching
            ``profile.binary_name``.

    Returns:
        :class:`AgentCoverage` with covered sets and summary percentages.

    Raises:
        FileNotFoundError: If ``llvm-profdata`` or ``llvm-cov`` is not on PATH.
        RuntimeError: If either tool exits with a non-zero return code.
        ValueError: If ``profile.profraw_paths`` is empty.
    """
    if not profile.profraw_paths:
        raise ValueError(
            f"Agent {profile.agent_id!r}: no .profraw paths provided. "
            "Cannot build coverage without raw profile data."
        )

    with tempfile.TemporaryDirectory(prefix="cov_agg_") as tmpdir:
        profdata_path = Path(tmpdir) / f"{profile.agent_id}.profdata"

        _merge_profraw(profile.profraw_paths, profdata_path)
        export_json = _export_coverage_json_full(binary_path, profdata_path)

    return _extract_coverage_sets(export_json, profile.binary_name, profile.agent_id)


def merge_agent_coverage(
    profiles: list[CoverageProfile],
    binary_path: Path,
) -> AggregateCoverage:
    """Merge coverage from N agents and compute union/marginal/Jaccard metrics.

    All profiles must share the same ``binary_name``.  Coverage merging is
    per-binary — you cannot meaningfully combine profiles from different
    binaries because the instrumentation edge maps differ.

    Args:
        profiles: One :class:`CoverageProfile` per agent.  All must have the
            same ``binary_name``.
        binary_path: Filesystem path to the instrumented binary.  Must be the
            same binary that produced all ``.profraw`` files in *profiles*.

    Returns:
        :class:`AggregateCoverage` with union, per-agent marginal, Jaccard
        similarity, and coverage growth curve data.

    Raises:
        ValueError: If *profiles* is empty, or if profiles have mismatched
            ``binary_name`` values.
        FileNotFoundError: If ``llvm-profdata`` or ``llvm-cov`` is not on PATH.
        RuntimeError: If any LLVM tool exits with a non-zero return code.
    """
    if not profiles:
        raise ValueError("profiles must be non-empty")

    binary_names = {p.binary_name for p in profiles}
    if len(binary_names) > 1:
        raise ValueError(
            f"All profiles must share the same binary_name; "
            f"got: {sorted(binary_names)!r}. "
            "Merge only profiles from the same binary."
        )

    binary_name = profiles[0].binary_name

    # Build per-agent coverage sets (runs llvm-profdata + llvm-cov per agent).
    agent_coverages: list[AgentCoverage] = []
    for profile in profiles:
        log.info(
            "Building coverage for agent %r (binary=%r, %d profraw files)",
            profile.agent_id,
            profile.binary_name,
            len(profile.profraw_paths),
        )
        cov = build_agent_coverage(profile, binary_path)
        agent_coverages.append(cov)

    return _compute_aggregate(agent_coverages, binary_name)


def merge_agent_coverage_from_sets(
    agent_coverages: list[AgentCoverage],
) -> AggregateCoverage:
    """Compute aggregate coverage from pre-built :class:`AgentCoverage` objects.

    This is the set-arithmetic core of the aggregation pipeline.  It does NOT
    invoke any external tools, making it easy to test and to use when coverage
    sets have already been built by other means.

    Args:
        agent_coverages: One :class:`AgentCoverage` per agent.  All must share
            the same ``binary_name``.

    Returns:
        :class:`AggregateCoverage` with union, per-agent marginal, Jaccard
        similarity, and coverage growth curve data.

    Raises:
        ValueError: If *agent_coverages* is empty or ``binary_name`` values
            differ across entries.
    """
    if not agent_coverages:
        raise ValueError("agent_coverages must be non-empty")

    binary_names = {c.binary_name for c in agent_coverages}
    if len(binary_names) > 1:
        raise ValueError(
            f"All AgentCoverage entries must share the same binary_name; "
            f"got: {sorted(binary_names)!r}."
        )

    binary_name = agent_coverages[0].binary_name
    return _compute_aggregate(agent_coverages, binary_name)


def _compute_aggregate(
    agent_coverages: list[AgentCoverage],
    binary_name: str,
) -> AggregateCoverage:
    """Core set-arithmetic aggregation — no subprocess calls.

    Args:
        agent_coverages: List of per-agent coverage sets.
        binary_name: Shared binary name (already validated by callers).

    Returns:
        :class:`AggregateCoverage` with all derived metrics populated.
    """
    # --- Union ---
    union_lines: set[str] = set()
    union_branches: set[str] = set()
    union_functions: set[str] = set()
    for cov in agent_coverages:
        union_lines |= cov.covered_lines
        union_branches |= cov.covered_branches
        union_functions |= cov.covered_functions

    # --- Marginal coverage per agent ---
    per_agent: list[AgentMarginalCoverage] = []
    for cov in agent_coverages:
        # "others_lines" = union of all other agents' lines
        others_lines: set[str] = set()
        others_branches: set[str] = set()
        others_functions: set[str] = set()
        for other in agent_coverages:
            if other.agent_id == cov.agent_id:
                continue
            others_lines |= other.covered_lines
            others_branches |= other.covered_branches
            others_functions |= other.covered_functions

        marginal_lines = cov.covered_lines - others_lines
        marginal_branches = cov.covered_branches - others_branches
        marginal_functions = cov.covered_functions - others_functions

        per_agent.append(
            AgentMarginalCoverage(
                agent_id=cov.agent_id,
                binary_name=binary_name,
                marginal_lines=marginal_lines,
                marginal_branches=marginal_branches,
                marginal_functions=marginal_functions,
                marginal_line_count=len(marginal_lines),
                marginal_branch_count=len(marginal_branches),
                marginal_function_count=len(marginal_functions),
            )
        )

    # --- Pairwise Jaccard ---
    jaccard_lines: dict[str, float] = {}
    jaccard_branches: dict[str, float] = {}
    n = len(agent_coverages)
    for i in range(n):
        for j in range(i + 1, n):
            a = agent_coverages[i]
            b = agent_coverages[j]
            # Key in alphabetical order for stable output.
            key = f"{min(a.agent_id, b.agent_id)}::{max(a.agent_id, b.agent_id)}"
            jaccard_lines[key] = _jaccard(a.covered_lines, b.covered_lines)
            jaccard_branches[key] = _jaccard(a.covered_branches, b.covered_branches)

    # --- Coverage growth curves ---
    # Cumulative union as each agent is added in list order.
    growth_lines: list[int] = []
    growth_branches: list[int] = []
    running_lines: set[str] = set()
    running_branches: set[str] = set()
    for cov in agent_coverages:
        running_lines |= cov.covered_lines
        running_branches |= cov.covered_branches
        growth_lines.append(len(running_lines))
        growth_branches.append(len(running_branches))

    agent_ids = [c.agent_id for c in agent_coverages]

    return AggregateCoverage(
        binary_name=binary_name,
        agent_ids=agent_ids,
        union_lines=union_lines,
        union_branches=union_branches,
        union_functions=union_functions,
        union_line_count=len(union_lines),
        union_branch_count=len(union_branches),
        union_function_count=len(union_functions),
        per_agent=per_agent,
        jaccard_lines=jaccard_lines,
        jaccard_branches=jaccard_branches,
        coverage_growth_lines=growth_lines,
        coverage_growth_branches=growth_branches,
    )
