"""Call graph extraction for C/C++ parser targets.

Strategy:
- Use ``cflow`` (must be installed and available on PATH).

The result is pruned to depth <= ``depth_limit`` hops from each entry
point before being returned as a :class:`CallGraph`.
"""

from __future__ import annotations

import logging
import re
import shutil
import subprocess
from pathlib import Path

from pydantic import BaseModel

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


class FunctionNode(BaseModel):
    """A function discovered in the target source tree."""

    name: str
    signature: str  # return type + params as a string
    file: str
    line: int | None


class CallEdge(BaseModel):
    """A directed call edge: caller -> callee."""

    caller: str  # function name
    callee: str  # function name


class CallGraph(BaseModel):
    """Call graph for a parser target, centred on a set of entry points."""

    target: str
    entry_points: list[str]
    nodes: list[FunctionNode]
    edges: list[CallEdge]
    depth_limit: int = 5


# ---------------------------------------------------------------------------
# cflow-based extraction
# ---------------------------------------------------------------------------

_CFLOW_ENTRY_RE = re.compile(
    r"^(\s*)"  # leading indentation (one level = one call depth)
    r"(\w+)\s*\("  # function name followed by '('
    r"([^)]*)\)"  # parameter list (may be empty)
    r"(?:\s+<(.+):(\d+)>)?",  # optional file:line annotation
    re.MULTILINE,
)


def _parse_cflow_output(
    raw: str,
    source_dir: Path,
    entry_point: str,
    depth_limit: int,
) -> tuple[dict[str, FunctionNode], list[CallEdge]]:
    """Parse the indented tree output of ``cflow`` into nodes + edges.

    ``cflow`` prints a nested call tree; indentation level corresponds to
    call depth. We treat the tree BFS-style and stop at *depth_limit*.
    """
    nodes: dict[str, FunctionNode] = {}
    edges: list[CallEdge] = []

    # cflow outputs lines like:
    #   main() <main.c:10>:
    #       xmlParseDocument() <parser.c:42>:
    #           xmlParseElement() <parser.c:120>
    # We reconstruct the call stack by tracking indentation.

    call_stack: list[str] = []  # maps indent level -> function name

    for line in raw.splitlines():
        stripped = line.rstrip()
        if not stripped:
            continue

        # Measure indent depth (cflow uses 4-space indent by default)
        indent = len(stripped) - len(stripped.lstrip())
        depth = indent // 4  # approximate; cflow may vary

        # Extract function name and optional location
        m = re.match(r"\s*(\w+)\s*\(([^)]*)\)(?:\s+<(.+?):(\d+)>)?", stripped)
        if not m:
            continue

        func_name = m.group(1)
        params = m.group(2).strip()
        file_loc = m.group(3)
        line_no_str = m.group(4)
        line_no = int(line_no_str) if line_no_str else None

        if func_name not in nodes:
            sig = f"({params})"
            nodes[func_name] = FunctionNode(
                name=func_name,
                signature=sig,
                file=file_loc or "",
                line=line_no,
            )

        # Maintain the call stack
        if depth < len(call_stack):
            call_stack = call_stack[:depth]
        call_stack.append(func_name)

        if depth > 0 and depth <= depth_limit:
            caller = call_stack[depth - 1]
            edge = CallEdge(caller=caller, callee=func_name)
            if edge not in edges:
                edges.append(edge)

    return nodes, edges


def _extract_via_cflow(
    source_dir: Path,
    entry_points: list[str],
    depth: int,
) -> tuple[dict[str, FunctionNode], list[CallEdge]]:
    """Run ``cflow`` and return parsed nodes/edges.

    Raises
    ------
    RuntimeError
        If ``cflow`` is not found on PATH.
    """
    if not shutil.which("cflow"):
        raise RuntimeError(
            "cflow not found on PATH. Install cflow (e.g. apt-get install cflow)"
            " before running the pre-processing pipeline."
        )

    c_files = list(source_dir.rglob("*.c")) + list(source_dir.rglob("*.cpp"))
    if not c_files:
        return {}, []

    all_nodes: dict[str, FunctionNode] = {}
    all_edges: list[CallEdge] = []

    for entry in entry_points:
        cmd = [
            "cflow",
            "--depth",
            str(depth + 1),
            "--main",
            entry,
            *[str(f) for f in c_files[:200]],  # cap to avoid arg-list overflows
        ]
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60,
                cwd=str(source_dir),
            )
        except (subprocess.TimeoutExpired, OSError) as exc:
            logger.warning("cflow failed for %s: %s", entry, exc)
            continue

        if result.returncode != 0 and not result.stdout.strip():
            logger.debug("cflow returned %d for %s", result.returncode, entry)
            continue

        nodes, edges = _parse_cflow_output(result.stdout, source_dir, entry, depth)
        all_nodes.update(nodes)
        for edge in edges:
            if edge not in all_edges:
                all_edges.append(edge)

    return all_nodes, all_edges


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def extract_callgraph(
    source_dir: Path,
    entry_points: list[str],
    depth: int = 5,
    target_name: str = "",
) -> CallGraph:
    """Extract a call graph from C/C++ source files using ``cflow``.

    Parameters
    ----------
    source_dir:
        Root directory of the parser source tree (or a sub-directory
        containing the relevant C/C++ files).
    entry_points:
        Function names to treat as roots of the call graph.
    depth:
        Maximum number of hops from any entry point to include.
    target_name:
        Human-readable name for the target (stored in the returned model).

    Returns
    -------
    CallGraph
        The extracted call graph, pruned to *depth* hops.

    Raises
    ------
    RuntimeError
        If ``cflow`` is not found on PATH.
    ValueError
        If *entry_points* is empty.
    """
    if not entry_points:
        raise ValueError("entry_points must not be empty")

    nodes_dict, edges = _extract_via_cflow(source_dir, entry_points, depth)
    logger.info("Used cflow for call graph extraction of %s", target_name or source_dir)

    return CallGraph(
        target=target_name or str(source_dir),
        entry_points=entry_points,
        nodes=list(nodes_dict.values()),
        edges=edges,
        depth_limit=depth,
    )
