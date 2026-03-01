"""Call graph extraction for C/C++ parser targets.

Strategy:
- Try ``cflow`` first if available on PATH.
- Fall back to a grep/regex approach that finds function definitions and
  call sites in .c/.cpp/.h files.

In both cases the result is pruned to depth <= ``depth_limit`` hops from
each entry point before being returned as a :class:`CallGraph`.
"""

from __future__ import annotations

import logging
import re
import shutil
import subprocess
from collections import deque
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
) -> tuple[dict[str, FunctionNode], list[CallEdge]] | None:
    """Try to run ``cflow`` and return parsed nodes/edges, or ``None`` on failure."""
    if not shutil.which("cflow"):
        logger.debug("cflow not found on PATH; falling back to grep extraction")
        return None

    c_files = list(source_dir.rglob("*.c")) + list(source_dir.rglob("*.cpp"))
    if not c_files:
        return None

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

    return (all_nodes, all_edges) if all_nodes else None


# ---------------------------------------------------------------------------
# Grep/regex-based fallback
# ---------------------------------------------------------------------------

# Matches a C function definition (very approximate).
# Catches patterns like:
#   int xmlParseDocument(xmlDocPtr doc) {
#   static void png_read_row(png_structrp png_ptr, ...) {
_FUNC_DEF_RE = re.compile(
    r"^(?:(?:static|inline|extern|const|unsigned|signed|long|short|void|int|char"
    r"|float|double|size_t|ssize_t|uint\w*|int\w*)\s+)+"
    r"(\w+)\s*\(([^)]*)\)\s*\{",
    re.MULTILINE,
)

# Matches a call site: word followed by '('
_CALL_SITE_RE = re.compile(r"\b(\w+)\s*\(")

# Language keywords that look like function calls but are not
_KEYWORDS = frozenset(
    {
        "if",
        "for",
        "while",
        "switch",
        "return",
        "sizeof",
        "typeof",
        "alignof",
        "do",
        "else",
        "case",
        "default",
        "goto",
        "break",
        "continue",
    }
)


def _extract_via_grep(
    source_dir: Path,
    entry_points: list[str],
    depth: int,
) -> tuple[dict[str, FunctionNode], list[CallEdge]]:
    """Regex-based extraction of function definitions and call sites.

    This is an approximation: it does not handle macros, function pointers,
    or forward declarations reliably.  It is good enough to give an LLM
    useful structural context.
    """
    source_files = (
        list(source_dir.rglob("*.c"))
        + list(source_dir.rglob("*.cpp"))
        + list(source_dir.rglob("*.h"))
    )

    # Map: function name -> FunctionNode
    func_nodes: dict[str, FunctionNode] = {}
    # Map: function name -> set of callee names
    call_map: dict[str, set[str]] = {}

    for src_file in source_files:
        try:
            text = src_file.read_text(errors="replace")
        except OSError:
            continue

        rel_path = str(src_file.relative_to(source_dir))

        for m in _FUNC_DEF_RE.finditer(text):
            func_name = m.group(1)
            params = m.group(2).strip()
            if func_name in _KEYWORDS:
                continue
            line_no = text[: m.start()].count("\n") + 1
            if func_name not in func_nodes:
                func_nodes[func_name] = FunctionNode(
                    name=func_name,
                    signature=f"({params})",
                    file=rel_path,
                    line=line_no,
                )

            # Find calls within this function body.
            # Approximate: find the brace block that starts at m.end()-1
            body_start = m.end() - 1  # points at '{'
            # Walk forward counting braces to find the closing '}'
            depth_counter = 0
            body_end = body_start
            for i, ch in enumerate(text[body_start:], start=body_start):
                if ch == "{":
                    depth_counter += 1
                elif ch == "}":
                    depth_counter -= 1
                    if depth_counter == 0:
                        body_end = i
                        break

            body = text[body_start:body_end]
            callees: set[str] = set()
            for cm in _CALL_SITE_RE.finditer(body):
                callee = cm.group(1)
                if callee not in _KEYWORDS and callee != func_name:
                    callees.add(callee)

            if func_name not in call_map:
                call_map[func_name] = set()
            call_map[func_name].update(callees)

    # BFS from each entry point, limited to *depth* hops
    visited_funcs: set[str] = set()
    edges: list[CallEdge] = []

    queue: deque[tuple[str, int]] = deque()
    for ep in entry_points:
        queue.append((ep, 0))
        visited_funcs.add(ep)
        # Ensure entry point has a node even if not defined in source
        if ep not in func_nodes:
            func_nodes[ep] = FunctionNode(name=ep, signature="(?)", file="", line=None)

    while queue:
        current, current_depth = queue.popleft()
        if current_depth >= depth:
            continue
        for callee in call_map.get(current, set()):
            edge = CallEdge(caller=current, callee=callee)
            if edge not in edges:
                edges.append(edge)
            if callee not in visited_funcs:
                visited_funcs.add(callee)
                queue.append((callee, current_depth + 1))

    # Only keep nodes reachable from entry points
    reachable_nodes = {
        name: node for name, node in func_nodes.items() if name in visited_funcs
    }

    return reachable_nodes, edges


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def extract_callgraph(
    source_dir: Path,
    entry_points: list[str],
    depth: int = 5,
    target_name: str = "",
) -> CallGraph:
    """Extract a call graph from C/C++ source files.

    Tries ``cflow`` first; falls back to a regex-based approach.

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
    """
    if not entry_points:
        raise ValueError("entry_points must not be empty")

    result = _extract_via_cflow(source_dir, entry_points, depth)
    if result is None:
        logger.info(
            "Using grep-based call graph extraction for %s", target_name or source_dir
        )
        nodes_dict, edges = _extract_via_grep(source_dir, entry_points, depth)
    else:
        nodes_dict, edges = result
        logger.info(
            "Used cflow for call graph extraction of %s", target_name or source_dir
        )

    return CallGraph(
        target=target_name or str(source_dir),
        entry_points=entry_points,
        nodes=list(nodes_dict.values()),
        edges=edges,
        depth_limit=depth,
    )
