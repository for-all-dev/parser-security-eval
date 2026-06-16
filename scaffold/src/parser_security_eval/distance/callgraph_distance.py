"""Call-graph hop-count distance for directed greybox fuzzing.

This is the baseline AFLGo-style distance metric: each function's distance to
the target set is the shortest path in the call graph (counting edges/hops).
Functions unreachable from any target get distance ``float('inf')``.

The AFL++/AFLGo distance file format is a plain tab-separated text file::

    function_name\\tdistance\\n

with one line per function.  Distance values are normalised to [0, 1] relative
to the maximum finite distance observed in the graph so the file can be fed to
AFLGo's ``-distance`` flag without further scaling.
"""

from __future__ import annotations

import math
from collections import deque
from enum import StrEnum
from pathlib import Path

from pydantic import BaseModel

from parser_security_eval.preprocess.callgraph import CallGraph

# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


class DistanceMetric(StrEnum):
    """Which distance metric was used to populate a :class:`DistanceMap`."""

    CALLGRAPH = "callgraph"
    SEMANTIC = "semantic"


class FunctionDistance(BaseModel):
    """Distance from a single function to the nearest target function."""

    function_name: str
    distance: float  # hop count; float('inf') if unreachable


class DistanceMap(BaseModel):
    """All function distances for a target, keyed by function name."""

    target: str
    metric: DistanceMetric
    entries: list[FunctionDistance]

    def as_dict(self) -> dict[str, float]:
        return {e.function_name: e.distance for e in self.entries}


# ---------------------------------------------------------------------------
# Core algorithm
# ---------------------------------------------------------------------------


def _build_adjacency(callgraph: CallGraph) -> dict[str, set[str]]:
    """Build a caller → {callee} adjacency set from the call graph edges."""
    adj: dict[str, set[str]] = {}
    for edge in callgraph.edges:
        adj.setdefault(edge.caller, set()).add(edge.callee)
        # Also ensure every node appears even if it has no outgoing edges
        adj.setdefault(edge.callee, set())
    for node in callgraph.nodes:
        adj.setdefault(node.name, set())
    return adj


def _reverse_adjacency(adj: dict[str, set[str]]) -> dict[str, set[str]]:
    """Reverse the graph: callee → {callers}."""
    rev: dict[str, set[str]] = {k: set() for k in adj}
    for caller, callees in adj.items():
        for callee in callees:
            rev.setdefault(callee, set()).add(caller)
    return rev


def compute_callgraph_distances(
    callgraph: CallGraph,
    target_functions: list[str],
) -> DistanceMap:
    """Compute shortest hop-count distance from every function to *target_functions*.

    Uses multi-source BFS on the *reversed* call graph so that a single pass
    gives the minimum distance from any function to the nearest target.

    Parameters
    ----------
    callgraph:
        The call graph to measure distances over.
    target_functions:
        Functions considered "targets" (e.g. known-vulnerable functions).
        Distance from a target to itself is 0.

    Returns
    -------
    DistanceMap
        One :class:`FunctionDistance` per node in the call graph.
    """
    adj = _build_adjacency(callgraph)
    rev = _reverse_adjacency(adj)

    all_nodes = set(adj.keys())
    # Ensure target functions are included even if absent from graph
    for t in target_functions:
        all_nodes.add(t)

    dist: dict[str, float] = {n: math.inf for n in all_nodes}

    # Multi-source BFS from all targets simultaneously
    queue: deque[str] = deque()
    for t in target_functions:
        dist[t] = 0.0
        queue.append(t)

    while queue:
        current = queue.popleft()
        current_dist = dist[current]
        for predecessor in rev.get(current, set()):
            new_dist = current_dist + 1.0
            if new_dist < dist[predecessor]:
                dist[predecessor] = new_dist
                queue.append(predecessor)

    entries = [
        FunctionDistance(function_name=name, distance=d)
        for name, d in sorted(dist.items())
    ]
    return DistanceMap(
        target=callgraph.target, metric=DistanceMetric.CALLGRAPH, entries=entries
    )


# ---------------------------------------------------------------------------
# Normalisation + AFL++ file generation
# ---------------------------------------------------------------------------


def normalise_distances(distance_map: DistanceMap) -> DistanceMap:
    """Return a copy of *distance_map* with finite distances scaled to [0, 1].

    Unreachable functions (``inf``) remain ``inf`` and are omitted from the
    AFL++ distance file (AFL++ ignores functions it can't instrument anyway).
    """
    finite = [e.distance for e in distance_map.entries if math.isfinite(e.distance)]
    if not finite:
        return distance_map

    max_d = max(finite)
    if max_d == 0.0:
        # All targets; every finite distance is 0
        scaled = [
            FunctionDistance(
                function_name=e.function_name,
                distance=0.0 if math.isfinite(e.distance) else math.inf,
            )
            for e in distance_map.entries
        ]
    else:
        scaled = [
            FunctionDistance(
                function_name=e.function_name,
                distance=(e.distance / max_d)
                if math.isfinite(e.distance)
                else math.inf,
            )
            for e in distance_map.entries
        ]

    return DistanceMap(
        target=distance_map.target,
        metric=distance_map.metric,
        entries=scaled,
    )


def write_aflgo_distance_file(
    distance_map: DistanceMap,
    output_path: Path,
    *,
    normalise: bool = True,
    omit_unreachable: bool = True,
) -> None:
    """Write an AFL++/AFLGo ``target_distance.txt`` file.

    Format::

        function_name\\tdistance\\n

    Parameters
    ----------
    distance_map:
        The computed distances.
    output_path:
        Where to write the file.  Parent directories are created if needed.
    normalise:
        If ``True`` (default), divide all finite distances by the maximum
        so values lie in [0, 1].
    omit_unreachable:
        If ``True`` (default), skip functions with ``inf`` distance.
    """
    if normalise:
        distance_map = normalise_distances(distance_map)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    lines: list[str] = []
    for entry in distance_map.entries:
        if omit_unreachable and not math.isfinite(entry.distance):
            continue
        lines.append(f"{entry.function_name}\t{entry.distance:.6f}")

    output_path.write_text("\n".join(lines) + ("\n" if lines else ""))
