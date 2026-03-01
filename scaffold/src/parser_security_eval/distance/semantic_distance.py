"""LLM-derived semantic distance for directed greybox fuzzing.

Implements the *attention distance* metric from arXiv 2512.19758 (ICSE 2026):
replacing call-graph hop-count with LLM-computed semantic proximity produces a
3–7× speed-up over AFLGo/DAFL/WindRanger with *no changes to the fuzzing engine*.

The key idea: two functions may be logically adjacent (both handle integer
overflow in size calculations) while being far apart in the call graph.  An LLM
can spot that relationship; hop-count cannot.

Public API
----------
- :func:`compute_attention_distance` — score one function pair.
- :func:`compute_semantic_distance_map` — score all pairs between graph nodes
  and target functions, returning a :class:`~callgraph_distance.DistanceMap`.
- :func:`load_distance_cache` / :func:`save_distance_cache` — persist results
  to ``targets/<target>/distances.json`` (LLM calls are expensive).

AFL++ integration
-----------------
Import :func:`~callgraph_distance.write_aflgo_distance_file` and pass the
:class:`~callgraph_distance.DistanceMap` returned by
:func:`compute_semantic_distance_map` to generate ``target_distance.txt``.
"""

from __future__ import annotations

import json
import logging
import math
import re
from pathlib import Path
from typing import Any

from pydantic import BaseModel

from parser_security_eval.distance.callgraph_distance import (
    DistanceMap,
    DistanceMetric,
    FunctionDistance,
)
from parser_security_eval.preprocess.callgraph import CallGraph

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Cache model
# ---------------------------------------------------------------------------

_CACHE_FILENAME = "distances.json"


class PairwiseDistanceCache(BaseModel):
    """Persisted cache of (function_a, function_b) → semantic distance pairs."""

    target: str
    entries: dict[str, float] = {}  # key = "func_a::func_b", value in [0, 1]

    @staticmethod
    def _key(function_a: str, function_b: str) -> str:
        # Canonical order so (a, b) == (b, a)
        a, b = sorted([function_a, function_b])
        return f"{a}::{b}"

    def get(self, function_a: str, function_b: str) -> float | None:
        return self.entries.get(self._key(function_a, function_b))

    def set(self, function_a: str, function_b: str, distance: float) -> None:
        self.entries[self._key(function_a, function_b)] = distance


# ---------------------------------------------------------------------------
# Cache I/O
# ---------------------------------------------------------------------------


def load_distance_cache(target_dir: Path) -> PairwiseDistanceCache:
    """Load the persisted distance cache from *target_dir/distances.json*.

    Returns an empty cache if the file doesn't exist or can't be parsed.
    """
    cache_path = target_dir / _CACHE_FILENAME
    if cache_path.exists():
        try:
            return PairwiseDistanceCache.model_validate_json(cache_path.read_text())
        except Exception as exc:  # noqa: BLE001
            logger.warning("Could not load distance cache from %s: %s", cache_path, exc)
    target_name = target_dir.name
    return PairwiseDistanceCache(target=target_name)


def save_distance_cache(target_dir: Path, cache: PairwiseDistanceCache) -> None:
    """Persist *cache* to *target_dir/distances.json*."""
    target_dir.mkdir(parents=True, exist_ok=True)
    cache_path = target_dir / _CACHE_FILENAME
    cache_path.write_text(cache.model_dump_json(indent=2))


# ---------------------------------------------------------------------------
# LLM prompt
# ---------------------------------------------------------------------------

_SYSTEM_PROMPT = """\
You are a C/C++ security analyst specialising in parser vulnerabilities.
You will be shown two functions from a parser's source code and asked to rate
how *semantically close* they are from a security / vulnerability perspective.

Semantic closeness means: if one function has a bug (buffer overflow, integer
overflow, use-after-free, OOB read, etc.), how likely is it that the other
function is also involved in triggering or amplifying that bug?

Respond ONLY with a JSON object — no markdown fences, no prose:
{
  "score": <float in [0, 1]>,
  "reasoning": "<one sentence>"
}

Score guide:
  0.0 — identical security context (same function, or trivially equivalent wrappers)
  0.1–0.3 — very close: directly related error handling, same data flow path
  0.4–0.6 — moderate: share a common data structure or calling convention
  0.7–0.9 — loose: same subsystem but different concerns
  1.0 — completely unrelated from a security perspective
"""

_USER_TEMPLATE = """\
Source file context: {source_context}

Function A: {function_a}
```c
{body_a}
```

Function B: {function_b}
```c
{body_b}
```

Rate the semantic security proximity of Function A and Function B.
"""


# ---------------------------------------------------------------------------
# Source extraction helpers
# ---------------------------------------------------------------------------


def _extract_function_body(
    source: str, function_name: str, max_chars: int = 1500
) -> str:
    """Return the body of *function_name* from *source* (best-effort regex)."""
    # Match a function definition: some return type, the name, params, then '{'
    pattern = re.compile(
        r"(?:(?:static|inline|extern|const|unsigned|signed|long|short|void|int|char"
        r"|float|double|size_t|ssize_t|uint\w*|int\w*)\s+)*"
        + re.escape(function_name)
        + r"\s*\([^)]*\)\s*\{",
        re.MULTILINE,
    )
    m = pattern.search(source)
    if not m:
        return f"/* body of {function_name} not found in provided source */"

    start = m.end() - 1  # points at '{'
    depth = 0
    end = start
    for i, ch in enumerate(source[start:], start=start):
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                end = i + 1
                break

    body = source[start:end]
    if len(body) > max_chars:
        body = body[:max_chars] + "\n  /* ... truncated ... */"
    return body


# ---------------------------------------------------------------------------
# Public: single-pair distance
# ---------------------------------------------------------------------------


async def compute_attention_distance(
    source: str,
    function_a: str,
    function_b: str,
    *,
    source_context: str = "",
    _model: Any = None,
) -> float:
    """Compute the semantic distance between *function_a* and *function_b*.

    Uses an LLM to score how semantically proximate two functions are from a
    security perspective, matching the attention-distance approach in
    arXiv 2512.19758.

    Parameters
    ----------
    source:
        Full source text containing both functions (or as much as fits).
    function_a:
        Name of the first function.
    function_b:
        Name of the second function.
    source_context:
        Short description of the source file / subsystem shown in the prompt.
    _model:
        Optional pre-built ``inspect_ai`` model instance (used in tests).

    Returns
    -------
    float
        A value in ``[0, 1]``: 0 = identical security context, 1 = unrelated.
        Returns ``1.0`` on LLM or parsing failure (conservative: treat as far).
    """
    from inspect_ai.model import ChatMessageSystem, ChatMessageUser, get_model

    if function_a == function_b:
        return 0.0

    model = _model if _model is not None else get_model()

    body_a = _extract_function_body(source, function_a)
    body_b = _extract_function_body(source, function_b)

    user_content = _USER_TEMPLATE.format(
        source_context=source_context or "parser source",
        function_a=function_a,
        body_a=body_a,
        function_b=function_b,
        body_b=body_b,
    )

    try:
        response = await model.generate(
            [
                ChatMessageSystem(content=_SYSTEM_PROMPT),
                ChatMessageUser(content=user_content),
            ]
        )
        raw = response.completion.strip()
        # Strip accidental markdown fences
        raw = re.sub(r"^```[a-z]*\s*", "", raw)
        raw = re.sub(r"\s*```$", "", raw)
        data: dict[str, Any] = json.loads(raw)
        score = float(data["score"])
        score = max(0.0, min(1.0, score))  # clamp to [0, 1]
        logger.debug(
            "Semantic distance %s <-> %s = %.3f  reason: %s",
            function_a,
            function_b,
            score,
            data.get("reasoning", ""),
        )
        return score
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "LLM distance call failed for %s <-> %s: %s; defaulting to 1.0",
            function_a,
            function_b,
            exc,
        )
        return 1.0


# ---------------------------------------------------------------------------
# Public: full distance map over a call graph
# ---------------------------------------------------------------------------


async def compute_semantic_distance_map(
    callgraph: CallGraph,
    target_functions: list[str],
    source: str,
    *,
    target_dir: Path | None = None,
    source_context: str = "",
    _model: Any = None,
) -> DistanceMap:
    """Compute semantic distances for all nodes in *callgraph* to *target_functions*.

    For each function *f* in the call graph we compute:

        distance(f) = min over t in target_functions of
                          compute_attention_distance(source, f, t)

    Results are cached in ``target_dir/distances.json`` so expensive LLM calls
    are not repeated across runs.

    Parameters
    ----------
    callgraph:
        Call graph whose nodes define the function universe.
    target_functions:
        Known-vulnerable functions or security-critical entry points.
    source:
        Source text for all relevant functions (concatenated files or a single
        translation unit).
    target_dir:
        If provided, cache results here as ``distances.json``.
    source_context:
        Short description of the source context shown in LLM prompts.
    _model:
        Optional pre-built model instance (used in tests).

    Returns
    -------
    DistanceMap
        Distances for every node, using the ``"semantic"`` metric label.
    """
    # Load cache
    cache: PairwiseDistanceCache | None = None
    if target_dir is not None:
        cache = load_distance_cache(target_dir)

    all_nodes = {n.name for n in callgraph.nodes}
    # Include target functions even if absent from the extracted graph
    all_nodes.update(target_functions)

    entries: list[FunctionDistance] = []

    for func in sorted(all_nodes):
        if func in target_functions:
            entries.append(FunctionDistance(function_name=func, distance=0.0))
            continue

        min_dist = math.inf
        for target_func in target_functions:
            # Check cache first
            cached = cache.get(func, target_func) if cache is not None else None
            if cached is not None:
                d = cached
            else:
                d = await compute_attention_distance(
                    source,
                    func,
                    target_func,
                    source_context=source_context,
                    _model=_model,
                )
                if cache is not None:
                    cache.set(func, target_func, d)

            if d < min_dist:
                min_dist = d

        entries.append(FunctionDistance(function_name=func, distance=min_dist))

    # Persist updated cache
    if cache is not None and target_dir is not None:
        save_distance_cache(target_dir, cache)

    return DistanceMap(
        target=callgraph.target,
        metric=DistanceMetric.SEMANTIC,
        entries=entries,
    )
