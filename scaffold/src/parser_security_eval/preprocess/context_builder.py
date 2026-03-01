"""Assemble the full pre-processing context bundle for LLM calls.

:func:`build_context` reads a target's ``metadata.yaml``, runs call-graph
extraction and grammar extraction, then returns a :class:`HarnessContext`
ready to be serialised and passed to any downstream LLM call.

Results are cached as JSON files under ``targets/<target>/preprocess/`` so
that the expensive extraction steps are not repeated on every run.
"""

from __future__ import annotations

import logging
import textwrap
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel

from parser_security_eval.preprocess.callgraph import CallGraph, extract_callgraph
from parser_security_eval.preprocess.grammar import FormatGrammar, extract_grammar

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


class HarnessContext(BaseModel):
    """Full pre-processing context bundle for a single fuzz-harness target."""

    target: str
    entry_point: str  # the specific function being targeted
    callgraph: CallGraph
    grammar: FormatGrammar
    related_cves: list[str]  # CVE IDs from target metadata
    cve_descriptions: list[str]  # short descriptions of related vulnerabilities

    def to_prompt_text(self) -> str:
        """Format as a concise LLM-readable context block (~2 k tokens max).

        The output is plain text with section headers so it can be pasted
        directly into a system or user message.
        """
        lines: list[str] = []

        # --- Header ---
        lines.append(f"# Parser Context: {self.target} / {self.entry_point}")
        lines.append("")

        # --- Format grammar ---
        g = self.grammar
        lines.append(f"## Input format: {g.format_name}")
        lines.append(textwrap.fill(g.description, width=90))
        if g.magic_bytes_hex:
            lines.append(f"Magic bytes: {g.magic_bytes_hex}")
        if g.max_size_hint is not None:
            lines.append(f"Max size hint: {g.max_size_hint} bytes")
        if g.rules:
            lines.append("")
            lines.append("### Grammar rules (top 10):")
            for rule in g.rules[:10]:
                lines.append(f"- **{rule.name}**: {rule.description}")
                lines.append(f"  Pattern: `{rule.pattern}`")
                for c in rule.constraints[:3]:
                    lines.append(f"  Constraint: {c}")
        if g.notes:
            lines.append("")
            lines.append("### Format notes / edge cases:")
            for note in g.notes[:5]:
                lines.append(f"- {note}")
        lines.append("")

        # --- Call graph ---
        cg = self.callgraph
        lines.append("## Call graph")
        lines.append(
            f"Entry points: {', '.join(cg.entry_points)} "
            f"(depth limit: {cg.depth_limit})"
        )
        lines.append(f"Nodes reachable: {len(cg.nodes)}, edges: {len(cg.edges)}")
        lines.append("")

        # Show the entry-point node signature first, then a limited set of edges
        ep_node = next((n for n in cg.nodes if n.name == self.entry_point), None)
        if ep_node:
            lines.append(f"Entry point signature: `{ep_node.name}{ep_node.signature}`")
            if ep_node.file:
                lines.append(
                    f"Defined in: {ep_node.file}"
                    + (f":{ep_node.line}" if ep_node.line else "")
                )
            lines.append("")

        # Top direct callees from the entry point
        direct_callees = [e.callee for e in cg.edges if e.caller == self.entry_point][
            :15
        ]
        if direct_callees:
            lines.append(f"Direct callees of `{self.entry_point}`:")
            for callee in direct_callees:
                callee_node = next((n for n in cg.nodes if n.name == callee), None)
                sig = callee_node.signature if callee_node else "(?)"
                lines.append(f"  - `{callee}{sig}`")
            lines.append("")

        # --- CVEs ---
        if self.related_cves:
            lines.append("## Related CVEs")
            for cve_id, desc in zip(self.related_cves[:10], self.cve_descriptions[:10]):
                short_desc = textwrap.shorten(desc, width=120, placeholder="...")
                lines.append(f"- **{cve_id}**: {short_desc}")
            lines.append("")

        result = "\n".join(lines)
        # Hard cap: 8 000 chars (~2 k tokens).  Truncate with a notice.
        if len(result) > 8000:
            result = (
                result[:7900] + "\n\n[...context truncated to stay within token budget]"
            )
        return result


# ---------------------------------------------------------------------------
# Cache helpers
# ---------------------------------------------------------------------------

_CACHE_SUBDIR = "preprocess"


def _cache_path(target_dir: Path, filename: str) -> Path:
    cache_dir = target_dir / _CACHE_SUBDIR
    cache_dir.mkdir(parents=True, exist_ok=True)
    return cache_dir / filename


def _load_cached_callgraph(target_dir: Path) -> CallGraph | None:
    p = _cache_path(target_dir, "callgraph.json")
    if p.exists():
        try:
            return CallGraph.model_validate_json(p.read_text())
        except Exception as exc:  # noqa: BLE001
            logger.warning("Could not load cached callgraph: %s", exc)
    return None


def _save_cached_callgraph(target_dir: Path, cg: CallGraph) -> None:
    p = _cache_path(target_dir, "callgraph.json")
    p.write_text(cg.model_dump_json(indent=2))


def _load_cached_grammar(target_dir: Path) -> FormatGrammar | None:
    p = _cache_path(target_dir, "grammar.json")
    if p.exists():
        try:
            return FormatGrammar.model_validate_json(p.read_text())
        except Exception as exc:  # noqa: BLE001
            logger.warning("Could not load cached grammar: %s", exc)
    return None


def _save_cached_grammar(target_dir: Path, g: FormatGrammar) -> None:
    p = _cache_path(target_dir, "grammar.json")
    p.write_text(g.model_dump_json(indent=2))


def _save_cached_context(target_dir: Path, ctx: HarnessContext) -> None:
    p = _cache_path(target_dir, f"context_{ctx.entry_point}.json")
    p.write_text(ctx.model_dump_json(indent=2))


# ---------------------------------------------------------------------------
# Metadata loading
# ---------------------------------------------------------------------------


def _load_metadata(target_dir: Path) -> dict[str, Any]:
    meta_path = target_dir / "metadata.yaml"
    if not meta_path.exists():
        raise FileNotFoundError(f"No metadata.yaml in {target_dir}")
    with open(meta_path) as fh:
        return yaml.safe_load(fh)  # type: ignore[no-any-return]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


async def build_context(
    target_dir: Path,
    entry_point: str,
    *,
    spec_text: str = "",
    force_refresh: bool = False,
    source_subdir: str | None = None,
) -> HarnessContext:
    """Build a :class:`HarnessContext` for *entry_point* in *target_dir*.

    Parameters
    ----------
    target_dir:
        Absolute path to the target directory (e.g. ``targets/libpng``).
    entry_point:
        The specific entry-point function to focus on.
    spec_text:
        Optional format specification text.  If empty and a ``spec_url`` is
        present in ``metadata.yaml``, a warning is logged (fetching the URL
        is left to the caller).
    force_refresh:
        If ``True``, ignore any cached JSON and re-run extraction.
    source_subdir:
        Subdirectory of *target_dir* that contains the C/C++ source files.
        Defaults to *target_dir* itself.

    Returns
    -------
    HarnessContext
        Fully assembled context bundle, also written to
        ``<target_dir>/preprocess/context_<entry_point>.json``.
    """
    metadata = _load_metadata(target_dir)

    target_name: str = metadata.get("name", target_dir.name)
    format_name: str = metadata.get("format_name") or metadata.get(
        "format_type", "unknown"
    )
    all_entry_points: list[str] = metadata.get("key_entry_points", [entry_point])
    if entry_point not in all_entry_points:
        all_entry_points = [entry_point] + all_entry_points

    related_cves: list[str] = metadata.get("related_cves", [])
    cve_descriptions: list[str] = metadata.get("cve_descriptions", [])
    # Pad to same length
    while len(cve_descriptions) < len(related_cves):
        cve_descriptions.append("")

    source_dir = target_dir / source_subdir if source_subdir else target_dir

    # --- Call graph ---
    callgraph: CallGraph | None = (
        None if force_refresh else _load_cached_callgraph(target_dir)
    )
    if callgraph is None:
        logger.info("Extracting call graph for %s …", target_name)
        callgraph = extract_callgraph(
            source_dir=source_dir,
            entry_points=all_entry_points,
            depth=5,
            target_name=target_name,
        )
        _save_cached_callgraph(target_dir, callgraph)
    else:
        logger.info("Loaded cached call graph for %s", target_name)

    # --- Grammar ---
    grammar: FormatGrammar | None = (
        None if force_refresh else _load_cached_grammar(target_dir)
    )
    if grammar is None:
        logger.info("Extracting format grammar for %s …", target_name)
        if not spec_text:
            spec_url = metadata.get("spec_url", "")
            if spec_url:
                logger.warning(
                    "spec_url is set (%s) but spec_text was not provided; "
                    "falling back to source comment extraction.",
                    spec_url,
                )
            from parser_security_eval.preprocess.grammar import (
                extract_grammar_from_source,
            )

            grammar = await extract_grammar_from_source(
                target=target_name,
                format_name=format_name,
                source_dir=source_dir,
            )
        else:
            grammar = await extract_grammar(
                target=target_name,
                format_name=format_name,
                spec_text=spec_text,
            )
        _save_cached_grammar(target_dir, grammar)
    else:
        logger.info("Loaded cached grammar for %s", target_name)

    ctx = HarnessContext(
        target=target_name,
        entry_point=entry_point,
        callgraph=callgraph,
        grammar=grammar,
        related_cves=related_cves,
        cve_descriptions=cve_descriptions,
    )
    _save_cached_context(target_dir, ctx)
    return ctx


def build_context_from_parts(
    target_name: str,
    entry_point: str,
    callgraph: CallGraph,
    grammar: FormatGrammar,
    related_cves: list[str] | None = None,
    cve_descriptions: list[str] | None = None,
) -> HarnessContext:
    """Construct a :class:`HarnessContext` directly from pre-built parts.

    Useful in tests and when the caller has already run extraction separately.
    """
    return HarnessContext(
        target=target_name,
        entry_point=entry_point,
        callgraph=callgraph,
        grammar=grammar,
        related_cves=related_cves or [],
        cve_descriptions=cve_descriptions or [],
    )
