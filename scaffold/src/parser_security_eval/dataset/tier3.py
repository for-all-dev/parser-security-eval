"""Tier 3 dataset: per-sample parser classification.

Tier 3 covers OSS-Fuzz projects that are not purely parsers but contain
parser components (ffmpeg, imagemagick, curl, etc.).  Unlike Tiers 1/2,
this requires per-sample filtering — not all bugs in a project like ffmpeg
exercise parser code.

The workflow is a 3-command pipeline:

1. ``tier3 audit``    — generate a TOML audit file with heuristic pre-classification
2. ``tier3 classify`` — run LLM classification on uncertain fuzz targets
3. ``tier3 compile``  — compile the reviewed audit into a sample registry JSON
"""

from __future__ import annotations

import json
import logging
import tomllib
from collections import defaultdict
from datetime import datetime, timezone
from enum import StrEnum
from pathlib import Path
from typing import Any

from pydantic import BaseModel

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


class ParserRelevance(StrEnum):
    """Whether a fuzz target exercises parser code."""

    PARSER = "parser"
    NOT_PARSER = "not_parser"
    UNCERTAIN = "uncertain"


class ClassificationMethod(StrEnum):
    """How a fuzz target was classified."""

    HEURISTIC = "heuristic"
    LLM = "llm"
    MANUAL = "manual"


class FuzzTargetProfile(BaseModel):
    """Classification profile for a single fuzz target within a project."""

    name: str
    record_count: int
    relevance: ParserRelevance
    method: ClassificationMethod = ClassificationMethod.HEURISTIC
    include: bool | None = None  # None = not yet reviewed
    reasoning: str = ""


class ProjectAuditEntry(BaseModel):
    """Audit entry for a single OSS-Fuzz project."""

    name: str
    total_records: int
    include: bool | None = None  # project-level override
    fuzz_targets: list[FuzzTargetProfile] = []


class SampleRegistryEntry(BaseModel):
    """A single ARVO sample included in the Tier 3 registry."""

    local_id: int
    project: str
    fuzz_target: str


class Tier3SampleRegistry(BaseModel):
    """Registry of ARVO localIds included in the Tier 3 dataset."""

    version: str = "0.1.0"
    generated: str = ""
    total_samples: int = 0
    projects: int = 0
    samples: list[SampleRegistryEntry] = []

    @property
    def local_ids(self) -> set[int]:
        """Return the set of all localIds in this registry."""
        return {s.local_id for s in self.samples}


# ---------------------------------------------------------------------------
# Keyword-based heuristic classification
# ---------------------------------------------------------------------------

# Keywords that indicate a fuzz target exercises *parsing* logic.
_PARSER_KEYWORDS: tuple[str, ...] = (
    "demux",
    "decoder",
    "reader",
    "parse",
    "deserializ",
    "decode",
    "inflate",
    "uncompress",
    "decompres",
    "unpack",
    "read_frame",
    "read_packet",
    "ingest",
    "load",
    "import",
    "recv",
    "from_bytes",
    "from_str",
    "unmarshal",
)

# Keywords that indicate a fuzz target does NOT exercise parsing.
_NON_PARSER_KEYWORDS: tuple[str, ...] = (
    "encoder",
    "muxer",
    "render",
    "serialize",
    "compress",
    "bsf",
    "filter",
    "hash",
    "writer",
    "output",
    "emit",
    "export",
    "marshal",
    "to_bytes",
    "to_str",
    "encrypt",
    "sign",
    "verify_sig",
    "generate",
)


def _keyword_positions(text: str, keywords: tuple[str, ...]) -> list[tuple[int, int]]:
    """Return (start, end) positions for all keyword matches in *text*."""
    positions: list[tuple[int, int]] = []
    for kw in keywords:
        idx = text.find(kw)
        if idx != -1:
            positions.append((idx, idx + len(kw)))
    return positions


def _overlaps(a: tuple[int, int], b: tuple[int, int]) -> bool:
    """Check if two (start, end) ranges overlap."""
    return a[0] < b[1] and b[0] < a[1]


def classify_fuzz_target(project: str, fuzz_target: str) -> ParserRelevance:
    """Classify a fuzz target as parser/not_parser/uncertain using keyword heuristics.

    Handles keyword overlap: e.g. "demuxer" contains both "demux" (parser)
    and "muxer" (non-parser).  When a non-parser keyword match overlaps
    with a parser keyword match, the non-parser match is ignored.

    Parameters
    ----------
    project:
        OSS-Fuzz project name (used for context but not for classification).
    fuzz_target:
        The fuzz target binary name from ARVO metadata.

    Returns
    -------
    ParserRelevance
        The heuristic classification.
    """
    lower = fuzz_target.lower()

    parser_positions = _keyword_positions(lower, _PARSER_KEYWORDS)
    non_parser_positions = _keyword_positions(lower, _NON_PARSER_KEYWORDS)

    # Remove non-parser matches that overlap with parser matches.
    # e.g. "muxer" in "demuxer" overlaps with "demux" → drop it.
    if parser_positions and non_parser_positions:
        filtered = [
            np
            for np in non_parser_positions
            if not any(_overlaps(np, pp) for pp in parser_positions)
        ]
        non_parser_positions = filtered

    has_parser = len(parser_positions) > 0
    has_non_parser = len(non_parser_positions) > 0

    if has_parser and has_non_parser:
        return ParserRelevance.UNCERTAIN
    if has_parser:
        return ParserRelevance.PARSER
    if has_non_parser:
        return ParserRelevance.NOT_PARSER
    return ParserRelevance.UNCERTAIN


# ---------------------------------------------------------------------------
# Build audit list from ARVO metadata
# ---------------------------------------------------------------------------


def build_audit_list(
    metadata_path: Path,
    exclude_projects: set[str] | None = None,
) -> list[ProjectAuditEntry]:
    """Parse ARVO metadata.jsonl and build a grouped audit list.

    Groups entries by (project, fuzz_target), runs heuristic classification,
    and filters out projects in *exclude_projects* (Tier 1/2).

    Parameters
    ----------
    metadata_path:
        Path to the ARVO ``metadata.jsonl`` file.
    exclude_projects:
        Project names to exclude (e.g. Tier 1 and Tier 2 targets).

    Returns
    -------
    list[ProjectAuditEntry]
        Sorted by project name.
    """
    from parser_security_eval.dataset.arvo import is_parser_project

    if exclude_projects is None:
        exclude_projects = set()
    exclude_lower = {p.lower() for p in exclude_projects}

    # Group: project -> fuzz_target -> list[entry]
    groups: dict[str, dict[str, list[dict]]] = defaultdict(lambda: defaultdict(list))

    with metadata_path.open() as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            entry = json.loads(line)
            project = entry.get("project", "")
            if not project:
                continue
            if project.lower() in exclude_lower:
                continue
            if not is_parser_project(project):
                continue
            fuzz_target = entry.get("fuzz_target") or "unknown"
            groups[project][fuzz_target].append(entry)

    # Build audit entries
    entries: list[ProjectAuditEntry] = []
    for project in sorted(groups):
        fuzz_target_profiles: list[FuzzTargetProfile] = []
        total = 0
        for ft_name in sorted(groups[project]):
            records = groups[project][ft_name]
            count = len(records)
            total += count
            relevance = classify_fuzz_target(project, ft_name)
            include = True if relevance == ParserRelevance.PARSER else None
            if relevance == ParserRelevance.NOT_PARSER:
                include = False
            fuzz_target_profiles.append(
                FuzzTargetProfile(
                    name=ft_name,
                    record_count=count,
                    relevance=relevance,
                    include=include,
                )
            )
        entries.append(
            ProjectAuditEntry(
                name=project,
                total_records=total,
                fuzz_targets=fuzz_target_profiles,
            )
        )

    return entries


# ---------------------------------------------------------------------------
# TOML audit file I/O
# ---------------------------------------------------------------------------


def write_audit_toml(entries: list[ProjectAuditEntry], output_path: Path) -> None:
    """Write a human-editable TOML audit file.

    Uses string formatting to produce well-commented TOML without requiring
    a TOML writer dependency.
    """
    lines: list[str] = []
    now = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d")
    lines.append(f"# Tier 3 Audit — generated {now}")
    lines.append("# Review each project. Set include = true or false.")
    lines.append('# Fuzz targets with relevance = "parser" are pre-included.')
    lines.append('# Fuzz targets with relevance = "uncertain" need your judgement.')
    lines.append("")

    for entry in entries:
        lines.append("[[projects]]")
        lines.append(f'name = "{entry.name}"')
        lines.append(f"total_records = {entry.total_records}")
        if entry.include is not None:
            lines.append(f"include = {_bool_toml(entry.include)}")
        else:
            lines.append(
                "# include =    # uncomment to override all fuzz targets in this project"
            )
        lines.append("")

        for ft in entry.fuzz_targets:
            lines.append("  [[projects.fuzz_targets]]")
            lines.append(f'  name = "{ft.name}"')
            lines.append(f"  record_count = {ft.record_count}")
            lines.append(f'  relevance = "{ft.relevance.value}"')
            if ft.include is not None:
                lines.append(f"  include = {_bool_toml(ft.include)}")
            else:
                lines.append("  # include =    # set true or false")
            if ft.reasoning:
                lines.append(f'  reasoning = "{_escape_toml_str(ft.reasoning)}"')
            lines.append("")

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text("\n".join(lines))
    logger.info("Wrote audit TOML to %s (%d projects)", output_path, len(entries))


def _bool_toml(val: bool) -> str:
    return "true" if val else "false"


def _escape_toml_str(s: str) -> str:
    """Escape a string for TOML double-quoted values."""
    return s.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def read_audit_toml(audit_path: Path) -> list[ProjectAuditEntry]:
    """Read back a TOML audit file into ProjectAuditEntry models.

    Uses ``tomllib`` (stdlib) to parse.
    """
    with audit_path.open("rb") as fh:
        data = tomllib.load(fh)

    entries: list[ProjectAuditEntry] = []
    for proj in data.get("projects", []):
        fuzz_targets: list[FuzzTargetProfile] = []
        for ft in proj.get("fuzz_targets", []):
            fuzz_targets.append(
                FuzzTargetProfile(
                    name=ft["name"],
                    record_count=ft.get("record_count", 0),
                    relevance=ParserRelevance(ft.get("relevance", "uncertain")),
                    method=ClassificationMethod(ft.get("method", "heuristic")),
                    include=ft.get("include"),
                    reasoning=ft.get("reasoning", ""),
                )
            )
        entries.append(
            ProjectAuditEntry(
                name=proj["name"],
                total_records=proj.get("total_records", 0),
                include=proj.get("include"),
                fuzz_targets=fuzz_targets,
            )
        )
    return entries


# ---------------------------------------------------------------------------
# LLM classification of uncertain fuzz targets
# ---------------------------------------------------------------------------


def _parse_llm_json(raw: str) -> dict[str, Any]:
    """Extract and parse a JSON object from an LLM response string."""
    import re

    text = raw.strip()
    text = re.sub(r"^```[a-z]*\s*", "", text)
    text = re.sub(r"\s*```$", "", text)
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        m = re.search(r"\{.*\}", text, re.DOTALL)
        if m:
            return json.loads(m.group(0))
        raise


async def classify_uncertain_targets(
    profiles: list[FuzzTargetProfile],
    project: str,
    cache_path: Path | None = None,
    _model: Any = None,
) -> list[FuzzTargetProfile]:
    """Run LLM classification on uncertain fuzz targets.

    Parameters
    ----------
    profiles:
        Fuzz target profiles to classify (only ``uncertain`` ones are sent to LLM).
    project:
        The project name for context.
    cache_path:
        Optional JSON cache file to avoid re-classifying targets.
    _model:
        Optional pre-built model instance (for testing).

    Returns
    -------
    list[FuzzTargetProfile]
        Updated profiles with LLM classifications applied.
    """
    from inspect_ai.model import ChatMessageSystem, ChatMessageUser, get_model

    from parser_security_eval import prompts

    model = _model if _model is not None else get_model()

    # Load cache
    cache: dict[str, dict[str, str]] = {}
    if cache_path and cache_path.exists():
        cache = json.loads(cache_path.read_text())

    system_prompt = prompts.load("classification.system")

    updated: list[FuzzTargetProfile] = []
    for profile in profiles:
        if profile.relevance != ParserRelevance.UNCERTAIN:
            updated.append(profile)
            continue

        cache_key = f"{project}/{profile.name}"
        if cache_key in cache:
            cached = cache[cache_key]
            updated.append(
                profile.model_copy(
                    update={
                        "relevance": ParserRelevance(cached["relevance"]),
                        "method": ClassificationMethod.LLM,
                        "reasoning": cached.get("reasoning", ""),
                        "include": cached["relevance"] == "parser",
                    }
                )
            )
            continue

        user_content = prompts.load(
            "classification.user",
            project=project,
            fuzz_target=profile.name,
            record_count=profile.record_count,
            crash_types="(not available)",
        )

        try:
            response = await model.generate(
                [
                    ChatMessageSystem(content=system_prompt),
                    ChatMessageUser(content=user_content),
                ]
            )
            data = _parse_llm_json(response.completion)
            relevance_str = data.get("relevance", "uncertain")
            if relevance_str not in ("parser", "not_parser"):
                relevance_str = "uncertain"
            reasoning = data.get("reasoning", "")

            cache[cache_key] = {
                "relevance": relevance_str,
                "reasoning": reasoning,
            }

            updated.append(
                profile.model_copy(
                    update={
                        "relevance": ParserRelevance(relevance_str),
                        "method": ClassificationMethod.LLM,
                        "reasoning": reasoning,
                        "include": relevance_str == "parser"
                        if relevance_str != "uncertain"
                        else None,
                    }
                )
            )
        except Exception as exc:
            logger.warning(
                "LLM classification failed for %s/%s: %s",
                project,
                profile.name,
                exc,
            )
            updated.append(profile)

    # Save cache
    if cache_path:
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        cache_path.write_text(json.dumps(cache, indent=2))

    return updated


# ---------------------------------------------------------------------------
# Registry compilation
# ---------------------------------------------------------------------------


def compile_registry(
    audit_entries: list[ProjectAuditEntry],
    metadata_path: Path,
) -> Tier3SampleRegistry:
    """Compile reviewed audit entries into a sample registry.

    For each included fuzz target (or project-level include), collects all
    matching ARVO localIds from the metadata.

    Parameters
    ----------
    audit_entries:
        Reviewed audit entries with include/exclude decisions.
    metadata_path:
        Path to the ARVO ``metadata.jsonl`` file.

    Returns
    -------
    Tier3SampleRegistry
        Registry ready for JSON persistence.
    """
    # Build lookup: (project, fuzz_target) -> include?
    include_map: dict[tuple[str, str], bool] = {}
    project_overrides: dict[str, bool] = {}

    for entry in audit_entries:
        if entry.include is not None:
            project_overrides[entry.name] = entry.include
        for ft in entry.fuzz_targets:
            if ft.include is not None:
                include_map[(entry.name, ft.name)] = ft.include

    # Known project names for filtering
    known_projects = {e.name for e in audit_entries}

    # Scan metadata for matching localIds
    samples: list[SampleRegistryEntry] = []
    with metadata_path.open() as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            entry = json.loads(line)
            project = entry.get("project", "")
            if project not in known_projects:
                continue
            local_id = entry.get("localId")
            if local_id is None:
                continue
            fuzz_target = entry.get("fuzz_target") or "unknown"

            # Determine inclusion
            included = False

            # Project-level override takes precedence
            if project in project_overrides:
                included = project_overrides[project]
            elif (project, fuzz_target) in include_map:
                included = include_map[(project, fuzz_target)]

            if included:
                samples.append(
                    SampleRegistryEntry(
                        local_id=local_id,
                        project=project,
                        fuzz_target=fuzz_target,
                    )
                )

    now = datetime.now(tz=timezone.utc).isoformat()
    projects_included = len({s.project for s in samples})

    return Tier3SampleRegistry(
        generated=now,
        total_samples=len(samples),
        projects=projects_included,
        samples=samples,
    )


# ---------------------------------------------------------------------------
# Registry persistence
# ---------------------------------------------------------------------------


def save_registry(registry: Tier3SampleRegistry, output_path: Path) -> None:
    """Write a Tier3SampleRegistry to JSON."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(registry.model_dump_json(indent=2))
    logger.info(
        "Saved Tier 3 registry: %d samples from %d projects to %s",
        registry.total_samples,
        registry.projects,
        output_path,
    )


def load_registry(registry_path: Path) -> Tier3SampleRegistry:
    """Load a Tier3SampleRegistry from JSON."""
    data = json.loads(registry_path.read_text())
    return Tier3SampleRegistry(**data)
