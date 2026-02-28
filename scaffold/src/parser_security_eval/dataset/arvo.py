"""Ingest vulnerability data from the ARVO dataset.

ARVO: Atlas of Reproducible Vulnerabilities for Open Source Software
https://github.com/n132/ARVO

Contains 5,001 patches over 5,651 vulnerabilities with triggering inputs,
canonical patches, and reproducible Docker builds.
"""

from pathlib import Path

from parser_security_eval.models import VulnerabilityRecord


def fetch_arvo_index(cache_dir: Path) -> Path:
    """Download or update the ARVO dataset index."""
    raise NotImplementedError


def parse_arvo_entry(entry: dict) -> VulnerabilityRecord | None:
    """Parse a single ARVO entry into our data model.

    Returns None if the entry is not a parser-related vulnerability.
    """
    raise NotImplementedError


def is_parser_project(project_name: str) -> bool:
    """Heuristic: does this oss-fuzz project involve parsing?

    Uses a curated allowlist of known parser projects plus keyword matching.
    """
    raise NotImplementedError


def ingest_arvo(
    cache_dir: Path,
    output_dir: Path,
    limit: int | None = None,
) -> list[VulnerabilityRecord]:
    """Ingest ARVO dataset, filter for parser vulns, write to output_dir."""
    raise NotImplementedError
