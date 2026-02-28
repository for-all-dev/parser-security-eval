"""Ingest vulnerability data from the oss-fuzz bug tracker.

Public oss-fuzz bugs (after 90-day disclosure):
https://bugs.chromium.org/p/oss-fuzz/issues/list

Also integrates with oss-fuzz project definitions for target metadata.
"""

from pathlib import Path

from parser_security_eval.models import ParserTarget, VulnerabilityRecord


def fetch_ossfuzz_bugs(
    project: str,
    cache_dir: Path,
) -> list[dict]:
    """Fetch public oss-fuzz bug reports for a project."""
    raise NotImplementedError


def parse_ossfuzz_bug(bug: dict, project: str) -> VulnerabilityRecord | None:
    """Parse an oss-fuzz bug into our data model."""
    raise NotImplementedError


def import_ossfuzz_target(
    project: str,
    ossfuzz_repo: Path,
    targets_dir: Path,
) -> ParserTarget:
    """Import an oss-fuzz project definition as a ParserTarget.

    Copies Dockerfile, build.sh, corpus, and dictionary from the oss-fuzz
    repo into our targets/ directory.
    """
    raise NotImplementedError


def list_parser_projects(ossfuzz_repo: Path) -> list[str]:
    """List oss-fuzz projects that are parser-related."""
    raise NotImplementedError
