"""CLI entry point for parser-security-eval."""

from __future__ import annotations

import json
import logging
from pathlib import Path

import typer

from parser_security_eval.dataset.arvo import ingest_arvo
from parser_security_eval.dataset.curator import DatasetCurator
from parser_security_eval.dataset.ossfuzz import fetch_ossfuzz_bugs, parse_ossfuzz_bug
from parser_security_eval.models.vulnerability import VulnerabilityRecord

app = typer.Typer(
    name="parser-security-eval", help="Parser security evaluation framework."
)

logger = logging.getLogger(__name__)

# Tier 1 parser targets for the initial benchmark.
TIER1_TARGETS: list[str] = ["libpng", "libjpeg-turbo", "libxml2", "zlib"]


def _format_summary(summary: dict) -> str:
    """Format a curation summary dict as human-readable text."""
    lines: list[str] = []
    lines.append(f"Total vulnerabilities: {summary['total']}")
    lines.append("")
    lines.append("Vulnerabilities by target:")
    for target, count in sorted(summary["by_target"].items()):
        lines.append(f"  {target}: {count}")
    lines.append("")
    lines.append("Severity distribution:")
    for severity, count in sorted(summary["by_severity"].items()):
        lines.append(f"  {severity}: {count}")
    lines.append("")
    lines.append("Difficulty distribution:")
    for difficulty, count in sorted(summary["by_difficulty"].items()):
        lines.append(f"  {difficulty}: {count}")
    lines.append("")
    lines.append("Crash type distribution:")
    for crash_type, count in sorted(
        summary["by_crash_type"].items(), key=lambda x: -x[1]
    ):
        lines.append(f"  {crash_type}: {count}")
    return "\n".join(lines)


def run_curation_pipeline(
    source: str,
    output: Path,
    targets: list[str],
    cache_dir: Path,
    limit: int | None = None,
) -> dict:
    """Run the full curation pipeline and return the summary.

    This is the core orchestration function that:
    1. Ingests from ARVO and/or oss-fuzz depending on *source*
    2. Filters to the specified targets
    3. Merges and deduplicates via DatasetCurator
    4. Validates artifacts
    5. Exports metadata.json and dataset.jsonl
    6. Returns summary statistics

    Parameters
    ----------
    source:
        Data source to use: "arvo", "ossfuzz", or "all" (both).
    output:
        Directory where benchmark artifacts are written.
    targets:
        List of parser target names to include (e.g. TIER1_TARGETS).
    cache_dir:
        Directory for caching downloaded data.
    limit:
        Optional cap on total vulnerabilities to ingest per source.

    Returns
    -------
    dict
        Summary statistics from ``DatasetCurator.summary()``.
    """
    target_set = {t.lower() for t in targets}
    curator = DatasetCurator(output)
    all_records: list[VulnerabilityRecord] = []

    # --- ARVO ingestion ---
    if source in ("arvo", "all"):
        logger.info("Ingesting from ARVO (targets: %s)", targets)
        arvo_output = output / "arvo"
        arvo_records = ingest_arvo(cache_dir, arvo_output, limit=limit)
        # Filter to requested targets
        filtered = [r for r in arvo_records if r.target.lower() in target_set]
        logger.info(
            "ARVO: %d records total, %d matching targets",
            len(arvo_records),
            len(filtered),
        )
        all_records.extend(filtered)

    # --- oss-fuzz ingestion ---
    if source in ("ossfuzz", "all"):
        logger.info("Ingesting from oss-fuzz (targets: %s)", targets)
        ossfuzz_cache = cache_dir / "ossfuzz"
        for target in targets:
            logger.info("Fetching oss-fuzz bugs for %s", target)
            bugs = fetch_ossfuzz_bugs(target, ossfuzz_cache)
            target_records: list[VulnerabilityRecord] = []
            for bug in bugs:
                record = parse_ossfuzz_bug(bug, target)
                if record is not None:
                    target_records.append(record)
            logger.info(
                "oss-fuzz %s: %d bugs fetched, %d parsed",
                target,
                len(bugs),
                len(target_records),
            )
            if limit is not None:
                target_records = target_records[:limit]
            all_records.extend(target_records)

    # --- Merge, deduplicate, validate, export ---
    curator.add_records(all_records)

    errors = curator.validate()
    if errors:
        logger.warning("Validation found %d issues:", len(errors))
        for err in errors[:20]:
            logger.warning("  %s", err)
        if len(errors) > 20:
            logger.warning("  ... and %d more", len(errors) - 20)

    curator.export_metadata()
    curator.export_inspect_dataset()

    summary = curator.summary()

    # Write summary statistics to a JSON file alongside the exports
    summary_path = output / "summary.json"
    summary_path.write_text(json.dumps(summary, indent=2, default=str))

    return summary


@app.command()
def curate(
    source: str = typer.Argument(
        help="Data source: 'arvo', 'ossfuzz', or 'all' (both)"
    ),
    output: Path = typer.Option(
        Path("benchmark"), help="Output directory for curated data"
    ),
    cache_dir: Path = typer.Option(
        Path(".cache"), help="Cache directory for downloaded data"
    ),
    targets: str = typer.Option(
        ",".join(TIER1_TARGETS),
        help="Comma-separated list of target parser projects",
    ),
    limit: int | None = typer.Option(
        None, help="Max vulnerabilities to ingest per source"
    ),
) -> None:
    """Ingest and curate vulnerability data from ARVO, oss-fuzz, or both.

    Runs the full curation pipeline: ingest, filter, deduplicate, validate,
    and export benchmark/metadata.json + benchmark/dataset.jsonl.
    """
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    if source not in ("arvo", "ossfuzz", "all"):
        typer.echo(f"Error: source must be 'arvo', 'ossfuzz', or 'all', got '{source}'")
        raise typer.Exit(code=1)

    target_list = [t.strip() for t in targets.split(",") if t.strip()]

    typer.echo(f"Curating from source={source} for targets={target_list}")
    typer.echo(f"Output directory: {output}")

    summary = run_curation_pipeline(
        source=source,
        output=output,
        targets=target_list,
        cache_dir=cache_dir,
        limit=limit,
    )

    typer.echo("\n" + _format_summary(summary))
    typer.echo(f"\nExported to {output}/metadata.json and {output}/dataset.jsonl")


@app.command()
def evaluate(
    task: str = typer.Argument(help="Task to run: 'patching', 'harness', 'triage'"),
    target: str = typer.Option(..., help="Parser target name (e.g. 'libpng')"),
    model: str = typer.Option("openai/gpt-4o", help="Model to evaluate"),
) -> None:
    """Run an Inspect-AI evaluation task."""
    raise NotImplementedError(f"Task {task} not yet implemented")


@app.command()
def build_target(
    target: str = typer.Argument(help="Parser target to build"),
    sanitizer: str = typer.Option(
        "address", help="Sanitizer: address, undefined, memory"
    ),
    engine: str = typer.Option(
        "libfuzzer", help="Fuzz engine: libfuzzer, afl++, honggfuzz"
    ),
) -> None:
    """Build a parser target in Docker with the specified sanitizer and engine."""
    raise NotImplementedError(f"Building {target} not yet implemented")


@app.command()
def verify(
    target: str = typer.Argument(help="Parser target"),
    vuln_id: str = typer.Argument(help="Vulnerability ID"),
    patch: Path = typer.Argument(help="Path to patch file"),
) -> None:
    """Verify a patch against a specific vulnerability."""
    raise NotImplementedError(f"Verification of {vuln_id} not yet implemented")
