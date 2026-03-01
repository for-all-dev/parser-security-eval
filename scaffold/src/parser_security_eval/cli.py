"""CLI entry point for parser-security-eval."""

from __future__ import annotations

import asyncio
import json
import logging
from pathlib import Path

import typer

from parser_security_eval.dataset.artifacts import (
    extract_vulnerable_sources,
    fetch_reference_patches,
    resolve_vulnerable_refs,
)
from parser_security_eval.dataset.arvo import ingest_arvo
from parser_security_eval.dataset.curator import DatasetCurator
from parser_security_eval.dataset.enrich import (
    enrich_crash_reports,
    enrich_cwe,
    extract_crash_inputs,
)
from parser_security_eval.dataset.ossfuzz import fetch_ossfuzz_bugs, parse_ossfuzz_bug
from parser_security_eval.models.vulnerability import VulnerabilityRecord

app = typer.Typer(
    name="parser-security-eval", help="Parser security evaluation framework."
)

logger = logging.getLogger(__name__)

_DEFAULT_CACHE = Path.home() / ".cache" / "parser-security-eval"

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
        arvo_records = ingest_arvo(
            cache_dir, arvo_output, limit=limit, targets=target_set
        )
        logger.info("ARVO: %d records matching targets", len(arvo_records))
        all_records.extend(arvo_records)

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
        Path("../benchmark"), help="Output directory for curated data"
    ),
    cache_dir: Path = typer.Option(
        _DEFAULT_CACHE, help="Cache directory for downloaded data"
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
    task: str = typer.Argument(help="Task: 'patching', 'triage', or 'harness'"),
    model: str = typer.Option("anthropic/claude-sonnet-4-6", help="Model to evaluate"),
    target: str | None = typer.Option(
        None, help="Parser target filter (e.g. 'libpng')"
    ),
    benchmark_dir: Path = typer.Option(
        Path("../benchmark"), help="Benchmark directory (patching / triage)"
    ),
    targets_root: Path = typer.Option(
        Path("../targets"), help="Targets root directory (patching / harness)"
    ),
    engine: str = typer.Option(
        "libfuzzer", help="Fuzz engine: libfuzzer, afl, honggfuzz"
    ),
    fuzz_duration: int = typer.Option(
        300, help="Fuzzer run duration in seconds (harness only)"
    ),
    limit: int | None = typer.Option(
        None, help="Max samples to evaluate (passed to inspect_eval)"
    ),
    ready_only: bool = typer.Option(
        False,
        help="Only include samples with all required artifacts "
        "(crash_input for patching, crash_report for triage)",
    ),
    sample_id: str | None = typer.Option(
        None, help="Run only the sample with this ID (passed to inspect_eval)"
    ),
) -> None:
    """Run an Inspect-AI evaluation task."""
    from inspect_ai import eval as inspect_eval

    if task == "patching":
        from parser_security_eval.tasks.patching import vulnerability_patching

        inspect_task = vulnerability_patching(
            benchmark_dir=str(benchmark_dir),
            target=target,
            targets_root=str(targets_root),
            fuzzing_engine=engine,
            ready_only=ready_only,
        )

    elif task == "triage":
        from parser_security_eval.tasks.triage import crash_triage

        inspect_task = crash_triage(
            benchmark_dir=str(benchmark_dir),
            target=target,
            ready_only=ready_only,
        )

    elif task == "harness":
        if target is None:
            typer.echo("Error: --target is required for 'harness' task", err=True)
            raise typer.Exit(1)

        from parser_security_eval.tasks.harness import harness_generation

        inspect_task = harness_generation(
            targets_dir=str(targets_root),
            target=target,
            fuzz_duration=fuzz_duration,
            engine=engine,
        )

    else:
        typer.echo(
            f"Error: unknown task '{task}'. Choose 'patching', 'triage', or 'harness'.",
            err=True,
        )
        raise typer.Exit(1)

    eval_kwargs: dict[str, object] = {"model": model, "limit": limit}
    if sample_id is not None:
        eval_kwargs["sample_id"] = sample_id
    logs = inspect_eval(inspect_task, **eval_kwargs)

    for log in logs:
        typer.echo(f"\nTask:   {log.eval.task}")
        typer.echo(f"Status: {log.status}")
        if log.results:
            for score in log.results.scores:
                metrics_str = ", ".join(
                    f"{k}={v.value:.3f}" for k, v in score.metrics.items()
                )
                typer.echo(f"  {score.name}: {metrics_str}")


@app.command()
def build_target(
    target: str = typer.Argument(help="Parser target to build"),
    sanitizer: str = typer.Option(
        "address", help="Sanitizer: address, undefined, memory"
    ),
    engine: str = typer.Option(
        "libfuzzer", help="Fuzz engine: libfuzzer, afl, honggfuzz"
    ),
    targets_root: Path = typer.Option(
        Path("../targets"), help="Targets root directory"
    ),
) -> None:
    """Build a parser target in Docker with the specified sanitizer and engine."""
    from parser_security_eval.sandbox.docker import DockerSandbox, SandboxConfig

    target_dir = targets_root / target
    if not target_dir.exists():
        typer.echo(f"Error: target directory not found: {target_dir}", err=True)
        raise typer.Exit(1)

    config = SandboxConfig(
        target_name=target,
        target_dir=target_dir,
        sanitizer=sanitizer,
        engine=engine,
    )

    async def _run() -> bool:
        async with DockerSandbox(config) as sandbox:
            return await sandbox.build_target()

    typer.echo(f"Building {target} (sanitizer={sanitizer}, engine={engine})...")
    ok = asyncio.run(_run())
    if ok:
        typer.echo("Build succeeded.")
    else:
        typer.echo("Build failed.", err=True)
        raise typer.Exit(1)


@app.command()
def verify(
    target: str = typer.Argument(help="Parser target"),
    vuln_id: str = typer.Argument(help="Vulnerability ID"),
    patch: Path = typer.Argument(help="Path to patch file (.diff)"),
    benchmark_dir: Path = typer.Option(
        Path("../benchmark"), help="Benchmark directory"
    ),
    targets_root: Path = typer.Option(
        Path("../targets"), help="Targets root directory"
    ),
    sanitizer: str = typer.Option(
        "address", help="Sanitizer: address, undefined, memory"
    ),
    engine: str = typer.Option(
        "libfuzzer", help="Fuzz engine: libfuzzer, afl, honggfuzz"
    ),
) -> None:
    """Verify a patch against a specific vulnerability."""
    from parser_security_eval.sandbox.docker import DockerSandbox, SandboxConfig
    from parser_security_eval.scorers.patch import score_patch
    from parser_security_eval.tasks.patching import _resolve_fuzz_binary

    # Resolve the vulnerability record to get crash input path.
    metadata_path = benchmark_dir / "metadata.json"
    if not metadata_path.exists():
        typer.echo(f"Error: benchmark metadata not found at {metadata_path}", err=True)
        raise typer.Exit(1)

    raw = json.loads(metadata_path.read_text())
    record = next((r for r in raw.get("records", []) if r["id"] == vuln_id), None)
    if record is None:
        typer.echo(
            f"Error: vulnerability '{vuln_id}' not found in {metadata_path}",
            err=True,
        )
        raise typer.Exit(1)

    crash_input_rel = record.get("crash_input_path")
    if not crash_input_rel:
        typer.echo(f"Error: no crash_input_path in record for '{vuln_id}'", err=True)
        raise typer.Exit(1)

    triggering_input = str(benchmark_dir / crash_input_rel)
    patch_diff = patch.read_text()

    target_dir = targets_root / target
    fuzz_binary = _resolve_fuzz_binary(target_dir, target)

    config = SandboxConfig(
        target_name=target,
        target_dir=target_dir,
        sanitizer=sanitizer,
        engine=engine,
    )

    async def _run():
        async with DockerSandbox(config) as sandbox:
            return await score_patch(
                sandbox=sandbox,
                patch_diff=patch_diff,
                triggering_input_path=triggering_input,
                fuzz_target_binary=fuzz_binary,
                sanitizer=sanitizer,
                fuzzing_engine=engine,
            )

    typer.echo(f"Verifying patch for {vuln_id} ({target})...")
    result = asyncio.run(_run())

    typer.echo(f"  patch_applies:    {result.patch_applies}")
    typer.echo(f"  compiles:         {result.compiles}")
    typer.echo(f"  crash_eliminated: {result.crash_eliminated}")
    typer.echo(f"  tests_pass:       {result.tests_pass}")
    typer.echo(f"  diff_lines:       {result.diff_lines}")
    typer.echo(f"  success:          {result.success}")

    if not result.success:
        raise typer.Exit(1)


@app.command()
def triage(
    crashes_dir: Path = typer.Argument(help="Directory containing crash input files"),
    target: str = typer.Option(
        "unknown", help="Human-readable name for the fuzzing target"
    ),
    container: str | None = typer.Option(
        None, help="Docker container ID to run CASR inside"
    ),
    binary_path: str | None = typer.Option(
        None, help="Path to the sanitized binary for casr-san"
    ),
) -> None:
    """Triage crash files using CASR (or stack-hash fallback).

    Analyzes crash files in CRASHES_DIR, deduplicates them into clusters,
    and prints a summary of exploitability classifications.
    """
    from parser_security_eval.triage.casr import CASRTriager

    if not crashes_dir.exists():
        typer.echo(f"Error: crashes directory not found: {crashes_dir}", err=True)
        raise typer.Exit(1)

    triager = CASRTriager(container_id=container)

    result = asyncio.run(
        triager.triage_crashes(
            crashes_dir=crashes_dir,
            target_name=target,
            binary_path=binary_path,
        )
    )

    typer.echo(result.summary())


@app.command()
def fetch_artifacts(
    benchmark_dir: Path = typer.Option(
        Path("../benchmark"), help="Benchmark directory with metadata.json"
    ),
    cache_dir: Path = typer.Option(
        _DEFAULT_CACHE, help="Cache directory for arvo.db and repo clones"
    ),
) -> None:
    """Fetch reference patches from ARVO-Meta for all benchmark records."""
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    if not (benchmark_dir / "metadata.json").exists():
        typer.echo(f"Error: metadata.json not found in {benchmark_dir}", err=True)
        raise typer.Exit(1)

    typer.echo(f"Fetching reference patches into {benchmark_dir} …")
    success, total = fetch_reference_patches(benchmark_dir, cache_dir)
    typer.echo(f"\nDone: {success} / {total} reference patches fetched.")


@app.command()
def enrich_dataset(
    benchmark_dir: Path = typer.Option(
        Path("../benchmark"), help="Benchmark directory with metadata.json"
    ),
    cache_dir: Path = typer.Option(
        _DEFAULT_CACHE, help="Cache directory containing arvo.db"
    ),
    crash_reports: bool = typer.Option(
        True, help="Enrich crash reports with full ASAN output"
    ),
    cwe: bool = typer.Option(True, help="Map crash_type to CWE IDs"),
    crash_inputs: bool = typer.Option(
        False, help="Extract crash inputs from ARVO Docker images (slow, pulls images)"
    ),
    extract_sources: bool = typer.Option(
        True, help="Extract vulnerable source files from cached git repos"
    ),
    resolve_refs: bool = typer.Option(
        True, help="Resolve vulnerable_source_ref commit hashes from fix commits"
    ),
    timeout: int = typer.Option(120, help="Timeout per Docker image pull in seconds"),
) -> None:
    """Enrich benchmark dataset with crash reports, CWE mappings, crash inputs, and source."""
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    if not (benchmark_dir / "metadata.json").exists():
        typer.echo(f"Error: metadata.json not found in {benchmark_dir}", err=True)
        raise typer.Exit(1)

    if crash_reports:
        typer.echo("Enriching crash reports with ASAN output from arvo.db …")
        enriched, total = enrich_crash_reports(benchmark_dir, cache_dir)
        typer.echo(f"  Crash reports enriched: {enriched} / {total}")

    if cwe:
        typer.echo("Mapping crash_type → CWE …")
        mapped, total = enrich_cwe(benchmark_dir)
        typer.echo(f"  CWE mapped: {mapped} / {total}")

    if crash_inputs:
        typer.echo("Extracting crash inputs from ARVO Docker images …")
        extracted, skipped, total = extract_crash_inputs(
            benchmark_dir, timeout_per_image=timeout
        )
        typer.echo(
            f"  Crash inputs: {extracted} extracted ({skipped} cached) / {total} total"
        )

    if extract_sources:
        typer.echo("Extracting vulnerable source files from cached repos …")
        sourced, total = extract_vulnerable_sources(benchmark_dir, cache_dir)
        typer.echo(f"  Vulnerable sources: {sourced} / {total}")

    if resolve_refs:
        typer.echo("Resolving vulnerable_source_ref commit hashes …")
        resolved, total = resolve_vulnerable_refs(benchmark_dir, cache_dir)
        typer.echo(f"  Vulnerable refs: {resolved} / {total}")


@app.command()
def fuzzing(
    target: str = typer.Option("libxml2", help="Parser target (e.g. 'libxml2')"),
    engine: str = typer.Option(
        "libfuzzer", help="Fuzz engine: libfuzzer, afl, honggfuzz"
    ),
    max_rounds: int = typer.Option(3, help="Maximum fuzzing rounds for the agent"),
    round_duration: int = typer.Option(60, help="Default round duration in seconds"),
    model: str = typer.Option("anthropic/claude-sonnet-4-6", help="Model to evaluate"),
    targets_root: Path = typer.Option(
        Path("../targets"), help="Targets root directory"
    ),
    limit: int | None = typer.Option(None, help="Max samples to evaluate"),
) -> None:
    """Run a single-agent live fuzzing campaign (Inspect-AI task).

    The agent iteratively writes, compiles, and refines a fuzz harness inside
    a Docker sandbox, running up to *max_rounds* fuzzing rounds to find crashes.

    Example:
        parser-security-eval fuzzing --target libxml2 --engine libfuzzer --max-rounds 3 --round-duration 60
    """
    from inspect_ai import eval as inspect_eval

    from parser_security_eval.tasks.fuzzing import live_fuzzing

    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    inspect_task = live_fuzzing(
        targets_dir=str(targets_root),
        target=target,
        engine=engine,
        max_rounds=max_rounds,
        round_duration=round_duration,
    )

    eval_kwargs: dict[str, object] = {"model": model, "limit": limit}
    logs = inspect_eval(inspect_task, **eval_kwargs)

    for log in logs:
        typer.echo(f"\nTask:   {log.eval.task}")
        typer.echo(f"Status: {log.status}")
        if log.results:
            for score in log.results.scores:
                metrics_str = ", ".join(
                    f"{k}={v.value:.3f}" for k, v in score.metrics.items()
                )
                typer.echo(f"  {score.name}: {metrics_str}")
