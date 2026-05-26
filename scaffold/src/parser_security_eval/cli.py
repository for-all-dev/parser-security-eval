"""CLI entry point for parser-security-eval."""

from __future__ import annotations

import asyncio
import json
import logging
from enum import Enum
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


# ---------------------------------------------------------------------------
# Enums for finite-choice CLI arguments
# ---------------------------------------------------------------------------


class TaskName(str, Enum):
    """Evaluation task names."""

    patching = "patching"
    triage = "triage"
    harness = "harness"


class FuzzEngine(str, Enum):
    """Supported fuzz engines."""

    libfuzzer = "libfuzzer"
    afl = "afl"
    honggfuzz = "honggfuzz"


class SanitizerType(str, Enum):
    """Supported sanitizers."""

    address = "address"
    undefined = "undefined"
    memory = "memory"


class DataSource(str, Enum):
    """Data sources for the curation pipeline."""

    arvo = "arvo"
    ossfuzz = "ossfuzz"
    all = "all"


app = typer.Typer(
    name="parser-security-eval", help="Parser security evaluation framework."
)

memory_app = typer.Typer(name="memory", help="Inspect per-target agent memory.")
app.add_typer(memory_app, name="memory")

# Register swarm sub-commands
from parser_security_eval.swarm.cli import app as swarm_app  # noqa: E402

app.add_typer(swarm_app, name="swarm")

# Register experiment sub-commands
from parser_security_eval.experiments.cli import app as experiment_app  # noqa: E402

app.add_typer(experiment_app, name="experiment")

# Register category3 sub-commands
category3_app = typer.Typer(
    name="category3", help="Category 3 dataset: per-sample parser classification."
)
app.add_typer(category3_app, name="category3")

logger = logging.getLogger(__name__)

_DEFAULT_CACHE = Path.home() / ".cache" / "parser-security-eval"

# Category 1 parser targets for the initial benchmark.
CATEGORY1_TARGETS: list[str] = ["libpng", "libjpeg-turbo", "libxml2", "zlib"]

# Category 2 parser targets (Dockerfiles exist, not yet battle-tested).
CATEGORY2_TARGETS: list[str] = ["freetype2", "libarchive", "expat", "pcre2"]


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
    source: str | DataSource,
    output: Path,
    targets: list[str],
    cache_dir: Path,
    limit: int | None = None,
    local_ids: set[int] | None = None,
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
        List of parser target names to include (e.g. CATEGORY1_TARGETS).
    cache_dir:
        Directory for caching downloaded data.
    limit:
        Optional cap on total vulnerabilities to ingest per source.
    local_ids:
        Optional set of ARVO localIds to include (Category 3 per-sample inclusion).

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
            cache_dir, arvo_output, limit=limit, targets=target_set, local_ids=local_ids
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
    source: DataSource = typer.Argument(
        help="Data source: 'arvo', 'ossfuzz', or 'all' (both)"
    ),
    output: Path = typer.Option(
        Path("../benchmark"), help="Output directory for curated data"
    ),
    cache_dir: Path = typer.Option(
        _DEFAULT_CACHE, help="Cache directory for downloaded data"
    ),
    targets: str = typer.Option(
        ",".join(CATEGORY1_TARGETS),
        help="Comma-separated list of target parser projects",
    ),
    limit: int | None = typer.Option(
        None, help="Max vulnerabilities to ingest per source"
    ),
    category3_registry: Path | None = typer.Option(
        None,
        help="Path to a Category 3 sample registry JSON. "
        "When provided, those ARVO localIds are included alongside target-based filtering.",
    ),
) -> None:
    """Ingest and curate vulnerability data from ARVO, oss-fuzz, or both.

    Runs the full curation pipeline: ingest, filter, deduplicate, validate,
    and export benchmark/metadata.json + benchmark/dataset.jsonl.
    """
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    target_list = [t.strip() for t in targets.split(",") if t.strip()]

    # Load Category 3 registry if provided
    local_ids: set[int] | None = None
    if category3_registry is not None:
        from parser_security_eval.dataset.category3 import load_registry

        registry = load_registry(category3_registry)
        local_ids = registry.local_ids
        typer.echo(
            f"Loaded Category 3 registry: {registry.total_samples} samples "
            f"from {registry.projects} projects"
        )

    typer.echo(f"Curating from source={source.value} for targets={target_list}")
    typer.echo(f"Output directory: {output}")

    summary = run_curation_pipeline(
        source=source,
        output=output,
        targets=target_list,
        cache_dir=cache_dir,
        limit=limit,
        local_ids=local_ids,
    )

    typer.echo("\n" + _format_summary(summary))
    typer.echo(f"\nExported to {output}/metadata.json and {output}/dataset.jsonl")


@app.command()
def evaluate(
    task: TaskName = typer.Argument(help="Task: 'patching', 'triage', or 'harness'"),
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
    engine: FuzzEngine = typer.Option(
        FuzzEngine.libfuzzer, help="Fuzz engine: libfuzzer, afl, honggfuzz"
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
    seed: int | None = typer.Option(
        None,
        help="Random seed for sample shuffling (patching task only). Requires --limit to have effect.",
    ),
) -> None:
    """Run an Inspect-AI evaluation task."""
    import warnings

    from inspect_ai import eval as inspect_eval

    if seed is not None and limit is None:
        warnings.warn(
            "--seed has no effect without --limit: the full dataset will be used.",
            stacklevel=1,
        )

    if task is TaskName.patching:
        from parser_security_eval.tasks.patching import vulnerability_patching

        inspect_task = vulnerability_patching(
            benchmark_dir=str(benchmark_dir),
            target=target,
            targets_root=str(targets_root),
            fuzzing_engine=engine.value,
            ready_only=ready_only,
            seed=seed,
        )

    elif task is TaskName.triage:
        from parser_security_eval.tasks.triage import crash_triage

        inspect_task = crash_triage(
            benchmark_dir=str(benchmark_dir),
            target=target,
            ready_only=ready_only,
        )

    elif task is TaskName.harness:
        if target is None:
            typer.echo("Error: --target is required for 'harness' task", err=True)
            raise typer.Exit(1)

        from parser_security_eval.tasks.harness import harness_generation

        inspect_task = harness_generation(
            targets_dir=str(targets_root),
            target=target,
            fuzz_duration=fuzz_duration,
            engine=engine.value,
        )

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
    sanitizer: SanitizerType = typer.Option(
        SanitizerType.address, help="Sanitizer: address, undefined, memory"
    ),
    engine: FuzzEngine = typer.Option(
        FuzzEngine.libfuzzer, help="Fuzz engine: libfuzzer, afl, honggfuzz"
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
        sanitizer=sanitizer.value,
        engine=engine.value,
    )

    async def _run() -> bool:
        async with DockerSandbox(config) as sandbox:
            return await sandbox.build_target()

    typer.echo(
        f"Building {target} (sanitizer={sanitizer.value}, engine={engine.value})..."
    )
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
    sanitizer: SanitizerType = typer.Option(
        SanitizerType.address, help="Sanitizer: address, undefined, memory"
    ),
    engine: FuzzEngine = typer.Option(
        FuzzEngine.libfuzzer, help="Fuzz engine: libfuzzer, afl, honggfuzz"
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
        sanitizer=sanitizer.value,
        engine=engine.value,
    )

    async def _run():
        async with DockerSandbox(config) as sandbox:
            return await score_patch(
                sandbox=sandbox,
                patch_diff=patch_diff,
                triggering_input_path=triggering_input,
                fuzz_target_binary=fuzz_binary,
                sanitizer=sanitizer.value,
                fuzzing_engine=engine.value,
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
    engine: FuzzEngine = typer.Option(
        FuzzEngine.libfuzzer, help="Fuzz engine: libfuzzer, afl, honggfuzz"
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
        engine=engine.value,
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


@memory_app.command("show")
def memory_show(
    target: str = typer.Argument(help="Parser target name (e.g. 'libxml2')"),
    targets_root: Path = typer.Option(
        Path("../targets"), help="Targets root directory"
    ),
    max_tokens: int = typer.Option(2000, help="Token budget for the context block"),
) -> None:
    """Print the agent memory context (as would be sent to an LLM) for a target.

    Example:
        parser-security-eval memory show libxml2
    """
    from parser_security_eval.memory.store import load_memory, memory_to_context

    memory = load_memory(target, targets_dir=targets_root)
    ctx = memory_to_context(memory, max_tokens=max_tokens)
    typer.echo(ctx)


@app.command()
def preprocess(
    target: str = typer.Argument(help="Parser target name (e.g. 'libpng')"),
    entry_point: str | None = typer.Option(
        None,
        "--entry-point",
        "-e",
        help=(
            "Entry-point function to focus on.  "
            "Defaults to the first value in key_entry_points from metadata.yaml."
        ),
    ),
    targets_root: Path = typer.Option(
        Path("../targets"), help="Targets root directory"
    ),
    model: str = typer.Option(
        "anthropic/claude-sonnet-4-6", help="Model to use for grammar extraction"
    ),
    force_refresh: bool = typer.Option(
        False,
        "--force-refresh",
        help="Ignore cached results and re-run all extraction steps",
    ),
) -> None:
    """Run the pre-processing pipeline for a parser target.

    Extracts a call graph and input-format grammar, assembles them into a
    HarnessContext, and outputs the result as JSON to stdout.  Results are
    also cached in targets/<target>/preprocess/ for subsequent runs.

    Example:
        parser-security-eval preprocess libpng --entry-point png_read_png
    """
    import os

    import yaml

    from parser_security_eval.preprocess.context_builder import build_context

    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    target_dir = targets_root / target
    if not target_dir.exists():
        typer.echo(f"Error: target directory not found: {target_dir}", err=True)
        raise typer.Exit(1)

    metadata_path = target_dir / "metadata.yaml"
    if not metadata_path.exists():
        typer.echo(f"Error: no metadata.yaml in {target_dir}", err=True)
        raise typer.Exit(1)

    with open(metadata_path) as fh:
        metadata = yaml.safe_load(fh)

    # Resolve entry point
    key_entry_points: list[str] = metadata.get("key_entry_points", [])
    if entry_point is None:
        if not key_entry_points:
            typer.echo(
                "Error: no --entry-point given and key_entry_points is empty in metadata.yaml",
                err=True,
            )
            raise typer.Exit(1)
        entry_point = key_entry_points[0]

    # Set the model environment variable for inspect_ai.model.get_model()
    os.environ.setdefault("INSPECT_EVAL_MODEL", model)

    async def _run() -> str:
        ctx = await build_context(
            target_dir=target_dir,
            entry_point=entry_point,  # type: ignore[arg-type]
            force_refresh=force_refresh,
        )
        return ctx.model_dump_json(indent=2)

    result_json = asyncio.run(_run())
    typer.echo(result_json)


# ---------------------------------------------------------------------------
# category3 sub-commands
# ---------------------------------------------------------------------------


@category3_app.command()
def audit(
    output: Path = typer.Option(
        Path("../benchmark/category3_audit.toml"),
        help="Path for the generated TOML audit file",
    ),
    cache_dir: Path = typer.Option(
        _DEFAULT_CACHE, help="Cache directory for ARVO clone"
    ),
) -> None:
    """Generate a TOML audit file listing candidate Category 3 projects.

    Scans the ARVO metadata index, excludes Category 1 and Category 2 projects,
    groups entries by (project, fuzz_target), and applies keyword-based
    heuristic classification.  The resulting TOML file is intended for
    human review.
    """
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    from parser_security_eval.dataset.arvo import fetch_arvo_index
    from parser_security_eval.dataset.category3 import (
        build_audit_list,
        write_audit_toml,
    )
    from parser_security_eval.dataset.ossfuzz import clone_ossfuzz_repo

    typer.echo("Fetching ARVO index...")
    metadata_path = fetch_arvo_index(cache_dir)

    typer.echo("Cloning/updating google/oss-fuzz (to verify project existence)...")
    ossfuzz_repo = clone_ossfuzz_repo(cache_dir)
    ossfuzz_projects = {
        p.name for p in (ossfuzz_repo / "projects").iterdir() if p.is_dir()
    }

    exclude = set(CATEGORY1_TARGETS + CATEGORY2_TARGETS)
    typer.echo(
        f"Building audit list (excluding {len(exclude)} Category 1/2 targets)..."
    )
    entries = build_audit_list(
        metadata_path,
        exclude_projects=exclude,
        ossfuzz_projects=ossfuzz_projects,
    )

    write_audit_toml(entries, output)

    # Summary statistics
    total_projects = len(entries)
    total_records = sum(e.total_records for e in entries)
    parser_fts = sum(
        1 for e in entries for ft in e.fuzz_targets if ft.relevance.value == "parser"
    )
    uncertain_fts = sum(
        1 for e in entries for ft in e.fuzz_targets if ft.relevance.value == "uncertain"
    )
    not_parser_fts = sum(
        1
        for e in entries
        for ft in e.fuzz_targets
        if ft.relevance.value == "not_parser"
    )

    typer.echo(f"\nAudit file written to {output}")
    typer.echo(f"  Projects: {total_projects}")
    typer.echo(f"  Total ARVO records: {total_records}")
    typer.echo(
        f"  Fuzz targets — parser: {parser_fts}, uncertain: {uncertain_fts}, not_parser: {not_parser_fts}"
    )
    typer.echo("\nReview the TOML file and set include = true/false for each target.")


@category3_app.command()
def classify(
    audit_file: Path = typer.Option(
        Path("../benchmark/category3_audit.toml"),
        help="Path to the TOML audit file to update",
    ),
    cache_dir: Path = typer.Option(
        _DEFAULT_CACHE, help="Cache directory for LLM classification results"
    ),
    model: str = typer.Option(
        "anthropic/claude-sonnet-4-6",
        help="Model to use for LLM classification of uncertain targets",
    ),
) -> None:
    """Run LLM classification on uncertain fuzz targets in the audit file.

    Reads the TOML audit file, sends uncertain fuzz targets to an LLM for
    classification, and writes the updated audit file back.
    """
    import os

    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    from parser_security_eval.dataset.category3 import (
        classify_uncertain_targets,
        read_audit_toml,
        write_audit_toml,
    )

    if not audit_file.exists():
        typer.echo(f"Error: audit file not found: {audit_file}", err=True)
        raise typer.Exit(1)

    entries = read_audit_toml(audit_file)
    os.environ.setdefault("INSPECT_EVAL_MODEL", model)

    classification_cache = cache_dir / "category3_classification_cache.json"
    classified = 0

    async def _run() -> list:
        nonlocal classified
        updated_entries = []
        for entry in entries:
            uncertain_count = sum(
                1 for ft in entry.fuzz_targets if ft.relevance.value == "uncertain"
            )
            if uncertain_count == 0:
                updated_entries.append(entry)
                continue

            updated_fts = await classify_uncertain_targets(
                profiles=entry.fuzz_targets,
                project=entry.name,
                cache_path=classification_cache,
            )
            classified += uncertain_count
            updated_entries.append(
                entry.model_copy(update={"fuzz_targets": updated_fts})
            )
        return updated_entries

    typer.echo(f"Classifying uncertain targets in {audit_file}...")
    updated_entries = asyncio.run(_run())

    write_audit_toml(updated_entries, audit_file)
    typer.echo(f"Classified {classified} uncertain fuzz targets.")
    typer.echo(f"Updated audit file: {audit_file}")


@category3_app.command("compile")
def compile_cmd(
    audit_file: Path = typer.Option(
        Path("../benchmark/category3_audit.toml"),
        help="Path to the reviewed TOML audit file",
    ),
    output: Path = typer.Option(
        Path("../benchmark/category3_samples.json"),
        help="Path for the compiled sample registry JSON",
    ),
    cache_dir: Path = typer.Option(
        _DEFAULT_CACHE, help="Cache directory containing the ARVO clone"
    ),
) -> None:
    """Compile the reviewed audit file into a Category 3 sample registry.

    Reads the TOML audit file (after human review), collects all ARVO
    localIds for included fuzz targets, and writes a JSON registry suitable
    for ``curate --category3-registry``.
    """
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    from parser_security_eval.dataset.arvo import fetch_arvo_index
    from parser_security_eval.dataset.category3 import (
        compile_registry,
        read_audit_toml,
        save_registry,
    )

    if not audit_file.exists():
        typer.echo(f"Error: audit file not found: {audit_file}", err=True)
        raise typer.Exit(1)

    entries = read_audit_toml(audit_file)
    metadata_path = fetch_arvo_index(cache_dir)
    registry = compile_registry(entries, metadata_path)

    save_registry(registry, output)
    typer.echo(
        f"\nCategory 3 registry: {registry.total_samples} samples from {registry.projects} projects"
    )
    typer.echo(f"Written to {output}")


@category3_app.command()
def bootstrap(
    registry_path: Path = typer.Option(
        Path("../benchmark/category3_samples.json"),
        help="Path to the Category 3 sample registry JSON",
    ),
    targets_root: Path = typer.Option(
        Path("../targets"), help="Root targets directory"
    ),
    cache_dir: Path = typer.Option(
        _DEFAULT_CACHE, help="Cache directory for the oss-fuzz clone"
    ),
    force: bool = typer.Option(False, help="Overwrite existing target directories"),
    projects: str | None = typer.Option(
        None,
        help="Comma-separated project names to bootstrap (default: all from registry)",
    ),
) -> None:
    """Bootstrap Docker target directories from oss-fuzz for Category 3 projects.

    Clones (or updates) google/oss-fuzz, extracts unique project names from
    the Category 3 sample registry, and imports Dockerfile + build.sh +
    metadata.yaml for each project into targets/.
    """
    import subprocess as _sp

    from parser_security_eval.dataset.category3 import load_registry
    from parser_security_eval.dataset.ossfuzz import (
        bootstrap_targets,
        clone_ossfuzz_repo,
    )

    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    if not registry_path.exists():
        typer.echo(f"Error: registry not found: {registry_path}", err=True)
        raise typer.Exit(1)

    registry = load_registry(registry_path)
    typer.echo(
        f"Loaded registry: {registry.total_samples} samples, "
        f"{registry.projects} projects"
    )

    # Determine which projects to bootstrap.
    if projects is not None:
        project_list = [p.strip() for p in projects.split(",") if p.strip()]
    else:
        project_list = sorted({s.project for s in registry.samples})

    # Exclude Category 1 and Category 2 targets.
    exclude = set(CATEGORY1_TARGETS + CATEGORY2_TARGETS)
    project_list = [p for p in project_list if p not in exclude]

    typer.echo(f"Projects to bootstrap: {len(project_list)}")

    typer.echo("Cloning/updating google/oss-fuzz …")
    try:
        ossfuzz_repo = clone_ossfuzz_repo(cache_dir)
    except _sp.CalledProcessError as exc:
        typer.echo(f"Error cloning oss-fuzz: {exc}", err=True)
        raise typer.Exit(1) from exc

    typer.echo(f"Bootstrapping into {targets_root} …")
    result = bootstrap_targets(project_list, ossfuzz_repo, targets_root, force=force)
    typer.echo(result.summary)


@category3_app.command()
def validate(
    targets_root: Path = typer.Option(
        Path("../targets"), help="Root targets directory"
    ),
    registry_path: Path = typer.Option(
        Path("../benchmark/category3_samples.json"),
        help="Path to the Category 3 sample registry JSON",
    ),
    build: bool = typer.Option(
        False, help="Attempt `docker build` for each target (slow)"
    ),
    projects: str | None = typer.Option(
        None,
        help="Comma-separated project names to validate (default: all from registry)",
    ),
) -> None:
    """Validate bootstrapped Category 3 target directories.

    Checks that each target has a valid Dockerfile, build.sh, and
    metadata.yaml.  With ``--build``, also runs ``docker build``.
    """
    import subprocess as _sp

    from parser_security_eval.dataset.category3 import load_registry
    from parser_security_eval.sandbox.build import validate_target_layout

    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    if not registry_path.exists():
        typer.echo(f"Error: registry not found: {registry_path}", err=True)
        raise typer.Exit(1)

    registry = load_registry(registry_path)

    if projects is not None:
        project_list = [p.strip() for p in projects.split(",") if p.strip()]
    else:
        project_list = sorted({s.project for s in registry.samples})

    exclude = set(CATEGORY1_TARGETS + CATEGORY2_TARGETS)
    project_list = [p for p in project_list if p not in exclude]

    ok_count = 0
    invalid_count = 0
    missing_count = 0

    for project in project_list:
        target_dir = targets_root / project
        if not target_dir.exists():
            typer.echo(f"  MISSING  {project}")
            missing_count += 1
            continue

        errors = validate_target_layout(target_dir)
        if errors:
            typer.echo(f"  INVALID  {project}")
            for err in errors:
                typer.echo(f"           {err}")
            invalid_count += 1
        else:
            typer.echo(f"  OK       {project}")
            ok_count += 1

        if build and not errors:
            tag = f"parser-eval-{project}:latest"
            typer.echo(f"           Building {tag} …")
            try:
                _sp.run(
                    ["docker", "build", "-t", tag, str(target_dir)],
                    check=True,
                    capture_output=True,
                    timeout=600,
                )
                typer.echo("           Build OK")
            except _sp.CalledProcessError as exc:
                stderr = exc.stderr.decode(errors="replace") if exc.stderr else ""
                typer.echo(f"           Build FAILED: {stderr[:200]}")
            except _sp.TimeoutExpired:
                typer.echo("           Build TIMEOUT (600s)")

    typer.echo(
        f"\nSummary: {ok_count} OK, {invalid_count} invalid, {missing_count} missing "
        f"(of {len(project_list)} projects)"
    )
