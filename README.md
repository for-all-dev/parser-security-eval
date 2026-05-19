# parser-security-eval

Evaluation framework for AI-driven parser security. An AI agent is given a vulnerable parser and a crash report, and must produce a patch that eliminates the vulnerability. Benchmarked against 209 real-world vulnerabilities from [ARVO](https://github.com/n132/ARVO) across 4 parser libraries, with ground-truth reference patches for scoring.

## Prerequisites

- Python 3.14+ and [uv](https://docs.astral.sh/uv/)
- Docker (for building and fuzzing parser targets)
- ~200 MB disk for the ARVO-Meta database download (cached)

## Quickstart

All commands run from the `scaffold/` directory.

```bash
cd scaffold
uv sync
```

### 1. Curate the benchmark dataset

Ingest vulnerability metadata from ARVO and/or oss-fuzz, filter to Tier 1 targets, deduplicate, and export `benchmark/metadata.json`:

```bash
uv run parser-security-eval curate arvo
```

This populates `benchmark/` with per-vulnerability directories containing crash reports and empty reference patch stubs.

### 2. Fetch reference patches

Download the ARVO-Meta SQLite database, look up fix commits, and generate `reference_patch.diff` for each vulnerability from upstream git history:

```bash
uv run parser-security-eval fetch-artifacts
```

This fills in the `reference_patch.diff` files that step 1 left empty. Patches are generated via `git diff fix_commit~1..fix_commit` from shallow upstream clones. Expects ~87% coverage of ARVO records.

### 3. Enrich the dataset

Replace stub crash reports with full ASAN output from the ARVO-Meta database, map crash types to CWE IDs, and optionally extract crash inputs from ARVO Docker images:

```bash
# Fast: enrich crash reports + CWE mapping + vulnerable sources (seconds)
uv run parser-security-eval enrich-dataset --no-crash-inputs

# Full: also extract crash inputs from Docker images (slow, pulls ~127 images)
uv run parser-security-eval enrich-dataset --crash-inputs
```

### 4. Build parser targets

Build the Tier 1 parser targets in Docker (oss-fuzz base-builder images with AddressSanitizer):

```bash
uv run parser-security-eval build-target libpng
uv run parser-security-eval build-target libjpeg-turbo
uv run parser-security-eval build-target libxml2
uv run parser-security-eval build-target zlib
```

### 5. Run evaluations

Run an Inspect-AI evaluation task against a model:

```bash
uv run parser-security-eval evaluate patching --model anthropic/claude-sonnet-4-6
uv run parser-security-eval evaluate triage
uv run parser-security-eval evaluate harness --target libpng
```

### 6. Run experiment sweeps

Run multi-model, multi-target evaluation sweeps from a TOML config:

```bash
# Preview what will run (no execution)
uv run parser-security-eval experiment run experiments/patching-model-sweep.toml --dry-run

# Execute the sweep (restartable — safe to Ctrl-C and resume)
uv run parser-security-eval experiment run experiments/patching-model-sweep.toml

# Check progress
uv run parser-security-eval experiment status results/patching-model-sweep

# Analyze results (rich tables + optional JSON export)
uv run parser-security-eval experiment analyze results/patching-model-sweep --json results.json
```

Example TOML configs in `scaffold/experiments/`: `patching-model-sweep.toml`, `triage-sweep.toml`, `fuzzing-baseline.toml`.

### 7. Verify a patch

Test a specific patch against a vulnerability:

```bash
uv run parser-security-eval verify libpng ARVO-42498959 path/to/patch.diff
```

## Project structure

```
parser-security-eval/
  benchmark/              Curated vulnerability dataset
    metadata.json           209 records with IDs, targets, severities, paths
    arvo/ARVO-{id}/         Per-vulnerability artifacts (gitignored — run steps 1–3 below)
      crash_report.txt        Full ASAN/MSAN crash output
      crash_input             Triggering input bytes (from ARVO Docker images)
      reference_patch.diff    Ground-truth fix (from upstream git)
      vulnerable_src/         Pre-fix source files (from upstream git)
  scaffold/               Python package (uv project)
    src/parser_security_eval/
      cli.py                  Typer CLI entry point
      dataset/
        arvo.py                 ARVO metadata ingestion
        artifacts.py            Reference patch fetching from ARVO-Meta
        enrich.py               Crash report, CWE, and crash input enrichment
        curator.py              Deduplication, validation, export
        ossfuzz.py              oss-fuzz bug ingestion
      models/
        vulnerability.py        VulnerabilityRecord pydantic model
      sandbox/
        docker.py               Docker sandbox for builds and fuzzing
      scorers/
        patch.py                Patch correctness scorer
        coverage.py             Code coverage scorer
      tasks/
        patching.py             Vulnerability patching eval task
        triage.py               Crash triage eval task
        harness.py              Fuzz harness generation eval task
        fuzzing.py              Live fuzzing eval task
      experiments/
        models.py               Pydantic models for experiment configs and state
        runner.py               Grid expansion, task building, run loop
        state.py                Manifest persistence (atomic save/load/resume)
        analysis.py             Results aggregation and breakdowns
        cli.py                  Typer sub-app (run/status/analyze commands)
    experiments/                Example TOML experiment configs
  targets/                Parser target definitions (oss-fuzz compatible)
    libpng/                 Dockerfile, build.sh, metadata.yaml, corpus/
    libjpeg-turbo/
    libxml2/
    zlib/
    _template/              Skeleton for adding new targets
```

## CLI reference

All commands: `uv run parser-security-eval <command> --help`

| Command | Description |
|---|---|
| `curate <source>` | Ingest from `arvo`, `ossfuzz`, or `all`. Writes `benchmark/metadata.json`. |
| `fetch-artifacts` | Download ARVO-Meta DB, generate reference patches from upstream repos. |
| `enrich-dataset` | Enrich crash reports with ASAN output, map CWE, extract crash inputs/sources. |
| `build-target <target>` | Build a parser target in Docker with sanitizer + fuzz engine. |
| `evaluate <task>` | Run an Inspect-AI eval: `patching`, `triage`, or `harness`. |
| `fuzzing` | Run a single-agent live fuzzing campaign. |
| `experiment run <config.toml>` | Run or resume a TOML-driven experiment sweep. |
| `experiment status <output_dir>` | Show run statuses for an experiment. |
| `experiment analyze <output_dir>` | Leaderboard + breakdowns from completed runs. |
| `verify <target> <id> <patch>` | Test a patch against a specific vulnerability. |

## Development

```bash
cd scaffold
uv run ruff check --fix    # lint
uv run ruff format         # format
uv run pytest              # test (333 tests)
```
