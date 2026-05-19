# Parser Security Eval

AI agents attack and defend parsers. Red-team agents fuzz C/C++ parser targets; blue-team agents patch what they find. The goal is an RL environment for parser security, but this repo is the eval/benchmark scaffolding that precedes it.

**Core crux**: what is the incidence of vulns per unit walltime of fuzzing in targeted parsers, as a function of model and agent architecture?

## Repository Structure

```
parser-security-eval/
├── scaffold/                        # Python package (uv, Python 3.14+)
│   ├── pyproject.toml
│   ├── experiments/                 # TOML sweep configs
│   ├── results/                     # Experiment run outputs
│   ├── logs/                        # .eval log files (ZIP archives from Inspect-AI)
│   └── src/parser_security_eval/
│       ├── cli.py                   # Typer CLI entry point
│       ├── models/                  # Pydantic data models
│       ├── dataset/                 # ARVO ingestion, OSV fetching, enrichment
│       ├── tasks/                   # Inspect-AI task definitions
│       │   ├── fuzzing.py           # Live single-agent fuzzing (4-phase loop)
│       │   ├── patching.py          # Vulnerability patching
│       │   ├── triage.py            # Crash triage
│       │   └── harness.py           # Harness generation
│       ├── sandbox/
│       │   ├── docker.py            # DockerSandbox, SandboxConfig
│       │   ├── campaign.py          # FuzzingCampaign, FuzzerEngine protocol + 3 impls
│       │   └── build.py             # Target build utilities
│       ├── scorers/                 # Patch scorer (apply/compile/crash_eliminated/tests_pass)
│       ├── triage/
│       │   └── casr.py              # CASRTriager: casr-san + casr-cluster, SHA-256 fallback
│       ├── memory/
│       │   ├── models.py            # Hypothesis, HarnessRecord, CrashSummary, TargetMemory
│       │   ├── store.py             # load_memory/save_memory/memory_to_context
│       │   └── merge.py             # Memory merging (cross-agent)
│       ├── experiments/
│       │   ├── models.py            # ExperimentConfig, RunSpec, ExperimentGrid
│       │   ├── runner.py            # TOML-driven restartable sweep runner
│       │   ├── state.py             # Crash-safe manifest persistence
│       │   ├── analysis.py          # Leaderboard + CWE/difficulty/target breakdowns
│       │   └── cli.py               # experiment run/status/analyze
│       ├── swarm/
│       │   ├── diversity.py         # FuzzEngine, MutationStrategy, AgentRole, DiversityConfig
│       │   ├── orchestrator.py      # SwarmOrchestrator.run_swarm() (asyncio + semaphore)
│       │   ├── result.py            # LiveFuzzingSessionResult, AgentResult, SwarmResult
│       │   └── cli.py               # swarm run/show-config
│       ├── scoring/                 # Coverage aggregation, crash dedup, swarm scoring
│       ├── distance/                # callgraph_distance.py, semantic_distance.py
│       ├── preprocess/
│       │   ├── callgraph.py         # FunctionNode, CallEdge, CallGraph (cflow or grep fallback)
│       │   ├── grammar.py           # FormatGrammar (LLM-based format spec extraction)
│       │   └── context_builder.py   # HarnessContext assembly, target-level caching
│       ├── prompts/                 # Jinja2 prompt files (NEVER inline in Python)
│       │   ├── loader.py
│       │   ├── fuzzing/
│       │   ├── harness/
│       │   ├── patching/
│       │   └── triage/
│       └── viz/                     # Streamlit visualizer
│           ├── app.py               # Entry: `uv run streamlit run viz/app.py` from scaffold/
│           ├── loader.py            # EvalLog → pandas DataFrame
│           └── views/               # overview, breakdown, samples, patching, trajectory, diff_viewer, usage
├── targets/                         # OSS-Fuzz parser targets
│   ├── _template/                   # Dockerfile, build.sh, metadata.yaml templates
│   ├── libpng/                      # Tier 1: corpus/, dictionary/png.dict
│   ├── libxml2/                     # Tier 1: corpus/, dictionary/xml.dict
│   ├── libjpeg-turbo/               # Tier 1: corpus/, dictionary/jpeg.dict
│   ├── zlib/                        # Tier 1: corpus/, dictionary/zlib.dict
│   ├── freetype/                    # Tier 2 (created, not battle-tested)
│   ├── libarchive/                  # Tier 2
│   ├── expat/                       # Tier 2
│   ├── pcre2/                       # Tier 2
│   └── fetch_corpora.py             # Idempotent seed corpus generator (stdlib only)
├── benchmark/                       # ARVO vulnerability benchmark
│   ├── dataset.jsonl                # 145 vulnerability records
│   ├── metadata.json
│   ├── summary.json
│   └── arvo/                        # ARVO-XXXXXXXX/ dirs: crash_input, crash_report.txt,
│                                    #   reference_patch.diff, vulnerable_src/
├── docs/                            # Architecture docs, lit review, direction notes
│   ├── 00-synthesis-and-recommendation.md
│   ├── fuzzing-litreview-recommendations.md  # 22 recs from 8+ papers
│   ├── fuzzing-diagnosis.agents.md           # v1 pipeline bug analysis
│   └── investigation-44-sonnet-patching.md
└── comms/site/                      # Static funder-facing results site
    ├── build.py                     # Python-Markdown + Jinja2 static site gen
    ├── content/                     # Markdown pages
    ├── templates/                   # Jinja2 HTML templates
    └── data/                        # example-results.json, schema.md
```

## Commands

```bash
# From scaffold/
uv run parser-security-eval --help

# Linting / formatting / type check / tests (run all before finishing any task)
uv run ruff check --fix
uv run ruff format
uv run ty check
uv run pytest

# Run an experiment sweep
uv run parser-security-eval experiment run experiments/patching-model-sweep.toml
uv run parser-security-eval experiment status results/patching-model-sweep-v2/
uv run parser-security-eval experiment analyze results/patching-model-sweep-v2/ --json out.json

# Visualizer
uv run streamlit run viz/app.py   # from scaffold/

# Dataset management
uv run parser-security-eval dataset --help
uv run parser-security-eval preprocess --help

# Swarm
uv run parser-security-eval swarm run --help
```

## Code Style

- Python 3.14+, `uv` package manager
- All data models: `pydantic.BaseModel`
- Full type hints; type-checked with `ty` (not pyright, not mypy)
- Avoid numpy. Use pandas where tabular data is needed.
- `ty` quirks:
  - `pd.DataFrame(columns=...)` needs `pd.Index([...])` not a plain list
  - `st.dataframe(on_select="rerun")` returns an unresolved `.selection` — use `getattr(event, "selection", None)`
  - `Score.value` is a union `ScoreValue` — use `score.as_float()` not `float(score.value)`

## Prompts

**Never inline prompt strings in Python.** Use the Jinja2-backed loader:

- Plain prompts: `scaffold/src/parser_security_eval/prompts/{domain}/system.prompt`
- Templates: `scaffold/src/parser_security_eval/prompts/{domain}/user.prompt.template` (Jinja2 `{{ var }}` syntax)
- Load via: `from parser_security_eval import prompts; prompts.load("domain.key", **kwargs)`

## Architecture: Fuzzing Task

`tasks/fuzzing.py` implements a 4-phase Analyze→Synthesize→Fuzz→Triage loop (from PBFuzz literature):

- `CYCLE_CAP_SECONDS = 1800` (30-minute cycles)
- `MAX_REPAIR_ITERS = 5`
- `FuzzingState` dataclass stored in `TaskState.store["fuzzing_state"]`
- 7 tool closures over shared state: `write_harness`, `compile_harness`, `add_seed`, `start_fuzzing`, `get_fuzzer_stats`, `get_crash_info`, `refine_harness`
- Memory integration: `load_memory(target)` / `save_memory()` / `memory_to_context()` for cross-session persistence

## Architecture: Targets (OSS-Fuzz Conventions)

All targets follow OSS-Fuzz conventions:

- Base image: `gcr.io/oss-fuzz-base/base-builder`
- Key env vars: `$CC`, `$CXX`, `$CFLAGS`, `$CXXFLAGS`, `$LIB_FUZZING_ENGINE`, `$SANITIZER`, `$FUZZING_ENGINE`, `$FUZZING_LANGUAGE`, `$OUT`, `$SRC`, `$WORK`
- `compile` entrypoint runs `build.sh`
- Supported engines: `libfuzzer`, `afl`, `honggfuzz`, `centipede`

**Known target gotchas:**
- `libpng`: Dockerfile must pin `git clone -b libpng16` — upstream moved to libpng18 and breaks the build
- `zlib/build.sh`: needs `shopt -s nullglob` for C-fuzzer glob to work

## Architecture: FuzzerEngine Protocol

`sandbox/campaign.py` defines `FuzzerEngine` as an explicitly-inherited Protocol (not structural). Three implementations: `LibFuzzerEngine`, `AFLPlusPlusEngine`, `HonggfuzzEngine`. OOM detection via exit code 137.

## Architecture: CASR Triage

`triage/casr.py` — CASRTriager:
- Primary: `casr-san` + `casr-cluster` if available in container
- Fallback: SHA-256 of top-5 stack frames for deduplication
- Can run locally or via `docker exec` (pass `container_id`)

## Architecture: Experiment Runner

- TOML config defines a Cartesian grid: models × targets × (durations or other axes)
- Crash-safe manifest persistence (JSON) — sweeps are restartable, skips completed runs
- CLI: `experiment run <config.toml> [--dry-run]`, `experiment status <dir>`, `experiment analyze <dir>`

## Architecture: Swarm

- `DiversityConfig.default_portfolio(n)`: mixed roles (explorer/exploiter), mixed engines, mixed mutation strategies
- `SwarmOrchestrator.run_swarm()`: asyncio gather with semaphore for parallelism cap
- `SwarmResult.marginal_crash_curve()`: tracks marginal value of each additional agent

## Architecture: Pre-processing

- `callgraph.py`: tries `cflow`, falls back to grep/regex on source
- `grammar.py`: LLM-based extraction of format grammar from spec text → `FormatGrammar`
- `context_builder.py`: assembles `HarnessContext` from call graph + grammar + type signatures; cached as JSON in target dir
- `HarnessContext` is passed to all downstream LLM calls (key quality driver from CKGFuzzer literature)

## Architecture: Memory System

Per-target persistent memory stored in `targets/<name>/memory.json`:
- `TargetMemory`: `hypotheses_tried`, `crashes_found`, `harness_variants`, `coverage_snapshots`
- `memory_to_context(mem, max_tokens=2000)` renders to string for LLM context injection
- Cross-agent merging via `memory/merge.py`

## Architecture: Visualizer

`scaffold/viz/` — Streamlit dashboard for `.eval` log files:
- `.eval` files are ZIP archives in `scaffold/logs/`
- Run: `uv run streamlit run viz/app.py` from `scaffold/`
- `EvalLog.results` IS populated (not None) — aggregate metrics exist
- Use `read_eval_log_sample_summaries()` for fast metadata without loading full logs
- Scorers: `cwe_scorer`, `severity_scorer`, `model_graded_fact` (value = 'C' or 'I'); `_patch_scorer` (value = float 0–1)

## Benchmark Dataset

- **145 ARVO records** from OSS-Fuzz corpus
- Breakdown: primarily libxml2 (~115), libjpeg-turbo (~22), libpng (~5), zlib (~3)
- Each record: `crash_input` (binary), `crash_report.txt` (ASAN output), `reference_patch.diff`, `vulnerable_src/`
- `_extract_affected_file()` priority: `database_specific.affected_file` → crash-state filename → `/blob/` URL reference → `affected[].package.name`

## Experiment Results (v2, for context)

**Patching** (`patching-model-sweep-v2`, 12 runs: 3 models × 4 targets):
- Claude Opus: mean ~76% across targets
- Claude Sonnet: mean ~72.5%
- GPT-4o-mini: mean ~52.5% (notably failed on libjpeg-turbo and zlib)

**Fuzzing** (`fuzzing-baseline-v2`, 36 runs: 3 models × 4 targets × 3 durations):
- All near-zero crashes. This is genuine, not a pipeline bug.
- v1 zeros were pipeline bugs (3 bugs fixed in commit `a245066`).
- v2 near-zeros mean: agents compile harnesses and run fuzzing cycles but find 0 crashes. This is the open challenge.

## Key Literature (from docs/fuzzing-litreview-recommendations.md)

- **PBFuzz**: 4-phase loop (Analyze/Synthesize/Fuzz/Triage), 30-min cycles → 25.6× speedup
- **HGFuzzer**: per-function targeting → 24.8× speedup
- **RandLuzz**: LLM-targeted seed generation → 2.1–4.8× speedup
- **MultiGo**: explorer/exploiter agent roles → crash diversity
- **CKGFuzzer**: call graph context for LLM → better harness quality
- Key principle: LLMs operate best on structured IRs (call graphs, type signatures), not raw source

## Git / Workflow

- Branch name convention: `issue-<N>-<slug>`
- Never push to main without asking first
- Never open PRs before local testing (especially UI changes)
- `uv run ruff check --fix && uv run ruff format && uv run ty check && uv run pytest` before any commit
