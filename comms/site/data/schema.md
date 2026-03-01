# Experiment Data Schema

The site generator ingests all `.json` and `.toml` files in `comms/site/data/`
(files prefixed with `_` are ignored). Files are merged in sorted order; later
files override earlier ones for `experiment` keys, and `runs` arrays are
concatenated.

## Top-level structure

```json
{
  "experiment": { ... },
  "runs": [ ... ]
}
```

## `experiment` object

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | yes | Human-readable experiment name |
| `issue` | int | no | GitHub issue number |
| `date` | string | no | ISO 8601 date (`"2026-03-01"`) |
| `description` | string | no | Short prose description |
| `targets` | string[] | no | Canonical target list (for ordering) |
| `models` | string[] | no | Canonical model list |
| `engines` | string[] | no | Canonical engine list |
| `conditions` | string[] | no | Canonical condition list |
| `notes` | string | no | Arbitrary notes shown in site banner |

## `runs` array items

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `id` | string | yes | Unique run identifier |
| `target` | string | yes | Parser library name |
| `model` | string\|null | yes | LLM model ID, or null for baselines |
| `engine` | string | yes | Fuzzing engine (`"libFuzzer"`, `"AFL++"`) |
| `condition` | string | yes | `"30min-cycles"`, `"2hr-continuous"`, `"oss-fuzz-baseline"`, `"random-harness"` |
| `replicate` | int | no | Replicate number within this config |
| `duration_seconds` | int | no | Actual wall-clock duration |
| `unique_crashes` | int | yes | Number of unique crashes found |
| `cpu_hours` | float | yes | CPU time consumed |
| `coverage_pct` | float | no | Line/branch coverage % at end of run |
| `harness_compile_attempts` | int\|null | no | Compile iterations needed (null for baselines) |
| `time_to_first_crash_seconds` | int\|null | no | Seconds to first crash (null if no crash) |
| `timeline` | object[] | no | Time-series data (see below) |

## `timeline` items

| Field | Type | Description |
|-------|------|-------------|
| `time_seconds` | int | Elapsed seconds from run start |
| `crashes` | int | Cumulative unique crashes at this point |
| `coverage_pct` | float | Coverage % at this point |

## TOML equivalent

The same schema works in TOML. Arrays of inline tables are used for `runs` and
`timeline`. Example:

```toml
[experiment]
name = "Baseline: Vulns per CPU-Hour"
issue = 53
date = "2026-03-01"

[[runs]]
id = "run-001"
target = "libpng"
model = "claude-sonnet-4-6"
engine = "libFuzzer"
condition = "30min-cycles"
unique_crashes = 3
cpu_hours = 2.0

[[runs.timeline]]
time_seconds = 0
crashes = 0
coverage_pct = 0.0
```
