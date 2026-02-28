# parser-security-eval

Parser security evaluation framework: AI agents attack and defend parsers.

## Setup

```bash
cd scaffold
uv sync
```

## CLI Commands

All commands are available via `uv run parser-security-eval <command>`.

### `curate` — Ingest vulnerability data

```bash
uv run parser-security-eval curate <source> [--output PATH] [--limit N]
```

| Argument/Option | Description |
|---|---|
| `source` | Data source: `arvo` or `ossfuzz` |
| `--output PATH` | Output directory for curated data (default: `benchmark`) |
| `--limit N` | Max vulnerabilities to ingest |

### `evaluate` — Run an Inspect-AI evaluation task

```bash
uv run parser-security-eval evaluate <task> --target TARGET [--model MODEL]
```

| Argument/Option | Description |
|---|---|
| `task` | Task to run: `patching`, `harness`, or `triage` |
| `--target TARGET` | Parser target name (e.g. `libpng`) |
| `--model MODEL` | Model to evaluate (default: `openai/gpt-4o`) |

### `build-target` — Build a parser target in Docker

```bash
uv run parser-security-eval build-target <target> [--sanitizer SANITIZER] [--engine ENGINE]
```

| Argument/Option | Description |
|---|---|
| `target` | Parser target to build (e.g. `libpng`) |
| `--sanitizer` | Sanitizer: `address`, `undefined`, `memory` (default: `address`) |
| `--engine` | Fuzz engine: `libfuzzer`, `afl++`, `honggfuzz` (default: `libfuzzer`) |

### `verify` — Verify a patch against a vulnerability

```bash
uv run parser-security-eval verify <target> <vuln_id> <patch>
```

| Argument/Option | Description |
|---|---|
| `target` | Parser target name |
| `vuln_id` | Vulnerability ID (CVE or oss-fuzz issue number) |
| `patch` | Path to the patch file |

## Development

```bash
cd scaffold
uv run ruff check --fix    # lint
uv run ruff format          # format
uv run pytest               # test
```
