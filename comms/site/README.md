# Parser Security Eval — Results Site

Static site generator for experiment results from [issue #53](https://github.com/for-all-dev/parser-security-eval/issues/53) and future experiments.

## Quick start

```sh
cd comms/site
uv run python build.py          # builds to dist/ from data/
open dist/index.html            # view locally
```

## Using real experiment data

The builder reads from `comms/site/data/`. Point it at your actual results with
`--data-dir`, or copy/symlink the framework output files there:

```sh
# Option A: point directly at the output directory
uv run python build.py --data-dir ../../scaffold/results/fuzzing-baseline

# Option B: copy the files in
cp ../../scaffold/results/fuzzing-baseline/manifest.json data/
uv run python build.py
```

### Generating the analysis JSON

The Breakdowns page (CWE, difficulty, target charts) needs the analysis output:

```sh
cd scaffold
uv run parser-security-eval experiment analyze results/fuzzing-baseline \
    --json ../comms/site/data/analysis.json

cd ../comms/site
uv run python build.py
```

## Data formats

Two file types are accepted (auto-detected by structure). See [`data/schema.md`](data/schema.md) for details.

| File | Source | Populates |
|------|--------|-----------|
| `manifest.json` | Written by `experiment run` to `<output_dir>/manifest.json` | Overview (status grid, run durations), Results (run table) |
| `analysis.json` | Written by `experiment analyze --json` | Results (leaderboard, pipeline stages, token usage), Breakdowns (CWE, difficulty, target charts) |

Files starting with `_` are ignored. Both files can coexist.

## Output pages

| Page | Contents |
|------|----------|
| `dist/index.html` | Hero, stat cards (runs / status / timing), model×target status grid, run duration chart, content prose |
| `dist/results.html` | Full run table; leaderboard + pipeline + token charts (when analysis available) |
| `dist/breakdowns.html` | Target, CWE, and difficulty score breakdowns (when analysis available); empty-state with instructions otherwise |

All pages are self-contained. Charts use Chart.js from CDN (internet required to render).

## Adding prose content

Drop `.md` files into `comms/site/content/` with YAML frontmatter:

```markdown
---
title: Post-Experiment Analysis
order: 4
---

Written analysis goes here...
```

Content pages appear on the Overview page in order.

## CLI options

```
uv run python build.py --help
```

| Flag | Default | Description |
|------|---------|-------------|
| `--data-dir` | `data/` | Directory with manifest.json / analysis.json |
| `--content-dir` | `content/` | Markdown content directory |
| `--output-dir` | `dist/` | Output directory |
| `--templates-dir` | `templates/` | Jinja2 templates directory |
